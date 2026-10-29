"""analysis/pcap_parser.py — PCAP Flow Parser & Network Traffic Analysis (Module 3B).

Parses Wireshark/tshark .pcap capture files, aggregates packets into 5-tuple
network flows, populates a SQLite database, and executes detection queries for:
  1. Data exfiltration to Attacker IP
  2. C2 beaconing activity
  3. Large outbound volume anomalies
"""

import argparse
from datetime import datetime, timezone
import math
import os
import sqlite3
import sys
from typing import Dict, List, Optional, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import config

try:
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP
except ImportError:
    PcapReader = None


def format_timestamp(epoch_seconds: float) -> str:
    """Convert UNIX epoch float to ISO 8601 UTC string with millisecond precision."""
    dt = datetime.fromtimestamp(epoch_seconds, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def init_database(db_path: str):
    """Create flows table with required schema."""
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT NOT NULL,
            packet_count INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            duration_ms REAL NOT NULL
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_ips ON flows(src_ip, dst_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_ports ON flows(dst_port)")
    conn.commit()
    conn.close()


def parse_pcap(pcap_file: str, db_path: str) -> int:
    """Parse a PCAP file using Scapy, aggregate packets into flows, and load into SQLite.
    
    Args:
        pcap_file: Path to .pcap or .pcapng file
        db_path: Path to target SQLite database
        
    Returns:
        Number of flows inserted into database
    """
    if PcapReader is None:
        raise ImportError("Scapy is required to parse PCAP files. Please install scapy.")

    if not os.path.exists(pcap_file):
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

    init_database(db_path)

    # Dictionary mapping 5-tuple -> flow stats
    # Key: (src_ip, dst_ip, src_port, dst_port, protocol)
    flows: Dict[Tuple, Dict] = {}

    reader = PcapReader(pcap_file)
    try:
        for pkt in reader:
            if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                continue

            ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            pkt_len = len(pkt)
            pkt_time = float(pkt.time)

            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
                sport = 0
                dport = 0
            else:
                proto = "OTHER"
                sport = 0
                dport = 0

            flow_key = (src_ip, dst_ip, sport, dport, proto)

            if flow_key not in flows:
                flows[flow_key] = {
                    "first_ts": pkt_time,
                    "last_ts": pkt_time,
                    "packet_count": 1,
                    "total_bytes": pkt_len
                }
            else:
                f = flows[flow_key]
                if pkt_time < f["first_ts"]:
                    f["first_ts"] = pkt_time
                if pkt_time > f["last_ts"]:
                    f["last_ts"] = pkt_time
                f["packet_count"] += 1
                f["total_bytes"] += pkt_len
    finally:
        reader.close()

    # Insert flows into SQLite
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    rows = []
    for (src_ip, dst_ip, sport, dport, proto), stats in flows.items():
        duration_ms = (stats["last_ts"] - stats["first_ts"]) * 1000.0
        ts_str = format_timestamp(stats["first_ts"])
        rows.append((
            ts_str,
            src_ip,
            dst_ip,
            sport,
            dport,
            proto,
            stats["packet_count"],
            stats["total_bytes"],
            duration_ms
        ))

    cursor.executemany("""
        INSERT INTO flows (ts, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, total_bytes, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)

    conn.commit()
    inserted_count = len(rows)
    conn.close()

    return inserted_count


def flag_exfiltration(
    db_path: str,
    threshold_bytes: int = 50000,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None
) -> List[Dict]:
    """Query 1: Return flows exceeding size threshold from victim to attacker."""
    if src_ip is None:
        src_ip = getattr(config, "VICTIM_IP", "192.168.56.20")
    if dst_ip is None:
        dst_ip = getattr(config, "ATTACKER_IP", "192.168.56.10")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = """
        SELECT id, ts, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, total_bytes, duration_ms
        FROM flows
        WHERE total_bytes >= ? AND src_ip = ? AND dst_ip = ?
        ORDER BY total_bytes DESC
    """
    cursor.execute(query, (threshold_bytes, src_ip, dst_ip))
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


def flag_c2_beacon(
    db_path: str,
    dst_ip: Optional[str] = None,
    c2_port: Optional[int] = None,
    min_connections: int = 2
) -> Dict:
    """Query 2: Detect periodic beaconing to C2 server based on connection intervals."""
    if dst_ip is None:
        dst_ip = getattr(config, "ATTACKER_IP", "192.168.56.10")
    if c2_port is None:
        c2_port = getattr(config, "C2_PORT", 9001)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = """
        SELECT id, ts, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, total_bytes
        FROM flows
        WHERE dst_ip = ? AND dst_port = ?
        ORDER BY ts ASC
    """
    cursor.execute(query, (dst_ip, c2_port))
    flows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    if len(flows) < min_connections:
        return {
            "beaconing_detected": False,
            "flow_count": len(flows),
            "reason": f"Insufficient connections ({len(flows)} < {min_connections})",
            "flows": flows
        }

    # Calculate inter-arrival intervals
    timestamps = []
    for f in flows:
        try:
            dt = datetime.fromisoformat(f["ts"].replace("Z", "+00:00"))
            timestamps.append(dt.timestamp())
        except Exception:
            continue

    intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

    if not intervals:
        return {"beaconing_detected": False, "flow_count": len(flows), "flows": flows}

    mean_interval = sum(intervals) / len(intervals)
    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
    stddev = math.sqrt(variance)

    # Beaconing is considered periodic if intervals are relatively consistent
    is_periodic = stddev < (mean_interval * 0.4) or stddev < 5.0

    return {
        "beaconing_detected": True,
        "is_periodic": is_periodic,
        "flow_count": len(flows),
        "mean_interval_sec": round(mean_interval, 3),
        "stddev_sec": round(stddev, 3),
        "intervals": [round(x, 3) for x in intervals],
        "flows": flows
    }


def flag_large_outbound(
    db_path: str,
    threshold_bytes: int = 100000
) -> List[Dict]:
    """Query 3: General query for any outbound flow exceeding a high-volume threshold."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = """
        SELECT id, ts, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, total_bytes, duration_ms
        FROM flows
        WHERE total_bytes >= ?
        ORDER BY total_bytes DESC
    """
    cursor.execute(query, (threshold_bytes,))
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


def record_detection_latency(
    db_path: str,
    analysis_ts: Optional[datetime] = None
) -> Optional[float]:
    """Calculate detection latency: delta between first exfiltration packet and detection.
    
    Returns:
        Latency in seconds, or None if no exfiltration was detected.
    """
    exfil_flows = flag_exfiltration(db_path, threshold_bytes=1000)
    if not exfil_flows:
        return None

    # Earliest exfiltration packet timestamp
    first_flow_ts_str = sorted(exfil_flows, key=lambda f: f["ts"])[0]["ts"]
    first_flow_dt = datetime.fromisoformat(first_flow_ts_str.replace("Z", "+00:00"))

    if analysis_ts is None:
        analysis_ts = datetime.now(timezone.utc)

    latency_sec = max(0.0, (analysis_ts - first_flow_dt).total_seconds())
    return latency_sec


def main():
    parser = argparse.ArgumentParser(description="ISL PCAP Flow Parser & Analyzer (Module 3B)")
    parser.add_argument("--pcap", required=True, help="Path to input PCAP file")
    parser.add_argument("--db", default="flows.sqlite", help="Path to output SQLite database")
    parser.add_argument("--threshold", type=int, default=50000, help="Exfiltration size threshold in bytes")
    args = parser.parse_args()

    print(f"[*] Parsing {args.pcap} into {args.db}...")
    count = parse_pcap(args.pcap, args.db)
    print(f"[+] Loaded {count} network flows into SQLite database.")

    print("\n--- Detection Query 1: Data Exfiltration ---")
    exfil = flag_exfiltration(args.db, threshold_bytes=args.threshold)
    print(f"Flagged {len(exfil)} exfiltration flows:")
    for f in exfil:
        print(f"  [{f['ts']}] {f['src_ip']}:{f['src_port']} -> {f['dst_ip']}:{f['dst_port']} ({f['total_bytes']} bytes)")

    print("\n--- Detection Query 2: C2 Beaconing ---")
    beacon = flag_c2_beacon(args.db)
    print(f"Beaconing detected: {beacon['beaconing_detected']} ({beacon['flow_count']} flows)")
    if beacon.get("mean_interval_sec") is not None:
        print(f"  Mean interval: {beacon['mean_interval_sec']}s, StdDev: {beacon['stddev_sec']}s")

    print("\n--- Detection Query 3: Large Outbound Flows ---")
    large = flag_large_outbound(args.db, threshold_bytes=args.threshold)
    print(f"Flagged {len(large)} large outbound flows.")


if __name__ == "__main__":
    main()
