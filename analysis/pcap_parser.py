"""Summarize a lab PCAP into SQLite and flag observable network behavior.

Run on Kali: python3 -m analysis.pcap_parser results/pcap/capture.pcapng
Requires tshark. Only packet metadata is analyzed; encrypted payload is not decoded.
"""

import argparse
import csv
import ipaddress
import sqlite3
import subprocess
from collections import defaultdict
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    packet_count INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    duration_ms REAL NOT NULL,
    payload_bytes INTEGER NOT NULL,
    tcp_stream INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    flow_id INTEGER,
    detail TEXT NOT NULL,
    FOREIGN KEY (flow_id) REFERENCES flows(id)
);
"""


def _packets(pcap_file):
    command = [
        "tshark", "-n", "-r", str(pcap_file), "-Y", "ip && tcp",
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
    ]
    for field in (
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
        "frame.len", "tcp.len", "tcp.stream",
    ):
        command.extend(("-e", field))
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"tshark failed: {result.stderr.strip()}")
    for row in csv.reader(result.stdout.splitlines(), delimiter="\t"):
        if len(row) != 8 or any(not item for item in row):
            continue
        ts, src, dst, sport, dport, size, payload, stream = row
        yield (float(ts), src, dst, int(sport), int(dport), int(size),
               int(payload), int(stream))


def parse_pcap(pcap_file, db_path):
    """Replace derived rows with directional TCP flows for one capture."""
    pcap_file = Path(pcap_file).expanduser().resolve(strict=True)
    db_path = Path(db_path).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    aggregates = defaultdict(lambda: [float("inf"), float("-inf"), 0, 0, 0])
    for ts, src, dst, sport, dport, size, payload, stream in _packets(pcap_file):
        key = (src, dst, sport, dport, stream)
        item = aggregates[key]
        item[0] = min(item[0], ts)
        item[1] = max(item[1], ts)
        item[2] += 1
        item[3] += size
        item[4] += payload
    with sqlite3.connect(db_path) as db:
        db.executescript(SCHEMA)
        db.execute("DELETE FROM alerts")
        db.execute("DELETE FROM flows")
        for (src, dst, sport, dport, stream), (first, last, count, size, payload) in sorted(
            aggregates.items(), key=lambda pair: (pair[1][0], pair[0])
        ):
            db.execute(
                "INSERT INTO flows (ts, src_ip, dst_ip, src_port, dst_port, "
                "protocol, packet_count, total_bytes, duration_ms, payload_bytes, tcp_stream) "
                "VALUES (?, ?, ?, ?, ?, 'TCP', ?, ?, ?, ?, ?)",
                (first, src, dst, sport, dport, count, size,
                 (last - first) * 1000, payload, stream),
            )
        return len(aggregates)


def flag_exfiltration(db_path, attacker_ip="192.168.56.10", port=9002,
                       min_payload=4096):
    """Flag victim-to-attacker transfer-port flows with enough TCP payload."""
    ipaddress.ip_address(attacker_ip)
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM alerts WHERE kind = 'suspected_exfiltration'")
        rows = db.execute(
            "SELECT id, payload_bytes FROM flows "
            "WHERE dst_ip = ? AND dst_port = ? AND payload_bytes >= ?",
            (attacker_ip, port, min_payload),
        ).fetchall()
        db.executemany(
            "INSERT INTO alerts (kind, flow_id, detail) VALUES (?, ?, ?)",
            [("suspected_exfiltration", flow_id,
              f"{size} outbound TCP payload bytes to {attacker_ip}:{port}")
             for flow_id, size in rows],
        )
        return len(rows)


def flag_large_outbound(db_path, victim_ip="192.168.56.20", min_payload=1048576):
    """Flag outbound flows above a separate volume threshold."""
    ipaddress.ip_address(victim_ip)
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM alerts WHERE kind = 'large_outbound'")
        rows = db.execute(
            "SELECT id, dst_ip, payload_bytes FROM flows "
            "WHERE src_ip = ? AND dst_ip != ? AND payload_bytes >= ?",
            (victim_ip, victim_ip, min_payload),
        ).fetchall()
        db.executemany(
            "INSERT INTO alerts (kind, flow_id, detail) VALUES (?, ?, ?)",
            [("large_outbound", flow_id, f"{size} TCP payload bytes to {dst}")
             for flow_id, dst, size in rows],
        )
        return len(rows)


def flag_c2_beacon(db_path, attacker_ip="192.168.56.10", port=9001,
                   min_connections=3, tolerance=0.25):
    """Flag regularly spaced C2 connections; one-shot C2 is not a beacon."""
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM alerts WHERE kind = 'c2_beacon'")
        rows = db.execute(
            "SELECT id, ts FROM flows WHERE dst_ip = ? AND dst_port = ? "
            "ORDER BY ts", (attacker_ip, port),
        ).fetchall()
        if len(rows) < min_connections:
            return 0
        intervals = [b[1] - a[1] for a, b in zip(rows, rows[1:])]
        average = sum(intervals) / len(intervals)
        if average <= 0 or any(abs(gap - average) > average * tolerance
                               for gap in intervals):
            return 0
        db.execute(
            "INSERT INTO alerts (kind, flow_id, detail) VALUES (?, ?, ?)",
            ("c2_beacon", rows[-1][0],
             f"{len(rows)} C2 connections, mean interval {average:.3f}s"),
        )
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--db", type=Path, default=Path("results/pcap/flows.sqlite"))
    parser.add_argument("--attacker-ip", default="192.168.56.10")
    parser.add_argument("--victim-ip", default="192.168.56.20")
    args = parser.parse_args()
    count = parse_pcap(args.pcap, args.db)
    exfil = flag_exfiltration(args.db, args.attacker_ip)
    large = flag_large_outbound(args.db, args.victim_ip)
    beacon = flag_c2_beacon(args.db, args.attacker_ip)
    print(f"PASS: {count} directional TCP flows saved to {args.db}")
    print(f"Alerts: suspected exfiltration={exfil}, large outbound={large}, C2 beacon={beacon}")
    with sqlite3.connect(args.db) as db:
        for row in db.execute(
            "SELECT src_ip, src_port, dst_ip, dst_port, packet_count, "
            "total_bytes, payload_bytes FROM flows ORDER BY ts"
        ):
            src, sport, dst, dport, packets, wire, payload = row
            print(f"{src}:{sport} -> {dst}:{dport}: "
                  f"{packets} packets, {wire} frame bytes, {payload} payload bytes")


if __name__ == "__main__":
    main()
