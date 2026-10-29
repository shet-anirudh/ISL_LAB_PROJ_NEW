"""analysis/forensic_report.py — Forensic Incident Report Generator (Module 3C).

Aggregates all JSON-lines logs from victim defense, attacker C2, ransomware simulator,
file transfer exfiltration, and SQLite PCAP network flows into a comprehensive,
structured forensic incident report in Markdown.
"""

import argparse
from datetime import datetime, timezone
import json
import os
import sqlite3
import sys
from typing import Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import config


def parse_json_lines_file(file_path: Optional[str]) -> List[Dict]:
    """Safely parse a JSON-lines formatted log file."""
    if not file_path or not os.path.exists(file_path):
        return []

    events = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    data = json.loads(line_str)
                    events.append(data)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[!] Warning reading log {file_path}: {e}", file=sys.stderr)
    return events


def parse_iso_timestamp(ts_str: str) -> float:
    """Convert ISO timestamp string to epoch seconds for chronological sorting."""
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return 0.0


def extract_iocs(all_events: List[Dict], flows: List[Dict]) -> Dict:
    """Extract and categorize IOCs across Network, Filesystem, Process, and Cryptographic domains."""
    iocs = {
        "network": {
            "c2_ips": set(),
            "c2_ports": set(),
            "transfer_ports": set(),
            "exfiltrated_flows_count": 0,
            "total_exfiltrated_bytes": 0
        },
        "filesystem": {
            "honeypot_triggers": [],
            "ransom_extension": config.ENCRYPTED_EXT,
            "key_extension": config.KEY_EXT,
            "ransom_notes_dropped": set(),
            "encrypted_files": [],
            "shadow_copy_attempts": []
        },
        "process": {
            "malware_pids": set(),
            "containment_actions": [],
            "process_names": set()
        },
        "crypto": {
            "symmetric_cipher": "AES-256-CBC (PKCS7 Padding)",
            "asymmetric_cipher": "RSA-2048 (OAEP Padding with SHA-256)",
            "key_exchange_pattern": "Per-file hybrid encryption with RSA-wrapped AES key sidecars"
        }
    }

    # Inspect logs
    for ev in all_events:
        mod = ev.get("module")
        event = ev.get("event")
        pid = ev.get("pid")
        if pid:
            iocs["process"]["malware_pids"].add(pid)

        # Network from C2 and Transfer logs
        if mod == "c2":
            if "server_ip" in ev:
                iocs["network"]["c2_ips"].add(ev["server_ip"])
            if "port" in ev:
                iocs["network"]["c2_ports"].add(ev["port"])
        elif mod == "transfer":
            if "dst_ip" in ev:
                iocs["network"]["c2_ips"].add(ev["dst_ip"])
            if "port" in ev:
                iocs["network"]["transfer_ports"].add(ev["port"])
            if "file_size" in ev:
                iocs["network"]["total_exfiltrated_bytes"] += ev["file_size"]

        # Filesystem
        if mod == "honeypot" and event == "decoy_touched":
            iocs["filesystem"]["honeypot_triggers"].append({
                "ts": ev.get("ts"),
                "file": ev.get("file"),
                "pid": ev.get("pid")
            })
        elif mod == "simulator":
            if event == "file_encrypted":
                iocs["filesystem"]["encrypted_files"].append(ev.get("file"))
            elif event == "shadow_copy_simulated":
                iocs["filesystem"]["shadow_copy_attempts"].append(ev.get("command", "vssadmin delete shadows"))
        
        # Containment
        if mod == "containment":
            iocs["process"]["containment_actions"].append({
                "ts": ev.get("ts"),
                "action": event,
                "target_pid": ev.get("target_pid", ev.get("pid")),
                "latency_ms": ev.get("latency_ms")
            })

    # Network from SQLite flows
    for flow in flows:
        iocs["network"]["c2_ips"].add(flow["dst_ip"])
        if flow["dst_port"] == getattr(config, "C2_PORT", 9001):
            iocs["network"]["c2_ports"].add(flow["dst_port"])
        if flow["dst_port"] == getattr(config, "TRANSFER_PORT", 9002):
            iocs["network"]["transfer_ports"].add(flow["dst_port"])
            iocs["network"]["exfiltrated_flows_count"] += 1
            iocs["network"]["total_exfiltrated_bytes"] = max(
                iocs["network"]["total_exfiltrated_bytes"],
                flow["total_bytes"]
            )

    return iocs


def generate_report(
    honeypot_log: Optional[str] = None,
    containment_log: Optional[str] = None,
    simulator_log: Optional[str] = None,
    c2_log: Optional[str] = None,
    transfer_log: Optional[str] = None,
    db_path: Optional[str] = None,
    baseline_hashes_json: Optional[str] = None,
    output_path: Optional[str] = None
) -> str:
    """Generate comprehensive forensic incident report."""
    # Ingest all logs
    events_by_source = {
        "honeypot": parse_json_lines_file(honeypot_log),
        "containment": parse_json_lines_file(containment_log),
        "simulator": parse_json_lines_file(simulator_log),
        "c2": parse_json_lines_file(c2_log),
        "transfer": parse_json_lines_file(transfer_log)
    }

    all_events = []
    for mod, evs in events_by_source.items():
        all_events.extend(evs)

    # Sort chronological timeline
    all_events.sort(key=lambda x: parse_iso_timestamp(x.get("ts", "")))

    # Ingest PCAP flows from SQLite if available
    flows = []
    if db_path and os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT id, ts, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, total_bytes, duration_ms FROM flows ORDER BY ts ASC")
            flows = [dict(r) for r in cursor.fetchall()]
            conn.close()
        except Exception as e:
            print(f"[!] Warning reading database {db_path}: {e}", file=sys.stderr)

    # Ingest baseline hashes to calculate files saved ratio
    total_baseline_files = 0
    if baseline_hashes_json and os.path.exists(baseline_hashes_json):
        try:
            with open(baseline_hashes_json, "r", encoding="utf-8") as f:
                hashes = json.load(f)
                total_baseline_files = len(hashes)
        except Exception as e:
            print(f"[!] Warning reading baseline hashes: {e}", file=sys.stderr)

    # Extract IOCs
    iocs = extract_iocs(all_events, flows)

    # Calculate metrics
    encrypted_count = len(iocs["filesystem"]["encrypted_files"])
    if total_baseline_files > 0:
        saved_files = max(0, total_baseline_files - encrypted_count)
        files_saved_ratio = round((saved_files / total_baseline_files) * 100.0, 2)
    else:
        saved_files = 0
        files_saved_ratio = 100.0 if encrypted_count == 0 else 0.0

    # Honeypot detection latency
    honeypot_latency_ms = "N/A"
    for ev in events_by_source["honeypot"]:
        if "latency_ms" in ev:
            honeypot_latency_ms = f"{ev['latency_ms']} ms"
            break
        elif "response_latency_sec" in ev:
            honeypot_latency_ms = f"{round(ev['response_latency_sec'] * 1000, 2)} ms"
            break

    # Traffic detection latency
    traffic_latency_str = "N/A"
    exfil_flows = [f for f in flows if f["dst_port"] == getattr(config, "TRANSFER_PORT", 9002)]
    if exfil_flows:
        first_exfil = sorted(exfil_flows, key=lambda f: f["ts"])[0]
        first_ts = parse_iso_timestamp(first_exfil["ts"])
        # If subsequent detection occurred or comparison to honeypot
        traffic_latency_str = f"~{round(first_exfil['duration_ms'] / 1000.0, 2)} s flow window"

    report_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build Markdown Content
    md = []
    md.append(f"# Digital Forensic Incident & Post-Attack Analysis Report")
    md.append(f"**Report Generated:** {report_ts} | **Investigator:** Person 3 (Analysis & Forensics Lead)\n")
    md.append("---")
    md.append("## 1. Executive Summary")
    md.append(
        "A hybrid double-extortion ransomware attack was simulated and detected within the isolated testbed. "
        "The attack encompassed encrypted C2 orchestration, automated file exfiltration over TCP, "
        "and an in-situ alphabetical ransomware encryption traversal targeting operational military assets. "
        "The victim defense tripwire (canary honeypot directory) successfully intercepted the attacker "
        "mid-traversal, initiating automated active containment."
    )
    md.append(f"\n- **Total Baseline Target Files:** {total_baseline_files if total_baseline_files else 'N/A'}")
    md.append(f"- **Files Encrypted Prior to Containment:** {encrypted_count}")
    md.append(f"- **Files Successfully Saved:** {saved_files}")
    md.append(f"- **Files-Saved Ratio:** **{files_saved_ratio}%**")
    md.append(f"- **Tripwire Containment Latency:** {honeypot_latency_ms}\n")

    md.append("---")
    md.append("## 2. Comprehensive Indicators of Compromise (IOCs)")

    # Network IOCs
    md.append("### 2.1 Network IOCs")
    md.append("| Indicator Type | Observed Value | Description |")
    md.append("| :--- | :--- | :--- |")
    md.append(f"| Attacker C2 IP | `{getattr(config, 'ATTACKER_IP', '192.168.56.10')}` | Command & Control server |")
    md.append(f"| Victim Host IP | `{getattr(config, 'VICTIM_IP', '192.168.56.20')}` | Compromised endpoint |")
    md.append(f"| C2 Channel Port | `TCP/{getattr(config, 'C2_PORT', 9001)}` | Orchestration & tasking channel |")
    md.append(f"| Exfiltration Port | `TCP/{getattr(config, 'TRANSFER_PORT', 9002)}` | Encrypted data exfiltration receiver |")
    md.append(f"| Exfiltrated Volume | `{iocs['network']['total_exfiltrated_bytes']} bytes` | Total payload outbound to attacker |")
    md.append("")

    # Filesystem IOCs
    md.append("### 2.2 File-System IOCs")
    md.append("| Artifact | Signature / Path | Forensic Significance |")
    md.append("| :--- | :--- | :--- |")
    md.append(f"| Decoy Tripwire | `{getattr(config, 'HONEYPOT_DIR', '/MILITARY_DATA/A_COMMAND_ARCHIVE')}` | Monitored canary directory |")
    md.append(f"| Ciphertext Extension | `{iocs['filesystem']['ransom_extension']}` | Renamed encrypted payload files |")
    md.append(f"| Key Sidecar Extension | `{iocs['filesystem']['key_extension']}` | RSA-OAEP encrypted AES key sidecars |")
    md.append(f"| Ransom Note | `{config.RANSOM_NOTE}` | Extortion notification dropped per folder |")
    if iocs["filesystem"]["shadow_copy_attempts"]:
        for cmd in iocs["filesystem"]["shadow_copy_attempts"]:
            md.append(f"| Defense Impairment | `{cmd}` | Shadow volume copy destruction |")
    md.append("")

    # Process IOCs
    md.append("### 2.3 Host Process IOCs")
    pids_str = ", ".join(str(p) for p in iocs["process"]["malware_pids"]) if iocs["process"]["malware_pids"] else "None recorded"
    md.append("| Attribute | Value | Details |")
    md.append("| :--- | :--- | :--- |")
    md.append(f"| Malware PID(s) | `{pids_str}` | Process identifier of ransomware simulator |")
    md.append(f"| Containment Action | `SIGKILL / Process Termination` | Forcefully killed upon tripwire fire |")
    md.append(f"| Containment Events | `{len(iocs['process']['containment_actions'])} event(s)` | Automated defense tripwire invocation |")
    md.append("")

    # Cryptographic IOCs
    md.append("### 2.4 Cryptographic IOCs")
    md.append("| Category | Standard | Purpose |")
    md.append("| :--- | :--- | :--- |")
    md.append(f"| Symmetric Cipher | `{iocs['crypto']['symmetric_cipher']}` | High-throughput file payload encryption |")
    md.append(f"| Asymmetric Cipher | `{iocs['crypto']['asymmetric_cipher']}` | Attacker key wrapping / unwrap |")
    md.append(f"| Architecture | `{iocs['crypto']['key_exchange_pattern']}` | Prevents decryption without attacker private key |")
    md.append("")

    # Detection Comparison Table
    md.append("---")
    md.append("## 3. Detection Methodology Evaluation: Honeypot vs. Traffic Analysis")
    md.append(
        "| Evaluation Metric | Honeypot Tripwire (In-Situ) | Network Traffic Analysis (PCAP) |"
    )
    md.append("| :--- | :--- | :--- |")
    md.append(f"| **Detection Speed / Latency** | **Sub-second ({honeypot_latency_ms})** | Post-flow window ({traffic_latency_str}) |")
    md.append("| **False Positive Rate** | **0.0%** (decoys contain zero operational data) | Subject to volume thresholds & benign noise |")
    md.append("| **Evasion Potential** | Can be bypassed if traversal skips decoy | Can be evaded via slow trickle or fragmentation |")
    md.append("| **Actionability** | **Instantaneous** (triggers local process SIGKILL) | Requires external SIEM / firewall block rule |")
    md.append("| **Blindspots** | Does not detect exfiltration prior to traversal | Encrypted payloads prevent payload inspection |")
    md.append("")

    # Chronological Timeline
    md.append("---")
    md.append("## 4. Chronological Incident Timeline")
    md.append("| Timestamp (UTC) | Module | Event | Details / Context |")
    md.append("| :--- | :--- | :--- | :--- |")
    if all_events:
        for ev in all_events:
            ts = ev.get("ts", "UNKNOWN_TS")
            mod = ev.get("module", "system")
            event_name = ev.get("event", "action")
            # Build context summary from remaining keys
            context_keys = [f"{k}={v}" for k, v in ev.items() if k not in ("ts", "module", "event")]
            context = ", ".join(context_keys[:3])
            md.append(f"| `{ts}` | `{mod}` | `{event_name}` | {context} |")
    else:
        md.append("| *No events recorded in provided logs* | - | - | - |")
    md.append("")

    # Conclusion & Recommendations
    md.append("---")
    md.append("## 5. Defense Recommendations & Lessons Learned")
    md.append(
        "1. **Defense-in-Depth Synergy:** The canary tripwire provided the earliest and highest-confidence containment signal, "
        "saving operational assets before complete traversal. Combining this with egress traffic inspection ensures full coverage against dual-extortion attacks.\n"
        "2. **Immutable Backup Isolation:** High-confidence automated restores from TLS-authenticated backup repositories "
        "render ransomware encryption ineffective without requiring ransom payment.\n"
        "3. **Zero-Trust C2 Authentication:** As demonstrated in C2 authenticated mode, cryptographically signed commands (HMAC-SHA256) "
        "prevent unauthorized orchestration."
    )

    report_content = "\n".join(md)

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_content)
        print(f"[+] Forensic incident report written to: {output_path}")

    return report_content


def main():
    parser = argparse.ArgumentParser(description="ISL Forensic Report Generator (Module 3C)")
    parser.add_argument("--honeypot-log", default=None, help="Path to honeypot.log")
    parser.add_argument("--containment-log", default=None, help="Path to containment.log")
    parser.add_argument("--simulator-log", default=None, help="Path to simulator.log")
    parser.add_argument("--c2-log", default=None, help="Path to c2.log")
    parser.add_argument("--transfer-log", default=None, help="Path to transfer.log")
    parser.add_argument("--db", default=None, help="Path to SQLite PCAP flows database")
    parser.add_argument("--baseline", default=None, help="Path to baseline_hashes.json")
    parser.add_argument("--output", default="reports/incident_report.md", help="Output path for Markdown report")
    args = parser.parse_args()

    # If default log files exist in project root logs/, use them
    log_dir = os.path.join(PROJECT_ROOT, "logs")
    honeypot_log = args.honeypot_log or os.path.join(log_dir, "honeypot.log")
    containment_log = args.containment_log or os.path.join(log_dir, "containment.log")
    simulator_log = args.simulator_log or os.path.join(log_dir, "simulator.log")
    c2_log = args.c2_log or os.path.join(log_dir, "c2.log")
    transfer_log = args.transfer_log or os.path.join(log_dir, "transfer.log")

    generate_report(
        honeypot_log=honeypot_log,
        containment_log=containment_log,
        simulator_log=simulator_log,
        c2_log=c2_log,
        transfer_log=transfer_log,
        db_path=args.db,
        baseline_hashes_json=args.baseline,
        output_path=args.output
    )


if __name__ == "__main__":
    main()
