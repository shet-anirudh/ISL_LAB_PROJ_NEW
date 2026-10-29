"""analysis/dashboard/app.py — Real-Time Containment & Attack Monitor Dashboard (Module 3E).

Flask application running on the victim VM, exposing:
  - GET /status: live JSON statistics aggregated from all log files
  - GET /: rich, real-time Chart.js web dashboard with emergency containment banner
"""

import argparse
from datetime import datetime, timezone
import json
import os
import sys
from flask import Flask, jsonify, render_template

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import config

app = Flask(__name__, template_folder="templates")

# Path to logs
LOG_DIR = getattr(config, "LOG_DIR", os.path.join(PROJECT_ROOT, "logs"))


def read_json_lines(file_path: str):
    """Read structured events from a JSON-lines log file."""
    if not os.path.exists(file_path):
        return []
    events = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass
    return events


@app.route("/status")
def status():
    """Poll endpoint returning current defense and attack metrics."""
    # Read logs
    honeypot_events = read_json_lines(os.path.join(LOG_DIR, "honeypot.log"))
    containment_events = read_json_lines(os.path.join(LOG_DIR, "containment.log"))
    simulator_events = read_json_lines(os.path.join(LOG_DIR, "simulator.log"))
    c2_events = read_json_lines(os.path.join(LOG_DIR, "c2.log"))
    transfer_events = read_json_lines(os.path.join(LOG_DIR, "transfer.log"))

    # Calculate status
    decoys_touched = len([e for e in honeypot_events if e.get("event") == "decoy_touched"])
    containment_triggered = len(containment_events) > 0 or decoys_touched > 0

    encrypted_files = [e for e in simulator_events if e.get("event") == "file_encrypted"]
    files_encrypted_count = len(encrypted_files)
    total_bytes_encrypted = sum(e.get("size_bytes", 0) for e in encrypted_files)

    # Offending process PID
    killed_pid = None
    kill_timestamp = None
    for e in containment_events:
        if e.get("event") == "kill_process":
            killed_pid = e.get("target_pid", e.get("pid"))
            kill_timestamp = e.get("ts")
            break
    if not killed_pid and honeypot_events:
        killed_pid = honeypot_events[-1].get("pid")
        kill_timestamp = honeypot_events[-1].get("ts")

    # Threat phase
    if containment_triggered:
        threat_phase = "CONTAINED / TERMINATED"
        threat_level = "RESOLVED"
    elif files_encrypted_count > 0:
        threat_phase = "ACTIVE ENCRYPTION"
        threat_level = "CRITICAL"
    elif len(transfer_events) > 0:
        threat_phase = "DATA EXFILTRATION"
        threat_level = "HIGH"
    elif len(c2_events) > 0:
        threat_phase = "C2 BEACONING / STAGING"
        threat_level = "ELEVATED"
    else:
        threat_phase = "SYSTEM SECURE / MONITORING"
        threat_level = "NORMAL"

    # Merge last 15 log events for feed
    all_events = []
    for mod, evs in [("honeypot", honeypot_events), ("containment", containment_events),
                     ("simulator", simulator_events), ("c2", c2_events), ("transfer", transfer_events)]:
        for e in evs:
            all_events.append({
                "ts": e.get("ts", ""),
                "module": mod,
                "event": e.get("event", ""),
                "details": str({k: v for k, v in e.items() if k not in ("ts", "module", "event")})
            })
    all_events.sort(key=lambda x: x["ts"], reverse=True)
    recent_feed = all_events[:15]

    return jsonify({
        "containment_triggered": containment_triggered,
        "threat_phase": threat_phase,
        "threat_level": threat_level,
        "decoys_touched": decoys_touched,
        "files_encrypted_count": files_encrypted_count,
        "total_bytes_encrypted": total_bytes_encrypted,
        "killed_pid": killed_pid,
        "kill_timestamp": kill_timestamp,
        "recent_feed": recent_feed,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.route("/")
def index():
    """Render main dashboard view."""
    return render_template("index.html")


def main():
    parser = argparse.ArgumentParser(description="ISL Defense & Containment Dashboard")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host")
    parser.add_argument("--port", type=int, default=5000, help="HTTP listening port")
    parser.add_argument("--log-dir", default=None, help="Custom log directory")
    args = parser.parse_args()

    global LOG_DIR
    if args.log_dir:
        LOG_DIR = args.log_dir
    os.makedirs(LOG_DIR, exist_ok=True)

    print(f"[*] Starting ISL Containment Dashboard on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
