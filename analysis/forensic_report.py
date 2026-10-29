"""Build a timestamped Markdown forensic report from one lab PCAP run.

Run on Kali while victim.dashboard is serving authenticated telemetry:
    python3 -m analysis.forensic_report results/pcap/capture.pcapng

The report uses PCAP metadata, the parsed SQLite flows, Kali logs, and the
victim's current read-only status. It never reads or changes the dataset.
"""

import argparse
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from config import ATTACKER_IP, LOG_DIR, VICTIM_IP
from shared.dashboard import _remote_victim


def _safe(value):
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")[:240]


def _when(raw):
    try:
        if isinstance(raw, (float, int)):
            return float(raw)
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def _log(path):
    if path.is_symlink() or not path.is_file():
        return []
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    rows.append(item)
            except (ValueError, UnicodeError):
                continue
    return rows


def _network(db_path):
    with sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True) as db:
        flows = db.execute(
            "SELECT ts, src_ip, src_port, dst_ip, dst_port, packet_count, "
            "total_bytes, payload_bytes, duration_ms FROM flows ORDER BY ts"
        ).fetchall()
        alerts = db.execute(
            "SELECT kind, detail FROM alerts ORDER BY id"
        ).fetchall()
    if not flows:
        raise ValueError("The flow database has no packets; parse this capture first")
    return flows, alerts


def _victim_clock_offset(attacker_events, victim_status, bounds):
    """Align host clocks only when command and file anchors agree.

    Returns victim clock minus Kali clock in seconds; this is an estimate,
    never a guarantee that the underlying events have the same origin.
    """
    if not victim_status:
        return None
    victim_events = [e for e in victim_status.get("events", []) if isinstance(e, dict)]
    commands = []
    files = []
    for kali in attacker_events:
        kali_ts = _when(kali.get("ts"))
        # Require both Kali anchors to be near the actual packet capture.
        if kali_ts is None or not bounds[0] <= kali_ts <= bounds[1]:
            continue
        for victim in victim_events:
            victim_ts = _when(victim.get("ts"))
            if victim_ts is None or abs(victim_ts - kali_ts) > 120:
                continue
            offset = victim_ts - kali_ts
            if (kali.get("event") == "command_sent" and
                    victim.get("event") == "command_accepted" and
                    kali.get("cmd") == victim.get("detail") == "START_EXFIL"):
                commands.append(offset)
            if (kali.get("event") == "file_received" and
                    victim.get("event") == "file_sent" and
                    kali.get("file") == victim.get("detail")):
                files.append(offset)
    matches = [(a, b) for a in commands for b in files if abs(a - b) <= 1.5]
    if len(matches) != 1:
        return None
    return sum(matches[0]) / 2


def build_report(pcap, db_path, flows, alerts, attacker_events, victim_status,
                 window_seconds=120):
    """Render evidence without claiming a telemetry snapshot is historical proof."""
    start = min(row[0] for row in flows)
    end = max(row[0] + row[8] / 1000 for row in flows)
    bounds = (start - window_seconds, end + window_seconds)
    offset = _victim_clock_offset(attacker_events, victim_status,
                                  (start - 10, end + 10))
    timeline = []
    unaligned = []
    for row in flows:
        ts, src, sport, dst, dport, packets, wire, payload, duration = row
        timeline.append((ts, "PCAP", f"{src}:{sport} → {dst}:{dport}; "
                         f"{packets} packets, {payload} TCP payload bytes"))
    for event in attacker_events:
        ts = _when(event.get("ts"))
        if ts is not None and bounds[0] <= ts <= bounds[1]:
            detail = (event.get("file") or event.get("requested") or
                      event.get("cmd") or event.get("reason") or "")
            timeline.append((ts, "Kali log", f"{event.get('event', '')}: {detail}"))
    if victim_status:
        for event in victim_status.get("events", []):
            if not isinstance(event, dict):
                continue
            ts = _when(event.get("ts"))
            if ts is not None and bounds[0] <= ts - (offset or 0) <= bounds[1]:
                description = (f"{event.get('module', '')} / {event.get('event', '')}: "
                               f"{event.get('detail', '')}")
                if offset is None:
                    unaligned.append((ts, description))
                else:
                    timeline.append((ts - offset, "Victim telemetry (aligned)",
                                     f"{description}; raw victim time {_utc(ts)}"))
    timeline.sort(key=lambda item: (item[0], item[1], item[2]))

    outbound = [f for f in flows if f[1] == VICTIM_IP and f[3] == ATTACKER_IP]
    transfer = [f for f in outbound if f[4] == 9002]
    c2 = [f for f in outbound if f[4] == 9001]
    received = [e for e in attacker_events if e.get("event") == "file_received" and
                (ts := _when(e.get("ts"))) is not None and bounds[0] <= ts <= bounds[1]]
    telemetry = victim_status.get("telemetry", {}) if victim_status else {}
    trial = victim_status.get("trial") if victim_status else None
    lines = [
        "# Synthetic lab forensic report", "",
        f"Generated: {_utc(datetime.now(timezone.utc).timestamp())}",
        f"Capture window: {_utc(start)} to {_utc(end)} (UTC)", "",
        "## Evidence and scope", "",
        f"- PCAP: `{_safe(pcap)}`; SHA-256 `{_digest(pcap)}`",
        f"- Parsed SQLite: `{_safe(db_path)}`; {_safe(len(flows))} directional TCP flows",
        f"- Kali event sources: `logs/c2.log` and `logs/transfer.log` "
        f"(events within {window_seconds} seconds of capture shown below).",
        "- Victim event source: live TLS telemetry, limited to its recent events. "
        + ("Available at report generation." if victim_status else "Unavailable at report generation."),
        (f"- Host clock estimate: victim clock {offset:+.3f} seconds relative to Kali, "
         "based on matching START_EXFIL command and file transfer events. "
         "Only the timeline display is adjusted; raw victim times are retained."
         if offset is not None else
         "- Host clock alignment: not established by two matching event types. "
         "Victim events are not interleaved with Kali's packet timeline."),
        "- This capture contains TCP metadata. Payload encryption and file identity "
        "are verified by the application transfer log, not inferred from PCAP bytes.",
        "", "## Network observations", "",
        "| Time (UTC) | Source | Destination | Packets | Frame bytes | TCP payload bytes | Duration (ms) |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for ts, src, sport, dst, dport, packets, wire, payload, duration in flows:
        lines.append(f"| {_utc(ts)} | {_safe(src)}:{sport} | {_safe(dst)}:{dport} | "
                     f"{packets} | {wire} | {payload} | {duration:.1f} |")
    lines.extend(["", f"Victim → Kali C2 flows: {len(c2)}; "
                  f"victim → Kali transfer flows: {len(transfer)}. "
                  f"Transfer TCP payload bytes: {sum(f[7] for f in transfer)}.", "",
                  "## Detection and recovery", ""])
    if alerts:
        for kind, detail in alerts:
            lines.append(f"- Parser alert `{_safe(kind)}`: {_safe(detail)}.")
    else:
        lines.append("- No parser alerts for this capture.")
    if received:
        for event in received:
            lines.append(f"- Kali recorded recovery of `{_safe(event.get('file', '?'))}` "
                         f"({_safe(event.get('bytes', '?'))} bytes), SHA-256 "
                         f"`{_safe(event.get('sha256', '?'))}`. "
                         "The receiver checks this against the baseline before saving.")
    else:
        lines.append("- No matching Kali file-received log event in the capture window.")
    if victim_status:
        lines.append("- Current victim dataset baseline: " +
                     ("intact" if telemetry.get("intact") is True else "not confirmed intact") +
                     "; confirmed stops to date: " + _safe(telemetry.get("stops", "unknown")) + ".")
        if trial:
            lines.append(f"- Current latest trial `{_safe(trial.get('name', '?'))}`: "
                         f"{_safe(trial.get('decoy', '?'))} decoy and "
                         f"{_safe(trial.get('real', '?'))} real encrypted copies. "
                         "This is a live status snapshot, not proof it belongs to this capture.")
    else:
        lines.append("- Victim containment and dataset state could not be verified remotely.")
    lines.extend(["", "## Event timeline", "",
                  "| Time (UTC) | Source | Recorded event |", "|---|---|---|"])
    for ts, source, description in timeline:
        lines.append(f"| {_utc(ts)} | {_safe(source)} | {_safe(description)} |")
    if unaligned:
        lines.extend(["", "### Victim events (raw UTC; clocks unaligned)", "",
                      "| Victim time (UTC) | Recorded event |", "|---|---|"])
        for ts, description in sorted(unaligned):
            lines.append(f"| {_utc(ts)} | {_safe(description)} |")
    lines.extend(["", "## Indicators and limits", "",
                  f"- Lab hosts: Kali `{ATTACKER_IP}`, victim `{VICTIM_IP}`; "
                  "C2 TCP/9001 and file transfer TCP/9002.",
                  "- These are private lab IPs and are not public threat indicators.",
                  "- The transfer-port threshold identifies an observed outbound flow; "
                  "it does not by itself prove unauthorized data loss.",
                  "- The report joins events by capture time. Historical local logs may "
                  "contain other trials; current victim telemetry may have changed since the capture.", ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--db", type=Path, default=Path("results/pcap/flows.sqlite"))
    parser.add_argument("--out", type=Path)
    parser.add_argument("--window-seconds", type=int, default=120)
    args = parser.parse_args()
    if args.window_seconds < 0:
        parser.error("--window-seconds must be nonnegative")
    pcap = args.pcap.resolve(strict=True)
    db_path = args.db.resolve(strict=True)
    flows, alerts = _network(db_path)
    logs = Path(LOG_DIR)
    attacker_events = _log(logs / "c2.log") + _log(logs / "transfer.log")
    victim_status = _remote_victim()
    report = build_report(pcap, db_path, flows, alerts, attacker_events,
                          victim_status, args.window_seconds)
    output = args.out or Path("results/reports") / (
        pcap.stem + "_forensic_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".md")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"PASS: forensic report saved to {output}")
    print("Victim telemetry:", "CONNECTED" if victim_status else "UNAVAILABLE")
    print(f"Flows: {len(flows)}; parser alerts: {len(alerts)}")


if __name__ == "__main__":
    main()
