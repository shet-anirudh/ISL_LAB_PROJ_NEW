"""Compare controlled copy-only trials with and without trial containment.

On Ubuntu, from the repository root:
    python3 -m tests.defense_evaluation --trials 1
    python3 -m tests.defense_evaluation --trials 10

Both modes write new results/simtrial-* directories. Neither changes the
original MILITARY_DATA. The 'without' condition starts no trial watcher.
"""

import argparse
import hashlib
import json
import re
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from config import LOG_DIR, PROJECT_ROOT, TEST_DATA_DIR


ROOT = Path(PROJECT_ROOT)
DATA = Path(TEST_DATA_DIR)
LOGS = Path(LOG_DIR)


def _baseline():
    baseline = json.loads((ROOT / "results" / "baseline_hashes.json").read_text())["files"]
    if len(baseline) != 20:
        raise ValueError("Expected exactly 20 synthetic baseline files")
    if DATA != Path.home() / "MILITARY_DATA" or DATA.is_symlink():
        raise ValueError("Only the configured synthetic victim dataset is allowed")
    return baseline


def _verify_original(baseline):
    for name, expected in baseline.items():
        target = DATA / name
        if target.is_symlink() or not target.is_file():
            raise AssertionError(f"Original file missing or unsafe: {name}")
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise AssertionError(f"Original file differs from baseline: {name}")


def _events(name, start_offset):
    path = LOGS / name
    if not path.is_file() or path.is_symlink():
        return []
    with path.open("rb") as stream:
        stream.seek(start_offset)
        raw = stream.read().splitlines()
    rows = []
    for line in raw:
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _log_end(name):
    path = LOGS / name
    return path.stat().st_size if path.is_file() and not path.is_symlink() else 0


def _timestamp(raw):
    return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()


def _run(mode, baseline):
    _verify_original(baseline)
    existing = set((ROOT / "results").glob("simtrial-*"))
    starts = {name: _log_end(name) for name in
              ("honeypot.log", "containment.log", "simulator.log")}
    module = "tests.full_defense_trial" if mode == "with" else "ransomware.simulator"
    completed = subprocess.run([sys.executable, "-m", module], cwd=ROOT,
                               capture_output=True, text=True, timeout=90)
    if completed.returncode:
        raise RuntimeError(f"{module} failed: {(completed.stderr or completed.stdout)[-1200:]}")
    new_trials = [p for p in (ROOT / "results").glob("simtrial-*")
                  if p not in existing and p.is_dir() and not p.is_symlink()]
    if len(new_trials) != 1:
        raise RuntimeError(f"Expected one fresh trial, found {len(new_trials)}")
    trial = new_trials[0]
    locked = [p for p in trial.rglob("*.locked") if p.is_file() and not p.is_symlink()]
    decoy = sum("A_COMMAND_ARCHIVE" in p.relative_to(trial).parts for p in locked)
    real = len(locked) - decoy
    _verify_original(baseline)
    result = {"mode": mode, "trial": trial.name, "decoy_copies": decoy,
              "real_copies": real, "total_copies": len(locked),
              "original_intact": True}
    if mode == "without":
        summary = json.loads((trial / "summary.json").read_text())
        if (len(summary["files"]) != 10 or decoy != 5 or real != 5 or
                not all(row["kind"] == ("DECOY" if index < 5 else "REAL")
                        for index, row in enumerate(summary["files"]))):
            raise AssertionError("Unmonitored trial did not complete decoy-first plan")
        result["elapsed_s"] = summary["elapsed_s"]
    else:
        pid_match = re.search(r"containment of simulator PID (\d+)", completed.stdout)
        if not pid_match or decoy != 1 or real != 0:
            raise AssertionError("Monitored trial did not stop at first decoy")
        pid = int(pid_match.group(1))
        honeypot = _events("honeypot.log", starts["honeypot.log"])
        containment = _events("containment.log", starts["containment.log"])
        first = [event for event in honeypot
                 if event.get("event") == "decoy_touched" and
                 event.get("action") == "created" and
                 str(event.get("file", "")).startswith(str(trial) + "/") and
                 str(event.get("file", "")).endswith(".locked")]
        stops = [event for event in containment
                 if event.get("event") == "process_killed" and event.get("pid") == pid]
        if len(first) != 1 or len(stops) != 1:
            raise AssertionError("Could not uniquely match decoy alert and confirmed stop")
        detection_to_stop_ms = round(1000 * (
            _timestamp(stops[0]["ts"]) - _timestamp(first[0]["ts"])), 3)
        if detection_to_stop_ms < 0 or detection_to_stop_ms > 10000:
            raise AssertionError("Invalid alert-to-stop interval")
        result.update({"pid": pid, "alert_to_stop_ms": detection_to_stop_ms,
                       "kill_response_ms": stops[0].get("response_ms")})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.trials <= 20:
        parser.error("--trials must be between 1 and 20")
    baseline = _baseline()
    records = []
    for index in range(args.trials):
        # Alternate order across pairs to reduce a simple warm-cache bias.
        order = ("with", "without") if index % 2 == 0 else ("without", "with")
        for mode in order:
            record = _run(mode, baseline)
            record["pair"] = index + 1
            records.append(record)
            print(f"PASS: pair {index + 1}/{args.trials}, {mode} monitoring: "
                  f"{record['decoy_copies']} decoy, {record['real_copies']} real copies", flush=True)
    with_monitor = [r for r in records if r["mode"] == "with"]
    without = [r for r in records if r["mode"] == "without"]
    output = {
        "description": "Controlled synthetic copy-only evaluation; no original files modified",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "pairs": args.trials, "runs": records,
        "summary": {
            "with_real_copies_median": statistics.median(r["real_copies"] for r in with_monitor),
            "without_real_copies_median": statistics.median(r["real_copies"] for r in without),
            "alert_to_stop_ms_median": statistics.median(r["alert_to_stop_ms"] for r in with_monitor),
            "kill_response_ms_median": statistics.median(r["kill_response_ms"] for r in with_monitor),
        },
    }
    destination = ROOT / "results" / ("defense_evaluation_" +
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json")
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(output, stream, indent=2)
        stream.write("\n")
    _verify_original(baseline)
    print(f"PASS: {len(records)} runs; 20 original files match baseline. Saved {destination}")
    print("Summary:", json.dumps(output["summary"], sort_keys=True))


if __name__ == "__main__":
    main()