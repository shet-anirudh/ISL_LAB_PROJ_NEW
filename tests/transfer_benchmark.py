"""Summarize successful Phase 3 sender events from the victim VM.

Run from the victim repository root: python3 -m tests.transfer_benchmark
Writes results/transfer_benchmarks.json; does not send files.
"""

import json
from pathlib import Path

from config import LOG_DIR, PROJECT_ROOT
from shared.transfer_protocol import FILE_CHOICES


def summarize():
    log_path = Path(LOG_DIR) / "transfer.log"
    events = {name: [] for name in FILE_CHOICES}
    for line_number, line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON at {log_path}:{line_number}") from exc
        if row.get("module") == "transfer" and row.get("event") == "file_sent":
            name = row.get("file")
            if name in events:
                size, seconds = row.get("bytes"), row.get("elapsed_s")
                if not isinstance(size, int) or size <= 0 or not isinstance(seconds, (int, float)) or seconds <= 0:
                    raise ValueError(f"Invalid transfer timing at line {line_number}")
                events[name].append({"bytes": size, "elapsed_s": seconds,
                                     "mib_per_s": round(size / (1024 * 1024) / seconds, 4),
                                     "sha256": row.get("sha256"), "ts": row.get("ts")})
    missing = [name for name, trials in events.items() if not trials]
    if missing:
        raise ValueError(f"No successful sender event for: {missing}")
    return {"unit": "MiB/s", "source": str(log_path),
            "measurements": {name: {"trial_count": len(trials), "trials": trials}
                             for name, trials in events.items()}}


def main():
    result = summarize()
    output = Path(PROJECT_ROOT) / "results" / "transfer_benchmarks.json"
    if output.is_symlink():
        raise ValueError("Output must not be a symlink")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PASS: summarized {len(result['measurements'])} file types in {output}")
    for name, record in result["measurements"].items():
        latest = record["trials"][-1]
        print(f"{name}: {latest['bytes']} bytes in {latest['elapsed_s']}s, "
              f"{latest['mib_per_s']} MiB/s ({record['trial_count']} trial(s))")


if __name__ == "__main__":
    main()