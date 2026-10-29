"""Victim-side containment helpers with explicit process identity checks.

Isolated Ubuntu VM test, from the repository root:
    python3 -m victim.containment --probe

The probe starts and stops only its own ``sleep 30`` child process.
"""

import argparse
import hashlib
import json
import os
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from config import LOG_DIR, TEST_DATA_DIR


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def log_event(event, **fields):
    directory = Path(LOG_DIR)
    data_root = Path(TEST_DATA_DIR).resolve(strict=True)
    log_root = directory.resolve(strict=False)
    if log_root == data_root or log_root.is_relative_to(data_root):
        raise ValueError("Logs must be outside the dataset")
    directory.mkdir(parents=True, exist_ok=True)
    row = {"ts": stamp(), "module": "containment", "event": event, **fields}
    with (directory / "containment.log").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True) + "\n")
    return row


def process_identity(pid):
    """Return (Linux start ticks, exact argv, process name, parent PID)."""
    # A mismatched /proc mount must never be used to attribute or kill a PID.
    if int(Path("/proc/self/stat").read_text().split(" ", 1)[0]) != os.getpid():
        raise RuntimeError("/proc does not match this process namespace")
    if not isinstance(pid, int) or pid <= 1 or pid == os.getpid():
        raise ValueError("Invalid or self PID")
    stat = (Path("/proc") / str(pid) / "stat").read_text()
    fields = stat[stat.rfind(")") + 2:].split()
    start_ticks = int(fields[19])  # /proc/<pid>/stat field 22
    parent_pid = int(fields[1])
    argv = tuple(part.decode("utf-8", "surrogateescape") for part in
                 (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0") if part)
    name = stat[stat.find("(") + 1:stat.rfind(")")]
    return start_ticks, argv, name, parent_pid


def kill_process(pid, *, expected_start_ticks, expected_argv):
    """Stop only a process whose PID, creation token, and complete argv match.

    The caller must receive this identity through a trusted registration channel.
    A watchdog file event does not contain a PID and cannot supply it by itself.
    """
    expected_argv = tuple(expected_argv)
    if not expected_argv:
        raise ValueError("An exact expected command is required")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("Linux pidfd support is required for safe signaling")
    started = time.monotonic_ns()
    with os.fdopen(os.pidfd_open(pid), "rb", closefd=True) as pid_handle:
        start_ticks, argv, name, parent_pid = process_identity(pid)
        if start_ticks != expected_start_ticks or argv != expected_argv:
            log_event("kill_rejected", pid=pid, reason="process_identity_mismatch")
            return False
        signal.pidfd_send_signal(pid_handle.fileno(), signal.SIGKILL)
        deadline = time.monotonic() + 2
        stopped = False
        while time.monotonic() < deadline:
            try:
                state = (Path("/proc") / str(pid) / "stat").read_text().split(") ", 1)[1][0]
                if state == "Z":
                    stopped = True
                    break
            except FileNotFoundError:
                stopped = True
                break
            time.sleep(0.01)
        elapsed_ms = round((time.monotonic_ns() - started) / 1_000_000, 3)
        log_event("process_killed" if stopped else "kill_unconfirmed", pid=pid,
                  process=name, parent_pid=parent_pid, response_ms=elapsed_ms)
        return stopped


def snapshot_filesystem(data_dir=TEST_DATA_DIR):
    """Record size, hash, and locked state of every file without changing data."""
    configured = Path(TEST_DATA_DIR)
    root = Path(data_dir)
    if configured.is_symlink() or root.is_symlink() or root.resolve(strict=True) != configured.resolve(strict=True):
        raise ValueError("Snapshot target must be the configured dataset directory")
    entries = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in [*dirs, *files]:
            if (Path(directory) / name).is_symlink():
                raise ValueError("Symlinks are not allowed in the dataset")
        for filename in files:
            path = Path(directory) / filename
            if not path.is_file():
                raise ValueError(f"Not a regular file: {path}")
            contents = path.read_bytes()
            relative = path.relative_to(root).as_posix()
            entries[relative] = {"size": len(contents), "sha256": hashlib.sha256(contents).hexdigest(),
                                 "locked": filename.endswith(".locked")}
    out = Path(LOG_DIR)
    if out.resolve(strict=False).is_relative_to(root.resolve(strict=True)):
        raise ValueError("Snapshot log must be outside dataset")
    out.mkdir(parents=True, exist_ok=True)
    destination = out / f"snapshot_{time.time_ns()}.json"
    with destination.open("x", encoding="utf-8") as stream:
        json.dump({"ts": stamp(), "files": dict(sorted(entries.items()))}, stream, indent=2)
        stream.write("\n")
    log_event("filesystem_snapshot", file=str(destination), file_count=len(entries))
    return entries


def probe():
    child = subprocess.Popen(["sleep", "30"])
    try:
        deadline = time.monotonic() + 2
        while True:
            start_ticks, argv, name, parent_pid = process_identity(child.pid)
            if argv and Path(argv[0]).name == "sleep" and argv[1:] == ("30",):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Probe did not start as expected")
            time.sleep(0.01)
        stopped = kill_process(child.pid, expected_start_ticks=start_ticks, expected_argv=argv)
        child.wait(timeout=3)
        if not stopped:
            raise RuntimeError("Probe process was not confirmed stopped")
        print(f"PASS: stopped probe PID {child.pid} ({name}); log: {Path(LOG_DIR) / 'containment.log'}")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true", help="Start and stop an owned dummy process")
    parser.add_argument("--snapshot", action="store_true", help="Save a read-only dataset snapshot")
    args = parser.parse_args()
    if not (args.probe or args.snapshot):
        parser.error("select --probe or --snapshot")
    if args.probe:
        probe()
    if args.snapshot:
        entries = snapshot_filesystem()
        print(f"PASS: snapshot contains {len(entries)} files")


if __name__ == "__main__":
    main()