"""Stop the owned simulator on its first encrypted decoy copy.

Run on the Ubuntu victim VM, with the normal honeypot monitor stopped:
    python3 -m tests.full_defense_trial

The simulator writes only beneath results/simtrial-*; original MILITARY_DATA
stays read-only. This test registers its own child PID and watches the trial
decoy directory, not the original dataset.
"""

import hashlib
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

from watchdog.observers import Observer

from config import HONEYPOT_DIR, LOG_DIR, PROJECT_ROOT, TEST_DATA_DIR
from victim.containment import kill_process, log_event, process_identity, snapshot_filesystem
from victim.honeypot_monitor import DecoyHandler


class TrialHandler(DecoyHandler):
    def __init__(self, log_path, decoy, registered):
        super().__init__(log_path)
        self.decoy = decoy
        self.registered = registered
        self.done = threading.Event()
        self.once = threading.Lock()
        self.stopped = False
        self.error = None

    def on_any_event(self, event):
        super().on_any_event(event)
        path = Path(event.src_path)
        if (event.event_type != "created" or event.is_directory or
                path.parent != self.decoy or not path.name.endswith(".locked") or
                not self.once.acquire(blocking=False)):
            return
        try:
            pid, ticks, argv = self.registered
            self.stopped = kill_process(pid, expected_start_ticks=ticks,
                                        expected_argv=argv)
            snapshot_filesystem(TEST_DATA_DIR)
        except Exception as exc:
            self.error = exc
        finally:
            self.done.set()


def main():
    source = Path(TEST_DATA_DIR).absolute()
    decoy = Path(HONEYPOT_DIR).absolute()
    if source != Path.home() / "MILITARY_DATA" or decoy != source / "A_COMMAND_ARCHIVE":
        raise ValueError("Trial requires the configured victim synthetic dataset")
    baseline = json.loads((Path(PROJECT_ROOT) / "results" / "baseline_hashes.json")
                          .read_text(encoding="utf-8"))["files"]
    if len(baseline) != 20:
        raise ValueError("Expected 20 baseline files")
    for name, expected in baseline.items():
        if hashlib.sha256((source / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"Dataset differs from baseline: {name}")

    results = Path(PROJECT_ROOT) / "results"
    if results.is_symlink() or results.resolve().is_relative_to(source.resolve()):
        raise ValueError("Trial results must be outside the original dataset")
    existing = set(results.glob("simtrial-*"))
    gate = results / f"defense-gate-{time.time_ns()}"
    log_dir = Path(LOG_DIR)
    if log_dir.resolve(strict=False).is_relative_to(source.resolve()):
        raise ValueError("Logs must be outside the original dataset")
    log_dir.mkdir(parents=True, exist_ok=True)

    child = None
    observer = None
    try:
        child = subprocess.Popen(
            [sys.executable, "-m", "ransomware.simulator", "--step-delay", "2",
             "--gate-file", str(gate)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 8
        while True:
            ticks, argv, _, _ = process_identity(child.pid)
            if (len(argv) >= 7 and argv[1:3] == ("-m", "ransomware.simulator")
                    and argv[-1] == str(gate)):
                break
            if child.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("Simulator process did not start as expected")
            time.sleep(0.01)
        trial = None
        while trial is None:
            candidates = [p for p in results.glob("simtrial-*") if p not in existing
                          and (p / "A_COMMAND_ARCHIVE").is_dir()]
            if candidates:
                trial = candidates[0]
            elif child.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("Simulator did not prepare its trial decoy")
            else:
                time.sleep(0.01)
        handler = TrialHandler(log_dir / "honeypot.log", trial / "A_COMMAND_ARCHIVE",
                               (child.pid, ticks, argv))
        observer = Observer()
        observer.schedule(handler, str(handler.decoy), recursive=True)
        observer.start()
        gate.touch(exist_ok=False)
        if not handler.done.wait(timeout=10):
            raise TimeoutError("No encrypted decoy event received")
        if handler.error:
            raise handler.error
        child.wait(timeout=3)
        if not handler.stopped:
            raise RuntimeError("Simulator was not confirmed stopped")
        decoy_locked = list((trial / "A_COMMAND_ARCHIVE").glob("*.locked"))
        real_locked = [p for p in trial.rglob("*.locked") if
                       "A_COMMAND_ARCHIVE" not in p.relative_to(trial).parts]
        if len(decoy_locked) != 1 or real_locked:
            raise AssertionError("Containment happened after a real file was encrypted")
        for name, expected in baseline.items():
            if hashlib.sha256((source / name).read_bytes()).hexdigest() != expected:
                raise AssertionError(f"Original dataset changed: {name}")
        log_event("trial_contained", trial=trial.name, pid=child.pid,
                  decoy_file=str(decoy_locked[0]), decoy_copies=1,
                  real_copies=0, baseline_files=len(baseline))
        print(f"PASS: first decoy copy triggered containment of simulator PID {child.pid}")
        print("PASS: zero real encrypted copies; original 20 dataset files match baseline")
        print(f"Trial evidence: {trial}")
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()
        if child is not None and child.stdout:
            child.stdout.close()
        if child is not None and child.stderr:
            child.stderr.close()
        if observer is not None:
            observer.stop()
            observer.join(timeout=5)
        gate.unlink(missing_ok=True)


if __name__ == "__main__":
    main()