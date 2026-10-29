"""One-shot, controlled integration test of honeypot event and containment.

Run on the Ubuntu victim VM, with the normal monitor stopped:
    python3 -m tests.defense_probe

Launches and kills only its own dummy child. It does not run the simulator.
"""

import subprocess
import sys
import threading
import time
from pathlib import Path

from watchdog.observers import Observer

from config import HONEYPOT_DIR, LOG_DIR, TEST_DATA_DIR
from victim.containment import kill_process, process_identity, snapshot_filesystem
from victim.honeypot_monitor import DecoyHandler


class ProbeHandler(DecoyHandler):
    def __init__(self, log_path, probe_path):
        super().__init__(log_path)
        self.probe_path = probe_path
        self.registered = None
        self.once = threading.Lock()
        self.done = threading.Event()
        self.stopped = False
        self.error = None

    def on_any_event(self, event):
        super().on_any_event(event)
        if (event.event_type != "created" or event.is_directory or
                Path(event.src_path) != self.probe_path or self.registered is None):
            return
        if not self.once.acquire(blocking=False):
            return
        try:
            pid, start_ticks, argv = self.registered
            self.stopped = kill_process(pid, expected_start_ticks=start_ticks,
                                        expected_argv=argv)
            snapshot_filesystem(TEST_DATA_DIR)
        except Exception as exc:
            self.error = exc
        finally:
            self.done.set()


def main():
    root = Path(TEST_DATA_DIR).absolute()
    decoy = Path(HONEYPOT_DIR).absolute()
    if root != Path.home() / "MILITARY_DATA" or decoy != root / "A_COMMAND_ARCHIVE":
        raise ValueError("Probe requires the configured victim synthetic dataset")
    if not decoy.is_dir() or decoy.is_symlink():
        raise ValueError("Decoy directory missing or unsafe")
    probe_path = decoy / "defense_probe.tmp"
    if probe_path.exists() or probe_path.is_symlink():
        raise FileExistsError(probe_path)
    log_dir = Path(LOG_DIR)
    if log_dir.resolve(strict=False).is_relative_to(root.resolve(strict=True)):
        raise ValueError("Logs must be outside the dataset")
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = ProbeHandler(log_dir / "honeypot.log", probe_path)
    observer = Observer()
    observer.schedule(handler, str(decoy), recursive=True)
    observer.start()
    child = None
    try:
        worker = ("import sys,time;from pathlib import Path;"
                  "sys.stdin.buffer.read(1);Path(sys.argv[1]).touch();time.sleep(30)")
        child = subprocess.Popen([sys.executable, "-c", worker, str(probe_path)],
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 3
        while True:
            start_ticks, argv, _, _ = process_identity(child.pid)
            if len(argv) >= 4 and argv[1] == "-c" and argv[-1] == str(probe_path):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Dummy process did not start as expected")
            time.sleep(0.01)
        handler.registered = (child.pid, start_ticks, argv)
        child.stdin.write(b"x")
        child.stdin.flush()
        child.stdin.close()
        if not handler.done.wait(timeout=10):
            raise TimeoutError("No decoy creation event received within 10 seconds")
        if handler.error:
            raise handler.error
        child.wait(timeout=3)
        if not handler.stopped:
            raise RuntimeError("Dummy process was not confirmed stopped")
        print(f"PASS: decoy event stopped registered dummy PID {child.pid}")
        print("PASS: containment snapshot saved; temporary decoy will be removed")
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()
        observer.stop()
        observer.join(timeout=5)
        probe_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
