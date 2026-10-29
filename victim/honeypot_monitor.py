"""Watch the fictional lab decoy directory and record file changes.

Run on the Ubuntu victim VM from the repository root:
    python3 -m victim.honeypot_monitor

This first-stage monitor logs events only. It does not identify or kill processes.
"""

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from config import HONEYPOT_DIR, LOG_DIR, TEST_DATA_DIR


EVENTS = {"created", "modified", "deleted", "moved"}


def utc_timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class DecoyHandler(FileSystemEventHandler):
    def __init__(self, log_path):
        super().__init__()
        self.log_path = Path(log_path)
        self.lock = threading.Lock()

    def on_any_event(self, event):
        if event.event_type not in EVENTS or event.is_directory:
            return
        record = {
            "ts": utc_timestamp(),
            "module": "honeypot",
            "event": "decoy_touched",
            "action": event.event_type,
            "file": str(event.src_path),
        }
        if event.event_type == "moved":
            record["destination"] = str(event.dest_path)
        with self.lock:
            with self.log_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
        print(json.dumps(record, sort_keys=True), flush=True)


def main():
    configured_root = Path(TEST_DATA_DIR)
    configured_decoy = Path(HONEYPOT_DIR)
    root = configured_root.resolve(strict=True)
    decoy = configured_decoy.resolve(strict=True)
    if configured_root.is_symlink() or configured_decoy.is_symlink():
        raise ValueError("Dataset and decoy directories must not be symlinks")
    if not root.is_dir() or not decoy.is_dir() or decoy == root or not decoy.is_relative_to(root):
        raise ValueError("HONEYPOT_DIR must be a directory inside TEST_DATA_DIR")
    log_dir = Path(LOG_DIR).resolve(strict=False)
    if log_dir == root or log_dir.is_relative_to(root):
        raise ValueError("LOG_DIR must be outside the dataset")
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "honeypot.log"

    observer = Observer()
    observer.schedule(DecoyHandler(log_path), str(decoy), recursive=True)
    observer.start()
    print(f"Watching {decoy}; logging to {log_path}. Press Ctrl+C to stop.", flush=True)
    try:
        while True:
            time.sleep(0.2)
            if not observer.is_alive():
                raise RuntimeError("File-system observer stopped unexpectedly")
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join(timeout=5)


if __name__ == "__main__":
    main()
