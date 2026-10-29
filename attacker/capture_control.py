"""Bounded Kali host-only PCAP capture owned by the attacker dashboard.

TShark watches only victim C2 and file-transfer traffic on eth1. Capture
stops automatically after five minutes or 10 MiB, whichever comes first.
"""

import json
import shutil
import signal
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from config import C2_PORT, LOG_DIR, PROJECT_ROOT, TRANSFER_PORT, VICTIM_IP


INTERFACE = "eth1"
DURATION_SECONDS = 300
MAX_KIB = 10240


def _stamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class CaptureController:
    def __init__(self):
        self.lock = threading.Lock()
        self.process = None
        self.path = None
        self.error_log = None
        self.state = {"status": "idle", "detail": "No dashboard capture started"}

    def _event(self, event, **fields):
        logs = Path(LOG_DIR)
        logs.mkdir(parents=True, exist_ok=True)
        with (logs / "capture.log").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"ts": _stamp(), "module": "capture",
                                     "event": event, **fields}, sort_keys=True) + "\n")

    def _sync(self):
        if self.process is None or self.state["status"] != "capturing":
            return
        exit_code = self.process.poll()
        if exit_code is not None:
            self.state = {"status": "completed" if exit_code == 0 else "failed",
                          "file": self.path.name, "bytes": self.path.stat().st_size if self.path.exists() else 0,
                          "detail": "Automatic capture limit reached" if exit_code == 0
                          else self._error(), "finished": _stamp()}
            self._event("capture_finished", file=self.path.name, exit_code=exit_code)

    def _error(self):
        try:
            return self.error_log.read_text(encoding="utf-8", errors="replace")[-220:].strip() or "TShark failed"
        except OSError:
            return "TShark failed"

    def status(self):
        with self.lock:
            self._sync()
            current = dict(self.state)
            if self.path and self.path.is_file():
                current["bytes"] = self.path.stat().st_size
            return current

    def is_running(self):
        return self.status()["status"] == "capturing"

    def start(self):
        with self.lock:
            self._sync()
            if self.state["status"] == "capturing":
                raise RuntimeError("A dashboard capture is already running")
            executable = shutil.which("tshark")
            try:
                interface_exists = socket.if_nametoindex(INTERFACE) > 0
            except OSError:
                interface_exists = False
            if executable is None or not interface_exists:
                raise RuntimeError("TShark or Kali host-only interface eth1 is unavailable")
            results = Path(PROJECT_ROOT) / "results" / "pcap"
            if results.is_symlink():
                raise ValueError("Capture directory is a symlink")
            results.mkdir(parents=True, exist_ok=True)
            filename = "dashboard_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"_{time.time_ns()}.pcapng"
            self.path = results / filename
            self.error_log = Path(LOG_DIR) / (filename + ".tshark.log")
            self.error_log.parent.mkdir(parents=True, exist_ok=True)
            filter_expression = f"host {VICTIM_IP} and (tcp port {C2_PORT} or tcp port {TRANSFER_PORT})"
            command = [executable, "-i", INTERFACE, "-f", filter_expression,
                       "-a", f"duration:{DURATION_SECONDS}", "-a", f"filesize:{MAX_KIB}",
                       "-w", str(self.path)]
            with self.error_log.open("x", encoding="utf-8") as errors:
                self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors,
                                                stdin=subprocess.DEVNULL)
            deadline = time.monotonic() + 3
            healthy_after = time.monotonic() + 0.8
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError(self._error())
                if ((self.path.exists() and self.path.stat().st_size > 0) or
                        time.monotonic() >= healthy_after):
                    break
                time.sleep(0.1)
            else:
                self.process.terminate()
                self.process.wait(timeout=5)
                raise RuntimeError("TShark did not start within three seconds: " + self._error())
            self.state = {"status": "capturing", "file": filename,
                          "bytes": self.path.stat().st_size if self.path.exists() else 0,
                          "detail": f"Capturing {VICTIM_IP} C2/transfer on {INTERFACE}; max 5 min or 10 MiB",
                          "started": _stamp()}
            self._event("capture_started", file=filename, interface=INTERFACE,
                        filter=filter_expression)
            return dict(self.state)

    def stop(self):
        with self.lock:
            self._sync()
            if self.state["status"] != "capturing" or self.process is None:
                raise RuntimeError("No active dashboard capture to stop")
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            self.state = {"status": "completed" if self.path.exists() else "failed",
                          "file": self.path.name, "bytes": self.path.stat().st_size if self.path.exists() else 0,
                          "detail": "Capture stopped; ready for PCAP analysis" if self.path.exists()
                          else self._error(), "finished": _stamp()}
            self._event("capture_stopped", file=self.path.name, bytes=self.state["bytes"])
            return dict(self.state)
