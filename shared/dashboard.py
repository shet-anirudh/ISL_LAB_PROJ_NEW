"""Local dashboards for the synthetic lab's attacker and victim VMs.

Launch through ``python3 -m attacker.dashboard`` on Kali or
``python3 -m victim.dashboard`` on Ubuntu. Victim status is read-only; Kali's
local dashboard can queue only signed, controlled synthetic C2 actions.
"""

import argparse
import hashlib
import hmac
import json
import secrets
import ssl
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from config import ATTACKER_IP, HMAC_SECRET, LOG_DIR, PROJECT_ROOT, TEST_DATA_DIR, VICTIM_IP


ROOT = Path(PROJECT_ROOT)
LOGS = Path(LOG_DIR)
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_EVENTS = 24
TELEMETRY_PORT = 9083


class ActionController:
    """At most one local, allowlisted C2 action at a time."""

    ALLOWED = {"PING", "START_ENCRYPT", "START_EXFIL", "ANALYZE_PCAP", "VERIFY_SIGNATURE",
               "VERIFY_DATASET", "RUN_BACKUP", "RESTORE_TRIAL", "FULL_LAB_SEQUENCE"}

    def __init__(self, capture=None):
        self.lock = threading.Lock()
        self.capture = capture
        self.state = {"status": "idle", "command": None, "detail": "No action run yet"}

    def status(self):
        with self.lock:
            return dict(self.state)

    def start(self, command):
        if command not in self.ALLOWED:
            raise ValueError("Action is not in the synthetic command allowlist")
        if command in {"ANALYZE_PCAP", "FULL_LAB_SEQUENCE"} and self.capture is not None and self.capture.is_running():
            raise RuntimeError("Stop the dashboard capture before analyzing its PCAP")
        with self.lock:
            if self.state["status"] == "running":
                raise RuntimeError("An action is already running")
            self.state = {"status": "running", "command": command,
                          "detail": "Running full lab sequence" if command == "FULL_LAB_SEQUENCE"
                          else "Running local analysis" if command in {"ANALYZE_PCAP", "VERIFY_SIGNATURE"}
                          else "Waiting for the victim lab agent", "started": _now(), "steps": []}
        threading.Thread(target=self._run, args=(command,), daemon=True).start()
        return self.status()

    def _run(self, command):
        try:
            if command == "FULL_LAB_SEQUENCE":
                detail = self._full_sequence()
            elif command == "ANALYZE_PCAP":
                detail = self._analyze()
            elif command == "VERIFY_SIGNATURE":
                detail = self._verify_signature()
            else:
                detail = self._remote(command)
            status = "completed"
        except Exception as exc:
            status, detail = "failed", str(exc)[:220]
        with self.lock:
            self.state.update(status=status, detail=detail, finished=_now())

    def _step(self, label, operation):
        with self.lock:
            self.state["steps"].append({"name": label, "status": "running", "detail": "In progress"})
            self.state["detail"] = label
            index = len(self.state["steps"]) - 1
        started = time.perf_counter_ns()
        try:
            result = operation()
        except Exception as exc:
            with self.lock:
                self.state["steps"][index].update(status="failed", detail=str(exc)[:180],
                                                  duration_ms=round((time.perf_counter_ns()-started)/1e6, 3))
            raise
        with self.lock:
            self.state["steps"][index].update(status="completed", detail=str(result)[:180],
                                              duration_ms=round((time.perf_counter_ns()-started)/1e6, 3))
        return result

    def _full_sequence(self):
        if self.capture is None:
            raise RuntimeError("Kali dashboard capture control is unavailable")
        started = False
        try:
            name = self._step("Start PCAP capture", lambda: self.capture.start()["file"])
            started = True
            self._step("Verified TLS backup", lambda: self._remote("RUN_BACKUP"))
            self._step("Contained trial", lambda: self._remote("START_ENCRYPT"))
            self._step("Synthetic PDF transfer", lambda: self._remote("START_EXFIL"))
            self._step("Verify original dataset", lambda: self._remote("VERIFY_DATASET"))
            self._step("Isolated restore trial", lambda: self._remote("RESTORE_TRIAL"))
            self._step("Stop PCAP capture", lambda: self.capture.stop()["file"])
            started = False
            report = self._step("Analyze and report", lambda: self._analyze(self.capture.path))
            self._step("Verify signed evaluation", self._verify_signature)
            return f"Full synthetic sequence completed; {name}; {report}"
        except Exception:
            if started and self.capture.is_running():
                try:
                    self._step("Stop capture after failure", lambda: self.capture.stop()["file"])
                except Exception:
                    pass
            raise

    def _analyze(self, capture=None):
        if capture is None:
            captures = [p for p in (ROOT / "results" / "pcap").glob("*.pcapng")
                        if p.is_file() and not p.is_symlink()]
            if not captures:
                raise FileNotFoundError("No Kali PCAP found in results/pcap")
            capture = max(captures, key=lambda p: p.stat().st_mtime_ns)
        report_name = None
        for module in ("analysis.pcap_parser", "analysis.forensic_report"):
            started = time.perf_counter_ns()
            result = subprocess.run([sys.executable, "-m", module, str(capture)],
                                    cwd=ROOT, capture_output=True, text=True, timeout=60)
            _append_dashboard_timing(module, round((time.perf_counter_ns()-started)/1e6, 3),
                                     result.returncode == 0)
            if result.returncode:
                raise RuntimeError(f"{module}: {(result.stderr or result.stdout)[-180:]}")
            if module == "analysis.forensic_report":
                prefix = "PASS: forensic report saved to "
                names = [line[len(prefix):].strip() for line in result.stdout.splitlines()
                         if line.startswith(prefix)]
                if names:
                    report_name = Path(names[-1]).name
        if not report_name:
            raise RuntimeError("Forensic report completed without a saved report path")
        return f"Analyzed {capture.name}; report: {report_name}"

    def _verify_signature(self):
        signatures = [p for p in (ROOT / "results" / "signatures").glob("*.sig.json")
                      if p.is_file() and not p.is_symlink()]
        if not signatures:
            raise FileNotFoundError("No committed signature result found")
        newest = max(signatures, key=lambda p: p.stat().st_mtime_ns)
        source = _json_file(newest, {}).get("source")
        if not isinstance(source, str) or not source.startswith("results/defense_evaluation_"):
            raise ValueError("Signature record does not identify a synthetic evaluation")
        started = time.perf_counter_ns()
        result = subprocess.run([sys.executable, "-m", "tests.signature_demo", "--verify", source],
                                cwd=ROOT, capture_output=True, text=True, timeout=20)
        _append_dashboard_timing("signature_verify_file", round((time.perf_counter_ns()-started)/1e6, 3),
                                 result.returncode == 0)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout)[-180:])
        return f"Verified RSA-PSS signature for {Path(source).name}"

    def _remote(self, command):
        started = time.perf_counter_ns()
        receiver_thread = None
        receiver_result = {}
        try:
            if command == "START_EXFIL":
                from attacker.transfer_receiver import receive_once
                ready = threading.Event()

                def receive():
                    try:
                        receiver_result["record"] = receive_once(ready=ready, accept_timeout=25)
                    except Exception as exc:
                        receiver_result["error"] = str(exc)[:180]
                        ready.set()

                receiver_thread = threading.Thread(target=receive, daemon=True)
                receiver_thread.start()
                if not ready.wait(timeout=3) or "error" in receiver_result:
                    raise RuntimeError(receiver_result.get("error", "Transfer receiver did not start"))
            from attacker.c2_server import serve_once
            response = serve_once(command, accept_timeout=20)
            _append_dashboard_timing("c2_" + command.lower(),
                                     round((time.perf_counter_ns()-started)/1e6, 3),
                                     response["cmd"] == "ACK")
            if response["cmd"] != "ACK":
                raise RuntimeError(f"Victim rejected {command}: {response['data']}")
            data = response["data"]
            if command == "START_ENCRYPT" and not (data.get("executed") and data.get("contained")):
                raise RuntimeError("Victim did not confirm copy-only containment")
            if command == "VERIFY_DATASET" and not (data.get("executed") and data.get("intact") and data.get("files") == 20):
                raise RuntimeError("Victim did not confirm 20 baseline files")
            if command == "RUN_BACKUP" and not (data.get("executed") and data.get("verified") and data.get("files") == 20):
                raise RuntimeError("Victim did not confirm a verified backup")
            if command == "RESTORE_TRIAL" and not (data.get("executed") and data.get("files") == 20 and data.get("trial")):
                raise RuntimeError("Victim did not confirm an isolated restore")
            if command == "START_EXFIL":
                receiver_thread.join(timeout=28)
                if "error" in receiver_result or receiver_thread.is_alive():
                    raise RuntimeError(receiver_result.get("error", "Transfer receiver timed out"))
                record = receiver_result.get("record", {})
                if not data.get("executed") or record.get("file") != "01_Operations/report.pdf":
                    raise RuntimeError("Verified synthetic transfer was not confirmed")
                return f"Recovered {record['file']} ({record['bytes']} bytes), SHA-256 verified"
            if command == "START_ENCRYPT":
                return f"Contained copy-only trial {data['trial']}"
            if command == "VERIFY_DATASET":
                return "Victim verified all 20 baseline files"
            if command == "RUN_BACKUP":
                return f"TLS backup {data['snapshot']} verified (20 files)"
            if command == "RESTORE_TRIAL":
                return f"Restored {data['snapshot']} into isolated {data['trial']} (20 files)"
            return "Victim acknowledged PING (dry run)"
        except Exception:
            if receiver_thread is not None and receiver_thread.is_alive():
                receiver_thread.join(timeout=27)
            raise


def _json_file(path, default):
    try:
        if path.is_symlink() or not path.is_file():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return default


def _events(name):
    path = LOGS / name
    try:
        if path.is_symlink() or not path.is_file():
            return []
        with path.open("rb") as stream:
            stream.seek(0, 2)
            size = stream.tell()
            stream.seek(max(0, size - MAX_LOG_BYTES))
            if size > MAX_LOG_BYTES:
                stream.readline()
            raw = stream.read().splitlines()
        events = []
        for line in raw[-3000:]:
            try:
                row = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if isinstance(row, dict):
                events.append(row)
        return events
    except OSError:
        return []


def _append_dashboard_timing(operation, duration_ms, successful):
    """Record bounded wall-time measurements for dashboard-initiated stages."""
    LOGS.mkdir(parents=True, exist_ok=True)
    path = LOGS / "dashboard_timing.log"
    if path.is_symlink():
        raise ValueError("Timing log must not be a symlink")
    row = {"ts": _now(), "module": "dashboard", "event": "stage_timed",
           "operation": operation, "duration_ms": duration_ms, "successful": successful}
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(row, sort_keys=True) + "\n")


def _performance_data(evaluation, crypto, text_result, image_result, audio_result, signature, hash_result):
    """Expose observed measurements with source, units, and sample counts."""
    rows = []

    def add(group, label, value, unit, source, count=None):
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
            rows.append({"group": group, "label": label, "value": round(float(value), 6),
                         "unit": unit, "source": source, "samples": count})

    for label, result, group in (("Text", text_result, "Encryption / decryption"),
                                  ("RGB pixels", image_result, "Encryption / decryption"),
                                  ("MP3", audio_result, "Encryption / decryption")):
        timings = result.get("timings_ms_median") or {}
        for name in ("encrypt", "decrypt"):
            add(group, label + " " + name, timings.get(name), "ms", "sample AES median", 10)
    for kind, result in crypto.items():
        if not isinstance(result, dict):
            continue
        for name in ("encrypt", "decrypt"):
            add("File-level AES", kind.title() + " " + name,
                result.get("aes_" + name + "_median_ms"), "ms", "file benchmark", 10)
            add("AES throughput", kind.title() + " " + name,
                result.get("aes_" + name + "_mib_per_s"), "MiB/s", "file benchmark", 10)
        add("Key operations", kind.title() + " RSA wrap", result.get("rsa_wrap_median_ms"),
            "ms", "file benchmark", 10)
    add("Hashing", "SHA-256 digest", hash_result.get("generation_time_ms_median"),
        "ms", "synthetic mission brief", hash_result.get("generation_trials"))
    for key, label in (("sha256", "Artifact hash"), ("sign", "RSA-PSS sign"),
                       ("verify", "RSA-PSS verify")):
        add("Signature", label, (signature.get("timings_ms_median") or {}).get(key),
            "ms", "signed evaluation", signature.get("trials"))
    runs = evaluation.get("runs") or []
    for key, label in (("alert_to_stop_ms", "Honeypot alert to stop"),
                       ("kill_response_ms", "Containment kill response")):
        values = [run[key] for run in runs if run.get("mode") == "with" and
                  isinstance(run.get(key), (float, int))]
        if values:
            add("Honeypot / containment", label, statistics.median(values),
                "ms", "monitored paired trials", len(values))
    unmonitored = [run.get("elapsed_s") for run in runs if run.get("mode") == "without" and
                   isinstance(run.get("elapsed_s"), (int, float))]
    if unmonitored:
        add("Ransomware trial", "Copy-only lock trial", statistics.median(unmonitored)*1000,
            "ms", "unmonitored complete trials", len(unmonitored))
    locked_files = [e for e in _events("simulator.log")
                    if e.get("event") == "synthetic_file_encrypted"]
    for key, label in (("encrypt_ms", "Per-file AES lock"),
                       ("wrap_ms", "Per-file RSA key wrap"),
                       ("write_ms", "Per-file locked copy write")):
        values = [e[key] for e in locked_files if isinstance(e.get(key), (int, float))]
        if values:
            add("Ransomware trial", label, statistics.median(values),
                "ms", "synthetic file log", len(values))
    sent = [e.get("elapsed_s") for e in _events("transfer.log") if e.get("event") == "file_sent"
            and isinstance(e.get("elapsed_s"), (int, float))]
    if sent:
        add("Transfer", "Encrypted file transfer", statistics.median(sent)*1000,
            "ms", "victim transfer log", len(sent))
    timings = _events("dashboard_timing.log")
    for op, label, group in (("analysis.pcap_parser", "PCAP parse", "Forensics"),
                             ("analysis.forensic_report", "Report generation", "Forensics"),
                             ("signature_verify_file", "Artifact verification", "Signature"),
                             ("c2_start_encrypt", "C2 contained trial round trip", "C2 workflow"),
                             ("c2_start_exfil", "C2 transfer round trip", "C2 workflow"),
                             ("c2_run_backup", "TLS backup round trip", "Backup / recovery"),
                             ("c2_restore_trial", "Isolated restore round trip", "Backup / recovery"),
                             ("c2_verify_dataset", "Dataset verification round trip", "Integrity")):
        values = [e.get("duration_ms") for e in timings
                  if e.get("operation") == op and e.get("successful") is True and
                  isinstance(e.get("duration_ms"), (int, float))]
        if values:
            add(group, label, statistics.median(values), "ms", "Kali dashboard wall time", len(values))
    return rows


def _baseline():
    data = _json_file(ROOT / "results" / "baseline_hashes.json", {})
    files = data.get("files", {}) if isinstance(data, dict) else {}
    if not isinstance(files, dict):
        return {}
    return {n: h for n, h in files.items() if isinstance(n, str) and
            isinstance(h, str) and len(h) == 64}


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _event_feed(groups):
    rows = []
    for group in groups:
        for event in group:
            rows.append({"ts": str(event.get("ts", "")),
                         "module": str(event.get("module", ""))[:30],
                         "event": str(event.get("event", ""))[:50],
                         "detail": str(event.get("detail") or event.get("file") or event.get("cmd") or
                                       event.get("reason") or event.get("trial") or
                                       event.get("pid") or "")[:160]})
    rows.sort(key=lambda row: row["ts"].replace("+00:00", "Z"), reverse=True)
    return rows[:MAX_EVENTS]


def _latest_trial():
    results = ROOT / "results"
    if results.is_symlink() or not results.is_dir():
        return None
    trials = [p for p in results.glob("simtrial-*") if p.is_dir() and not p.is_symlink()]
    if not trials:
        return None
    latest = max(trials, key=lambda p: p.stat().st_mtime_ns)
    locked = list(latest.rglob("*.locked"))
    decoys = sum("A_COMMAND_ARCHIVE" in p.relative_to(latest).parts for p in locked)
    summary = _json_file(latest / "summary.json", {})
    complete = isinstance(summary, dict) and isinstance(summary.get("files"), list)
    return {"name": latest.name, "decoy": decoys, "real": len(locked) - decoys,
            "complete": complete, "count": len(locked)}


def _security_data():
    """Read bounded, locally generated measurement summaries for the UI."""
    results = ROOT / "results"
    text_result = _json_file(results / "text_security.json", {})
    hash_result = _json_file(results / "hash_security.json", {})
    image_dirs = [p for p in results.glob("image_security_*")
                  if p.is_dir() and not p.is_symlink()]
    image_dir = max(image_dirs, key=lambda p: p.stat().st_mtime_ns) if image_dirs else None
    image_result = _json_file(image_dir / "metrics.json", {}) if image_dir else {}
    audio_dirs = [p for p in results.glob("audio_security_*")
                  if p.is_dir() and not p.is_symlink()]
    audio_dir = max(audio_dirs, key=lambda p: p.stat().st_mtime_ns) if audio_dirs else None
    audio_result = _json_file(audio_dir / "metrics.json", {}) if audio_dir else {}
    evaluations = [p for p in results.glob("defense_evaluation_*.json")
                   if p.is_file() and not p.is_symlink()]
    evaluation = _json_file(max(evaluations, key=lambda p: p.stat().st_mtime_ns), {}) if evaluations else {}
    signatures = [p for p in (results / "signatures").glob("*.sig.json")
                  if p.is_file() and not p.is_symlink()]
    signature = _json_file(max(signatures, key=lambda p: p.stat().st_mtime_ns), {}) if signatures else {}
    crypto = _json_file(results / "crypto_benchmarks.json", {})
    return {
        "text": {key: text_result.get(key) for key in
                 ("plaintext", "ciphertext_base64", "recovered_plaintext", "timings_ms_median",
                  "diffusion_one_plaintext_bit", "confusion_one_key_bit", "algorithm",
                  "iv_base64", "plaintext_bytes", "ciphertext_bytes", "metric_definition")},
        "hash": {key: hash_result.get(key) for key in
                 ("digest_hex", "generation_time_ms_median",
                  "one_input_bit_digest_change_pct_median", "digest_changed_bits_each_trial",
                  "generation_trials", "source_bytes", "bounded_search", "definitions", "limit")},
        "image": {"metrics": image_result.get("metrics"),
                  "timings_ms_median": image_result.get("timings_ms_median"),
                  "previews_available": image_dir is not None and all(
                      (image_dir / filename).is_file() and not (image_dir / filename).is_symlink()
                      for filename in ("original.png", "encrypted_pixels.png", "recovered.png"))},
        "audio": {"source_bytes": audio_result.get("source_bytes"),
                  "sha256": audio_result.get("sha256"),
                  "ciphertext_prefix_base64": audio_result.get("ciphertext_prefix_base64"),
                  "timings_ms_median": audio_result.get("timings_ms_median"),
                  "recovered_matches_baseline": audio_result.get("recovered_matches_baseline"),
                  "playback_available": audio_dir is not None and
                  (audio_dir / "recovered.mp3").is_file() and
                  not (audio_dir / "recovered.mp3").is_symlink()},
        "evaluation": {"pairs": evaluation.get("pairs"), "summary": evaluation.get("summary"),
                       "runs": evaluation.get("runs", [])[:40]},
        "signature": {key: signature.get(key) for key in
                      ("algorithm", "source", "source_bytes", "sha256", "signature_base64",
                       "public_key_sha256", "timings_ms_median", "tampered_byte_rejected", "trials")},
        "crypto": crypto.get("measurements", {}),
        "performance": _performance_data(evaluation, crypto.get("measurements", {}),
                                          text_result, image_result, audio_result,
                                          signature, hash_result),
    }


def _reports():
    results = ROOT / "results"
    files = [p for pattern in ("security_summary_*.md", "reports/*.md")
             for p in results.glob(pattern) if p.is_file() and not p.is_symlink()]
    output = []
    for path in sorted(files, key=lambda p: p.stat().st_mtime_ns, reverse=True)[:8]:
        try:
            output.append({"name": path.name, "kind": "Forensic" if path.parent.name == "reports" else "Security",
                           "text": path.read_text(encoding="utf-8")[:12000]})
        except (OSError, UnicodeError):
            pass
    return output


def _victim():
    baseline = _baseline()
    data_root = Path(TEST_DATA_DIR)
    intact = missing = changed = 0
    for name, expected in baseline.items():
        path = data_root / name
        try:
            if path.is_symlink() or not path.is_file():
                missing += 1
            elif _sha256(path) == expected:
                intact += 1
            else:
                changed += 1
        except OSError:
            missing += 1
    honeypot = _events("honeypot.log")
    containment = _events("containment.log")
    simulator = _events("simulator.log")
    transfer = _events("transfer.log")
    c2 = _events("c2.log")
    backups = Path.home() / "BACKUP"
    snapshots = [] if not backups.is_dir() or backups.is_symlink() else [
        p for p in backups.glob("snapshot-*") if p.is_dir() and not p.is_symlink()]
    latest_backup = max(snapshots, key=lambda p: p.stat().st_mtime_ns).name if snapshots else "None"
    restore_trials = [p for p in (ROOT / "results").glob("restore-trial-*")
                      if p.is_dir() and not p.is_symlink()]
    trial = _latest_trial()
    kills = [e for e in containment if e.get("event") == "process_killed"]
    return {
        "role": "victim", "title": "Victim Defense", "updated": _now(),
        "cards": [
            {"label": "Dataset integrity", "value": f"{intact}/{len(baseline)}", "note": f"{changed} changed · {missing} missing"},
            {"label": "Decoy alerts", "value": len([e for e in honeypot if e.get("event") == "decoy_touched"]), "note": "Historical file events"},
            {"label": "Confirmed stops", "value": len(kills), "note": "Registered processes only"},
            {"label": "Backup snapshots", "value": len(snapshots), "note": latest_backup},
        ],
        "trial": trial,
        "telemetry": {"intact": bool(baseline) and intact == len(baseline),
                      "stops": len(kills), "alerts": len(honeypot),
                      "backups": len(snapshots)},
        "summary": [
            {"label": "Dataset", "value": "Matches baseline" if baseline and intact == len(baseline) else "Attention required"},
            {"label": "Latest trial", "value": "None" if trial is None else trial["name"] + (" · complete" if trial["complete"] else " · interrupted/in progress")},
            {"label": "Last containment", "value": kills[-1].get("ts", "Unknown") if kills else "None"},
            {"label": "Restore trials", "value": str(len(restore_trials)) + " isolated directories"},
            {"label": "Files sent", "value": str(sum(e.get("event") == "file_sent" for e in transfer))},
            {"label": "C2 messages", "value": str(len(c2)) + " · signed lab and dry-run actions"},
        ],
        "events": _event_feed([honeypot, containment, simulator, transfer, c2]),
        "security": _security_data(),
        "reports": _reports(),
    }


def _token():
    if not isinstance(HMAC_SECRET, bytes) or len(HMAC_SECRET) < 16:
        raise ValueError("A shared HMAC_SECRET of at least 16 bytes is required")
    return hmac.new(HMAC_SECRET, b"islab-dashboard-telemetry-v1",
                    hashlib.sha256).hexdigest()


def _remote_victim():
    """Fetch read-only victim telemetry with pinned TLS and a shared token."""
    cert = ROOT / "keys" / "backup.crt"
    try:
        context = ssl.create_default_context(cafile=str(cert))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
        request = Request(f"https://{VICTIM_IP}:{TELEMETRY_PORT}/api/status",
                          headers={"X-ISLab-Telemetry": _token()})
        with opener.open(request, timeout=1.5) as response:
            raw = response.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            return None
        data = json.loads(raw)
        if (not isinstance(data, dict) or data.get("role") != "victim" or
                not isinstance(data.get("telemetry"), dict)):
            return None
        return data
    except (OSError, ValueError, ssl.SSLError):
        return None


def _attacker():
    baseline = _baseline()
    transfer = _events("transfer.log")
    c2 = _events("c2.log")
    received = ROOT / "received"
    allowed = {}
    for name, digest in baseline.items():
        allowed.setdefault(Path(name).name, set()).add(digest)
    recovered = []
    if received.is_dir() and not received.is_symlink():
        for path in sorted(received.rglob("*")):
            if path.is_file() and not path.is_symlink():
                try:
                    recovered.append({"name": path.relative_to(received).as_posix(),
                                      "bytes": path.stat().st_size,
                                      "valid": _sha256(path) in allowed.get(path.name, set())})
                except OSError:
                    pass
    verified = sum(item["valid"] for item in recovered)
    responses = [e for e in c2 if e.get("event") == "response_received"]
    rejects = sum(e.get("event") == "spoof_rejected" for e in c2)
    remote = _remote_victim()
    remote_info = remote["telemetry"] if remote else {}
    trial = remote.get("trial") if remote else None
    remote_events = [] if not remote else [
        {**event, "module": "victim / " + str(event.get("module", ""))}
        for event in remote.get("events", []) if isinstance(event, dict)]
    security = remote.get("security") if remote else _security_data()
    security = dict(security or {})
    local_performance = [row for row in _security_data().get("performance", [])
                         if row.get("source") == "Kali dashboard wall time"]
    security["performance"] = [row for row in security.get("performance", [])
                               if row.get("source") != "Kali dashboard wall time"] + local_performance
    return {
        "role": "attacker", "title": "Attacker Activity", "updated": _now(),
        "cards": [
            {"label": "Recovered samples", "value": verified, "note": f"{len(recovered)} local files · baseline checked"},
            {"label": "Received transfers", "value": sum(e.get("event") == "file_received" for e in transfer), "note": "Historical verified events"},
            {"label": "C2 responses", "value": len(responses), "note": "Signed lab commands and dry runs"},
            {"label": "Spoof attempts blocked", "value": rejects, "note": "Authenticated relay demo"},
            {"label": "Victim confirmed stops", "value": remote_info.get("stops", "—"),
             "note": "Live victim telemetry" if remote else "Victim telemetry unavailable"},
            {"label": "Victim latest trial", "value": "—" if trial is None else
             str(trial.get("decoy", 0)) + " / " + str(trial.get("real", 0)),
             "note": "Decoy / real encrypted copies" if trial else "No live trial data"},
        ],
        "files": recovered,
        "summary": [
            {"label": "Last C2 response", "value": "None" if not responses else str(responses[-1].get("cmd", "")) + " · " + str(responses[-1].get("requested", ""))},
            {"label": "Signed commands sent", "value": str(sum(e.get("event") == "command_sent" and e.get("signed") is True for e in c2))},
            {"label": "Bytes recovered", "value": f"{sum(item['bytes'] for item in recovered):,}"},
            {"label": "Victim telemetry", "value": "Connected · " + remote.get("updated", "") if remote else "Unavailable · start victim dashboard"},
            {"label": "Victim dataset", "value": "Baseline intact" if remote_info.get("intact") else
             "Attention required" if remote else "Unavailable"},
            {"label": "Latest victim trial", "value": trial.get("name", "Unknown") if trial else "None reported"},
        ],
        "events": _event_feed([transfer, c2, remote_events]),
        "security": security,
        "reports": _reports(),
    }


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IS Lab Dashboard</title>
<style>
:root{color-scheme:dark;font-family:Inter,system-ui,-apple-system,sans-serif;background:#0b1220;color:#e5ecf5}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 75% -10%,#183857 0,transparent 37%),#0b1220}
main{max-width:1240px;margin:auto;padding:35px 25px 65px}header{display:flex;justify-content:space-between;align-items:start;gap:16px;margin-bottom:28px}
.eyebrow{text-transform:uppercase;letter-spacing:.16em;color:#53d6bf;font-size:12px;font-weight:750}h1{font-size:clamp(28px,4vw,42px);margin:8px 0 5px}h2{font-size:18px;margin:0 0 17px}
.muted{color:#9badbf;font-size:14px}.pill{border:1px solid #3a6874;background:#143d47;color:#98f3dd;border-radius:20px;padding:8px 13px;font-size:12px;white-space:nowrap}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card,.panel{border:1px solid #25374b;background:#142235d9;border-radius:16px;box-shadow:0 14px 28px #0002}
.card{padding:20px}.label{color:#a6b8cb;font-size:13px}.value{font-size:34px;letter-spacing:-.05em;font-weight:750;margin:12px 0 4px}.note{color:#83cabf;font-size:12px;overflow-wrap:anywhere}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:18px}.panel{padding:22px;min-width:0}.wide{grid-column:1/-1}
.row{display:flex;justify-content:space-between;gap:20px;border-bottom:1px solid #26374a;padding:11px 0;font-size:13px}.row:last-child{border:0}.row span:first-child{color:#9badbf}.row span:last-child{text-align:right;overflow-wrap:anywhere}
.bars{display:grid;gap:18px}.barhead{display:flex;justify-content:space-between;color:#b9cddd;font-size:13px;margin-bottom:7px}.track{height:10px;border-radius:8px;background:#28384b;overflow:hidden}.fill{height:100%;border-radius:8px;background:#42c9af;transition:width .3s}.fill.real{background:#ff9878}
.scroll{max-height:390px;overflow:auto}table{width:100%;border-collapse:collapse;text-align:left;font-size:12px}th{color:#8fa6ba;font-weight:650;position:sticky;top:0;background:#142235}td,th{padding:11px 9px;border-bottom:1px solid #26374a;vertical-align:top}td{overflow-wrap:anywhere}.ok{color:#65dec2}.bad{color:#ff9b83}
.measure-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:22px}.measure-grid h3{margin:12px 0;font-size:15px}.measure-grid pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1727;border:1px solid #294059;border-radius:10px;padding:12px;max-height:170px;overflow:auto;font-size:12px}.previews{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:16px 0}.previews img{width:100%;height:auto;aspect-ratio:4/3;object-fit:contain;background:#0b1727;border:1px solid #294059;border-radius:9px}.previews figure{margin:0}.previews figcaption{font-size:12px;color:#a6b8cb;margin-top:7px}.measure-note{color:#9badbf;font-size:12px;line-height:1.5}
.app-shell{display:grid;grid-template-columns:230px minmax(0,1fr);gap:26px;align-items:start}.tabs{display:flex;flex-direction:column;gap:6px;position:sticky;top:20px;max-height:calc(100vh - 40px);overflow:auto;padding:14px;border:1px solid #25374b;border-radius:16px;background:#101e30}.nav-label{padding:12px 10px 5px;color:#65dec2;font-size:11px;text-transform:uppercase;letter-spacing:.12em}.tabs button,.action-button{font:inherit;cursor:pointer;border:1px solid #386079;border-radius:10px;color:#b9d5e6;background:#1b3248;padding:10px 14px}.tabs button{text-align:left;width:100%;border-color:transparent;background:transparent}.tabs button[aria-selected="true"]{background:#24645e;border-color:#49c9ad;color:#fff}.tab-view[hidden],.tabs button[hidden]{display:none}.tab-view>.panel{margin-top:14px}.action-buttons{display:flex;flex-wrap:wrap;gap:12px}.action-button{background:#215b55;border-color:#48b9a7}.action-button:disabled{opacity:.5;cursor:wait}.action-status{margin-top:18px;padding:16px;background:#0c1b2d;border-radius:10px;min-height:70px}.tab-view audio{width:100%;margin:12px 0 18px}
.tab-view pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1727;border:1px solid #294059;border-radius:10px;padding:12px;max-height:500px;overflow:auto;font-size:12px}
.chart-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;margin:18px 0}.chart{border:1px solid #294059;border-radius:12px;background:#0d1b2b;padding:15px;min-width:0}.chart h3{font-size:14px;margin:0 0 12px}.chart svg{display:block;width:100%;height:auto;overflow:visible}.chart small{color:#9badbf}.legend{display:flex;gap:14px;flex-wrap:wrap;color:#b9cddd;font-size:12px;margin-top:9px}.legend span:before{content:'●';color:var(--swatch);margin-right:5px}.process-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.process{background:#10263a;border:1px solid #294059;padding:15px;border-radius:12px}.process strong{display:block;margin-bottom:8px;color:#65dec2}.table-wrap{overflow:auto}.table-wrap table{min-width:650px}.insight{border-left:3px solid #49c9ad;padding:12px 15px;background:#102b38;margin:15px 0;color:#c2dae5}.signature-value{word-break:break-all;font-family:ui-monospace,monospace;line-height:1.6}.status-good{color:#65dec2}.status-warn{color:#ffba83}
.report-list{display:flex;flex-wrap:wrap;gap:9px;margin:0 0 18px}.report-list button{font:inherit;cursor:pointer;border:1px solid #386079;background:#183149;color:#c4dbe9;border-radius:9px;padding:8px 11px}.report-list button[aria-selected="true"]{border-color:#49c9ad;background:#24645e;color:#fff}
.sequence-steps{padding-left:22px;color:#bad0dc;font-size:13px}.sequence-steps li{padding:5px 0}.sequence-steps li[data-status="completed"]{color:#65dec2}.sequence-steps li[data-status="failed"]{color:#ff9b83}
@media(max-width:850px){.app-shell{grid-template-columns:1fr}.tabs{position:static;max-height:none;display:flex;flex-direction:row;overflow-x:auto;white-space:nowrap;padding:8px}.tabs button{width:auto;flex:none}.tabs .nav-label{display:none}.cards{grid-template-columns:repeat(2,1fr)}.grid,.chart-grid,.process-grid{grid-template-columns:1fr}.wide{grid-column:auto}}@media(max-width:520px){.cards{grid-template-columns:1fr 1fr}.card{padding:14px}.value{font-size:27px}main{padding:20px 14px}.pill{display:none}}
</style></head><body><main>
<header><div><div class="eyebrow">IS Lab · Synthetic Environment</div><h1 id="title">Dashboard</h1><div class="muted" id="updated">Loading local evidence…</div></div><span class="pill" id="mode-pill">LAB VM</span></header>
<div class="app-shell"><nav class="tabs" aria-label="Dashboard sections" id="tabs">
<span class="nav-label">Mission</span><button data-tab="overview" aria-selected="true">Overview</button><button data-tab="controls" hidden>Lab controls</button><button data-tab="honeypot">Honeypot demo</button><button data-tab="defense">Defense</button>
<span class="nav-label">Security analysis</span><button data-tab="text">Plaintext &amp; ciphertext</button><button data-tab="avalanche">Avalanche / diffusion</button><button data-tab="confusion">Confusion</button><button data-tab="image">Image</button><button data-tab="audio">Audio</button><button data-tab="hash">Hashing</button><button data-tab="signature">Signature</button>
<span class="nav-label">Evidence</span><button data-tab="performance">Performance</button><button data-tab="reports">Reports</button><button data-tab="events">Events</button></nav><div class="workspace">
<div class="tab-view" id="tab-overview"><section class="cards" id="cards"></section><div class="grid"><section class="panel"><h2>Activity summary</h2><div id="summary"></div></section>
<section class="panel"><h2 id="chart-title">Latest trial</h2><div class="bars" id="visual"></div></section>
</div></div>
<div class="tab-view" id="tab-controls" hidden><section class="panel"><h2>Controlled synthetic actions</h2>
<p class="muted">Ubuntu must run the armed lab agent. Actions use signed C2; encryption writes disposable copies and transfer sends only the fixed synthetic report.</p>
<div class="action-buttons"><button class="action-button" data-action="PING">Ping victim</button>
<button class="action-button" data-action="START_ENCRYPT">Run contained trial</button>
<button class="action-button" data-action="START_EXFIL">Transfer synthetic PDF</button>
<button class="action-button" data-action="ANALYZE_PCAP">Analyze latest PCAP</button>
<button class="action-button" data-action="VERIFY_SIGNATURE">Verify evaluation signature</button></div>
<h3>Victim defense workflows</h3><p class="muted">These signed requests verify the synthetic baseline, create a verified TLS backup, or restore only into an isolated trial directory.</p>
<div class="action-buttons"><button class="action-button" data-action="VERIFY_DATASET">Verify dataset</button>
<button class="action-button" data-action="RUN_BACKUP">Create TLS backup</button>
<button class="action-button" data-action="RESTORE_TRIAL">Restore latest backup to trial</button></div>
<h3>Host-only network capture</h3><p class="muted">Capture only victim C2 and transfer ports on Kali eth1. Automatically stops after five minutes or 10 MiB.</p>
<div class="action-buttons"><button class="action-button" data-capture="start">Start PCAP capture</button>
<button class="action-button" data-capture="stop">Stop PCAP capture</button></div>
<div class="action-status" id="capture-status" role="status">No dashboard capture started.</div>
<div class="action-status" id="action-status" role="status">No action run yet.</div></section></div>
<div class="tab-view" id="tab-honeypot" hidden><section class="panel"><h2>Honeypot monitoring demo</h2><p class="muted">The simulator writes encrypted copies into a disposable trial. Its first decoy event triggers containment of its registered PID. The original dataset is verified after the run.</p><div id="security-honeypot"></div><div id="demo-control" hidden><p class="insight">Run the full guided sequence: capture, verified backup, contained trial, encrypted transfer, dataset check, isolated restore, PCAP analysis, report, and signature verification. Keep the victim dashboard and armed C2 agent running.</p><button class="action-button" data-action="FULL_LAB_SEQUENCE">Run entire synthetic demo</button><div class="action-status" id="demo-status" role="status">No demo run yet.</div><ol id="sequence-steps" class="sequence-steps"></ol></div><h3>Recent decoy and containment events</h3><div id="honeypot-events"></div></section></div>
<div class="tab-view" id="tab-text" hidden><section class="panel"><h2>Plaintext and ciphertext</h2><div id="security-text"></div></section></div>
<div class="tab-view" id="tab-avalanche" hidden><section class="panel"><h2>Avalanche effect / diffusion</h2><div id="security-avalanche"></div></section></div>
<div class="tab-view" id="tab-confusion" hidden><section class="panel"><h2>Confusion</h2><div id="security-confusion"></div></section></div>
<div class="tab-view" id="tab-image" hidden><section class="panel"><h2>RGB image analysis</h2><div id="security-image"></div></section></div>
<div class="tab-view" id="tab-audio" hidden><section class="panel"><h2>Audio encryption</h2><div id="security-audio"></div></section></div>
<div class="tab-view" id="tab-defense" hidden><section class="panel"><h2>Containment evaluation</h2><div id="security-defense"></div></section></div>
<div class="tab-view" id="tab-performance" hidden><section class="panel"><h2>Performance analysis</h2><div id="security-performance"></div></section></div>
<div class="tab-view" id="tab-hash" hidden><section class="panel"><h2>SHA-256 security and performance</h2><div id="security-hash"></div></section></div>
<div class="tab-view" id="tab-signature" hidden><section class="panel"><h2>Digital signature generation and verification</h2><div id="security-signature"></div></section></div>
<div class="tab-view" id="tab-reports" hidden><section class="panel"><h2>Generated reports</h2><div id="reports"></div></section></div>
<div class="tab-view" id="tab-events" hidden><section class="panel"><h2>Recorded events</h2><div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Module</th><th>Event</th><th>Detail</th></tr></thead><tbody id="events"></tbody></table></div></section></div>
</div></div></main><script>
const ACTION_TOKEN='__ACTION_TOKEN__';
const $=id=>document.getElementById(id);
let activeTab='overview',role='victim';
let selectedReport=null;
function showTab(name){
  if(name==='controls'&&role!=='attacker')name='overview';
  activeTab=name;
  for(const button of document.querySelectorAll('#tabs button'))button.setAttribute('aria-selected',String(button.dataset.tab===name));
  for(const pane of document.querySelectorAll('.tab-view'))pane.hidden=pane.id!=='tab-'+name;
}
for(const button of document.querySelectorAll('#tabs button'))button.addEventListener('click',()=>showTab(button.dataset.tab));
function el(tag,cls,content){const node=document.createElement(tag);if(cls)node.className=cls;if(content!==undefined)node.textContent=String(content);return node}
function measurement(container,label,value,max,unit){
  if(typeof value!=='number'||!isFinite(value))return;
  const head=el('div','barhead');head.append(el('span','',label),el('strong','',value.toFixed(3)+' '+unit));
  const track=el('div','track'),fill=el('div','fill');fill.style.width=Math.min(100,Math.max(0,value/max*100))+'%';
  track.append(fill);container.append(head,track);
}
function metricRow(container,label,value){const row=el('div','row');row.append(el('span','',label),el('span','',value));container.append(row)}
function section(parent,title){const box=el('div','');box.append(el('h3','',title));parent.append(box);return box}
const SVG_NS='http://www.w3.org/2000/svg';
function svgEl(tag,attrs={}){const node=document.createElementNS(SVG_NS,tag);for(const [key,value] of Object.entries(attrs))node.setAttribute(key,String(value));return node}
function chart(parent,title,series,{kind='bar',unit='',note='',labels=null}={}){
  const valid=series.filter(s=>Array.isArray(s.values)&&s.values.some(v=>Number.isFinite(Number(v))));
  if(!valid.length)return;
  const box=el('div','chart');box.append(el('h3','',title));const width=500,height=215,padL=42,padB=39,padT=12,padR=12;
  const values=valid.flatMap(s=>s.values.filter(v=>Number.isFinite(Number(v))).map(Number));
  const top=Math.max(1,...values)*1.1,n=Math.max(...valid.map(s=>s.values.length));
  const svg=svgEl('svg',{viewBox:`0 0 ${width} ${height}`,role:'img','aria-label':title});
  for(let tick=0;tick<=4;tick++){
    const y=height-padB-(height-padB-padT)*tick/4;
    svg.append(svgEl('line',{x1:padL,y1:y,x2:width-padR,y2:y,stroke:'#2c4054'}));
    const t=svgEl('text',{x:padL-5,y:y+4,'text-anchor':'end',fill:'#a6b8cb','font-size':10});t.textContent=(top*tick/4).toFixed(top<10?2:0);svg.append(t);
  }
  const plotW=width-padL-padR,plotH=height-padB-padT;
  if(kind==='line'){
    valid.forEach((s,index)=>{
      const points=s.values.map((v,i)=>`${padL+(n===1?plotW/2:i*plotW/(n-1))},${height-padB-Number(v)/top*plotH}`).join(' ');
      svg.append(svgEl('polyline',{points,fill:'none',stroke:s.color||['#49c9ad','#ffad83','#81aafb'][index%3],'stroke-width':2.5,'stroke-linejoin':'round'}));
      if(s.values.length<=25)s.values.forEach((v,i)=>svg.append(svgEl('circle',{cx:padL+(n===1?plotW/2:i*plotW/(n-1)),cy:height-padB-Number(v)/top*plotH,r:2.5,fill:s.color||['#49c9ad','#ffad83','#81aafb'][index%3]})));
    });
  }else{
    const band=plotW/n,barW=Math.max(2,Math.min(24,band/(valid.length+0.4)));
    valid.forEach((s,index)=>s.values.forEach((v,i)=>{
      const h=Math.max(0,Number(v)/top*plotH),x=padL+i*band+(band-barW*valid.length)/2+index*barW;
      const rect=svgEl('rect',{x,y:height-padB-h,width:barW-1,height:h,rx:2,fill:s.color||['#49c9ad','#ffad83','#81aafb'][index%3]});
      const tip=svgEl('title');tip.textContent=`${labels?.[i]||i+1} · ${s.name}: ${v} ${unit}`;rect.append(tip);svg.append(rect);
    }));
  }
  const indexes=n<=12?Array.from({length:n},(_,i)=>i):[0,Math.floor((n-1)/2),n-1];
  indexes.forEach(i=>{const t=svgEl('text',{x:padL+(kind==='bar'?(i+.5)*plotW/n:(n===1?plotW/2:i*plotW/(n-1))),y:height-12,'text-anchor':'middle',fill:'#a6b8cb','font-size':10});t.textContent=String(labels?.[i]??i+1).slice(0,15);svg.append(t)});
  box.append(svg);const legend=el('div','legend');valid.forEach((s,i)=>{const label=el('span','',s.name);label.style.setProperty('--swatch',s.color||['#49c9ad','#ffad83','#81aafb'][i%3]);legend.append(label)});box.append(legend);
  if(note)box.append(el('small','',note));parent.append(box);
}
function chartGrid(parent){const grid=el('div','chart-grid');parent.append(grid);return grid}
function process(parent,title,detail){const box=el('div','process');box.append(el('strong','',title),el('div','muted',detail));parent.append(box)}
function table(parent,headers,rows){const wrap=el('div','table-wrap'),t=el('table',''),thead=el('thead',''),head=el('tr','');headers.forEach(h=>head.append(el('th','',h)));thead.append(head);const body=el('tbody','');rows.forEach(row=>{const tr=el('tr','');row.forEach(value=>tr.append(el('td','',value??'—')));body.append(tr)});t.append(thead,body);wrap.append(t);parent.append(wrap)}
const number=(value,digits=3)=>value!==null&&value!==undefined&&value!==''&&Number.isFinite(Number(value))?Number(value).toFixed(digits):'Not recorded';
function renderReports(items){
  const root=$('reports');root.replaceChildren();
  if(!items.length){root.append(el('p','muted','No generated report is available on this VM.'));return}
  if(!items.some(item=>item.name===selectedReport))selectedReport=items[0].name;
  const list=el('div','report-list');
  for(const item of items){
    const button=el('button','',item.kind+' · '+item.name);
    button.setAttribute('aria-selected',String(item.name===selectedReport));
    button.addEventListener('click',()=>{selectedReport=item.name;renderReports(items)});
    list.append(button);
  }
  const current=items.find(item=>item.name===selectedReport);
  root.append(list,el('pre','',current.text));
}
let lastSecurity='';
function drawSecurity(data){
  const sec=data.security||{},text=sec.text||{},hash=sec.hash||{},im=sec.image||{},audio=sec.audio||{},ev=sec.evaluation||{},sig=sec.signature||{},perf=sec.performance||[];
  const fingerprint=JSON.stringify(sec)+data.role;if(fingerprint===lastSecurity)return;lastSecurity=fingerprint;
  const root={text:$('security-text'),avalanche:$('security-avalanche'),confusion:$('security-confusion'),image:$('security-image'),audio:$('security-audio'),
              defense:$('security-defense'),honeypot:$('security-honeypot'),performance:$('security-performance'),hash:$('security-hash'),signature:$('security-signature')};
  for(const node of Object.values(root))node.replaceChildren();
  if(text.plaintext){
    const box=root.text;
    box.append(el('p','insight',`${text.algorithm||'AES'} · ${text.plaintext_bytes||'?'} plaintext bytes → ${text.ciphertext_bytes||'?'} ciphertext bytes · one synthetic sample. The IV is displayed for inspection; the ephemeral key is never stored.`));
    for(const [label,value] of [['Plaintext',text.plaintext],['IV (Base64)',text.iv_base64],['Ciphertext (Base64)',text.ciphertext_base64],['Recovered plaintext',text.recovered_plaintext]]){
      box.append(el('div','label',label),el('pre','',value||'Not recorded'));
    }
    try{
      const plain=Array.from(new TextEncoder().encode(text.plaintext)),cipher=Array.from(Uint8Array.from(atob(text.ciphertext_base64),c=>c.charCodeAt(0)));
      const lines=chartGrid(box),count=Math.min(32,plain.length,cipher.length);
      chart(lines,'Plaintext vs ciphertext byte values (first '+count+')',[
        {name:'UTF-8 plaintext',values:plain.slice(0,count),color:'#49c9ad'},
        {name:'Ciphertext bytes',values:cipher.slice(0,count),color:'#ffad83'}],{kind:'line',unit:'byte value',note:'Position on x-axis; each y value is a byte from 0 to 255. The two formats have different lengths.'});
      const bins=16,hist=values=>Array.from({length:bins},(_,i)=>values.filter(v=>Math.floor(v/16)===i).length);
      chart(lines,'Byte frequency by 16-value range',[
        {name:'Plaintext',values:hist(plain),color:'#49c9ad'},
        {name:'Ciphertext',values:hist(cipher),color:'#ffad83'}],{unit:'bytes',labels:Array.from({length:bins},(_,i)=>`${i*16}–${i*16+15}`),note:'Counts depend on sample length. This is a visualization, not a randomness test.'});
    }catch(error){box.append(el('p','muted','Byte charts unavailable: '+error.message))}
  }else root.text.append(el('p','muted','Text evidence has not been generated on this VM.'));
  for(const [name,source,kind] of [
    ['avalanche',text.diffusion_one_plaintext_bit,'plaintext'],
    ['confusion',text.confusion_one_key_bit,'key']]){
    const box=root[name];
    box.append(el('p','insight',kind==='plaintext'
      ?'Diffusion experiment: hold the AES key and IV fixed, flip exactly one plaintext bit, re-encrypt, then compare each ciphertext bit with the original.'
      :'Confusion experiment: hold the plaintext and IV fixed, flip exactly one AES key bit, re-encrypt, then compare each ciphertext bit with the original.'));
    if(!source?.summary){box.append(el('p','muted','Ten-trial measurements unavailable.'));continue}
    const s=source.summary,trials=source.trials||[];
    const summary=el('div','process-grid');process(summary,'Ciphertext bits changed',number(s.bit_change_pct_median)+'% median · ideal expectation for avalanche near 50%');
    process(summary,'Hex digits changed',number(s.hex_character_change_pct_median)+'% median · positional ciphertext hex digits, not plaintext characters');box.append(summary);
    const grid=chartGrid(box);chart(grid,'One-bit trials: ciphertext bit changes',[
      {name:'Measured',values:trials.map(t=>t.bit_change_pct),color:'#49c9ad'},
      {name:'50% reference',values:trials.map(()=>50),color:'#ffad83'}],{kind:'line',unit:'%',note:'Each point is one bit flip with the other inputs held fixed.'});
    chart(grid,'One-bit trials: hex digit changes',[
      {name:'Measured',values:trials.map(t=>t.hex_character_change_pct)}],{kind:'bar',unit:'%',note:'Hex representation; 100% is an illustrative target, not a guarantee.'});
    table(box,['Trial','Changed ciphertext bits (%)','Changed ciphertext hex digits (%)'],trials.map((t,i)=>[i+1,number(t.bit_change_pct),number(t.hex_character_change_pct)]));
    box.append(el('p','measure-note',text.metric_definition||'Each controlled trial changes one input bit. Sample values do not prove a general cryptographic guarantee.'));
  }
  if(im.metrics){
    const box=root.image,m=im.metrics,grid=chartGrid(box);
    chart(grid,'RGB pixel encryption metrics',[
      {name:'Measured %',values:[m.npcr_ciphertexts_one_plaintext_bit_pct,m.uaci_ciphertexts_one_plaintext_bit_pct]}],
      {unit:'%',labels:['NPCR','UACI'],note:'Compare two ciphertext pixel views after one plaintext-bit change.'});
    chart(grid,'Entropy, original and encrypted bytes',[
      {name:'Bits/byte',values:[m.entropy_original_bits_per_byte,m.entropy_encrypted_bits_per_byte]}],
      {unit:'bits/byte',labels:['Original','Encrypted'],note:'The maximum for a byte is 8 bits.'});
    table(box,['RGB metric','Observation'],[
      ['Original neighbor correlation',number(m.horizontal_red_correlation_original,4)],['Encrypted neighbor correlation',number(m.horizontal_red_correlation_encrypted,4)],
      ['Original → encrypted MSE',number(m.mse_original_to_encrypted)],['Original → encrypted PSNR',String(m.psnr_original_to_encrypted_db)+' dB'],
      ['Original → recovered MSE',number(m.mse_original_to_recovered)],['Original → recovered PSNR',String(m.psnr_original_to_recovered_db)+' dB']]);
    box.append(el('p','measure-note','Ciphertext bytes are mapped to RGB pixels for display. This pixel view is not a decodable JPEG.'));
    if(data.role==='victim'&&im.previews_available){
      const gallery=el('div','previews');for(const [name,label] of [['original','Original RGB'],['encrypted','Ciphertext pixels'],['recovered','Recovered RGB']]){
        const figure=el('figure',''),picture=el('img','');picture.src='/api/security-image/'+name;picture.alt=label;
        figure.append(picture,el('figcaption','',label));gallery.append(figure);
      }box.append(gallery);
    }
  }else root.image.append(el('p','muted','Image measurements unavailable.'));
  if(audio.sha256){
    const box=root.audio;box.append(el('p','insight','Conventional AES encryption of synthetic MP3 bytes; the encrypted bytes cannot be played as audio. The recovered sample is checked against the committed SHA-256 baseline.'));
    metricRow(box,'Original MP3 bytes',audio.source_bytes);metricRow(box,'Recovered SHA-256',audio.sha256);
    metricRow(box,'Recovered matches baseline',audio.recovered_matches_baseline?'Yes':'Not confirmed');
    box.append(el('div','label','Ciphertext prefix (Base64)'),el('pre','',audio.ciphertext_prefix_base64||''));
    if(data.role==='victim'&&audio.playback_available)for(const [name,label] of [['original','Original synthetic MP3'],['recovered','Recovered synthetic MP3']]){
      box.append(el('div','label',label));const player=el('audio','');player.controls=true;player.preload='none';player.src='/api/security-audio/'+name;box.append(player);
    }
  }else root.audio.append(el('p','muted','Audio evidence unavailable.'));
  const runs=ev.runs||[],withRuns=runs.filter(r=>r.mode==='with'),withoutRuns=runs.filter(r=>r.mode==='without');
  if(ev.summary){
    const s=ev.summary,box=root.defense;box.append(el('p','insight',`${ev.pairs} matched pairs (${runs.length} controlled runs). The simulator writes copies under results/simtrial-*; original data is not changed.`));
    const grid=chartGrid(box);
    chart(grid,'Real encrypted copies per paired trial',[
      {name:'Monitored',values:withRuns.map(r=>r.real_copies),color:'#49c9ad'},
      {name:'Without watcher',values:withoutRuns.map(r=>r.real_copies),color:'#ffad83'}],
      {unit:'copies',labels:withRuns.map(r=>'Pair '+r.pair),note:'Measured trial copies, not damage to original files.'});
    chart(grid,'Alert to stop and kill response by trial',[
      {name:'Alert → stop',values:withRuns.map(r=>r.alert_to_stop_ms),color:'#49c9ad'},
      {name:'Kill response',values:withRuns.map(r=>r.kill_response_ms),color:'#81aafb'}],
      {kind:'line',unit:'ms',note:'Timestamps and process response from monitored trial logs.'});
    table(box,['Condition','Runs','Median real trial copies','Median alert → stop (ms)','Median kill response (ms)'],[
      ['Monitored',withRuns.length,s.with_real_copies_median,number(s.alert_to_stop_ms_median),number(s.kill_response_ms_median)],
      ['No trial watcher',withoutRuns.length,s.without_real_copies_median,'—','—']]);
    const details=el('details','');details.append(el('summary','','All intermediate trial records'));
    table(details,['Pair','Mode','Trial','Decoy copies','Real copies','Alert → stop (ms)','Kill response (ms)','Original intact'],runs.map(r=>[r.pair,r.mode,r.trial,r.decoy_copies,r.real_copies,r.alert_to_stop_ms??'—',r.kill_response_ms??'—',r.original_intact?'Yes':'No']));box.append(details);
  }else root.defense.append(el('p','muted','Paired defense evaluation unavailable.'));
  const hp=root.honeypot;hp.append(el('p','insight','1. Synthetic lock copy → 2. Decoy file event → 3. Registered simulator PID stopped → 4. Verify original baseline → 5. Recover and report. The standalone watcher records file events and cannot infer a PID from an event alone.'));
  if(ev.summary){metricRow(hp,'Trial pairs',ev.pairs);metricRow(hp,'Median alert-to-stop',number(ev.summary.alert_to_stop_ms_median)+' ms');metricRow(hp,'Median real copies with monitoring',ev.summary.with_real_copies_median);metricRow(hp,'Median real copies without monitoring',ev.summary.without_real_copies_median)}
  hp.append(el('p','measure-note','The button below runs fixed, signed actions only. It requires the Ubuntu victim dashboard and armed C2 agent. Historical evaluation results remain available under Defense.'));
  if(hash.digest_hex){
    const box=root.hash;box.append(el('div','label','SHA-256 digest of synthetic mission brief'),el('pre','signature-value',hash.digest_hex));
    metricRow(box,'Input length',hash.source_bytes+' bytes');metricRow(box,'Median generation time',number(hash.generation_time_ms_median,6)+' ms across '+hash.generation_trials+' trials');
    metricRow(box,'One-bit input change: median digest bits changed',number(hash.one_input_bit_digest_change_pct_median)+'%');
    const grid=chartGrid(box);chart(grid,'Digest generation time',[{name:'Median',values:[hash.generation_time_ms_median]}],{unit:'ms',labels:['SHA-256'],note:'The timing chart has one median from repeated trials, not a time series.'});
    chart(grid,'Digest avalanche by input bit',[
      {name:'Measured',values:hash.digest_changed_bits_each_trial||[]},
      {name:'128-bit reference',values:(hash.digest_changed_bits_each_trial||[]).map(()=>128),color:'#ffad83'}],
      {kind:'line',unit:'changed bits',note:'256-bit SHA-256 digest; each input experiment flips one bit.'});
    const defs=hash.definitions||{},search=hash.bounded_search||{};
    table(box,['Property','Meaning','Bounded search'],[
      ['Pre-image',defs.preimage_resistance,search.preimage_found?'Match found':'No match'],
      ['Second pre-image',defs.second_preimage_resistance,search.second_preimage_found?'Match found':'No match'],
      ['Collision',defs.collision_resistance,search.collision_found?'Match found':'No match']]);
    box.append(el('p','measure-note',`${search.candidates||0} candidates tested. ${hash.limit||'A bounded search cannot prove resistance.'}`));
  }else root.hash.append(el('p','muted','Hash security evidence unavailable.'));
  if(sig.sha256){
    const box=root.signature;box.append(el('p','insight',`${sig.algorithm||'RSA-PSS-SHA256'} signs the evaluation artifact on Kali. The public key verifies it on either VM; a one-byte change was ${sig.tampered_byte_rejected?'rejected':'not confirmed as rejected'}.`));
    for(const [label,value] of [['Signed artifact',sig.source],['Artifact SHA-256',sig.sha256],['Public key fingerprint (SHA-256)',sig.public_key_sha256],['Stored signature (Base64)',sig.signature_base64]]){
      box.append(el('div','label',label),el('pre','signature-value',value||'Not recorded'));
    }
    const timing=sig.timings_ms_median||{},grid=chartGrid(box);
    chart(grid,'Signature operations: median time',[
      {name:'Milliseconds',values:[timing.sha256,timing.sign,timing.verify]}],
      {unit:'ms',labels:['Hash','Sign','Verify'],note:`${sig.trials||'?'} trials · signed artifact ${sig.source_bytes||'?'} bytes`});
    table(box,['Step','Result'],[['Generate SHA-256',number(timing.sha256,6)+' ms'],['RSA-PSS sign',number(timing.sign,6)+' ms'],['Verify signature',number(timing.verify,6)+' ms'],['One-byte tamper test',sig.tampered_byte_rejected?'Rejected':'Not confirmed']]);
    box.append(el('p','measure-note','A displayed signature record is evidence of an earlier run. Use the attacker control to independently verify the artifact again.'));
  }else root.signature.append(el('p','muted','Signed evaluation record unavailable.'));
  const performance=root.performance;
  performance.append(el('p','insight','Charts show actual recorded medians in their own units and groups. AES sample timings, paired-trial timings, and dashboard wall times have different scopes; compare like with like.'));
  const groups=[...new Set(perf.map(r=>r.group))],charts=chartGrid(performance);
  for(const group of groups){const rows=perf.filter(r=>r.group===group);
    const byUnit=[...new Set(rows.map(r=>r.unit))];for(const unit of byUnit){const unitRows=rows.filter(r=>r.unit===unit);
      chart(charts,group+' · '+unit,[{name:'Observed median',values:unitRows.map(r=>r.value)}],{
        unit,labels:unitRows.map(r=>r.label),note:unitRows.map(r=>r.source).filter((v,i,a)=>a.indexOf(v)===i).join(' / ')+' · hover bars for exact values.'});
    }
  }
  table(performance,['Process','Median','Unit','Source / scope','Samples'],perf.map(r=>[r.label,number(r.value,6),r.unit,r.source,r.samples??'—']));
  const expected=['Text encrypt','Text decrypt','RGB pixels encrypt','RGB pixels decrypt','MP3 encrypt','MP3 decrypt',
    'Document encrypt','Document decrypt','Image encrypt','Image decrypt','Audio encrypt','Audio decrypt',
    'Video encrypt','Video decrypt','SHA-256 digest','RSA-PSS sign','RSA-PSS verify',
    'Copy-only lock trial','Per-file AES lock','Per-file RSA key wrap','Per-file locked copy write',
    'Honeypot alert to stop','Containment kill response','Encrypted file transfer',
    'TLS backup round trip','Isolated restore round trip','PCAP parse','Report generation','Artifact verification'];
  const missing=expected.filter(name=>!perf.some(row=>row.label===name));
  if(missing.length){const box=el('div','');box.append(el('h3','','Stages awaiting recorded measurements'));
    missing.forEach(name=>metricRow(box,name,'Not recorded on this VM'));performance.append(box)}
  performance.append(el('p','measure-note','Standalone honeypot event-handler CPU time and the full monitored simulator duration are not instrumented. The available alert-to-stop interval measures the observed defense response.'));
  if(!perf.length)performance.append(el('p','muted','Generate benchmark and evaluation evidence to populate performance charts.'));
}
function draw(data){role=data.role;$('title').textContent=data.title;$('updated').textContent='Updated '+data.updated.replace('T',' ')+' UTC · refreshes every 4 seconds';
$('mode-pill').textContent=role==='attacker'?'CONTROLLED LAB ACTIONS':'READ ONLY · LAB VM';
document.querySelector('[data-tab="controls"]').hidden=role!=='attacker';$('demo-control').hidden=role!=='attacker';showTab(activeTab);
const cards=$('cards');cards.replaceChildren();for(const c of data.cards){const box=el('div','card');box.append(el('div','label',c.label),el('div','value',c.value),el('div','note',c.note));cards.append(box)}
const summary=$('summary');summary.replaceChildren();for(const row of data.summary){const item=el('div','row');item.append(el('span','',row.label),el('span','',row.value));summary.append(item)}
const visual=$('visual');visual.replaceChildren();
if(data.role==='victim'){$('chart-title').textContent='Latest encryption trial';const t=data.trial;if(!t){visual.append(el('p','muted','No local simulator trial found.'))}else{for(const [label,n,cls] of [['Decoy copies',t.decoy,''],['Real copies',t.real,'real']]){const wrap=el('div','');const head=el('div','barhead');head.append(el('span','',label),el('strong','',n));const track=el('div','track');const fill=el('div','fill '+cls);fill.style.width=Math.min(100,n/10*100)+'%';track.append(fill);wrap.append(head,track);visual.append(wrap)}visual.append(el('p','muted',t.name+(t.complete?' · completed':' · interrupted or in progress')))}}
else{$('chart-title').textContent='Local recovered files';if(!data.files.length)visual.append(el('p','muted','No received files yet.'));for(const f of data.files){const row=el('div','row');row.append(el('span','',f.name),el('span',f.valid?'ok':'bad',(f.valid?'SHA-256 verified':'Unverified')+' · '+f.bytes.toLocaleString()+' bytes'));visual.append(row)}}
const eventsTable=$('events');eventsTable.replaceChildren();for(const event of data.events){const tr=el('tr','');for(const field of ['ts','module','event','detail'])tr.append(el('td','',event[field]));eventsTable.append(tr)}if(!data.events.length){const tr=el('tr','');const td=el('td','muted','No recorded events yet.');td.colSpan=4;tr.append(td);eventsTable.append(tr)}
const hpEvents=(data.events||[]).filter(e=>/honeypot|containment|simulator/.test(e.module)).slice(0,12),hp=$('honeypot-events');hp.replaceChildren();
if(hpEvents.length)tableView(hpEvents);else hp.append(el('p','muted','No recent monitored trial events in the bounded event feed.'));
function tableView(rows){table(hp,['Time (UTC)','Module','Event','Detail'],rows.map(e=>[e.ts,e.module,e.event,e.detail]))}
renderReports(data.reports||[]);
drawSecurity(data)}
async function refresh(){try{const response=await fetch('/api/status',{cache:'no-store'});if(!response.ok)throw Error('HTTP '+response.status);draw(await response.json())}catch(error){$('updated').textContent='Dashboard data unavailable: '+error.message}}
async function refreshAction(){
  if(role!=='attacker')return;
  try{
    const response=await fetch('/api/action/status',{cache:'no-store'});if(!response.ok)throw Error('HTTP '+response.status);
    const state=await response.json();const summary=(state.command||'Lab controls')+' · '+state.status+' · '+state.detail;
    $('action-status').textContent=summary;$('demo-status').textContent=summary;
    fullSequenceRunning=state.command==='FULL_LAB_SEQUENCE'&&state.status==='running';
    const progress=$('sequence-steps');progress.replaceChildren();
    for(const step of state.steps||[]){const item=el('li','',step.name+' · '+step.status+' · '+step.detail+
      (typeof step.duration_ms==='number'?' · '+step.duration_ms.toFixed(3)+' ms':''));item.dataset.status=step.status;progress.append(item)}
    for(const button of document.querySelectorAll('[data-action]'))button.disabled=state.status==='running'||(button.dataset.action==='ANALYZE_PCAP'&&captureRunning);
    if(['ANALYZE_PCAP','FULL_LAB_SEQUENCE'].includes(state.command)&&state.status==='completed'&&state.finished!==lastReportAction){
      lastReportAction=state.finished;selectedReport=null;await refresh();
    }
  }catch(error){$('action-status').textContent='Action status unavailable: '+error.message;$('demo-status').textContent=$('action-status').textContent}
}
let lastReportAction=null;
let captureRunning=false;
let fullSequenceRunning=false;
async function refreshCapture(){
  if(role!=='attacker')return;
  try{
    const response=await fetch('/api/capture/status',{cache:'no-store'});if(!response.ok)throw Error('HTTP '+response.status);
    const state=await response.json();captureRunning=state.status==='capturing';
    $('capture-status').textContent=(state.file||'Capture')+' · '+state.status+' · '+state.detail+' · '+(state.bytes||0)+' bytes';
    document.querySelector('[data-capture="start"]').disabled=captureRunning||fullSequenceRunning;
    document.querySelector('[data-capture="stop"]').disabled=!captureRunning||fullSequenceRunning;
    const analyze=document.querySelector('[data-action="ANALYZE_PCAP"]');
    analyze.disabled=captureRunning||document.querySelector('[data-action="PING"]').disabled;
  }catch(error){$('capture-status').textContent='Capture status unavailable: '+error.message}
}
for(const button of document.querySelectorAll('[data-capture]'))button.addEventListener('click',async()=>{
  button.disabled=true;$('capture-status').textContent=(button.dataset.capture==='start'?'Starting':'Stopping')+' capture…';
  try{
    const response=await fetch('/api/capture/'+button.dataset.capture,{
      method:'POST',headers:{'X-ISLab-Action-Token':ACTION_TOKEN}
    });
    const result=await response.json();if(!response.ok)throw Error(result.error||'HTTP '+response.status);
    await refreshCapture();
  }catch(error){$('capture-status').textContent='Capture action failed: '+error.message;await refreshCapture()}
});
for(const button of document.querySelectorAll('[data-action]'))button.addEventListener('click',async()=>{
  button.disabled=true;$('action-status').textContent='Starting '+button.dataset.action+'…';$('demo-status').textContent=$('action-status').textContent;
  try{
    const response=await fetch('/api/action/'+button.dataset.action,{
      method:'POST',headers:{'X-ISLab-Action-Token':ACTION_TOKEN}
    });
    const result=await response.json();if(!response.ok)throw Error(result.error||'HTTP '+response.status);
    await refreshAction();
  }catch(error){$('action-status').textContent='Could not start action: '+error.message;$('demo-status').textContent=$('action-status').textContent;button.disabled=false}
});
refresh();refreshAction();refreshCapture();setInterval(refresh,4000);setInterval(refreshAction,2000);setInterval(refreshCapture,2000);
</script></body></html>'''


def _telemetry_server():
    class TelemetryHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if (urlsplit(self.path).path != "/api/status" or
                    self.client_address[0] != ATTACKER_IP or
                    not hmac.compare_digest(self.headers.get("X-ISLab-Telemetry", ""), _token())):
                self.send_error(403)
                return
            try:
                body = json.dumps(_victim()).encode("utf-8")
            except (OSError, ValueError):
                self.send_error(500)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    _token()  # Fail before binding when the shared secret is not configured.
    server = ThreadingHTTPServer((VICTIM_IP, TELEMETRY_PORT), TelemetryHandler)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(ROOT / "keys" / "backup.crt"),
                                str(Path.home() / ".config" / "islab" / "backup.key"))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        return server
    except Exception:
        server.server_close()
        raise


def serve(role, port):
    collector = _victim if role == "victim" else _attacker
    if role == "attacker":
        from attacker.capture_control import CaptureController
        capture = CaptureController()
    else:
        capture = None
    controller = ActionController(capture) if capture is not None else None
    action_token = secrets.token_urlsafe(24) if controller else ""

    class Handler(BaseHTTPRequestHandler):
        def _local(self):
            return (self.client_address[0] == "127.0.0.1" and
                    self.headers.get("Host") in {f"127.0.0.1:{port}", f"localhost:{port}"})

        def _json_response(self, status, data):
            body = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not self._local():
                self.send_error(403)
                return
            path = urlsplit(self.path).path
            if path == "/":
                body, kind = HTML.replace("__ACTION_TOKEN__", action_token).encode("utf-8"), "text/html; charset=utf-8"
            elif path == "/api/status":
                try:
                    body = json.dumps(collector()).encode("utf-8")
                except (OSError, ValueError) as exc:
                    self.send_error(500, f"Could not read dashboard data: {exc}")
                    return
                kind = "application/json; charset=utf-8"
            elif controller is not None and path == "/api/action/status":
                body, kind = json.dumps(controller.status()).encode("utf-8"), "application/json; charset=utf-8"
            elif capture is not None and path == "/api/capture/status":
                body, kind = json.dumps(capture.status()).encode("utf-8"), "application/json; charset=utf-8"
            elif role == "victim" and path in {
                    "/api/security-image/original", "/api/security-image/encrypted",
                    "/api/security-image/recovered"}:
                filename = {"original": "original.png", "encrypted": "encrypted_pixels.png",
                            "recovered": "recovered.png"}[path.rsplit("/", 1)[1]]
                results = ROOT / "results"
                directories = [p for p in results.glob("image_security_*")
                               if p.is_dir() and not p.is_symlink()]
                if not directories:
                    self.send_error(404)
                    return
                latest = max(directories, key=lambda p: p.stat().st_mtime_ns)
                image_path = latest / filename
                if (image_path.is_symlink() or not image_path.is_file() or
                        not image_path.resolve().is_relative_to(results.resolve()) or
                        image_path.stat().st_size > 8 * 1024 * 1024):
                    self.send_error(404)
                    return
                body = image_path.read_bytes()
                if not body.startswith(b"\x89PNG\r\n\x1a\n"):
                    self.send_error(404)
                    return
                kind = "image/png"
            elif role == "victim" and path in {
                    "/api/security-audio/original", "/api/security-audio/recovered"}:
                if path.endswith("/original"):
                    audio_path = Path(TEST_DATA_DIR) / "03_Media" / "briefing.mp3"
                else:
                    directories = [p for p in (ROOT / "results").glob("audio_security_*")
                                   if p.is_dir() and not p.is_symlink()]
                    if not directories:
                        self.send_error(404)
                        return
                    audio_path = max(directories, key=lambda p: p.stat().st_mtime_ns) / "recovered.mp3"
                expected = _baseline().get("03_Media/briefing.mp3")
                if (audio_path.is_symlink() or not audio_path.is_file() or
                        audio_path.stat().st_size > 5 * 1024 * 1024 or
                        not expected or _sha256(audio_path) != expected):
                    self.send_error(404)
                    return
                body, kind = audio_path.read_bytes(), "audio/mpeg"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if controller is None or not self._local():
                self.send_error(403)
                return
            origin = self.headers.get("Origin")
            if (origin not in (None, f"http://127.0.0.1:{port}", f"http://localhost:{port}") or
                    not hmac.compare_digest(self.headers.get("X-ISLab-Action-Token", ""), action_token) or
                    self.headers.get("Content-Length", "0") != "0"):
                self.send_error(403)
                return
            path = urlsplit(self.path).path
            if path in {"/api/capture/start", "/api/capture/stop"}:
                current = controller.status()
                if current["status"] == "running" and current["command"] == "FULL_LAB_SEQUENCE":
                    self._json_response(409, {"error": "Full lab sequence owns this capture"})
                    return
                try:
                    state = capture.start() if path.endswith("/start") else capture.stop()
                except (RuntimeError, ValueError, OSError) as exc:
                    self._json_response(409, {"error": str(exc)[:220]})
                    return
                self._json_response(202, state)
                return
            if not path.startswith("/api/action/"):
                self.send_error(404)
                return
            command = path.removeprefix("/api/action/")
            try:
                status = controller.start(command)
            except ValueError as exc:
                self._json_response(400, {"error": str(exc)})
                return
            except RuntimeError as exc:
                self._json_response(409, {"error": str(exc)})
                return
            self._json_response(202, status)

        def log_message(self, format, *args):
            pass

    telemetry = _telemetry_server() if role == "victim" else None
    thread = None
    try:
        if telemetry is not None:
            thread = threading.Thread(target=telemetry.serve_forever, daemon=True)
            thread.start()
            print(f"Victim telemetry: TLS on {VICTIM_IP}:{TELEMETRY_PORT}", flush=True)
        with ThreadingHTTPServer(("127.0.0.1", port), Handler) as server:
            print(f"{role.title()} dashboard: http://127.0.0.1:{port}/ (Ctrl+C to stop)", flush=True)
            server.serve_forever()
    finally:
        if capture is not None and capture.is_running():
            capture.stop()
        if telemetry is not None:
            telemetry.shutdown()
            telemetry.server_close()
            if thread is not None:
                thread.join(timeout=3)


def main(default_role=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("attacker", "victim"), default=default_role,
                        required=default_role is None)
    parser.add_argument("--port", type=int, help="Local browser port")
    args = parser.parse_args()
    port = args.port or (9081 if args.role == "attacker" else 9082)
    if not 1024 <= port <= 65535:
        parser.error("Port must be between 1024 and 65535")
    serve(args.role, port)


if __name__ == "__main__":
    main()