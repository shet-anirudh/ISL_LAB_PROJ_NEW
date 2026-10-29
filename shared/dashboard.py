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
import subprocess
import sys
import threading
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
        try:
            result = operation()
        except Exception as exc:
            with self.lock:
                self.state["steps"][index].update(status="failed", detail=str(exc)[:180])
            raise
        with self.lock:
            self.state["steps"][index].update(status="completed", detail=str(result)[:180])
        return result

    def _full_sequence(self):
        if self.capture is None:
            raise RuntimeError("Kali dashboard capture control is unavailable")
        started = False
        try:
            name = self._step("Start PCAP capture", lambda: self.capture.start()["file"])
            started = True
            self._step("Contained trial", lambda: self._remote("START_ENCRYPT"))
            self._step("Synthetic PDF transfer", lambda: self._remote("START_EXFIL"))
            self._step("Verify original dataset", lambda: self._remote("VERIFY_DATASET"))
            self._step("Stop PCAP capture", lambda: self.capture.stop()["file"])
            started = False
            report = self._step("Analyze and report", lambda: self._analyze(self.capture.path))
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
            result = subprocess.run([sys.executable, "-m", module, str(capture)],
                                    cwd=ROOT, capture_output=True, text=True, timeout=60)
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
        result = subprocess.run([sys.executable, "-m", "tests.signature_demo", "--verify", source],
                                cwd=ROOT, capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout)[-180:])
        return f"Verified RSA-PSS signature for {Path(source).name}"

    def _remote(self, command):
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
                  "diffusion_one_plaintext_bit", "confusion_one_key_bit")},
        "hash": {key: hash_result.get(key) for key in
                 ("digest_hex", "generation_time_ms_median",
                  "one_input_bit_digest_change_pct_median", "bounded_search", "definitions", "limit")},
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
        "evaluation": {"pairs": evaluation.get("pairs"), "summary": evaluation.get("summary")},
        "signature": {key: signature.get(key) for key in
                      ("sha256", "signature_base64", "timings_ms_median", "tampered_byte_rejected")},
        "crypto": crypto.get("measurements", {}),
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
        "security": remote.get("security") if remote else _security_data(),
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
.tabs{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 22px}.tabs button,.action-button{font:inherit;cursor:pointer;border:1px solid #386079;border-radius:10px;color:#b9d5e6;background:#1b3248;padding:10px 14px}.tabs button[aria-selected="true"]{background:#24645e;border-color:#49c9ad;color:#fff}.tab-view[hidden],.tabs button[hidden]{display:none}.tab-view{margin-top:14px}.tab-view>.panel{margin-top:14px}.action-buttons{display:flex;flex-wrap:wrap;gap:12px}.action-button{background:#215b55;border-color:#48b9a7}.action-button:disabled{opacity:.5;cursor:wait}.action-status{margin-top:18px;padding:16px;background:#0c1b2d;border-radius:10px;min-height:70px}.tab-view audio{width:100%;margin:12px 0 18px}
.tab-view pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1727;border:1px solid #294059;border-radius:10px;padding:12px;max-height:500px;overflow:auto;font-size:12px}
.report-list{display:flex;flex-wrap:wrap;gap:9px;margin:0 0 18px}.report-list button{font:inherit;cursor:pointer;border:1px solid #386079;background:#183149;color:#c4dbe9;border-radius:9px;padding:8px 11px}.report-list button[aria-selected="true"]{border-color:#49c9ad;background:#24645e;color:#fff}
.sequence-steps{padding-left:22px;color:#bad0dc;font-size:13px}.sequence-steps li{padding:5px 0}.sequence-steps li[data-status="completed"]{color:#65dec2}.sequence-steps li[data-status="failed"]{color:#ff9b83}
@media(max-width:850px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.wide{grid-column:auto}}@media(max-width:520px){.cards{grid-template-columns:1fr 1fr}.card{padding:14px}.value{font-size:27px}main{padding:20px 14px}.pill{display:none}}
</style></head><body><main>
<header><div><div class="eyebrow">IS Lab · Synthetic Environment</div><h1 id="title">Dashboard</h1><div class="muted" id="updated">Loading local evidence…</div></div><span class="pill" id="mode-pill">LAB VM</span></header>
<nav class="tabs" aria-label="Dashboard sections" id="tabs">
<button data-tab="overview" aria-selected="true">Overview</button><button data-tab="controls" hidden>Lab controls</button>
<button data-tab="text">Text</button><button data-tab="image">Image</button><button data-tab="audio">Audio</button>
<button data-tab="defense">Defense</button><button data-tab="performance">Performance</button>
<button data-tab="evidence">Hash &amp; signature</button><button data-tab="reports">Reports</button><button data-tab="events">Events</button></nav>
<div class="tab-view" id="tab-overview"><section class="cards" id="cards"></section><div class="grid"><section class="panel"><h2>Activity summary</h2><div id="summary"></div></section>
<section class="panel"><h2 id="chart-title">Latest trial</h2><div class="bars" id="visual"></div></section>
</div></div>
<div class="tab-view" id="tab-controls" hidden><section class="panel"><h2>Controlled synthetic actions</h2>
<p class="muted">Ubuntu must run the armed lab agent. Actions use signed C2; encryption writes disposable copies and transfer sends only the fixed synthetic report.</p>
<div class="action-buttons"><button class="action-button" data-action="FULL_LAB_SEQUENCE">Run full lab sequence</button></div>
<p class="muted">Capture → contained trial → verified PDF transfer → dataset check → stop capture → forensic report.</p>
<ol id="sequence-steps" class="sequence-steps"></ol>
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
<div class="tab-view" id="tab-text" hidden><section class="panel"><h2>Text encryption</h2><div id="security-text"></div></section></div>
<div class="tab-view" id="tab-image" hidden><section class="panel"><h2>RGB image analysis</h2><div id="security-image"></div></section></div>
<div class="tab-view" id="tab-audio" hidden><section class="panel"><h2>Audio encryption</h2><div id="security-audio"></div></section></div>
<div class="tab-view" id="tab-defense" hidden><section class="panel"><h2>Containment evaluation</h2><div id="security-defense"></div></section></div>
<div class="tab-view" id="tab-performance" hidden><section class="panel"><h2>Processing efficiency</h2><div id="security-performance"></div></section></div>
<div class="tab-view" id="tab-evidence" hidden><section class="panel"><h2>Hash and signature evidence</h2><div class="measure-grid" id="security-evidence"></div></section></div>
<div class="tab-view" id="tab-reports" hidden><section class="panel"><h2>Generated reports</h2><div id="reports"></div></section></div>
<div class="tab-view" id="tab-events" hidden><section class="panel"><h2>Recorded events</h2><div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Module</th><th>Event</th><th>Detail</th></tr></thead><tbody id="events"></tbody></table></div></section></div>
</main><script>
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
  const sec=data.security||{},text=sec.text||{},hash=sec.hash||{},im=sec.image||{},audio=sec.audio||{},ev=sec.evaluation||{},sig=sec.signature||{},crypto=sec.crypto||{};
  const fingerprint=JSON.stringify(sec)+data.role;if(fingerprint===lastSecurity)return;lastSecurity=fingerprint;
  const root={text:$('security-text'),image:$('security-image'),audio:$('security-audio'),
              defense:$('security-defense'),performance:$('security-performance'),evidence:$('security-evidence')};
  for(const node of Object.values(root))node.replaceChildren();
  if(text.plaintext){
    const box=section(root.text,'Text encryption and one-bit changes');
    for(const [label,value] of [['Plaintext',text.plaintext],['Ciphertext (Base64)',text.ciphertext_base64],['Recovered',text.recovered_plaintext]]){
      box.append(el('div','label',label),el('pre','',value||''));
    }
    const diffusion=text.diffusion_one_plaintext_bit||{},confusion=text.confusion_one_key_bit||{};
    measurement(box,'Diffusion, ciphertext bits',diffusion.summary&&diffusion.summary.bit_change_pct_median,100,'%');
    measurement(box,'Diffusion, ciphertext hex digits',diffusion.summary&&diffusion.summary.hex_character_change_pct_median,100,'%');
    measurement(box,'Confusion, ciphertext bits',confusion.summary&&confusion.summary.bit_change_pct_median,100,'%');
    measurement(box,'Confusion, ciphertext hex digits',confusion.summary&&confusion.summary.hex_character_change_pct_median,100,'%');
    box.append(el('p','measure-note','One plaintext bit or one key bit changes with fixed IV. Hex digits are ciphertext representation, not plaintext characters.'));
  }
  if(hash.digest_hex){
    const box=section(root.evidence,'SHA-256 digest and properties');
    box.append(el('div','label','Synthetic mission brief digest'),el('pre','',hash.digest_hex));
    metricRow(box,'Median digest generation',hash.generation_time_ms_median+' ms');
    measurement(box,'One input-bit digest change',hash.one_input_bit_digest_change_pct_median,100,'%');
    const definitions=hash.definitions||{},search=hash.bounded_search||{};
    for(const [name,label] of [['preimage_resistance','Pre-image'],['second_preimage_resistance','Second pre-image'],['collision_resistance','Collision']]){
      metricRow(box,label,definitions[name]||'');
    }
    box.append(el('p','measure-note','Bounded '+search.candidates+'-candidate search: pre-image '+Boolean(search.preimage_found)+', second pre-image '+Boolean(search.second_preimage_found)+', collision '+Boolean(search.collision_found)+'. '+(hash.limit||'')));
  }
  if(im.metrics){
    const box=section(root.image,'RGB image measurements'),m=im.metrics;
    measurement(box,'Original entropy',m.entropy_original_bits_per_byte,8,'bits/byte');
    measurement(box,'Encrypted entropy',m.entropy_encrypted_bits_per_byte,8,'bits/byte');
    measurement(box,'NPCR, changed pixels',m.npcr_ciphertexts_one_plaintext_bit_pct,100,'%');
    measurement(box,'UACI, mean channel difference',m.uaci_ciphertexts_one_plaintext_bit_pct,100,'%');
    for(const [label,key,unit] of [
      ['Original neighbor correlation','horizontal_red_correlation_original',''],
      ['Encrypted neighbor correlation','horizontal_red_correlation_encrypted',''],
      ['Original to encrypted MSE','mse_original_to_encrypted',''],['Original to encrypted PSNR','psnr_original_to_encrypted_db','dB'],
      ['Original to recovered MSE','mse_original_to_recovered',''],['Original to recovered PSNR','psnr_original_to_recovered_db','dB']
    ])metricRow(box,label,typeof m[key]==='number'?m[key].toFixed(4)+' '+unit:String(m[key]));
    box.append(el('p','measure-note','Ciphertext bytes are mapped to RGB pixels for display. NPCR and UACI compare two ciphertext views after one plaintext-bit change.'));
  }
  if(audio.sha256){
    const box=section(root.audio,'Synthetic audio encryption');
    metricRow(box,'MP3 bytes',audio.source_bytes);metricRow(box,'Recovered SHA-256',audio.sha256);
    box.append(el('div','label','Ciphertext prefix (Base64)'),el('pre','',audio.ciphertext_prefix_base64||''));
    box.append(el('p','measure-note','Conventional AES encryption of MP3 bytes; recovered audio matches the baseline. Ciphertext is not playable.'));
    if(data.role==='victim'&&audio.playback_available){
      for(const [name,label] of [['original','Original synthetic MP3'],['recovered','Recovered synthetic MP3']]){
        box.append(el('div','label',label));const player=el('audio','');player.controls=true;player.preload='none';player.src='/api/security-audio/'+name;box.append(player);
      }
    }
  }
  if(ev.summary){
    const box=section(root.defense,'Containment comparison'),s=ev.summary;
    box.append(el('p','muted',ev.pairs+' trial pairs · copy-only simulator'));
    measurement(box,'Real copies with monitoring',s.with_real_copies_median,5,'median');
    measurement(box,'Real copies without monitoring',s.without_real_copies_median,5,'median');
    box.append(el('p','measure-note','Median alert-to-stop: '+Number(s.alert_to_stop_ms_median).toFixed(3)+' ms. Original dataset remains unchanged.'));
  }
  const perf=[];
  if(text.timings_ms_median)perf.push(['Text encrypt',text.timings_ms_median.encrypt],['Text decrypt',text.timings_ms_median.decrypt]);
  if(im.timings_ms_median)perf.push(['RGB encrypt',im.timings_ms_median.encrypt],['RGB decrypt',im.timings_ms_median.decrypt]);
  if(audio.timings_ms_median)perf.push(['Audio encrypt',audio.timings_ms_median.encrypt],['Audio decrypt',audio.timings_ms_median.decrypt]);
  else if(crypto.audio)perf.push(['Audio encrypt',crypto.audio.aes_encrypt_median_ms],['Audio decrypt',crypto.audio.aes_decrypt_median_ms]);
  if(crypto.video)perf.push(['Video encrypt',crypto.video.aes_encrypt_median_ms],['Video decrypt',crypto.video.aes_decrypt_median_ms]);
  if(perf.length){
    const box=section(root.performance,'AES processing time'),numbers=perf.map(x=>x[1]).filter(x=>typeof x==='number');
    const max=Math.max(...numbers,.001);for(const [label,value] of perf)measurement(box,label,value,max,'ms');
    box.append(el('p','measure-note','Median time per sample. File sizes differ; use throughput for size-normalized comparison.'));
  }
  if(sig.sha256){
    const box=section(root.evidence,'Stored digital signature');
    box.append(el('div','label','SHA-256 digest'),el('pre','',sig.sha256),el('div','label','RSA-PSS signature (Base64)'),el('pre','',sig.signature_base64||''));
    const timing=sig.timings_ms_median||{};
    box.append(el('p','measure-note','Median hash '+timing.sha256+' ms · sign '+timing.sign+' ms · verify '+timing.verify+' ms · tamper rejected: '+Boolean(sig.tampered_byte_rejected)+'. Displayed record; independently verify using tests.signature_demo.'));
  }
  if(data.role==='victim'&&im.previews_available){
    const box=section(root.image,'RGB pixel previews'),gallery=el('div','previews');
    for(const [name,label] of [['original','Original RGB'],['encrypted','Ciphertext pixels'],['recovered','Recovered RGB']]){
      const figure=el('figure',''),picture=el('img','');picture.src='/api/security-image/'+name;picture.alt=label;
      figure.append(picture,el('figcaption','',label));gallery.append(figure);
    }box.append(gallery);
  }
}
function draw(data){role=data.role;$('title').textContent=data.title;$('updated').textContent='Updated '+data.updated.replace('T',' ')+' UTC · refreshes every 4 seconds';
$('mode-pill').textContent=role==='attacker'?'CONTROLLED LAB ACTIONS':'READ ONLY · LAB VM';
document.querySelector('[data-tab="controls"]').hidden=role!=='attacker';showTab(activeTab);
const cards=$('cards');cards.replaceChildren();for(const c of data.cards){const box=el('div','card');box.append(el('div','label',c.label),el('div','value',c.value),el('div','note',c.note));cards.append(box)}
const summary=$('summary');summary.replaceChildren();for(const row of data.summary){const item=el('div','row');item.append(el('span','',row.label),el('span','',row.value));summary.append(item)}
const visual=$('visual');visual.replaceChildren();
if(data.role==='victim'){$('chart-title').textContent='Latest encryption trial';const t=data.trial;if(!t){visual.append(el('p','muted','No local simulator trial found.'))}else{for(const [label,n,cls] of [['Decoy copies',t.decoy,''],['Real copies',t.real,'real']]){const wrap=el('div','');const head=el('div','barhead');head.append(el('span','',label),el('strong','',n));const track=el('div','track');const fill=el('div','fill '+cls);fill.style.width=Math.min(100,n/10*100)+'%';track.append(fill);wrap.append(head,track);visual.append(wrap)}visual.append(el('p','muted',t.name+(t.complete?' · completed':' · interrupted or in progress')))}}
else{$('chart-title').textContent='Local recovered files';if(!data.files.length)visual.append(el('p','muted','No received files yet.'));for(const f of data.files){const row=el('div','row');row.append(el('span','',f.name),el('span',f.valid?'ok':'bad',(f.valid?'SHA-256 verified':'Unverified')+' · '+f.bytes.toLocaleString()+' bytes'));visual.append(row)}}
const table=$('events');table.replaceChildren();for(const event of data.events){const tr=el('tr','');for(const field of ['ts','module','event','detail'])tr.append(el('td','',event[field]));table.append(tr)}if(!data.events.length){const tr=el('tr','');const td=el('td','muted','No recorded events yet.');td.colSpan=4;tr.append(td);table.append(tr)}
renderReports(data.reports||[]);
drawSecurity(data)}
async function refresh(){try{const response=await fetch('/api/status',{cache:'no-store'});if(!response.ok)throw Error('HTTP '+response.status);draw(await response.json())}catch(error){$('updated').textContent='Dashboard data unavailable: '+error.message}}
async function refreshAction(){
  if(role!=='attacker')return;
  try{
    const response=await fetch('/api/action/status',{cache:'no-store'});if(!response.ok)throw Error('HTTP '+response.status);
    const state=await response.json();$('action-status').textContent=(state.command||'Lab controls')+' · '+state.status+' · '+state.detail;
    fullSequenceRunning=state.command==='FULL_LAB_SEQUENCE'&&state.status==='running';
    const progress=$('sequence-steps');progress.replaceChildren();
    for(const step of state.steps||[]){const item=el('li','',step.name+' · '+step.status+' · '+step.detail);item.dataset.status=step.status;progress.append(item)}
    for(const button of document.querySelectorAll('[data-action]'))button.disabled=state.status==='running'||(button.dataset.action==='ANALYZE_PCAP'&&captureRunning);
    if(['ANALYZE_PCAP','FULL_LAB_SEQUENCE'].includes(state.command)&&state.status==='completed'&&state.finished!==lastReportAction){
      lastReportAction=state.finished;selectedReport=null;await refresh();
    }
  }catch(error){$('action-status').textContent='Action status unavailable: '+error.message}
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
  button.disabled=true;$('action-status').textContent='Starting '+button.dataset.action+'…';
  try{
    const response=await fetch('/api/action/'+button.dataset.action,{
      method:'POST',headers:{'X-ISLab-Action-Token':ACTION_TOKEN}
    });
    const result=await response.json();if(!response.ok)throw Error(result.error||'HTTP '+response.status);
    await refreshAction();
  }catch(error){$('action-status').textContent='Could not start action: '+error.message;button.disabled=false}
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
