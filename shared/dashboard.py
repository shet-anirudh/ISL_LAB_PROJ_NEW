"""Read-only local dashboard for the synthetic lab's attacker and victim VMs.

Launch through ``python3 -m attacker.dashboard`` on Kali or
``python3 -m victim.dashboard`` on Ubuntu. No attack actions are exposed.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from config import LOG_DIR, PROJECT_ROOT, TEST_DATA_DIR


ROOT = Path(PROJECT_ROOT)
LOGS = Path(LOG_DIR)
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_EVENTS = 24


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
                         "detail": str(event.get("file") or event.get("cmd") or
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
        "summary": [
            {"label": "Dataset", "value": "Matches baseline" if baseline and intact == len(baseline) else "Attention required"},
            {"label": "Latest trial", "value": "None" if trial is None else trial["name"] + (" · complete" if trial["complete"] else " · interrupted/in progress")},
            {"label": "Last containment", "value": kills[-1].get("ts", "Unknown") if kills else "None"},
            {"label": "Restore trials", "value": str(len(restore_trials)) + " isolated directories"},
            {"label": "Files sent", "value": str(sum(e.get("event") == "file_sent" for e in transfer))},
            {"label": "C2 messages", "value": str(len(c2)) + " · dry-run commands"},
        ],
        "events": _event_feed([honeypot, containment, simulator, transfer, c2]),
    }


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
        for path in sorted(received.iterdir()):
            if path.is_file() and not path.is_symlink():
                try:
                    recovered.append({"name": path.name, "bytes": path.stat().st_size,
                                      "valid": _sha256(path) in allowed.get(path.name, set())})
                except OSError:
                    pass
    verified = sum(item["valid"] for item in recovered)
    responses = [e for e in c2 if e.get("event") == "response_received"]
    rejects = sum(e.get("event") == "spoof_rejected" for e in c2)
    return {
        "role": "attacker", "title": "Attacker Activity", "updated": _now(),
        "cards": [
            {"label": "Recovered samples", "value": verified, "note": f"{len(recovered)} local files · baseline checked"},
            {"label": "Received transfers", "value": sum(e.get("event") == "file_received" for e in transfer), "note": "Historical verified events"},
            {"label": "C2 responses", "value": len(responses), "note": "Commands are dry-run"},
            {"label": "Spoof attempts blocked", "value": rejects, "note": "Authenticated relay demo"},
        ],
        "files": recovered,
        "summary": [
            {"label": "Last C2 response", "value": "None" if not responses else str(responses[-1].get("cmd", "")) + " · " + str(responses[-1].get("requested", ""))},
            {"label": "Signed commands sent", "value": str(sum(e.get("event") == "command_sent" and e.get("signed") is True for e in c2))},
            {"label": "Bytes recovered", "value": f"{sum(item['bytes'] for item in recovered):,}"},
            {"label": "Simulation detail", "value": "Encryption trial logs are on the victim VM"},
        ],
        "events": _event_feed([transfer, c2]),
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
@media(max-width:850px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.wide{grid-column:auto}}@media(max-width:520px){.cards{grid-template-columns:1fr 1fr}.card{padding:14px}.value{font-size:27px}main{padding:20px 14px}.pill{display:none}}
</style></head><body><main>
<header><div><div class="eyebrow">IS Lab · Synthetic Environment</div><h1 id="title">Dashboard</h1><div class="muted" id="updated">Loading local evidence…</div></div><span class="pill">READ ONLY · LOCAL VM</span></header>
<section class="cards" id="cards"></section><div class="grid"><section class="panel"><h2>Activity summary</h2><div id="summary"></div></section>
<section class="panel"><h2 id="chart-title">Latest trial</h2><div class="bars" id="visual"></div></section>
<section class="panel wide"><h2>Recent recorded events</h2><div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Module</th><th>Event</th><th>Detail</th></tr></thead><tbody id="events"></tbody></table></div></section></div>
</main><script>
const $=id=>document.getElementById(id);
function el(tag,cls,content){const node=document.createElement(tag);if(cls)node.className=cls;if(content!==undefined)node.textContent=String(content);return node}
function draw(data){$('title').textContent=data.title;$('updated').textContent='Updated '+data.updated.replace('T',' ')+' UTC · refreshes every 4 seconds';
const cards=$('cards');cards.replaceChildren();for(const c of data.cards){const box=el('div','card');box.append(el('div','label',c.label),el('div','value',c.value),el('div','note',c.note));cards.append(box)}
const summary=$('summary');summary.replaceChildren();for(const row of data.summary){const item=el('div','row');item.append(el('span','',row.label),el('span','',row.value));summary.append(item)}
const visual=$('visual');visual.replaceChildren();
if(data.role==='victim'){$('chart-title').textContent='Latest encryption trial';const t=data.trial;if(!t){visual.append(el('p','muted','No local simulator trial found.'))}else{for(const [label,n,cls] of [['Decoy copies',t.decoy,''],['Real copies',t.real,'real']]){const wrap=el('div','');const head=el('div','barhead');head.append(el('span','',label),el('strong','',n));const track=el('div','track');const fill=el('div','fill '+cls);fill.style.width=Math.min(100,n/10*100)+'%';track.append(fill);wrap.append(head,track);visual.append(wrap)}visual.append(el('p','muted',t.name+(t.complete?' · completed':' · interrupted or in progress')))}}
else{$('chart-title').textContent='Local recovered files';if(!data.files.length)visual.append(el('p','muted','No received files yet.'));for(const f of data.files){const row=el('div','row');row.append(el('span','',f.name),el('span',f.valid?'ok':'bad',(f.valid?'SHA-256 verified':'Unverified')+' · '+f.bytes.toLocaleString()+' bytes'));visual.append(row)}}
const table=$('events');table.replaceChildren();for(const event of data.events){const tr=el('tr','');for(const field of ['ts','module','event','detail'])tr.append(el('td','',event[field]));table.append(tr)}if(!data.events.length){const tr=el('tr','');const td=el('td','muted','No recorded events yet.');td.colSpan=4;tr.append(td);table.append(tr)}}
async function refresh(){try{const response=await fetch('/api/status',{cache:'no-store'});if(!response.ok)throw Error('HTTP '+response.status);draw(await response.json())}catch(error){$('updated').textContent='Dashboard data unavailable: '+error.message}}
refresh();setInterval(refresh,4000);
</script></body></html>'''


def serve(role, port):
    collector = _victim if role == "victim" else _attacker

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/":
                body, kind = HTML.encode("utf-8"), "text/html; charset=utf-8"
            elif path == "/api/status":
                try:
                    body = json.dumps(collector()).encode("utf-8")
                except (OSError, ValueError) as exc:
                    self.send_error(500, f"Could not read dashboard data: {exc}")
                    return
                kind = "application/json; charset=utf-8"
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

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", port), Handler) as server:
        print(f"{role.title()} dashboard: http://127.0.0.1:{port}/ (Ctrl+C to stop)", flush=True)
        server.serve_forever()


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