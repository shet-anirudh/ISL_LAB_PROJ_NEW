"""Victim-side TLS backup and isolated restore for the synthetic dataset.

Run the server and client in separate victim VM terminals. The server accepts
one local victim connection, validates every file against the baseline, and
publishes a complete snapshot only after all files pass verification.
"""

import argparse
import hashlib
import json
import os
import shutil
import socket
import ssl
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from config import BACKUP_DIR, BACKUP_PORT, PROJECT_ROOT, TEST_DATA_DIR, VICTIM_IP


CERT = Path(PROJECT_ROOT) / "keys" / "backup.crt"
KEY = Path.home() / ".config" / "islab" / "backup.key"
BASELINE = Path(PROJECT_ROOT) / "results" / "baseline_hashes.json"
MAX_FILE_SIZE = 128 * 1024 * 1024
MAX_HEADER_SIZE = 8192
CHUNK_SIZE = 64 * 1024


def expected_files():
    data = json.loads(BASELINE.read_text(encoding="utf-8"))
    if data.get("algorithm") != "sha256" or not isinstance(data.get("files"), dict):
        raise ValueError("Invalid SHA-256 baseline manifest")
    files = data["files"]
    if len(files) != 20:
        raise ValueError("Expected 20 synthetic dataset files")
    for name, digest in files.items():
        path = PurePosixPath(name)
        if (path.is_absolute() or not path.parts or
                any(part in (".", "..") for part in path.parts) or
                not isinstance(digest, str) or len(digest) != 64 or
                any(c not in "0123456789abcdef" for c in digest)):
            raise ValueError("Unsafe baseline manifest entry")
    return files


def send_header(stream, value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(data) > MAX_HEADER_SIZE:
        raise ValueError("Header too large")
    stream.sendall(data)


def read_header(stream):
    data = bytearray()
    while len(data) <= MAX_HEADER_SIZE:
        ch = stream.recv(1)
        if ch == b"\n":
            result = json.loads(data)
            if not isinstance(result, dict):
                raise ValueError("Expected a JSON object")
            return result
        if not ch:
            raise EOFError("Connection ended mid-header")
        data.extend(ch)
    raise ValueError("Header too large")


def copy_exact(stream, destination, length):
    digest = hashlib.sha256()
    with destination.open("xb") as out:
        while length:
            block = stream.recv(min(length, CHUNK_SIZE))
            if not block:
                raise EOFError("Connection ended mid-file")
            out.write(block)
            digest.update(block)
            length -= len(block)
    return digest.hexdigest()


def serve_once(*, ready=None, accept_timeout=30):
    files = expected_files()
    if not CERT.is_file() or not KEY.is_file():
        raise FileNotFoundError("Generate backup.crt and backup.key on the victim first")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(CERT), str(KEY))
    root = Path(BACKUP_DIR)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((VICTIM_IP, BACKUP_PORT))
        listener.listen(1)
        listener.settimeout(accept_timeout)
        print(f"Backup TLS listening on {VICTIM_IP}:{BACKUP_PORT} for one victim connection", flush=True)
        if ready is not None:
            ready.set()
        raw, peer = listener.accept()
        with raw:
            raw.settimeout(30)
            if peer[0] != VICTIM_IP:
                raise PermissionError(f"Rejected non-victim peer {peer[0]}")
            with context.wrap_socket(raw, server_side=True) as stream:
                staging = Path(tempfile.mkdtemp(prefix=".incoming-", dir=root))
                try:
                    seen = set()
                    for _ in files:
                        header = read_header(stream)
                        name, size = header.get("name"), header.get("size")
                        if (name not in files or name in seen or
                                type(size) is not int or size < 0 or size > MAX_FILE_SIZE):
                            raise ValueError("Unexpected file name or size")
                        destination = staging.joinpath(*PurePosixPath(name).parts)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        actual = copy_exact(stream, destination, size)
                        if actual != files[name]:
                            raise ValueError(f"SHA-256 mismatch: {name}")
                        seen.add(name)
                    if read_header(stream) != {"end": True} or seen != set(files):
                        raise ValueError("Incomplete backup")
                    (staging / "manifest.json").write_text(
                        json.dumps({"algorithm": "sha256", "files": files},
                                   indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    destination = root / f"snapshot-{stamp}-{os.urandom(4).hex()}"
                    staging.rename(destination)
                    send_header(stream, {"ok": True, "snapshot": destination.name,
                                         "count": len(files)})
                    print(f"PASS: saved {len(files)} verified files to {destination}", flush=True)
                    return destination
                finally:
                    if staging.exists():
                        shutil.rmtree(staging)


def backup():
    files = expected_files()
    context = ssl.create_default_context(cafile=str(CERT))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((VICTIM_IP, BACKUP_PORT), timeout=30) as raw:
        with context.wrap_socket(raw, server_hostname=VICTIM_IP) as stream:
            stream.settimeout(30)
            for name, expected in files.items():
                path = Path(TEST_DATA_DIR).joinpath(*PurePosixPath(name).parts)
                if not path.is_file() or path.is_symlink():
                    raise ValueError(f"Missing or unsafe dataset file: {name}")
                data = path.read_bytes()
                if len(data) > MAX_FILE_SIZE or hashlib.sha256(data).hexdigest() != expected:
                    raise ValueError(f"Dataset changed from baseline: {name}")
                send_header(stream, {"name": name, "size": len(data)})
                stream.sendall(data)
            send_header(stream, {"end": True})
            response = read_header(stream)
            if response.get("ok") is not True or response.get("count") != len(files):
                raise ValueError(f"Backup failed: {response}")
            print(f"PASS: TLS backup saved {len(files)} files as {response['snapshot']}")
            return response


def snapshot_files(snapshot):
    root = Path(BACKUP_DIR).resolve(strict=True)
    path = Path(snapshot).resolve(strict=True)
    if path.parent != root or not path.name.startswith("snapshot-"):
        raise ValueError("Select a snapshot directly inside BACKUP_DIR")
    baseline = expected_files()
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    if manifest != {"algorithm": "sha256", "files": baseline}:
        raise ValueError("Snapshot manifest differs from baseline")
    for name, expected in baseline.items():
        file = path.joinpath(*PurePosixPath(name).parts)
        if file.is_symlink() or not file.is_file() or not file.resolve().is_relative_to(path):
            raise ValueError(f"Unsafe snapshot file: {name}")
        if hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise ValueError(f"Snapshot hash mismatch: {name}")
    return path, baseline


def restore_to_trial(snapshot):
    source, files = snapshot_files(snapshot)
    trial = Path(tempfile.mkdtemp(prefix="restore-trial-", dir=Path(PROJECT_ROOT) / "results"))
    try:
        for name in files:
            output = trial.joinpath(*PurePosixPath(name).parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            with source.joinpath(*PurePosixPath(name).parts).open("rb") as inp, output.open("xb") as out:
                shutil.copyfileobj(inp, out, CHUNK_SIZE)
            if hashlib.sha256(output.read_bytes()).hexdigest() != files[name]:
                raise ValueError(f"Restored hash mismatch: {name}")
        print(f"PASS: restored {len(files)} files into disposable trial {trial}")
        print("Original MILITARY_DATA was not modified")
        return trial
    except Exception:
        shutil.rmtree(trial)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--serve-once", action="store_true")
    group.add_argument("--backup", action="store_true")
    group.add_argument("--verify", metavar="SNAPSHOT")
    group.add_argument("--restore-trial", metavar="SNAPSHOT")
    args = parser.parse_args()
    if args.serve_once:
        serve_once()
    elif args.backup:
        backup()
    elif args.verify:
        _, files = snapshot_files(args.verify)
        print(f"PASS: verified {len(files)} files in {args.verify}")
    else:
        restore_to_trial(args.restore_trial)


if __name__ == "__main__":
    main()