"""Receive one authenticated synthetic file on the Kali host-only address.

Run from the Kali repository root before starting the victim sender:
    python3 -m attacker.transfer_receiver
"""

import argparse
import hashlib
import hmac
import json
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from config import ATTACKER_IP, LOG_DIR, PROJECT_ROOT, RSA_PRIV_KEY_PATH, TRANSFER_PORT, VICTIM_IP
from shared.crypto import aes_decrypt, rsa_unwrap_key
from shared.transfer_protocol import receive_header, recv_exact, tag


def receive_once(*, ready=None, accept_timeout=60):
    root = Path(PROJECT_ROOT).resolve()
    private_path = Path(RSA_PRIV_KEY_PATH).resolve(strict=True)
    if private_path.is_relative_to(root):
        raise ValueError("Private key must be outside the repository")
    manifest = json.loads((root / "results" / "baseline_hashes.json").read_text())
    expected_hashes = manifest["files"]
    output_dir = root / "received"
    if output_dir.is_symlink():
        raise ValueError("Received directory is a symlink")
    output_dir.mkdir(exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((ATTACKER_IP, TRANSFER_PORT))
        server.listen(1)
        server.settimeout(accept_timeout)
        print(f"Listening on {ATTACKER_IP}:{TRANSFER_PORT} for one victim file...", flush=True)
        if ready is not None:
            ready.set()
        connection, address = server.accept()
        with connection:
            connection.settimeout(15)
            if address[0] != VICTIM_IP:
                raise ValueError(f"Unexpected source IP: {address[0]}")
            started = time.perf_counter()
            name, size, iv, wrapped, raw_header = receive_header(connection)
            ciphertext = recv_exact(connection, size)
            received_tag = recv_exact(connection, 32)
            key = rsa_unwrap_key(wrapped, private_path)
            if not hmac.compare_digest(received_tag, tag(key, raw_header + ciphertext)):
                raise ValueError("HMAC verification failed; file not saved")
            plaintext = aes_decrypt(ciphertext, iv, key)
            digest = hashlib.sha256(plaintext).hexdigest()
            if digest != expected_hashes.get(name):
                raise ValueError("Recovered file differs from committed dataset baseline")
            # A fresh directory preserves prior demo evidence and permits
            # repeated trials without overwriting earlier recovered files.
            run_dir = output_dir / f"run-{time.time_ns()}-{os.urandom(3).hex()}"
            run_dir.mkdir(mode=0o700)
            destination = run_dir / Path(name).name
            with destination.open("xb") as output:
                output.write(plaintext)
            elapsed = round(time.perf_counter() - started, 4)
            record = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                      "module": "transfer", "event": "file_received", "file": name,
                      "bytes": len(plaintext), "sha256": digest, "elapsed_s": elapsed,
                      "src_ip": address[0], "src_port": address[1],
                      "saved_as": destination.relative_to(root).as_posix()}
            log_dir = Path(LOG_DIR)
            if log_dir.is_symlink():
                raise ValueError("Log directory is a symlink")
            log_dir.mkdir(parents=True, exist_ok=True)
            with (log_dir / "transfer.log").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
            connection.sendall(b"OK\n")
            print(f"PASS: recovered {name} ({len(plaintext)} bytes), SHA-256 {digest}", flush=True)
            return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    receive_once()


if __name__ == "__main__":
    main()
