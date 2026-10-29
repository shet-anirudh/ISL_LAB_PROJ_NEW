"""Conventional encryption and recovery of the synthetic MP3 sample.

On Ubuntu: python3 -m tests.audio_security_demo
Creates an isolated result containing AES ciphertext, RSA-wrapped AES key,
verified recovered audio, and timings. The source dataset stays unchanged.
"""

import base64
import hashlib
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from config import PROJECT_ROOT, RSA_PUB_KEY_PATH, TEST_DATA_DIR
from shared.crypto import (aes_decrypt, aes_encrypt, generate_aes_key,
                           generate_iv, rsa_wrap_key)


SOURCE = "03_Media/briefing.mp3"
TRIALS = 10


def run():
    root = Path(TEST_DATA_DIR)
    source = root / SOURCE
    if root != Path.home() / "MILITARY_DATA" or source.is_symlink() or not source.is_file():
        raise ValueError("Only the configured synthetic audio is allowed")
    data = source.read_bytes()
    baseline = json.loads((Path(PROJECT_ROOT) / "results" / "baseline_hashes.json").read_text())["files"]
    digest = hashlib.sha256(data).hexdigest()
    if digest != baseline[SOURCE]:
        raise ValueError("Synthetic audio differs from baseline")
    key, iv = generate_aes_key(), generate_iv()
    ciphertext = aes_encrypt(data, iv, key)
    recovered = aes_decrypt(ciphertext, iv, key)
    if hashlib.sha256(recovered).hexdigest() != digest:
        raise AssertionError("Recovered audio differs from baseline")
    wrapped = rsa_wrap_key(key, RSA_PUB_KEY_PATH)
    encrypt_ns, decrypt_ns = [], []
    for _ in range(TRIALS):
        start = time.perf_counter_ns()
        candidate = aes_encrypt(data, iv, key)
        encrypt_ns.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        if aes_decrypt(candidate, iv, key) != data:
            raise AssertionError("Audio round trip failed")
        decrypt_ns.append(time.perf_counter_ns() - start)
    results = Path(PROJECT_ROOT) / "results"
    if results.is_symlink():
        raise ValueError("Results directory is a symlink")
    output = results / ("audio_security_" + str(time.time_ns()))
    output.mkdir(parents=True, exist_ok=False)
    (output / "encrypted.bin").write_bytes(iv + ciphertext)
    (output / "wrapped_key.bin").write_bytes(wrapped)
    (output / "recovered.mp3").write_bytes(recovered)
    record = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source": SOURCE, "sha256": digest, "source_bytes": len(data),
        "encrypted_bytes": len(iv) + len(ciphertext),
        "ciphertext_prefix_base64": base64.b64encode(ciphertext[:48]).decode("ascii"),
        "algorithm": "AES-256-CBC with PKCS7; RSA-OAEP wrapped AES key",
        "files": {"encrypted": "encrypted.bin", "wrapped_key": "wrapped_key.bin",
                  "recovered": "recovered.mp3"},
        "timings_ms_median": {
            "encrypt": round(statistics.median(encrypt_ns) / 1e6, 6),
            "decrypt": round(statistics.median(decrypt_ns) / 1e6, 6)},
        "trials": TRIALS, "recovered_matches_baseline": True,
        "note": "Ciphertext is not a playable MP3; original and recovered previews "
                "are played locally on the victim dashboard.",
    }
    with (output / "metrics.json").open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    return output, record


def main():
    output, record = run()
    print(f"PASS: synthetic MP3 encrypted and recovered to {output}")
    print("SHA-256:", record["sha256"])
    print("Ciphertext prefix (Base64):", record["ciphertext_prefix_base64"])
    print("Median timings (ms):", json.dumps(record["timings_ms_median"], sort_keys=True))
    print("PASS: recovered audio matches committed baseline; source unchanged")


if __name__ == "__main__":
    main()