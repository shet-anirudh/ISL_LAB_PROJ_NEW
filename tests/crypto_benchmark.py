"""Benchmark the four synthetic victim file types without changing them.

Run on the Ubuntu victim VM from the repository root:
    python3 -m tests.crypto_benchmark

Writes results/crypto_benchmarks.json. The RSA private key is not needed.
"""

import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from config import PROJECT_ROOT, RSA_PUB_KEY_PATH, TEST_DATA_DIR
from shared.crypto import (
    aes_decrypt, aes_encrypt, generate_aes_key, generate_iv, rsa_wrap_key,
)


FILES = {
    "document": "01_Operations/report.pdf",
    "image": "02_Intelligence/marker.jpg",
    "audio": "03_Media/briefing.mp3",
    "video": "03_Media/training.mp4",
}
TRIALS = 10


def median_ms(samples_ns):
    return round(statistics.median(samples_ns) / 1_000_000, 4)


def benchmark():
    root = Path(TEST_DATA_DIR)
    if not root.is_dir():
        raise FileNotFoundError(root)
    public_key = Path(RSA_PUB_KEY_PATH)
    if not public_key.is_file():
        raise FileNotFoundError(public_key)
    records = {}
    for kind, relative in FILES.items():
        path = root / relative
        data = path.read_bytes()
        if not data:
            raise ValueError(f"Empty sample file: {path}")
        encrypt_ns, decrypt_ns, wrap_ns = [], [], []
        for _ in range(TRIALS):
            key, iv = generate_aes_key(), generate_iv()
            start = time.perf_counter_ns()
            ciphertext = aes_encrypt(data, iv, key)
            encrypt_ns.append(time.perf_counter_ns() - start)

            start = time.perf_counter_ns()
            recovered = aes_decrypt(ciphertext, iv, key)
            decrypt_ns.append(time.perf_counter_ns() - start)
            if recovered != data:
                raise AssertionError(f"AES round trip failed for {relative}")

            start = time.perf_counter_ns()
            rsa_wrap_key(key, public_key)
            wrap_ns.append(time.perf_counter_ns() - start)

        median_encrypt_s = statistics.median(encrypt_ns) / 1_000_000_000
        median_decrypt_s = statistics.median(decrypt_ns) / 1_000_000_000
        mib = len(data) / (1024 * 1024)
        records[kind] = {
            "file": relative,
            "bytes": len(data),
            "aes_encrypt_median_ms": median_ms(encrypt_ns),
            "aes_decrypt_median_ms": median_ms(decrypt_ns),
            "aes_encrypt_mib_per_s": round(mib / median_encrypt_s, 3),
            "aes_decrypt_mib_per_s": round(mib / median_decrypt_s, 3),
            "rsa_wrap_median_ms": median_ms(wrap_ns),
        }
    return {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "trials_per_file": TRIALS, "measurements": records}


def main():
    result = benchmark()
    output = Path(PROJECT_ROOT) / "results" / "crypto_benchmarks.json"
    if output.is_symlink():
        raise ValueError(f"Refusing to write through symlink: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PASS: benchmarked {len(FILES)} file types, {TRIALS} trials each; saved {output}")


if __name__ == "__main__":
    main()