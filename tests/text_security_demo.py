"""Text encryption demonstration and controlled AES confusion/diffusion metrics.

Run on Ubuntu: python3 -m tests.text_security_demo
Reads the synthetic mission brief and writes results/text_security.json. The
original file is never changed. The AES key is ephemeral and is not stored.
"""

import base64
import hashlib
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from config import PROJECT_ROOT, TEST_DATA_DIR
from shared.crypto import aes_decrypt, aes_encrypt, generate_aes_key, generate_iv


SOURCE = "01_Operations/mission_brief.txt"
TRIALS = 10


def _measure(operation, function, records):
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    start = time.perf_counter_ns()
    value = function()
    elapsed = time.perf_counter_ns() - start
    records.append({"ts": ts, "operation": operation, "duration_ms": round(elapsed / 1e6, 6)})
    return value, elapsed


def _changed(original, altered):
    if len(original) != len(altered) or not original:
        raise ValueError("Compare equal, nonempty ciphertexts")
    bit_changes = sum((a ^ b).bit_count() for a, b in zip(original, altered))
    hex_a, hex_b = original.hex(), altered.hex()
    hex_changes = sum(a != b for a, b in zip(hex_a, hex_b))
    return {"bit_change_pct": round(100 * bit_changes / (8 * len(original)), 3),
            "hex_character_change_pct": round(100 * hex_changes / len(hex_a), 3)}


def _median_ms(samples_ns):
    return round(statistics.median(samples_ns) / 1e6, 6)


def run():
    root = Path(TEST_DATA_DIR)
    path = root / SOURCE
    if root != Path.home() / "MILITARY_DATA" or path.is_symlink() or not path.is_file():
        raise ValueError("Only the configured synthetic text sample is allowed")
    original = path.read_bytes()
    operations = []
    source_digest, _ = _measure("hash_plaintext", lambda: hashlib.sha256(original).hexdigest(), operations)
    baseline = json.loads((Path(PROJECT_ROOT) / "results" / "baseline_hashes.json").read_text())
    if source_digest != baseline["files"][SOURCE]:
        raise ValueError("Synthetic text differs from baseline")
    plaintext = original.decode("utf-8")
    key, iv = generate_aes_key(), generate_iv()
    encrypted, _ = _measure("encrypt", lambda: aes_encrypt(original, iv, key), operations)
    cipher_digest, _ = _measure("hash_ciphertext", lambda: hashlib.sha256(encrypted).hexdigest(), operations)
    recovered, _ = _measure("decrypt", lambda: aes_decrypt(encrypted, iv, key), operations)
    recovered_digest, _ = _measure("hash_recovered", lambda: hashlib.sha256(recovered).hexdigest(), operations)
    if recovered != original:
        raise AssertionError("Text round trip failed")
    encrypt_ns, decrypt_ns = [], []
    for _ in range(TRIALS):
        candidate, elapsed = _measure("encrypt_trial", lambda: aes_encrypt(original, iv, key), operations)
        encrypt_ns.append(elapsed)
        decoded, elapsed = _measure("decrypt_trial", lambda: aes_decrypt(candidate, iv, key), operations)
        if decoded != original:
            raise AssertionError("AES round trip failed")
        decrypt_ns.append(elapsed)

    diffusion, confusion = [], []
    diffusion_times, confusion_times = [], []
    for bit in range(TRIALS):
        # Keep key and IV fixed: changing only one plaintext bit isolates
        # diffusion; changing only one key bit isolates confusion.
        changed_text = bytearray(original)
        changed_text[bit // 8] ^= 1 << (bit % 8)
        variant, elapsed = _measure("encrypt_plaintext_bit_variant", lambda: aes_encrypt(bytes(changed_text), iv, key), operations)
        diffusion_times.append(elapsed)
        diffusion.append(_changed(encrypted, variant))
        changed_key = bytearray(key)
        changed_key[bit // 8] ^= 1 << (bit % 8)
        variant, elapsed = _measure("encrypt_key_bit_variant", lambda: aes_encrypt(original, iv, bytes(changed_key)), operations)
        confusion_times.append(elapsed)
        confusion.append(_changed(encrypted, variant))

    def summary(rows):
        return {field + "_median": statistics.median(row[field] for row in rows)
                for field in ("bit_change_pct", "hex_character_change_pct")}

    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": "AES-256-CBC with PKCS7 padding",
        "source": SOURCE, "plaintext": plaintext,
        "source_sha256": source_digest, "ciphertext_sha256": cipher_digest,
        "recovered_sha256": recovered_digest, "operations": operations,
        "ciphertext_base64": base64.b64encode(encrypted).decode("ascii"),
        "iv_base64": base64.b64encode(iv).decode("ascii"),
        "recovered_plaintext": recovered.decode("utf-8"),
        "plaintext_bytes": len(original), "ciphertext_bytes": len(encrypted),
        "trials": TRIALS,
        "timings_ms_median": {"encrypt": _median_ms(encrypt_ns),
                              "decrypt": _median_ms(decrypt_ns)},
        "diffusion_one_plaintext_bit": {"trials": diffusion, "summary": summary(diffusion),
                                        "timings_ms_median": {"encrypt": _median_ms(diffusion_times)}},
        "confusion_one_key_bit": {"trials": confusion, "summary": summary(confusion),
                                  "timings_ms_median": {"encrypt": _median_ms(confusion_times)}},
        "metric_definition": "Same key and IV for each comparison. Bit change is "
        "Hamming distance over ciphertext bits; character change is positional "
        "difference over hexadecimal ciphertext characters. Hex digit values "
        "are not plaintext characters. These sample measurements are not "
        "cryptographic proofs or guaranteed percentages.",
    }


def main():
    result = run()
    output = Path(PROJECT_ROOT) / "results" / "text_security.json"
    if output.is_symlink():
        raise ValueError("Refusing to write through symlink")
    with output.open("w", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(f"PASS: text round trip and {TRIALS} one-bit trials; saved {output}")
    print("Plaintext:", result["plaintext"].replace("\n", " | "))
    print("Ciphertext (Base64):", result["ciphertext_base64"])
    print("Recovered:", result["recovered_plaintext"].replace("\n", " | "))
    print("Median timings (ms):", json.dumps(result["timings_ms_median"], sort_keys=True))
    print("Diffusion:", json.dumps(result["diffusion_one_plaintext_bit"]["summary"], sort_keys=True))
    print("Confusion:", json.dumps(result["confusion_one_key_bit"]["summary"], sort_keys=True))


if __name__ == "__main__":
    main()