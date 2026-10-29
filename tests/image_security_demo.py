"""RGB image encryption, previews, and image security metrics.

On Ubuntu: python3 -m tests.image_security_demo
Reads the baseline synthetic marker.jpg without modifying it. Encrypts raw RGB
bytes with AES-256-CBC; the ciphertext preview maps the first RGB byte count
of ciphertext back to pixels. It is a visualization, not a JPEG decoder.
"""

import hashlib
import json
import math
import statistics
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image

from config import PROJECT_ROOT, TEST_DATA_DIR
from shared.crypto import aes_decrypt, aes_encrypt, generate_aes_key, generate_iv


SOURCE = "02_Intelligence/marker.jpg"
TRIALS = 10


def entropy(data):
    """Shannon entropy in bits per byte across all RGB channel values."""
    if not data:
        raise ValueError("Empty image")
    histogram = Counter(data)
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in histogram.values())


def correlation(data, width, height, *, max_pairs=10000):
    """Pearson correlation of adjacent horizontal red-channel pixels."""
    count = (width - 1) * height
    if count < 2:
        raise ValueError("Need at least two horizontal pixel pairs")
    step = max(1, count // max_pairs)
    n = sx = sy = sxx = syy = sxy = 0
    for position in range(0, count, step):
        row, column = divmod(position, width - 1)
        left = 3 * (row * width + column)
        x, y = data[left], data[left + 3]
        n += 1
        sx += x
        sy += y
        sxx += x * x
        syy += y * y
        sxy += x * y
    dx, dy = n * sxx - sx * sx, n * syy - sy * sy
    return None if dx <= 0 or dy <= 0 else (n * sxy - sx * sy) / math.sqrt(dx * dy)


def mse(a, b):
    if len(a) != len(b) or not a:
        raise ValueError("Images must have the same RGB byte count")
    return sum((x - y) ** 2 for x, y in zip(a, b)) / len(a)


def psnr(error):
    return "Infinity" if error == 0 else 10 * math.log10(255 * 255 / error)


def npcr_uaci(a, b):
    if len(a) != len(b) or not a or len(a) % 3:
        raise ValueError("Images must have matching RGB pixel counts")
    changed_pixels = 0
    absolute_difference = 0
    view_a, view_b = memoryview(a), memoryview(b)
    for i in range(0, len(a), 3):
        if view_a[i:i+3] != view_b[i:i+3]:
            changed_pixels += 1
        absolute_difference += (abs(a[i] - b[i]) + abs(a[i+1] - b[i+1]) +
                                abs(a[i+2] - b[i+2]))
    return 100 * changed_pixels / (len(a) // 3), 100 * absolute_difference / (255 * len(a))


def _rounded(value):
    return round(value, 6) if value is not None and not isinstance(value, str) else value


def run():
    root = Path(TEST_DATA_DIR)
    source = root / SOURCE
    if root != Path.home() / "MILITARY_DATA" or source.is_symlink() or not source.is_file():
        raise ValueError("Only the configured synthetic image is allowed")
    expected = json.loads((Path(PROJECT_ROOT) / "results" / "baseline_hashes.json").read_text())["files"][SOURCE]
    if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
        raise ValueError("Synthetic image differs from baseline")
    with Image.open(source) as input_image:
        image = input_image.convert("RGB")
    width, height = image.size
    original = image.tobytes()
    key, iv = generate_aes_key(), generate_iv()
    encrypted = aes_encrypt(original, iv, key)
    recovered = aes_decrypt(encrypted, iv, key)
    if recovered != original:
        raise AssertionError("RGB round trip failed")
    preview = encrypted[:len(original)]
    changed = bytearray(original)
    changed[0] ^= 1  # One bit in the first pixel; keep the same key and IV.
    changed_cipher = aes_encrypt(bytes(changed), iv, key)[:len(original)]
    npcr, uaci = npcr_uaci(preview, changed_cipher)
    encrypt_ns, decrypt_ns = [], []
    for _ in range(TRIALS):
        start = time.perf_counter_ns()
        candidate = aes_encrypt(original, iv, key)
        encrypt_ns.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        if aes_decrypt(candidate, iv, key) != original:
            raise AssertionError("RGB round trip failed")
        decrypt_ns.append(time.perf_counter_ns() - start)
    encrypted_error = mse(original, preview)
    recovered_error = mse(original, recovered)
    results_dir = Path(PROJECT_ROOT) / "results"
    if results_dir.is_symlink():
        raise ValueError("Results directory is a symlink")
    output = results_dir / ("image_security_" + str(time.time_ns()))
    output.mkdir(parents=True, exist_ok=False)
    Image.frombytes("RGB", (width, height), original).save(output / "original.png")
    Image.frombytes("RGB", (width, height), preview).save(output / "encrypted_pixels.png")
    Image.frombytes("RGB", (width, height), recovered).save(output / "recovered.png")
    result = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source": SOURCE, "source_sha256": expected,
        "algorithm": "AES-256-CBC on decoded RGB bytes, PKCS7 padding",
        "image": {"width": width, "height": height, "channels": 3},
        "previews": {name: str((output / filename).relative_to(PROJECT_ROOT))
                     for name, filename in (("original", "original.png"),
                                            ("encrypted", "encrypted_pixels.png"),
                                            ("recovered", "recovered.png"))},
        "metrics": {
            "npcr_ciphertexts_one_plaintext_bit_pct": _rounded(npcr),
            "uaci_ciphertexts_one_plaintext_bit_pct": _rounded(uaci),
            "entropy_original_bits_per_byte": _rounded(entropy(original)),
            "entropy_encrypted_bits_per_byte": _rounded(entropy(preview)),
            "horizontal_red_correlation_original": _rounded(correlation(original, width, height)),
            "horizontal_red_correlation_encrypted": _rounded(correlation(preview, width, height)),
            "mse_original_to_encrypted": _rounded(encrypted_error),
            "psnr_original_to_encrypted_db": _rounded(psnr(encrypted_error)),
            "mse_original_to_recovered": _rounded(recovered_error),
            "psnr_original_to_recovered_db": psnr(recovered_error),
        },
        "timings_ms_median": {
            "encrypt": round(statistics.median(encrypt_ns) / 1e6, 6),
            "decrypt": round(statistics.median(decrypt_ns) / 1e6, 6)},
        "trials": TRIALS,
        "metric_definition": {
            "npcr_uaci": "Compare two ciphertext RGB visualizations with identical key "
                         "and IV, after flipping one bit in the first plaintext pixel. "
                         "NPCR is fraction of changed RGB pixels; UACI averages "
                         "absolute differences across RGB channels divided by 255.",
            "entropy": "Shannon entropy across all decoded RGB channel byte values.",
            "correlation": "Pearson correlation of up to 10,000 evenly sampled "
                           "horizontal neighbor red-channel pairs; null means zero variance.",
            "mse_psnr": "Compare original RGB against encrypted pixel visualization "
                        "and against recovered RGB. Perfect recovery has MSE 0 and "
                        "PSNR Infinity, stored as a string in JSON.",
            "visualization": "First width*height*3 ciphertext bytes mapped to RGB. "
                             "This is not a valid encrypted JPEG file format.",
        },
    }
    with (output / "metrics.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    return output, result


def main():
    output, result = run()
    print(f"PASS: RGB encrypted and recovered; previews and metrics saved to {output}")
    print("Image:", result["image"])
    print("Metrics:", json.dumps(result["metrics"], sort_keys=True))
    print("Median timings (ms):", json.dumps(result["timings_ms_median"], sort_keys=True))


if __name__ == "__main__":
    main()