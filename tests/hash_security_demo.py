"""Illustrate SHA-256 properties on the baseline synthetic mission brief.

On Ubuntu: python3 -m tests.hash_security_demo
The bounded searches are demonstrations, not proofs of SHA-256 resistance.
"""

import hashlib
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from config import PROJECT_ROOT, TEST_DATA_DIR


SOURCE = "01_Operations/mission_brief.txt"
TIMING_TRIALS = 100
SEARCH_LIMIT = 10000
BIT_TRIALS = 10


def _digest(data):
    return hashlib.sha256(data).digest()


def _measure(operation, payload, records):
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    start = time.perf_counter_ns()
    value = _digest(payload)
    elapsed = time.perf_counter_ns() - start
    records.append({"ts": ts, "operation": operation, "duration_ms": round(elapsed / 1e6, 6)})
    return value, elapsed


def run():
    root = Path(TEST_DATA_DIR)
    path = root / SOURCE
    if root != Path.home() / "MILITARY_DATA" or path.is_symlink() or not path.is_file():
        raise ValueError("Only the configured synthetic text is allowed")
    original = path.read_bytes()
    baseline = json.loads((Path(PROJECT_ROOT) / "results" / "baseline_hashes.json").read_text())["files"]
    operations = []
    target, _ = _measure("hash_source", original, operations)
    if target.hex() != baseline[SOURCE]:
        raise ValueError("Synthetic text differs from baseline")
    timing_ns = []
    for _ in range(TIMING_TRIALS):
        _, elapsed = _measure("hash_trial", original, operations)
        timing_ns.append(elapsed)
    changed_bits = []
    for bit in range(BIT_TRIALS):
        changed = bytearray(original)
        changed[bit // 8] ^= 1 << (bit % 8)
        different, _ = _measure("hash_one_bit_variant", changed, operations)
        changed_bits.append(sum((a ^ b).bit_count() for a, b in zip(target, different)))
    preimage_found = second_preimage_found = collision_found = False
    seen = {}
    for index in range(SEARCH_LIMIT):
        candidate = b"SYNTHETIC HASH CANDIDATE " + index.to_bytes(4, "big")
        digest = _digest(candidate)
        if digest == target:
            preimage_found = True
            if candidate != original:
                second_preimage_found = True
        if digest in seen and seen[digest] != candidate:
            collision_found = True
        else:
            seen[digest] = candidate
    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "operations": operations,
        "source": SOURCE, "source_bytes": len(original), "algorithm": "SHA-256",
        "digest_hex": target.hex(),
        "generation_time_ms_median": round(statistics.median(timing_ns) / 1e6, 6),
        "generation_trials": TIMING_TRIALS,
        "one_input_bit_digest_change_pct_median": round(
            100 * statistics.median(changed_bits) / 256, 3),
        "digest_changed_bits_each_trial": changed_bits,
        "bounded_search": {
            "candidates": SEARCH_LIMIT,
            "preimage_found": preimage_found,
            "second_preimage_found": second_preimage_found,
            "collision_found": collision_found,
        },
        "definitions": {
            "preimage_resistance": "Given a digest, finding any input that hashes to it should be infeasible.",
            "second_preimage_resistance": "Given a particular input, finding a different input with the same digest should be infeasible.",
            "collision_resistance": "Finding any two different inputs with the same digest should be infeasible.",
        },
        "limit": "No match in a bounded 10,000-candidate search does not prove a "
                 "cryptographic resistance property. The one-bit experiment "
                 "measures sample avalanche, not collision resistance.",
    }


def main():
    result = run()
    output = Path(PROJECT_ROOT) / "results" / "hash_security.json"
    if output.is_symlink():
        raise ValueError("Refusing to write through symlink")
    with output.open("w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(f"PASS: SHA-256 analysis saved to {output}")
    print("Digest:", result["digest_hex"])
    print("Median generation time (ms):", result["generation_time_ms_median"])
    print("One-bit digest change median (%):", result["one_input_bit_digest_change_pct_median"])
    print("Bounded search:", json.dumps(result["bounded_search"], sort_keys=True))
    print("Note: bounded searches cannot prove resistance")


if __name__ == "__main__":
    main()