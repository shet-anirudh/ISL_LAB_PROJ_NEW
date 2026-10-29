"""Controlled Phase 5 encryption trial of synthetic data on the victim VM.

Run from the victim repository root: python3 -m ransomware.simulator
Creates a new results/simtrial-* directory. Never edits MILITARY_DATA.
"""

import hashlib
import argparse
import json
import os
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from config import HONEYPOT_DIR, LOG_DIR, PROJECT_ROOT, RSA_PUB_KEY_PATH, TEST_DATA_DIR
from ransomware.traversal_plan import plan_targets
from shared.crypto import aes_decrypt, aes_encrypt, generate_aes_key, generate_iv, rsa_wrap_key


def utc_stamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def append_log(event, **fields):
    directory = Path(LOG_DIR)
    if directory.resolve(strict=False).is_relative_to(Path(TEST_DATA_DIR).resolve(strict=True)):
        raise ValueError("Log directory must be outside synthetic dataset")
    directory.mkdir(parents=True, exist_ok=True)
    record = {"ts": utc_stamp(), "module": "simulator", "event": event, **fields}
    with (directory / "simulator.log").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")


def _copy_non_targets(source, trial, target_set):
    for directory, folders, files in os.walk(source, followlinks=False):
        current = Path(directory)
        destination = trial / current.relative_to(source)
        destination.mkdir(parents=True, exist_ok=True)
        for name in [*folders, *files]:
            if (current / name).is_symlink():
                raise ValueError(f"Symlink in dataset: {current / name}")
        for name in files:
            path = current / name
            relative = path.relative_to(source).as_posix()
            if relative not in target_set:
                shutil.copy2(path, destination / name)


def simulate(*, step_delay=0, gate_file=None):
    source = Path(TEST_DATA_DIR).absolute()
    decoy = Path(HONEYPOT_DIR).absolute()
    if source != Path.home() / "MILITARY_DATA" or decoy != source / "A_COMMAND_ARCHIVE":
        raise ValueError("Simulator requires the configured victim synthetic dataset")
    if not Path(RSA_PUB_KEY_PATH).is_file():
        raise FileNotFoundError(RSA_PUB_KEY_PATH)
    plan = plan_targets()
    target_set = {name for _, name in plan}
    results = Path(PROJECT_ROOT) / "results"
    if results.is_symlink() or results.resolve(strict=False).is_relative_to(source.resolve(strict=True)):
        raise ValueError("Trial output must be outside the dataset")
    results.mkdir(parents=True, exist_ok=True)
    trial = Path(tempfile.mkdtemp(prefix="simtrial-", dir=results))
    started = time.perf_counter()
    _copy_non_targets(source, trial, target_set)
    if gate_file is not None:
        gate = Path(gate_file).absolute()
        if gate.parent != results or gate.is_symlink() or gate.exists():
            raise ValueError("Start gate must be a new file directly inside results")
        deadline = time.monotonic() + 10
        print(f"Trial ready; waiting for {gate}", flush=True)
        while not gate.is_file():
            if time.monotonic() > deadline:
                raise TimeoutError("Integration start gate was not released")
            time.sleep(0.01)
    records = []
    for kind, name in plan:
        original = source / name
        if original.is_symlink() or not original.is_file():
            raise ValueError(f"Missing or unsafe synthetic file: {original}")
        data = original.read_bytes()
        key, iv = generate_aes_key(), generate_iv()
        ciphertext = aes_encrypt(data, iv, key)
        if aes_decrypt(ciphertext, iv, key) != data:
            raise AssertionError(f"Encryption round trip failed: {name}")
        wrapped = rsa_wrap_key(key, RSA_PUB_KEY_PATH)
        dest = trial / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        locked = dest.with_name(dest.name + ".locked")
        sidecar = dest.with_name(dest.name + ".key")
        with locked.open("xb") as output:
            output.write(iv + ciphertext)
        with sidecar.open("xb") as output:
            output.write(wrapped)
        record = {"kind": kind, "file": name, "bytes": len(data),
                  "sha256_original": hashlib.sha256(data).hexdigest(),
                  "locked": locked.relative_to(trial).as_posix(),
                  "key_sidecar": sidecar.relative_to(trial).as_posix()}
        records.append(record)
        append_log("synthetic_file_encrypted", trial=str(trial), **record)
        if step_delay:
            time.sleep(step_delay)
    note = trial / "SIMULATION_README.txt"
    note.write_text("SYNTHETIC LAB TRIAL ONLY. The original MILITARY_DATA is unchanged.\n",
                    encoding="utf-8")
    summary = {"ts": utc_stamp(), "trial": str(trial), "files": records,
               "elapsed_s": round(time.perf_counter() - started, 4)}
    (trial / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    append_log("trial_complete", trial=str(trial), file_count=len(records),
               elapsed_s=summary["elapsed_s"])
    return trial, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--step-delay", type=float, default=0,
                        help="Pause after each copy for a controlled containment trial")
    parser.add_argument("--gate-file", help="Wait for this new results file before encrypting copies")
    args = parser.parse_args()
    if not 0 <= args.step_delay <= 5:
        parser.error("--step-delay must be between 0 and 5 seconds")
    trial, records = simulate(step_delay=args.step_delay, gate_file=args.gate_file)
    print(f"PASS: created {len(records)} encrypted synthetic copies in {trial}")
    print(f"First target: {records[0]['kind']} {records[0]['file']}")
    print("Original MILITARY_DATA was not modified")


if __name__ == "__main__":
    main()