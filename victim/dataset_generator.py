"""Create a small, reproducible, entirely fictional lab dataset.

Run from the repository root: python -m victim.dataset_generator --seed 42
The only output is under config.TEST_DATA_DIR. Existing files are never replaced.
"""

import argparse
import hashlib
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import TEST_DATA_DIR


BASE_TIME = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)


def _documents(seed: int) -> dict[str, bytes]:
    rng = random.Random(seed)
    operation = f"OP-{rng.randrange(1000, 10000)}"
    sector = f"SECTOR-{rng.randrange(10, 100)}"
    case = f"CASE-{rng.randrange(1000, 10000)}"
    # Every name, location, person, and identifier below is invented for the lab.
    text = {
        "01_Operations/mission_brief.txt": (
            f"SYNTHETIC TRAINING DATA — NOT REAL\nExercise: {operation}\n"
            f"Location: {sector} (fictional)\nStatus: simulated\n"
        ),
        "01_Operations/supply_log.csv": (
            "item,quantity,status\ntraining_kits,12,simulated\n"
            f"practice_radios,{rng.randrange(2, 9)},simulated\n"
        ),
        "01_Operations/schedule.txt": (
            f"SYNTHETIC TRAINING DATA\n{operation}: 09:00 planning, 13:00 review\n"
        ),
        "02_Intelligence/field_notes.txt": (
            f"SYNTHETIC TRAINING DATA\nCase: {case}\n"
            "Observation: fictional exercise marker only.\n"
        ),
        "02_Intelligence/observations.csv": (
            "marker,reading,source\n"
            f"alpha,{rng.randrange(10, 90)},simulation\n"
            f"beta,{rng.randrange(10, 90)},simulation\n"
        ),
        "02_Intelligence/summary.txt": (
            f"SYNTHETIC TRAINING DATA\n{case}: no real persons or locations.\n"
        ),
        "A_COMMAND_ARCHIVE/command_index.txt": (
            "SYNTHETIC HONEYPOT DECOY — NOT REAL\n"
            f"Archive reference: {operation}/{case}\n"
            "Contents: simulated exercise records.\n"
        ),
        "A_COMMAND_ARCHIVE/priority_memo.txt": (
            "SYNTHETIC HONEYPOT DECOY — NOT REAL\n"
            f"Training sector: {sector}\nPriority: exercise only.\n"
        ),
    }
    # PPM is a simple, dependency-free image format, useful as safe media bait.
    pixel = bytes((rng.randrange(30, 225), rng.randrange(30, 225), rng.randrange(30, 225)))
    image = b"P6\n16 16\n255\n" + pixel * (16 * 16)
    result = {name: content.encode("utf-8") for name, content in text.items()}
    result["03_Media/training_marker.ppm"] = image
    result["03_Media/README.txt"] = (
        "SYNTHETIC TRAINING DATA — NOT REAL\ntraining_marker.ppm is a generated image.\n"
    ).encode("utf-8")
    return result


def generate(seed: int, verify: bool = False) -> dict[str, str]:
    root = Path(TEST_DATA_DIR)
    if any(part.is_symlink() for part in (root, *root.parents)):
        raise ValueError(f"Symlink in dataset path: {root}")
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise ValueError(f"Unsafe dataset root: {root}")
    # Do not follow symlinks in an existing tree or alter unexpected files.
    expected = _documents(seed)
    if root.exists():
        for path in root.rglob("*"):
            if path.is_symlink():
                raise ValueError(f"Symlink in dataset: {path}")
            if path.is_file() and path.relative_to(root).as_posix() not in expected:
                raise ValueError(f"Unexpected file in dataset: {path}")
    elif verify:
        raise FileNotFoundError(root)
    else:
        root.mkdir(parents=True)

    hashes = {}
    for index, (relative, content) in enumerate(sorted(expected.items())):
        path = root / relative
        timestamp = (BASE_TIME + timedelta(minutes=index * 17 + seed % 17)).timestamp()
        digest = hashlib.sha256(content).hexdigest()
        if path.exists():
            if not path.is_file() or path.read_bytes() != content:
                raise ValueError(f"Existing file differs; left untouched: {path}")
            if verify and abs(path.stat().st_mtime - timestamp) > 0.001:
                raise ValueError(f"Timestamp differs: {path}")
        elif verify:
            raise FileNotFoundError(path)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            os.utime(path, (timestamp, timestamp))
        hashes[relative] = digest
    return hashes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42, help="Reproducible seed (default: 42)")
    parser.add_argument("--verify", action="store_true", help="Check files and timestamps without writing")
    args = parser.parse_args()
    for name, digest in generate(args.seed, args.verify).items():
        print(f"{digest}  {name}")


if __name__ == "__main__":
    main()
