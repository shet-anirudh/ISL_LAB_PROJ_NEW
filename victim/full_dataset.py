"""Generate or verify the complete synthetic Phase 1 dataset.

From the repository root on the Ubuntu victim VM:
    python3 -m victim.full_dataset --verify
    python3 -m victim.full_dataset --self-test

The self-test uses disposable temporary directories; it does not touch the
configured MILITARY_DATA directory or its baseline manifest.
"""

import argparse
import hashlib
import json
import os
import tempfile
from datetime import timedelta
from pathlib import Path

from config import PROJECT_ROOT, TEST_DATA_DIR
from victim.dataset_generator import BASE_TIME as TEXT_BASE_TIME
from victim.dataset_generator import _documents
from victim.phase1_media import BASE_TIME as MEDIA_BASE_TIME
from victim.phase1_media import planned_files


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _tree(root):
    found = {}
    if not root.exists():
        return found
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"Unsafe dataset root: {root}")
    for directory, folders, files in os.walk(root, followlinks=False):
        for name in [*folders, *files]:
            path = Path(directory) / name
            if path.is_symlink():
                raise ValueError(f"Symlink in dataset: {path}")
        for name in files:
            path = Path(directory) / name
            if not path.is_file():
                raise ValueError(f"Non-regular file: {path}")
            found[path.relative_to(root).as_posix()] = _hash(path.read_bytes())
    return dict(sorted(found.items()))


def _manifest(files):
    return {"algorithm": "sha256", "files": dict(sorted(files.items()))}


def generate_dataset(base_dir, *, seed=42, manifest_path=None, verify=False):
    """Create or check all twenty fictional files without replacing existing ones.

    Returns the filename-to-SHA-256 dictionary. Existing unexpected files and
    changed generated files cause an error. If manifest_path is supplied, write
    the manifest once or compare it during verification.
    """
    root = Path(base_dir).expanduser().absolute()
    if root.is_symlink() or any(parent.is_symlink() for parent in root.parents):
        raise ValueError(f"Symlink in dataset path: {root}")
    original = _documents(seed)
    media = planned_files()
    if set(original) & set(media):
        raise ValueError("Duplicate generated filename")
    expected = {**original, **media}
    hashes = {name: _hash(content) for name, content in sorted(expected.items())}
    actual = _tree(root)
    unexpected = sorted(set(actual) - set(hashes))
    changed = sorted(name for name in set(actual) & set(hashes) if actual[name] != hashes[name])
    if unexpected or changed:
        raise ValueError(f"Dataset differs: unexpected={unexpected}, changed={changed}")
    missing = sorted(set(hashes) - set(actual))
    if verify and missing:
        raise ValueError(f"Missing generated files: {missing}")

    text_names = sorted(original)
    media_names = sorted(media)
    for name in missing:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(expected[name])
        if name in original:
            index = text_names.index(name)
            timestamp = (TEXT_BASE_TIME + timedelta(minutes=index * 17 + seed % 17)).timestamp()
        else:
            index = media_names.index(name)
            timestamp = (MEDIA_BASE_TIME + timedelta(minutes=index * 17)).timestamp()
        os.utime(path, (timestamp, timestamp))

    if manifest_path is not None:
        manifest = Path(manifest_path)
        result = _manifest(hashes)
        if manifest.exists():
            if json.loads(manifest.read_text(encoding="utf-8")) != result:
                raise ValueError(f"Baseline manifest differs: {manifest}")
        elif verify:
            raise FileNotFoundError(manifest)
        else:
            manifest.parent.mkdir(parents=True, exist_ok=True)
            with manifest.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2, sort_keys=True)
                stream.write("\n")
    return hashes


def self_test():
    with tempfile.TemporaryDirectory(prefix="islab-dataset-check-") as workspace:
        root = Path(workspace)
        first = generate_dataset(root / "first", manifest_path=root / "first.json")
        second = generate_dataset(root / "second", manifest_path=root / "second.json")
        if first != second:
            raise AssertionError("Generated files differ across runs")
        generate_dataset(root / "first", manifest_path=root / "first.json", verify=True)
        generate_dataset(root / "second", manifest_path=root / "second.json", verify=True)
        print(f"PASS: two clean generations have identical hashes for {len(first)} files")


def repair_legacy_spreadsheets():
    """Replace only the two synthetic XLSX files after validating the old baseline."""
    root = Path(TEST_DATA_DIR)
    manifest = Path(PROJECT_ROOT) / "results" / "baseline_hashes.json"
    old = json.loads(manifest.read_text(encoding="utf-8"))
    actual = _tree(root)
    if old.get("algorithm") != "sha256" or old.get("files") != actual:
        raise ValueError("Existing dataset does not match its old baseline; nothing changed")
    expected_data = {**_documents(42), **planned_files()}
    expected_hashes = {name: _hash(data) for name, data in expected_data.items()}
    spreadsheet_names = {"01_Operations/logistics.xlsx", "A_COMMAND_ARCHIVE/logistics.xlsx"}
    if set(actual) != set(expected_hashes):
        raise ValueError("Dataset file list is unexpected; nothing changed")
    if any(actual[name] != expected_hashes[name] for name in set(actual) - spreadsheet_names):
        raise ValueError("A file other than the spreadsheets differs; nothing changed")
    if all(actual[name] == expected_hashes[name] for name in spreadsheet_names):
        print("PASS: spreadsheet metadata is already deterministic; no repair needed")
        return

    # Keep backup bytes outside the watched dataset until all writes succeed.
    with tempfile.TemporaryDirectory(prefix="islab-xlsx-backup-") as backup_dir:
        originals = {name: (root / name).read_bytes() for name in spreadsheet_names}
        old_manifest = manifest.read_bytes()
        try:
            for index, name in enumerate(sorted(spreadsheet_names)):
                path = root / name
                temp_path = path.with_name(path.name + ".phase1-new")
                with temp_path.open("xb") as stream:
                    stream.write(expected_data[name])
                os.replace(temp_path, path)
                timestamp = (MEDIA_BASE_TIME + timedelta(minutes=(sorted(planned_files()).index(name)) * 17)).timestamp()
                os.utime(path, (timestamp, timestamp))
            temp_manifest = manifest.with_name(manifest.name + ".phase1-new")
            with temp_manifest.open("x", encoding="utf-8") as stream:
                json.dump(_manifest(expected_hashes), stream, indent=2, sort_keys=True)
                stream.write("\n")
            os.replace(temp_manifest, manifest)
        except Exception:
            for name, data in originals.items():
                (root / name).write_bytes(data)
            manifest.write_bytes(old_manifest)
            raise
    print("PASS: repaired two synthetic XLSX files and updated baseline hashes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="Check configured data and baseline")
    parser.add_argument("--self-test", action="store_true", help="Test two fresh temporary datasets")
    parser.add_argument("--repair-legacy-xlsx", action="store_true",
                        help="Validate old baseline, then normalize two synthetic spreadsheets")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.repair_legacy_xlsx:
        repair_legacy_spreadsheets()
    else:
        manifest = Path(PROJECT_ROOT) / "results" / "baseline_hashes.json"
        result = generate_dataset(TEST_DATA_DIR, seed=args.seed,
                                  manifest_path=manifest, verify=args.verify)
        print(f"PASS: {len(result)} generated files match {manifest}" if args.verify else
              f"Dataset ready: {len(result)} files; baseline: {manifest}")


if __name__ == "__main__":
    main()