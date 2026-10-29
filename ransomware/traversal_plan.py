"""Read-only target inventory for the controlled Phase 5 simulator.

Run on the Ubuntu victim VM from the repository root:
    python3 -m ransomware.traversal_plan

No files are modified, renamed, or encrypted.
"""

from pathlib import Path

from config import HONEYPOT_DIR, TEST_DATA_DIR


TARGET_EXTENSIONS = {".docx", ".xlsx", ".pdf", ".jpg", ".mp3", ".mp4"}


def _walk(directory, root):
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.is_symlink():
            raise ValueError(f"Symlink in test dataset: {path}")
        if path.is_dir():
            yield from _walk(path, root)
        elif path.is_file():
            if path.suffix.lower() in TARGET_EXTENSIONS:
                yield path.relative_to(root)
        else:
            raise ValueError(f"Unexpected dataset entry: {path}")


def plan_targets():
    root = Path(TEST_DATA_DIR).absolute()
    decoy = Path(HONEYPOT_DIR).absolute()
    expected_root = Path.home() / "MILITARY_DATA"
    if root != expected_root or decoy != root / "A_COMMAND_ARCHIVE":
        raise ValueError("This planner runs only against the configured victim lab dataset")
    if any(path.is_symlink() for path in (root, decoy, *root.parents)):
        raise ValueError("Dataset path must not contain a symlink")
    if not root.is_dir() or not decoy.is_dir():
        raise FileNotFoundError("Synthetic dataset or decoy directory is missing")
    # Explicit priority is necessary: 'A_' sorts after '01_', '02_', '03_'.
    ordered_roots = [decoy]
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if path == decoy:
            continue
        if path.is_symlink():
            raise ValueError(f"Symlink in test dataset: {path}")
        if path.is_dir():
            ordered_roots.append(path)
        elif path.is_file() and path.suffix.lower() in TARGET_EXTENSIONS:
            raise ValueError(f"Unexpected target at dataset root: {path}")
    targets = [("DECOY" if folder == decoy else "REAL", relative.as_posix())
               for folder in ordered_roots for relative in _walk(folder, root)]
    if not targets or targets[0][0] != "DECOY":
        raise ValueError("No decoy would be encountered first")
    return targets


def main():
    targets = plan_targets()
    decoys = sum(kind == "DECOY" for kind, _ in targets)
    print(f"DRY RUN: {len(targets)} target files ({decoys} decoys, {len(targets)-decoys} real)")
    for index, (kind, relative) in enumerate(targets, 1):
        print(f"{index:02d} {kind:5} {relative}")


if __name__ == "__main__":
    main()