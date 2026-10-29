"""Add reproducible synthetic media and decoys to an existing Phase 1 dataset.

On the Ubuntu victim VM, run from the repository root:
    python3 -m victim.phase1_media
    python3 -m victim.phase1_media --verify

Existing files are never overwritten. For a clean re-run, restore the VM snapshot.
"""

import argparse
import hashlib
import io
import json
import math
import os
import subprocess
import tempfile
import wave
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from PIL import Image, ImageDraw
from openpyxl import Workbook
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from config import PROJECT_ROOT, TEST_DATA_DIR


ROOT = Path(TEST_DATA_DIR).resolve(strict=False)
MANIFEST = Path(PROJECT_ROOT) / "results" / "baseline_hashes.json"
BASE_TIME = datetime(2025, 1, 2, 12, tzinfo=timezone.utc)
STAMP = (2025, 1, 1, 0, 0, 0)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pdf_bytes(decoy):
    output = io.BytesIO()
    doc = canvas.Canvas(output, pagesize=A4, invariant=1, pageCompression=0)
    kind = "Command Archive" if decoy else "Operations Brief"
    for page in range(1, 3):
        doc.setTitle("Fictional Training Report")
        doc.setFont("Helvetica-Bold", 16)
        doc.drawString(50, 790, kind + " — Synthetic Lab Data")
        doc.setFont("Helvetica", 11)
        doc.drawString(50, 755, f"Exercise FALCON-42, page {page}/2")
        doc.drawString(50, 730, "All names, locations, and records in this file are fictional.")
        for row in range(18):
            doc.drawString(50, 690 - row * 25,
                           f"Entry {page:02d}-{row:02d}: simulated planning checkpoint and review.")
        doc.showPage()
    doc.save()
    return output.getvalue()


def normalize_xlsx(raw):
    """Remove variable ZIP entry times from an openpyxl workbook."""
    source, result = io.BytesIO(raw), io.BytesIO()
    with zipfile.ZipFile(source) as zin, zipfile.ZipFile(result, "w") as zout:
        for item in zin.infolist():
            info = zipfile.ZipInfo(item.filename, STAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = item.external_attr
            zout.writestr(info, zin.read(item.filename))
    return result.getvalue()


def xlsx_bytes(decoy):
    book = Workbook()
    book.properties.created = datetime(2025, 1, 1, 0, 0)
    book.properties.modified = datetime(2025, 1, 1, 0, 0)
    sheet = book.active
    sheet.title = "Simulated Logistics"
    sheet.append(["Record", "Fictional sector", "Training kits", "Status"])
    for index in range(1, 61):
        sheet.append([f"SIM-{index:03d}", f"SECTOR-{(index % 7) + 1}",
                      (index * 3 + (11 if decoy else 5)) % 30, "EXERCISE ONLY"])
    raw = io.BytesIO()
    book.save(raw)
    return normalize_xlsx(raw.getvalue())


def jpg_bytes(decoy):
    image = Image.new("RGB", (1024, 768), "#213b54" if decoy else "#42674d")
    draw = ImageDraw.Draw(image)
    for index in range(12):
        x = index * 85
        draw.rectangle((x, 180 + index * 12, x + 55, 650),
                       fill="#6f8797" if decoy else "#9dab79")
    draw.text((50, 45), "SYNTHETIC TRAINING IMAGE - FALCON-42", fill="white")
    output = io.BytesIO()
    image.save(output, format="JPEG", quality=85, optimize=False)
    return output.getvalue()


def run_ffmpeg(args):
    try:
        process = subprocess.run(["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
                                  "-y", *args], check=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=90)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = getattr(exc, "stderr", b"") or b""
        raise RuntimeError(f"ffmpeg failed: {detail.decode(errors='replace')}") from exc
    return process


def mp3_bytes(decoy):
    with tempfile.TemporaryDirectory() as directory:
        wav_path = Path(directory) / "tone.wav"
        mp3_path = Path(directory) / "tone.mp3"
        rate = 16000
        frequency = 523 if decoy else 440
        with wave.open(str(wav_path), "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(rate)
            for second in range(10):
                samples = bytearray()
                for n in range(rate):
                    sample = int(5500 * math.sin(2 * math.pi * frequency * n / rate))
                    samples += sample.to_bytes(2, "little", signed=True)
                wav.writeframes(samples)
        run_ffmpeg(["-i", str(wav_path), "-map_metadata", "-1", "-codec:a", "libmp3lame",
                    "-b:a", "64k", "-write_xing", "0", str(mp3_path)])
        return mp3_path.read_bytes()


def mp4_bytes(decoy):
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "clip.mp4"
        color = "navy" if decoy else "darkgreen"
        run_ffmpeg(["-f", "lavfi", "-i", f"color=c={color}:s=320x240:r=15:d=3",
                    "-an", "-c:v", "mpeg4", "-q:v", "5", "-threads", "1",
                    "-map_metadata", "-1", "-fflags", "+bitexact", "-flags:v", "+bitexact",
                    str(output)])
        return output.read_bytes()


def planned_files():
    makers = (
        ("report.pdf", pdf_bytes), ("logistics.xlsx", xlsx_bytes),
        ("marker.jpg", jpg_bytes), ("briefing.mp3", mp3_bytes),
        ("training.mp4", mp4_bytes),
    )
    originals = ("01_Operations", "01_Operations", "02_Intelligence", "03_Media", "03_Media")
    files = {}
    for (name, maker), folder in zip(makers, originals):
        files[f"{folder}/{name}"] = maker(False)
        files[f"A_COMMAND_ARCHIVE/{name}"] = maker(True)
    return files


def safe_path(relative):
    path = ROOT / relative
    if not path.resolve(strict=False).is_relative_to(ROOT):
        raise ValueError(f"Unsafe path: {path}")
    return path


def existing_files():
    if not ROOT.is_dir() or ROOT.is_symlink():
        raise ValueError(f"Dataset directory missing or unsafe: {ROOT}")
    files = {}
    for directory, dirs, names in os.walk(ROOT, followlinks=False):
        for name in [*dirs, *names]:
            path = Path(directory) / name
            if path.is_symlink():
                raise ValueError(f"Symlink in dataset: {path}")
        for name in names:
            path = Path(directory) / name
            if not path.is_file():
                raise ValueError(f"Non-regular file: {path}")
            files[path.relative_to(ROOT).as_posix()] = digest(path.read_bytes())
    return dict(sorted(files.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="Verify without writing any files")
    args = parser.parse_args()
    if args.verify:
        if not MANIFEST.is_file():
            raise FileNotFoundError(MANIFEST)
        expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
        actual = existing_files()
        if actual != expected["files"]:
            missing = sorted(set(expected["files"]) - set(actual))
            extra = sorted(set(actual) - set(expected["files"]))
            changed = sorted(k for k in set(actual) & set(expected["files"])
                             if actual[k] != expected["files"][k])
            raise ValueError(f"Baseline mismatch: missing={missing}, extra={extra}, changed={changed}")
        print(f"PASS: {len(actual)} dataset files match {MANIFEST}")
        return

    existing_files()
    if MANIFEST.exists():
        raise FileExistsError(f"Baseline already exists; use --verify: {MANIFEST}")
    planned = planned_files()
    for index, (relative, contents) in enumerate(sorted(planned.items())):
        path = safe_path(relative)
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"Refusing to replace existing file: {path}")
    for index, (relative, contents) in enumerate(sorted(planned.items())):
        path = safe_path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(contents)
        timestamp = (BASE_TIME + timedelta(minutes=index * 17)).timestamp()
        os.utime(path, (timestamp, timestamp))
    files = existing_files()
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    with MANIFEST.open("x", encoding="utf-8") as stream:
        json.dump({"algorithm": "sha256", "files": files}, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(f"Created {len(planned)} media files; baseline contains {len(files)} files: {MANIFEST}")


if __name__ == "__main__":
    main()