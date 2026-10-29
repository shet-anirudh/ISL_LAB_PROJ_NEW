"""Build a consolidated, evidence-backed security and efficiency summary.

On Ubuntu: python3 -m analysis.security_summary
Reads the existing synthetic results, checks the dataset and evaluation
signature, and saves Markdown in results/. No source data is modified.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image

from config import PROJECT_ROOT, TEST_DATA_DIR
from tests.signature_demo import verify_artifact


ROOT = Path(PROJECT_ROOT)
RESULTS = ROOT / "results"


def _load(path):
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError(path)
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return result


def _latest(pattern, *, directory=RESULTS, directories=False):
    matches = [p for p in directory.glob(pattern)
               if not p.is_symlink() and (p.is_dir() if directories else p.is_file())]
    if not matches:
        raise FileNotFoundError(f"Missing result: {directory / pattern}")
    return max(matches, key=lambda p: p.stat().st_mtime_ns)


def _fmt(value, digits=4):
    return f"{value:.{digits}f}" if isinstance(value, (float, int)) else str(value)


def build():
    manifest = _load(RESULTS / "baseline_hashes.json")["files"]
    if len(manifest) != 20 or Path(TEST_DATA_DIR) != Path.home() / "MILITARY_DATA":
        raise ValueError("Expected the 20-file synthetic victim dataset")
    for name, digest in manifest.items():
        path = Path(TEST_DATA_DIR) / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"Original dataset differs from baseline: {name}")
    text = _load(RESULTS / "text_security.json")
    hash_result = _load(RESULTS / "hash_security.json")
    image_dir = _latest("image_security_*", directories=True)
    image = _load(image_dir / "metrics.json")
    audio_dir = _latest("audio_security_*", directories=True)
    audio = _load(audio_dir / "metrics.json")
    crypto = _load(RESULTS / "crypto_benchmarks.json")
    transfer = _load(RESULTS / "transfer_benchmarks.json")
    signature_path = _latest("defense_evaluation_*.json.sig.json",
                             directory=RESULTS / "signatures")
    signature = _load(signature_path)
    evaluation_path = ROOT / signature["source"]
    verify_artifact(evaluation_path, signature_path=signature_path)
    evaluation = _load(evaluation_path)
    runs = evaluation["runs"]
    if evaluation["pairs"] != 10 or len(runs) != 20 or not all(r["original_intact"] for r in runs):
        raise ValueError("Expected ten signed trial pairs and intact originals")
    if text["plaintext"] != text["recovered_plaintext"] or not audio["recovered_matches_baseline"]:
        raise ValueError("Media recovery is not confirmed")
    if hashlib.sha256((audio_dir / "recovered.mp3").read_bytes()).hexdigest() != manifest[audio["source"]]:
        raise ValueError("Recovered MP3 does not match baseline")
    with Image.open(image_dir / "original.png") as original, Image.open(image_dir / "recovered.png") as recovered:
        if original.size != recovered.size or original.tobytes() != recovered.tobytes():
            raise ValueError("Recovered RGB pixels differ from original")
    if hash_result["digest_hex"] != manifest[hash_result["source"]]:
        raise ValueError("SHA-256 demonstration differs from baseline")

    t = text["timings_ms_median"]
    im, it = image["metrics"], image["timings_ms_median"]
    at = audio["timings_ms_median"]
    es = evaluation["summary"]
    signature_time = signature["timings_ms_median"]
    rows = [
        ("Text", text["plaintext_bytes"], t["encrypt"], t["decrypt"], "10 AES trials"),
        ("Decoded RGB image", image["image"]["width"] * image["image"]["height"] * 3,
         it["encrypt"], it["decrypt"], "10 AES trials"),
        ("MP3", audio["source_bytes"], at["encrypt"], at["decrypt"], "10 AES trials"),
    ]
    lines = [
        "# Synthetic lab security and efficiency results", "",
        f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')} (UTC)", "",
        "## Validated evidence", "",
        f"- Original dataset: all {len(manifest)} files match their committed SHA-256 baseline.",
        f"- Evaluation: {evaluation['pairs']} pairs, {len(runs)} runs; RSA-PSS signature independently verified with the public key.",
        f"- Signed evaluation SHA-256: `{signature['sha256']}`.",
        "- Recovered text, decoded RGB pixels, and MP3 match their originals.",
        "- Network capture and forensic timeline are stored on Kali; this victim-side report "
        "does not re-verify the Kali PCAP.", "",
        "## Security goals", "",
        "| Goal | Implemented evidence | Limit |", "|---|---|---|",
        "| Confidentiality | AES encryption of synthetic text, RGB image, MP3, and file transfer; TLS backup. | The ciphertext pixel view is not a valid JPEG. |",
        "| Integrity | SHA-256 baseline, authenticated transfer, and verified RSA-PSS signature on evaluation JSON. | Bounded searches do not prove hash resistance. |",
        "| Authentication | Signed C2 rejection demo, authenticated transfer, and pinned TLS telemetry. | Lab keys and host-only IPs define this trust boundary. |",
        "| Accountability | Timestamped C2, transfer, honeypot, and containment logs; Kali forensic timeline. | VM clocks differ; Kali report documents its offset. Logs are not signed. |",
        "| Availability | Verified backup/restore and contained copy-only trials. | Results apply to the controlled simulator and registered PID. |",
        "", "## Controlled defense comparison", "",
        "| Condition | Runs | Median real encrypted trial copies |", "|---|---:|---:|",
        f"| Monitored | 10 | {_fmt(es['with_real_copies_median'], 1)} |",
        f"| No trial watcher | 10 | {_fmt(es['without_real_copies_median'], 1)} |",
        "",
        f"Median alert-to-stop: **{_fmt(es['alert_to_stop_ms_median'], 3)} ms**; "
        f"median kill call response: **{_fmt(es['kill_response_ms_median'], 3)} ms**. "
        "The original dataset remained unchanged in every run.", "",
        "## Text and image security measurements", "",
        "| Metric | Observation | Method |", "|---|---:|---|",
        f"| Text diffusion bit changes | {_fmt(text['diffusion_one_plaintext_bit']['summary']['bit_change_pct_median'], 3)}% | One plaintext bit flipped; same key/IV. |",
        f"| Text diffusion hex-character changes | {_fmt(text['diffusion_one_plaintext_bit']['summary']['hex_character_change_pct_median'], 3)}% | Positional hex digits of ciphertext; not plaintext letters. |",
        f"| Text confusion bit changes | {_fmt(text['confusion_one_key_bit']['summary']['bit_change_pct_median'], 3)}% | One key bit flipped; same plaintext/IV. |",
        f"| Text confusion hex-character changes | {_fmt(text['confusion_one_key_bit']['summary']['hex_character_change_pct_median'], 3)}% | Positional hex digits of ciphertext; not plaintext letters. |",
        f"| Image NPCR | {_fmt(im['npcr_ciphertexts_one_plaintext_bit_pct'], 3)}% | Two ciphertext pixel views after one plaintext-bit change. |",
        f"| Image UACI | {_fmt(im['uaci_ciphertexts_one_plaintext_bit_pct'], 3)}% | Mean RGB-channel difference between those views. |",
        f"| Original / encrypted entropy | {_fmt(im['entropy_original_bits_per_byte'], 4)} / {_fmt(im['entropy_encrypted_bits_per_byte'], 4)} bits/byte | RGB channel byte distributions. |",
        f"| Original / encrypted neighbor correlation | {_fmt(im['horizontal_red_correlation_original'], 4)} / {_fmt(im['horizontal_red_correlation_encrypted'], 4)} | Sampled horizontal red-channel neighbors. |",
        f"| Original to encrypted MSE / PSNR | {_fmt(im['mse_original_to_encrypted'], 3)} / {_fmt(im['psnr_original_to_encrypted_db'], 3)} dB | Original RGB vs ciphertext pixel view. |",
        f"| Original to recovered MSE / PSNR | {_fmt(im['mse_original_to_recovered'], 1)} / {im['psnr_original_to_recovered_db']} | Perfect RGB recovery. |",
        "", "## Hash and signature", "",
        f"Synthetic text SHA-256: `{hash_result['digest_hex']}`; median generation time "
        f"**{_fmt(hash_result['generation_time_ms_median'], 6)} ms** over 100 trials. "
        f"One-bit input change altered a median **{_fmt(hash_result['one_input_bit_digest_change_pct_median'], 3)}%** of digest bits.",
        "", "Pre-image, second pre-image, and collision resistance describe three "
        "distinct search problems. The 10,000-candidate illustrations found no match; "
        "this does not establish the cryptographic hardness of SHA-256.", "",
        f"Stored RSA-PSS signature: median sign **{_fmt(signature_time['sign'], 6)} ms**, "
        f"verify **{_fmt(signature_time['verify'], 6)} ms**, "
        f"hash **{_fmt(signature_time['sha256'], 6)} ms** over {signature['trials']} trials. "
        "The one-byte tamper test was rejected.", "",
        "## Processing efficiency", "",
        "| Sample | Plain bytes | Median AES encrypt (ms) | Median AES decrypt (ms) | Basis |",
        "|---|---:|---:|---:|---|",
    ]
    for label, size, enc, dec, basis in rows:
        lines.append(f"| {label} | {size} | {_fmt(enc, 6)} | {_fmt(dec, 6)} | {basis} |")
    lines.extend(["", "The document, JPEG, MP3, and MP4 file-level benchmark also recorded "
                  "AES throughput (MiB/s) over ten trials per type:", "",
                  "| Type | Bytes | Encrypt MiB/s | Decrypt MiB/s |", "|---|---:|---:|---:|"])
    for kind, item in crypto["measurements"].items():
        lines.append(f"| {kind} | {item['bytes']} | {_fmt(item['aes_encrypt_mib_per_s'], 3)} | {_fmt(item['aes_decrypt_mib_per_s'], 3)} |")
    lines.extend(["", "Transfer measurements are from logged successful lab transfers; "
                  "trial counts are shown because most types currently have one observation:", "",
                  "| Synthetic file | Trials | Latest MiB/s |", "|---|---:|---:|"])
    for name, record in transfer["measurements"].items():
        lines.append(f"| `{name}` | {record['trial_count']} | {_fmt(record['trials'][-1]['mib_per_s'], 4)} |")
    lines.extend(["", "## Interpretation", "",
                  "- Percentages are observations for the chosen synthetic samples, keys, IVs, and comparison definitions; they are not universal guarantees.",
                  "- Small-file timing and one-trial transfer rates are sensitive to fixed overhead and VM scheduling.",
                  "- The dashboards graph these stored measurements and show local media previews. The Kali PCAP report provides the network timeline.", ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    report = build()
    output = args.out or RESULTS / ("security_summary_" +
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".md")
    with output.open("x", encoding="utf-8") as stream:
        stream.write(report)
    print(f"PASS: 20 baseline files and signed ten-pair result verified; saved {output}")
    print("Sections: security goals, defense comparison, text/image metrics, hash/signature, efficiency")


if __name__ == "__main__":
    main()