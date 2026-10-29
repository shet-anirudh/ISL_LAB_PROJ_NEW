# Synthetic lab security and efficiency results

Generated: 2026-10-29T13:59:57+00:00 (UTC)

## Validated evidence

- Original dataset: all 20 files match their committed SHA-256 baseline.
- Evaluation: 10 pairs, 20 runs; RSA-PSS signature independently verified with the public key.
- Signed evaluation SHA-256: `ad0530ca2560ec507ffc4cd747c0247490422242b223936201fbff9dacf89761`.
- Recovered text, decoded RGB pixels, and MP3 match their originals.
- Network capture and forensic timeline are stored on Kali; this victim-side report does not re-verify the Kali PCAP.

## Security goals

| Goal | Implemented evidence | Limit |
|---|---|---|
| Confidentiality | AES encryption of synthetic text, RGB image, MP3, and file transfer; TLS backup. | The ciphertext pixel view is not a valid JPEG. |
| Integrity | SHA-256 baseline, authenticated transfer, and verified RSA-PSS signature on evaluation JSON. | Bounded searches do not prove hash resistance. |
| Authentication | Signed C2 rejection demo, authenticated transfer, and pinned TLS telemetry. | Lab keys and host-only IPs define this trust boundary. |
| Accountability | Timestamped C2, transfer, honeypot, and containment logs; Kali forensic timeline. | VM clocks differ; Kali report documents its offset. Logs are not signed. |
| Availability | Verified backup/restore and contained copy-only trials. | Results apply to the controlled simulator and registered PID. |

## Controlled defense comparison

| Condition | Runs | Median real encrypted trial copies |
|---|---:|---:|
| Monitored | 10 | 0.0 |
| No trial watcher | 10 | 5.0 |

Median alert-to-stop: **6.500 ms**; median kill call response: **5.709 ms**. The original dataset remained unchanged in every run.

## Text and image security measurements

| Metric | Observation | Method |
|---|---:|---|
| Text diffusion bit changes | 49.609% | One plaintext bit flipped; same key/IV. |
| Text diffusion hex-character changes | 94.196% | Positional hex digits of ciphertext; not plaintext letters. |
| Text confusion bit changes | 49.163% | One key bit flipped; same plaintext/IV. |
| Text confusion hex-character changes | 93.973% | Positional hex digits of ciphertext; not plaintext letters. |
| Image NPCR | 100.000% | Two ciphertext pixel views after one plaintext-bit change. |
| Image UACI | 33.442% | Mean RGB-channel difference between those views. |
| Original / encrypted entropy | 3.6305 / 7.9999 bits/byte | RGB channel byte distributions. |
| Original / encrypted neighbor correlation | 0.9753 / 0.0082 | Sampled horizontal red-channel neighbors. |
| Original to encrypted MSE / PSNR | 7273.037 / 9.514 dB | Original RGB vs ciphertext pixel view. |
| Original to recovered MSE / PSNR | 0.0 / Infinity | Perfect RGB recovery. |

## Hash and signature

Synthetic text SHA-256: `7ee7b32fa7e543d5f4c8beb858e04a03a627a690b40821f678424f24741a655d`; median generation time **0.001071 ms** over 100 trials. One-bit input change altered a median **51.562%** of digest bits.

Pre-image, second pre-image, and collision resistance describe three distinct search problems. The 10,000-candidate illustrations found no match; this does not establish the cryptographic hardness of SHA-256.

Stored RSA-PSS signature: median sign **0.550809 ms**, verify **0.027482 ms**, hash **0.003619 ms** over 10 trials. The one-byte tamper test was rejected.

## Processing efficiency

| Sample | Plain bytes | Median AES encrypt (ms) | Median AES decrypt (ms) | Basis |
|---|---:|---:|---:|---|
| Text | 105 | 0.008403 | 0.008372 | 10 AES trials |
| Decoded RGB image | 2359296 | 2.531966 | 1.647476 | 10 AES trials |
| MP3 | 80685 | 0.073935 | 0.033973 | 10 AES trials |

The document, JPEG, MP3, and MP4 file-level benchmark also recorded AES throughput (MiB/s) over ten trials per type:

| Type | Bytes | Encrypt MiB/s | Decrypt MiB/s |
|---|---:|---:|---:|
| audio | 80685 | 1012.803 | 2208.905 |
| document | 5443 | 257.208 | 419.819 |
| image | 36219 | 823.771 | 1914.538 |
| video | 6248 | 306.778 | 482.123 |

Transfer measurements are from logged successful lab transfers; trial counts are shown because most types currently have one observation:

| Synthetic file | Trials | Latest MiB/s |
|---|---:|---:|
| `01_Operations/report.pdf` | 1 | 0.1248 |
| `02_Intelligence/marker.jpg` | 1 | 0.8789 |
| `03_Media/briefing.mp3` | 1 | 1.7253 |
| `03_Media/training.mp4` | 1 | 0.1505 |

## Interpretation

- Percentages are observations for the chosen synthetic samples, keys, IVs, and comparison definitions; they are not universal guarantees.
- Small-file timing and one-trial transfer rates are sensitive to fixed overhead and VM scheduling.
- The dashboards graph these stored measurements and show local media previews. The Kali PCAP report provides the network timeline.
