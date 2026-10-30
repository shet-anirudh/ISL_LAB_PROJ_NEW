"""Sign a synthetic results file on Kali and verify it on either VM.

    python3 -m tests.signature_demo --init-keys       # Kali, once
    python3 -m tests.signature_demo --sign results/defense_evaluation_<timestamp>.json
    python3 -m tests.signature_demo --verify results/defense_evaluation_<timestamp>.json

This uses a dedicated RSA-PSS signing key. The private key stays outside Git.
"""

import argparse
import base64
import hashlib
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from config import PROJECT_ROOT
from shared.crypto import generate_rsa_keypair


ROOT = Path(PROJECT_ROOT).resolve()
PUBLIC = ROOT / "keys" / "signing_public.pem"
PRIVATE = Path.home() / ".config" / "islab" / "signing_private.pem"
RESULTS = ROOT / "results"
TRIALS = 10


def _file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Source must be an existing regular file")
    absolute = path.resolve(strict=True)
    if not absolute.is_relative_to(RESULTS) or absolute.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Only synthetic results files up to 16 MiB are allowed")
    return absolute


def _keys():
    public = serialization.load_pem_public_key(PUBLIC.read_bytes())
    if not isinstance(public, rsa.RSAPublicKey):
        raise TypeError("Signing public key must be RSA")
    return public


def _pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                       salt_length=padding.PSS.MAX_LENGTH)


def _fingerprint(public):
    encoded = public.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(encoded).hexdigest()


def _timed(operation, name=None, timeline=None):
    stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    start = time.perf_counter_ns()
    result = operation()
    elapsed = time.perf_counter_ns() - start
    if timeline is not None:
        timeline.append({"ts": stamp, "operation": name, "duration_ms": round(elapsed / 1e6, 6)})
    return result, elapsed


def sign_artifact(source, *, private_path=PRIVATE, public_path=PUBLIC,
                  destination=None):
    source = _file(source)
    public = serialization.load_pem_public_key(Path(public_path).read_bytes())
    private_path = Path(private_path)
    if private_path.is_symlink() or private_path.resolve(strict=True).is_relative_to(ROOT):
        raise ValueError("Private signing key must be outside repository")
    if private_path.stat().st_mode & 0o077:
        raise PermissionError("Private signing key must have mode 600")
    private = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(private, rsa.RSAPrivateKey) or not isinstance(public, rsa.RSAPublicKey):
        raise TypeError("Expected RSA signing keys")
    if private.public_key().public_numbers() != public.public_numbers():
        raise ValueError("Signing private key does not match committed public key")
    data = source.read_bytes()
    timeline = []
    hashes_ns = [_timed(lambda: hashlib.sha256(data).digest(), "hash", timeline)[1]
                 for _ in range(TRIALS)]
    signature, first_ns = _timed(lambda: private.sign(data, _pss(), hashes.SHA256()), "sign", timeline)
    sign_ns = [first_ns]
    sign_ns.extend(_timed(lambda: private.sign(data, _pss(), hashes.SHA256()), "sign", timeline)[1]
                   for _ in range(TRIALS - 1))
    verify_ns = []
    for _ in range(TRIALS):
        _, elapsed = _timed(lambda: public.verify(signature, data, _pss(), hashes.SHA256()), "verify", timeline)
        verify_ns.append(elapsed)
    altered = bytearray(data)
    if altered:
        altered[0] ^= 1
    else:
        altered.append(1)
    try:
        public.verify(signature, bytes(altered), _pss(), hashes.SHA256())
    except InvalidSignature:
        tamper_rejected = True
    else:
        raise AssertionError("Altered bytes unexpectedly passed verification")
    result = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "algorithm": "RSA-PSS-SHA256", "source": source.relative_to(ROOT).as_posix(),
        "source_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "public_key_sha256": _fingerprint(public),
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "timings_ms_median": {
            "sha256": round(statistics.median(hashes_ns) / 1e6, 6),
            "sign": round(statistics.median(sign_ns) / 1e6, 6),
            "verify": round(statistics.median(verify_ns) / 1e6, 6),
        },
        "trials": TRIALS, "tampered_byte_rejected": tamper_rejected,
        "operations": timeline,
    }
    output = Path(destination) if destination is not None else (
        RESULTS / "signatures" / (source.name + ".sig.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    return output, result


def verify_artifact(source, *, signature_path=None, public_path=PUBLIC):
    source = _file(source)
    signature_path = Path(signature_path) if signature_path else (
        RESULTS / "signatures" / (source.name + ".sig.json"))
    if signature_path.is_symlink() or not signature_path.is_file():
        raise ValueError("Signature record missing or unsafe")
    record = json.loads(signature_path.read_text(encoding="utf-8"))
    public = serialization.load_pem_public_key(Path(public_path).read_bytes())
    if not isinstance(public, rsa.RSAPublicKey):
        raise TypeError("Expected RSA public key")
    data = source.read_bytes()
    if (record["algorithm"] != "RSA-PSS-SHA256" or
            record["source"] != source.relative_to(ROOT).as_posix() or
            record["public_key_sha256"] != _fingerprint(public) or
            record["source_bytes"] != len(data) or
            record["sha256"] != hashlib.sha256(data).hexdigest()):
        raise ValueError("Signed file, digest, or public key differs from signature record")
    signature = base64.b64decode(record["signature_base64"], validate=True)
    public.verify(signature, data, _pss(), hashes.SHA256())
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--init-keys", action="store_true")
    group.add_argument("--sign", type=Path)
    group.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.init_keys:
        generate_rsa_keypair(str(PUBLIC), str(PRIVATE))
        print(f"PASS: signing public key: {PUBLIC}")
        print(f"Private signing key: {PRIVATE} (keep outside Git)")
    elif args.sign:
        output, result = sign_artifact(args.sign)
        print(f"PASS: signature saved to {output}")
        print(f"SHA-256: {result['sha256']}")
        print(f"Signature (Base64): {result['signature_base64']}")
        print("Median milliseconds:", json.dumps(result["timings_ms_median"], sort_keys=True))
        print("PASS: one-byte change rejected by public-key verification")
    else:
        record = verify_artifact(args.verify)
        print(f"PASS: signature valid for {record['source']}")
        print(f"SHA-256: {record['sha256']}")


if __name__ == "__main__":
    main()
