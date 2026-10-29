"""Versioned, authenticated single-file protocol for the isolated lab transfer.

Wire format: magic (4), name length (4), relative name, ciphertext length (8),
IV (16), wrapped-key length (2), RSA-OAEP wrapped AES key, ciphertext,
HMAC-SHA256 tag (32). HMAC authenticates every preceding byte.
"""

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"ISL1"
MAX_CIPHERTEXT = 32 * 1024 * 1024
MAX_NAME = 200
MAX_WRAPPED = 512
FILE_CHOICES = (
    "01_Operations/report.pdf",
    "02_Intelligence/marker.jpg",
    "03_Media/briefing.mp3",
    "03_Media/training.mp4",
)


def mac_key(aes_key):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"islab-transfer-hmac-v1").derive(aes_key)


def tag(aes_key, payload):
    return hmac.new(mac_key(aes_key), payload, hashlib.sha256).digest()


def header(name, ciphertext_size, iv, wrapped_key):
    if name not in FILE_CHOICES:
        raise ValueError("Transfer is limited to the four synthetic sample files")
    encoded = name.encode("utf-8")
    if not (0 < len(encoded) <= MAX_NAME):
        raise ValueError("Invalid filename length")
    if not (16 <= ciphertext_size <= MAX_CIPHERTEXT and ciphertext_size % 16 == 0):
        raise ValueError("Invalid ciphertext size")
    if len(iv) != 16 or not (1 <= len(wrapped_key) <= MAX_WRAPPED):
        raise ValueError("Invalid IV or wrapped key")
    return (MAGIC + struct.pack("!I", len(encoded)) + encoded +
            struct.pack("!Q", ciphertext_size) + iv +
            struct.pack("!H", len(wrapped_key)) + wrapped_key)


def recv_exact(sock, length):
    chunks = bytearray()
    while len(chunks) < length:
        part = sock.recv(min(length - len(chunks), 65536))
        if not part:
            raise ConnectionError("Connection closed before complete transfer")
        chunks.extend(part)
    return bytes(chunks)


def receive_header(sock):
    magic = recv_exact(sock, 4)
    if magic != MAGIC:
        raise ValueError("Unknown transfer protocol")
    name_size_bytes = recv_exact(sock, 4)
    name_size = struct.unpack("!I", name_size_bytes)[0]
    if not (1 <= name_size <= MAX_NAME):
        raise ValueError("Invalid filename length")
    name_bytes = recv_exact(sock, name_size)
    name = name_bytes.decode("utf-8")
    if name not in FILE_CHOICES:
        raise ValueError("File is outside the synthetic transfer allowlist")
    length_bytes = recv_exact(sock, 8)
    size = struct.unpack("!Q", length_bytes)[0]
    if not (16 <= size <= MAX_CIPHERTEXT and size % 16 == 0):
        raise ValueError("Invalid ciphertext length")
    iv = recv_exact(sock, 16)
    wrapped_size_bytes = recv_exact(sock, 2)
    wrapped_size = struct.unpack("!H", wrapped_size_bytes)[0]
    if not (1 <= wrapped_size <= MAX_WRAPPED):
        raise ValueError("Invalid wrapped-key length")
    wrapped = recv_exact(sock, wrapped_size)
    raw = (magic + name_size_bytes + name_bytes + length_bytes + iv +
           wrapped_size_bytes + wrapped)
    return name, size, iv, wrapped, raw