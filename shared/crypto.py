"""Pure cryptographic helpers for the isolated lab simulation.

AES-256-CBC uses PKCS#7 padding. The caller must keep each IV with its
ciphertext and must authenticate the IV and ciphertext before decryption if
tamper detection is required. RSA-OAEP wraps only a 32-byte AES key.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_aes_key() -> bytes:
    return os.urandom(32)


def generate_iv() -> bytes:
    return os.urandom(16)


def _check_key_iv(key: bytes, iv: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    if not isinstance(iv, bytes) or len(iv) != 16:
        raise ValueError("AES-CBC IV must be 16 bytes")


def aes_encrypt(data: bytes, iv: bytes, key: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")
    _check_key_iv(key, iv)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(data: bytes, iv: bytes, key: bytes) -> bytes:
    if not isinstance(data, bytes) or len(data) == 0 or len(data) % 16:
        raise ValueError("Ciphertext must contain complete AES blocks")
    _check_key_iv(key, iv)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _oaep():
    return asymmetric_padding.OAEP(
        mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None,
    )


def rsa_wrap_key(aes_key: bytes, pub_key_path: str) -> bytes:
    if not isinstance(aes_key, bytes) or len(aes_key) != 32:
        raise ValueError("Only a 32-byte AES key can be wrapped")
    public_key = serialization.load_pem_public_key(Path(pub_key_path).read_bytes())
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Expected an RSA public key")
    return public_key.encrypt(aes_key, _oaep())


def rsa_unwrap_key(wrapped_key: bytes, priv_key_path: str) -> bytes:
    private_key = serialization.load_pem_private_key(
        Path(priv_key_path).read_bytes(), password=None,
    )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Expected an RSA private key")
    key = private_key.decrypt(wrapped_key, _oaep())
    if len(key) != 32:
        raise ValueError("Unwrapped key has the wrong size")
    return key


def generate_rsa_keypair(pub_path: str, priv_path: str) -> None:
    """Create a 2048-bit pair, refusing to overwrite either existing path."""
    public_path = Path(pub_path).expanduser()
    private_path = Path(priv_path).expanduser()
    if public_path.resolve(strict=False) == private_path.resolve(strict=False):
        raise ValueError("Public and private key paths must differ")
    if public_path.exists() or public_path.is_symlink() or private_path.exists() or private_path.is_symlink():
        raise FileExistsError("Key path already exists; keys were not replaced")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    created_private = False
    created_public = False
    try:
        fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created_private = True
        with os.fdopen(fd, "wb") as output:
            output.write(private_pem)
        fd = os.open(public_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        created_public = True
        with os.fdopen(fd, "wb") as output:
            output.write(public_pem)
    except Exception:
        if created_public:
            public_path.unlink(missing_ok=True)
        if created_private:
            private_path.unlink(missing_ok=True)
        raise
