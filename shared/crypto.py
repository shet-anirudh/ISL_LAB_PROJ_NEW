"""shared/crypto.py — Shared Cryptography Library for ISL Project.

Exports:
    aes_encrypt(data, iv, key)
    aes_decrypt(data, iv, key)
    generate_aes_key()
    generate_iv()
    rsa_wrap_key(aes_key, pub_key_path)
    rsa_unwrap_key(wrapped_key, priv_key_path)
    generate_rsa_keypair(pub_path, priv_path)
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend


def generate_aes_key() -> bytes:
    """Generate a random 256-bit (32 bytes) AES key."""
    return os.urandom(32)


def generate_iv() -> bytes:
    """Generate a random 128-bit (16 bytes) IV for AES-CBC."""
    return os.urandom(16)


def aes_encrypt(data: bytes, iv: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-256-CBC with PKCS7 padding.
    
    Args:
        data: Plaintext bytes to encrypt
        iv: 16-byte initialization vector
        key: 32-byte AES key
        
    Returns:
        Ciphertext bytes
    """
    if len(key) != 32:
        raise ValueError(f"AES key must be 32 bytes (256-bit), got {len(key)} bytes")
    if len(iv) != 16:
        raise ValueError(f"IV must be 16 bytes, got {len(iv)} bytes")

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


def aes_decrypt(data: bytes, iv: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-CBC ciphertext and remove PKCS7 padding.
    
    Args:
        data: Ciphertext bytes to decrypt
        iv: 16-byte initialization vector
        key: 32-byte AES key
        
    Returns:
        Original plaintext bytes
    """
    if len(key) != 32:
        raise ValueError(f"AES key must be 32 bytes (256-bit), got {len(key)} bytes")
    if len(iv) != 16:
        raise ValueError(f"IV must be 16 bytes, got {len(iv)} bytes")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def generate_rsa_keypair(pub_path: str, priv_path: str) -> Tuple[str, str]:
    """Generate an RSA-2048 keypair and save as PEM files.
    
    Args:
        pub_path: Path where public key PEM will be written
        priv_path: Path where private key PEM will be written
        
    Returns:
        Tuple of (pub_path, priv_path)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Ensure parent directories exist
    os.makedirs(os.path.dirname(os.path.abspath(pub_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(priv_path)), exist_ok=True)

    # Serialize private key
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(priv_path, "wb") as f:
        f.write(priv_pem)

    # Serialize public key
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    return pub_path, priv_path


def rsa_wrap_key(aes_key: bytes, pub_key_path: str) -> bytes:
    """Encrypt (wrap) an AES key using the RSA public key with OAEP padding.
    
    Args:
        aes_key: 32-byte AES key
        pub_key_path: Path to public key PEM
        
    Returns:
        RSA-encrypted key bytes
    """
    with open(pub_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    wrapped_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped_key


def rsa_unwrap_key(wrapped_key: bytes, priv_key_path: str) -> bytes:
    """Decrypt (unwrap) an AES key using the RSA private key with OAEP padding.
    
    Args:
        wrapped_key: RSA-encrypted key bytes
        priv_key_path: Path to private key PEM
        
    Returns:
        Decrypted 32-byte AES key
    """
    with open(priv_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    aes_key = private_key.decrypt(
        wrapped_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key
