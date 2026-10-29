"""tests/test_crypto.py — Unit tests for shared/crypto.py."""

import os
import sys
import tempfile
import unittest

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.crypto import (
    generate_aes_key,
    generate_iv,
    aes_encrypt,
    aes_decrypt,
    generate_rsa_keypair,
    rsa_wrap_key,
    rsa_unwrap_key
)


class TestCrypto(unittest.TestCase):

    def test_aes_generation_lengths(self):
        key = generate_aes_key()
        self.assertEqual(len(key), 32)
        iv = generate_iv()
        self.assertEqual(len(iv), 16)

    def test_aes_roundtrip(self):
        key = generate_aes_key()
        iv = generate_iv()
        test_payloads = [
            b"",
            b"Hello world, security research test!",
            b"A" * 15,
            b"B" * 16,
            b"C" * 17,
            os.urandom(1024 * 64),  # 64 KB binary data
        ]
        for data in test_payloads:
            ciphertext = aes_encrypt(data, iv, key)
            self.assertNotEqual(ciphertext, data)
            decrypted = aes_decrypt(ciphertext, iv, key)
            self.assertEqual(decrypted, data)

    def test_aes_tampered_ciphertext(self):
        key = generate_aes_key()
        iv = generate_iv()
        ciphertext = aes_encrypt(b"Top secret document", iv, key)
        
        # Tampering with first block produces corrupted plaintext
        tampered_first = bytearray(ciphertext)
        tampered_first[0] ^= 0xFF
        decrypted = aes_decrypt(bytes(tampered_first), iv, key)
        self.assertNotEqual(decrypted, b"Top secret document")

        # Tampering with last block corrupts PKCS7 padding and raises error
        tampered_last = bytearray(ciphertext)
        tampered_last[-1] ^= 0xFF
        with self.assertRaises(Exception):
            aes_decrypt(bytes(tampered_last), iv, key)

    def test_rsa_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pub_path = os.path.join(tmpdir, "public.pem")
            priv_path = os.path.join(tmpdir, "private.pem")
            generate_rsa_keypair(pub_path, priv_path)

            self.assertTrue(os.path.exists(pub_path))
            self.assertTrue(os.path.exists(priv_path))

            aes_key = generate_aes_key()
            wrapped = rsa_wrap_key(aes_key, pub_path)
            self.assertNotEqual(wrapped, aes_key)

            unwrapped = rsa_unwrap_key(wrapped, priv_path)
            self.assertEqual(unwrapped, aes_key)


if __name__ == "__main__":
    unittest.main()
