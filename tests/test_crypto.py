"""Run from the repository root: python3 -m unittest tests.test_crypto -v."""

import os
import tempfile
import unittest
from pathlib import Path

from config import TEST_DATA_DIR

from shared.crypto import (
    aes_decrypt, aes_encrypt, generate_aes_key, generate_iv,
    generate_rsa_keypair, rsa_unwrap_key, rsa_wrap_key,
)


class CryptoTests(unittest.TestCase):
    def test_aes_round_trip_for_binary_and_empty_content(self):
        samples = [b"", b"Synthetic report\n" * 8, os.urandom(1024), os.urandom(8193)]
        key = generate_aes_key()
        for sample in samples:
            with self.subTest(size=len(sample)):
                iv = generate_iv()
                ciphertext = aes_encrypt(sample, iv, key)
                self.assertNotEqual(ciphertext, sample)
                self.assertEqual(aes_decrypt(ciphertext, iv, key), sample)

    def test_new_iv_changes_ciphertext(self):
        key = generate_aes_key()
        data = b"Synthetic lab sample"
        self.assertNotEqual(aes_encrypt(data, generate_iv(), key),
                            aes_encrypt(data, generate_iv(), key))

    def test_generated_file_types_when_available(self):
        root = Path(TEST_DATA_DIR)
        samples = ["01_Operations/report.pdf", "02_Intelligence/marker.jpg",
                   "03_Media/briefing.mp3", "03_Media/training.mp4"]
        if not all((root / name).is_file() for name in samples):
            self.skipTest("Generated dataset is only present on the victim VM")
        for name in samples:
            with self.subTest(file=name):
                original = (root / name).read_bytes()
                key, iv = generate_aes_key(), generate_iv()
                self.assertEqual(aes_decrypt(aes_encrypt(original, iv, key), iv, key), original)

    def test_rsa_wrap_unwrap_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory) / "public.pem"
            private = Path(directory) / "private.pem"
            generate_rsa_keypair(public, private)
            if os.name == "posix":
                self.assertEqual(private.stat().st_mode & 0o777, 0o600)
            key = generate_aes_key()
            wrapped = rsa_wrap_key(key, public)
            self.assertNotEqual(wrapped, key)
            self.assertEqual(rsa_unwrap_key(wrapped, private), key)
            with self.assertRaises(FileExistsError):
                generate_rsa_keypair(public, private)

    def test_invalid_input_rejected(self):
        with self.assertRaises(ValueError):
            aes_encrypt(b"hello", b"short", generate_aes_key())
        with self.assertRaises(ValueError):
            aes_encrypt(b"hello", generate_iv(), b"short")
        with self.assertRaises(ValueError):
            aes_decrypt(b"not a full block", generate_iv(), generate_aes_key())


if __name__ == "__main__":
    unittest.main()
