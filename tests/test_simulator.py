"""tests/test_simulator.py — Unit and integration tests for ransomware/simulator.py."""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.crypto import (
    generate_rsa_keypair,
    rsa_unwrap_key,
    aes_decrypt
)
from ransomware.simulator import (
    validate_target_directory,
    run_traversal,
    TARGET_EXTENSIONS
)
import config


class TestSimulator(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="isl_sim_test_")
        self.keys_dir = tempfile.mkdtemp(prefix="isl_keys_test_")
        self.pub_key_path = os.path.join(self.keys_dir, "public.pem")
        self.priv_key_path = os.path.join(self.keys_dir, "private.pem")
        generate_rsa_keypair(self.pub_key_path, self.priv_key_path)

        # Set temporary log directory
        self.log_dir = tempfile.mkdtemp(prefix="isl_logs_test_")
        config.LOG_DIR = self.log_dir

        # Build mock dataset structure
        self.folders = [
            "A_COMMAND_ARCHIVE",
            "01_Operations",
            "02_Intelligence",
            "03_Media"
        ]
        self.created_files = {}

        for folder in self.folders:
            folder_path = os.path.join(self.test_dir, folder)
            os.makedirs(folder_path, exist_ok=True)

        # Create targeted files
        files_to_create = [
            ("A_COMMAND_ARCHIVE", "decoy_document.docx", b"CLASSIFIED DECOY REPORT 2026"),
            ("01_Operations", "mission_plan.pdf", b"%PDF-1.4 Mission Falcon Details"),
            ("02_Intelligence", "sat_recon.jpg", b"\xFF\xD8\xFF\xE0JFIF Recon Image"),
            ("03_Media", "briefing_audio.mp3", b"ID3v2.4 Audio Briefing Stream"),
            ("01_Operations", "unsupported_script.sh", b"#!/bin/bash\necho intact"),
        ]

        for folder, name, content in files_to_create:
            fpath = os.path.join(self.test_dir, folder, name)
            with open(fpath, "wb") as f:
                f.write(content)
            self.created_files[fpath] = content

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        shutil.rmtree(self.keys_dir, ignore_errors=True)
        shutil.rmtree(self.log_dir, ignore_errors=True)

    def test_safety_check_refusal(self):
        # Path outside permitted prefixes should raise PermissionError
        with self.assertRaises(PermissionError):
            validate_target_directory("C:\\Windows" if os.name == "nt" else "/etc", allow_local_override=False)

    def test_safety_check_nonexistent(self):
        with self.assertRaises(FileNotFoundError):
            validate_target_directory("/nonexistent_path_test_12345", allow_local_override=True)

    def test_run_traversal_encryption_and_recovery(self):
        # Run traversal with allow_local=True logic
        run_traversal(self.test_dir, self.pub_key_path)

        # 1. Verify targeted files were encrypted and removed
        for fpath, orig_content in self.created_files.items():
            ext = os.path.splitext(fpath)[1].lower()
            if ext in TARGET_EXTENSIONS:
                self.assertFalse(os.path.exists(fpath), f"Original file {fpath} should have been deleted!")
                locked_path = fpath + ".locked"
                key_path = fpath + ".key"
                self.assertTrue(os.path.exists(locked_path), f"Locked file {locked_path} must exist!")
                self.assertTrue(os.path.exists(key_path), f"Key file {key_path} must exist!")

                # Byte-for-byte decryption recovery test
                with open(locked_path, "rb") as f:
                    locked_data = f.read()
                iv = locked_data[:16]
                ciphertext = locked_data[16:]

                with open(key_path, "rb") as f:
                    wrapped_key = f.read()

                recovered_aes_key = rsa_unwrap_key(wrapped_key, self.priv_key_path)
                recovered_plaintext = aes_decrypt(ciphertext, iv, recovered_aes_key)
                self.assertEqual(recovered_plaintext, orig_content, f"Recovered plaintext mismatch for {fpath}!")
            else:
                # Unsupported extension should remain untouched
                self.assertTrue(os.path.exists(fpath), f"Non-target file {fpath} should remain untouched!")

        # 2. Verify ransom notes were dropped in folders containing targeted files
        for folder in self.folders:
            note_path = os.path.join(self.test_dir, folder, "README_DECRYPT.txt")
            self.assertTrue(os.path.exists(note_path), f"Ransom note should exist in {folder}")

        # 3. Verify logs
        log_file = os.path.join(self.log_dir, "simulator.log")
        self.assertTrue(os.path.exists(log_file), "Simulator log file must exist!")
        with open(log_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        events = [line["event"] for line in lines]
        self.assertIn("traversal_started", events)
        self.assertIn("shadow_copy_simulated", events)
        self.assertIn("file_encrypted", events)
        self.assertIn("traversal_complete", events)


if __name__ == "__main__":
    unittest.main()
