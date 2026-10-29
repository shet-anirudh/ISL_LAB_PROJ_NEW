"""tests/test_forensics.py — Unit and integration tests for analysis/forensic_report.py."""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analysis.forensic_report import generate_report


class TestForensics(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="isl_forensics_test_")
        self.output_md = os.path.join(self.test_dir, "incident_report_test.md")

        # 1. Create mock baseline hashes (10 files)
        self.baseline_path = os.path.join(self.test_dir, "baseline_hashes.json")
        mock_baseline = {f"file_{i}.docx": f"hash_{i}" for i in range(10)}
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(mock_baseline, f)

        # 2. Create mock honeypot log
        self.honeypot_log = os.path.join(self.test_dir, "honeypot.log")
        with open(self.honeypot_log, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": "2026-10-29T11:00:03.120Z",
                "module": "honeypot",
                "event": "decoy_touched",
                "pid": 4321,
                "file": "/home/victim/MILITARY_DATA/A_COMMAND_ARCHIVE/Decoy.docx",
                "latency_ms": 142.5
            }) + "\n")

        # 3. Create mock containment log
        self.containment_log = os.path.join(self.test_dir, "containment.log")
        with open(self.containment_log, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": "2026-10-29T11:00:03.200Z",
                "module": "containment",
                "event": "kill_process",
                "target_pid": 4321,
                "latency_ms": 80.0
            }) + "\n")

        # 4. Create mock simulator log (encrypted 2 files before kill)
        self.simulator_log = os.path.join(self.test_dir, "simulator.log")
        with open(self.simulator_log, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": "2026-10-29T11:00:01.000Z",
                "module": "simulator",
                "event": "traversal_started",
                "pid": 4321
            }) + "\n")
            f.write(json.dumps({
                "ts": "2026-10-29T11:00:01.500Z",
                "module": "simulator",
                "event": "shadow_copy_simulated",
                "pid": 4321,
                "command": "vssadmin delete shadows /all /quiet"
            }) + "\n")
            f.write(json.dumps({
                "ts": "2026-10-29T11:00:02.000Z",
                "module": "simulator",
                "event": "file_encrypted",
                "pid": 4321,
                "file": "/home/victim/MILITARY_DATA/file_0.docx",
                "size_bytes": 1024
            }) + "\n")
            f.write(json.dumps({
                "ts": "2026-10-29T11:00:02.500Z",
                "module": "simulator",
                "event": "file_encrypted",
                "pid": 4321,
                "file": "/home/victim/MILITARY_DATA/file_1.docx",
                "size_bytes": 2048
            }) + "\n")

        # 5. Create mock C2 log
        self.c2_log = os.path.join(self.test_dir, "c2.log")
        with open(self.c2_log, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": "2026-10-29T11:00:00.000Z",
                "module": "c2",
                "event": "command_received",
                "cmd": "START_ENCRYPT",
                "server_ip": "192.168.56.10",
                "port": 9001
            }) + "\n")

        # 6. Create mock transfer log
        self.transfer_log = os.path.join(self.test_dir, "transfer.log")
        with open(self.transfer_log, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": "2026-10-29T10:59:50.000Z",
                "module": "transfer",
                "event": "file_sent",
                "dst_ip": "192.168.56.10",
                "port": 9002,
                "file_size": 52400
            }) + "\n")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_generate_report(self):
        content = generate_report(
            honeypot_log=self.honeypot_log,
            containment_log=self.containment_log,
            simulator_log=self.simulator_log,
            c2_log=self.c2_log,
            transfer_log=self.transfer_log,
            baseline_hashes_json=self.baseline_path,
            output_path=self.output_md
        )

        self.assertTrue(os.path.exists(self.output_md))
        self.assertIn("Digital Forensic Incident", content)
        self.assertIn("Executive Summary", content)
        self.assertIn("Files-Saved Ratio:** **80.0%**", content)
        self.assertIn("192.168.56.10", content)
        self.assertIn("vssadmin delete shadows /all /quiet", content)
        self.assertIn("Chronological Incident Timeline", content)
        self.assertIn("Detection Methodology Evaluation", content)


if __name__ == "__main__":
    unittest.main()
