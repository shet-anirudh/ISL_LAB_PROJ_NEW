"""tests/test_dashboard.py — Unit test for Flask dashboard app and /status endpoint."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analysis.dashboard.app import app


class TestDashboard(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_status_endpoint(self):
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("containment_triggered", data)
        self.assertIn("files_encrypted_count", data)
        self.assertIn("decoys_touched", data)
        self.assertIn("threat_phase", data)

    def test_index_page(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("ISL Containment Operations Center", html)
        self.assertIn("timelineChart", html)


if __name__ == "__main__":
    unittest.main()
