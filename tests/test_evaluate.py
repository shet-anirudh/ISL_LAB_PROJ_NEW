"""tests/test_evaluate.py — Unit and integration tests for analysis/evaluate.py."""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analysis.evaluate import generate_sample_trials, aggregate, plot_charts, load_trials


class TestEvaluate(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="isl_eval_test_")
        self.results_dir = os.path.join(self.test_dir, "results")
        self.charts_dir = os.path.join(self.test_dir, "reports", "charts")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_evaluate_aggregation_and_chart_generation(self):
        # 1. Generate 5 sample trials per config
        generate_sample_trials(self.results_dir, num_trials=5)
        trials = load_trials(self.results_dir)
        self.assertEqual(len(trials), 10, "Should generate 10 total trials (5 with-HP, 5 without-HP)")

        # 2. Run aggregate()
        summary_path = os.path.join(self.results_dir, "summary_stats.json")
        summary = aggregate(self.results_dir, output_summary_path=summary_path)

        self.assertTrue(os.path.exists(summary_path))
        self.assertIn("with_honeypot", summary)
        self.assertIn("without_honeypot", summary)

        # Check values
        with_hp_saved = summary["with_honeypot"]["files_saved_ratio"]["mean"]
        self.assertGreater(with_hp_saved, 75.0, "With honeypot files-saved ratio should be high")
        without_hp_saved = summary["without_honeypot"]["files_saved_ratio"]["mean"]
        self.assertEqual(without_hp_saved, 0.0, "Without honeypot files-saved ratio should be 0.0")

        # 3. Plot charts
        plot_charts(summary, trials, self.charts_dir)

        # Verify all 4 chart files were generated
        expected_charts = [
            "latency_comparison.png",
            "files_saved_ratio.png",
            "encryption_throughput.png",
            "exfiltration_volume.png"
        ]
        for chart_name in expected_charts:
            chart_file = os.path.join(self.charts_dir, chart_name)
            self.assertTrue(os.path.exists(chart_file), f"Expected chart {chart_name} to exist")
            self.assertGreater(os.path.getsize(chart_file), 1000, f"Chart {chart_name} should not be empty")


if __name__ == "__main__":
    unittest.main()
