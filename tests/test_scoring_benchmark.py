import unittest
from pathlib import Path

from reachability_advisor.scoring_benchmark import run_scoring_benchmark

ROOT = Path(__file__).resolve().parents[1]


class ScoringBenchmarkTests(unittest.TestCase):
    def test_checked_in_scoring_benchmark_passes(self) -> None:
        report = run_scoring_benchmark(ROOT / "configs" / "scoring-benchmark.json")
        self.assertEqual(report["status"], "passed")
        self.assertGreaterEqual(report["case_count"], 5)
        self.assertEqual(report["failed_count"], 0)


if __name__ == "__main__":
    unittest.main()
