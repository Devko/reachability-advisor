import json
import tempfile
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
        tiers = {result["expected_tier"] for result in report["results"]}
        self.assertTrue({"urgent", "high", "medium", "low"}.issubset(tiers))
        for result in report["results"]:
            self.assertTrue(result["expected_decision"]["why"])
            self.assertEqual(
                result["expected_decision"]["required_reason_labels"],
                result["expected_decision"]["matched_reason_labels"],
            )

    def test_expected_decision_reason_labels_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            benchmark = Path(tmp) / "benchmark.json"
            benchmark.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "require_expected_decisions": True,
                        "cases": [
                            {
                                "id": "missing-label",
                                "component": {"name": "demo", "scope": "runtime"},
                                "vulnerability": {"id": "GHSA-demo", "package_name": "demo", "cvss": 7.5},
                                "source": {"reachability": "attacker_controlled", "confidence": "high"},
                                "context": {"exposure": "public", "environment": "prod", "privilege": "none", "confidence": "medium"},
                                "expected_tier": "high",
                                "expected_decision": {
                                    "why": "High due to public request-controlled source evidence.",
                                    "required_reason_labels": ["network:private"],
                                },
                            },
                            {
                                "id": "missing-rationale",
                                "component": {"name": "demo", "scope": "runtime"},
                                "vulnerability": {"id": "GHSA-demo", "package_name": "demo", "cvss": 7.5},
                                "source": {"reachability": "attacker_controlled", "confidence": "high"},
                                "context": {"exposure": "public", "environment": "prod", "privilege": "none", "confidence": "medium"},
                                "expected_tier": "high",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = run_scoring_benchmark(benchmark)

        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["failed_count"], 2)
        problems = {result["id"]: result["problems"] for result in report["results"]}
        self.assertIn("missing expected decision reason labels: network:private", problems["missing-label"])
        self.assertIn("missing expected_decision rationale", problems["missing-rationale"])


if __name__ == "__main__":
    unittest.main()
