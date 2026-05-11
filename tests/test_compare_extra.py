from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reachability_advisor.baseline import (
    baseline_as_findings_json,
    create_baseline,
    load_baseline,
    write_baseline,
)
from reachability_advisor.compare import (
    compare_findings,
    delta_fails,
    pr_delta,
    write_delta_markdown,
)


def finding(key: str, tier: str, score: float) -> dict:
    return {
        "key": key,
        "tier": tier,
        "score": score,
        "artifact": {"name": "app"},
        "component": {"name": "lib"},
        "vulnerability": {"id": "CVE-X"},
    }


class CompareExtraTests(unittest.TestCase):
    def test_compare_categorizes_new_resolved_regressed_improved_unchanged(self) -> None:
        base = {"findings": [finding("resolved", "high", 80), finding("regressed", "medium", 50), finding("improved", "high", 80), finding("same", "low", 10)]}
        head = {"findings": [finding("new", "urgent", 90), finding("regressed", "high", 55), finding("improved", "medium", 60), finding("same", "low", 11)]}
        delta = compare_findings(base, head, score_delta=5)
        self.assertEqual(delta["summary"], {"new": 1, "resolved": 1, "regressed": 1, "improved": 1, "unchanged": 1})
        self.assertTrue(delta_fails(delta, "high"))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "delta.md"
            write_delta_markdown(delta, out)
            text = out.read_text(encoding="utf-8")
            self.assertIn("## New findings", text)
            self.assertIn("## Regressed findings", text)
            self.assertIn("## Resolved findings", text)

    def test_delta_fails_false_for_low_new_at_high_threshold(self) -> None:
        delta = {"new": [finding("n", "low", 20)], "regressed": [{"after": finding("r", "medium", 50)}]}
        self.assertFalse(delta_fails(delta, "high"))

    def test_compare_ignores_items_without_keys(self) -> None:
        delta = compare_findings({"findings": [{"tier": "high"}]}, {"findings": [{"key": "a", "tier": "low", "score": 1}]})
        self.assertEqual(delta["summary"]["new"], 1)
        self.assertEqual(delta["summary"]["resolved"], 0)

    def test_baseline_artifact_is_stable_and_compact(self) -> None:
        data = {
            "metadata": {"sbom_count": 1},
            "findings": [
                {
                    **finding("b", "medium", 42.123),
                    "source_reachability": {"state": "imported", "label": "import observed", "locations": [{"path": "local"}]},
                    "context": {"exposure": "public", "evidence": ["volatile path"], "iam_impacts": ["data_access"]},
                    "rationale": ["volatile rationale"],
                },
                {**finding("a", "high", 80), "source_reachability": {"state": "package_present", "label": "SBOM only"}, "context": {"exposure": "internal"}},
            ],
        }
        baseline = create_baseline(data)
        self.assertEqual(baseline["kind"], "reachability-advisor-baseline")
        self.assertEqual([item["key"] for item in baseline["findings"]], ["a", "b"])
        self.assertEqual(baseline["findings"][1]["score"], 42.12)
        self.assertNotIn("rationale", baseline["findings"][1])
        self.assertNotIn("locations", baseline["findings"][1]["source_reachability"])
        self.assertNotIn("evidence", baseline["findings"][1]["context"])
        self.assertEqual(baseline["metadata"]["source_metadata"], {"sbom_count": 1})

    def test_baseline_and_compare_tolerate_non_numeric_scores(self) -> None:
        baseline = create_baseline({
            "findings": [
                finding("bad", "medium", 1.0) | {"score": "not-a-number"},
                finding("ok", "low", 2.5) | {"score": "3.75"},
            ]
        })

        self.assertEqual(baseline["findings"][0]["score"], 0.0)
        self.assertEqual(baseline["findings"][1]["score"], 3.75)
        delta = compare_findings(
            {"findings": [finding("bad", "medium", 1.0) | {"score": "not-a-number"}]},
            {"findings": [finding("bad", "high", 2.0) | {"score": "also-bad"}]},
        )
        self.assertEqual(delta["summary"]["regressed"], 1)

    def test_baseline_loads_as_compare_input_and_pr_delta_is_actionable_only(self) -> None:
        baseline = create_baseline({"findings": [finding("same", "medium", 50), finding("worse", "medium", 50), finding("resolved", "high", 80)]})
        head = {"findings": [finding("same", "medium", 50), finding("worse", "high", 60), finding("new", "high", 75)]}
        delta = compare_findings(baseline_as_findings_json(baseline), head)
        pr = pr_delta(delta)
        self.assertEqual(pr["summary"], {"new": 1, "worsened": 1, "total": 2})
        self.assertNotIn("resolved", pr)
        self.assertTrue(delta_fails(pr, "high"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            write_baseline(baseline, path)
            self.assertEqual(load_baseline(path)["metadata"]["finding_count"], 3)

    def test_policy_exception_removed_is_worsened(self) -> None:
        base_finding = {**finding("x", "high", 80), "policy_status": "excepted"}
        head_finding = {**finding("x", "high", 80), "policy_status": "active"}
        delta = compare_findings({"findings": [base_finding]}, {"findings": [head_finding]})
        self.assertEqual(delta["summary"]["regressed"], 1)


if __name__ == "__main__":
    unittest.main()
