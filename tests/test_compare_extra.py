from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.compare import compare_findings, delta_fails, write_delta_markdown


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


if __name__ == "__main__":
    unittest.main()
