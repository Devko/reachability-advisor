"""Audit regression tests for the baseline artifact and PR delta comparison."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from reachability_advisor.baseline import (
    BASELINE_KIND,
    BASELINE_SCHEMA_VERSION,
    baseline_as_findings_json,
    create_baseline,
    load_baseline,
)
from reachability_advisor.cli import main
from reachability_advisor.compare import (
    compare_findings,
    delta_fails,
    pr_delta,
    write_delta_markdown,
)


def finding(key: str, tier: str, score: float, component: str = "lib", **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "key": key,
        "tier": tier,
        "score": score,
        "artifact": {"name": "payments-api"},
        "component": {"name": component},
        "vulnerability": {"id": "js.taint"},
    }
    payload.update(extra)
    return payload


class DuplicateFindingKeyTests(unittest.TestCase):
    """`_finding_map` used to be a lossy dict comprehension keyed on `key`.

    Two findings sharing a key collapsed to the last one, which (because findings are emitted
    score-descending) was always the lowest-scoring duplicate. The higher-severity finding
    vanished from the delta and from `delta_fails`, silently bypassing the PR gate.
    """

    def test_duplicate_head_keys_are_all_reported_as_new(self) -> None:
        head = {"findings": [finding("code|payments-api|js.taint|a0b2", "medium", 58.0, "handlerA"), finding("code|payments-api|js.taint|a0b2", "low", 23.0, "handlerB")]}
        delta = compare_findings({"findings": []}, head)
        # Pre-fix this was 1 (only the trailing low finding survived the dict comprehension).
        self.assertEqual(delta["summary"]["new"], 2)
        self.assertEqual([item["tier"] for item in delta["new"]], ["medium", "low"])
        self.assertEqual([item["component"]["name"] for item in delta["new"]], ["handlerA", "handlerB"])
        # Pre-fix the surviving finding was `low`, so a `medium` gate returned False.
        self.assertTrue(delta_fails(delta, "medium"))

    def test_duplicate_base_keys_surplus_becomes_resolved(self) -> None:
        base = {"findings": [finding("dup", "high", 80.0, "handlerA"), finding("dup", "low", 20.0, "handlerB")]}
        head = {"findings": [finding("dup", "high", 80.0, "handlerA")]}
        delta = compare_findings(base, head)
        # Pre-fix: resolved == 0 because both base entries collapsed onto one key.
        self.assertEqual(delta["summary"]["resolved"], 1)
        self.assertEqual(delta["summary"]["unchanged"], 1)
        self.assertEqual(delta["resolved"][0]["component"]["name"], "handlerB")

    def test_duplicate_keys_pair_positionally_and_detect_regression(self) -> None:
        base = {"findings": [finding("dup", "medium", 50.0, "handlerA"), finding("dup", "low", 20.0, "handlerB")]}
        head = {"findings": [finding("dup", "urgent", 90.0, "handlerA"), finding("dup", "low", 20.0, "handlerB")]}
        delta = compare_findings(base, head)
        self.assertEqual(delta["summary"], {"new": 0, "resolved": 0, "regressed": 1, "improved": 0, "unchanged": 1})
        self.assertEqual(delta["regressed"][0]["after"]["tier"], "urgent")
        self.assertTrue(delta_fails(delta, "high"))

    def test_duplicate_key_pairing_is_independent_of_input_order(self) -> None:
        items = [finding("dup", "medium", 58.0, "handlerA"), finding("dup", "low", 23.0, "handlerB")]
        forward = compare_findings({"findings": []}, {"findings": items})
        reverse = compare_findings({"findings": []}, {"findings": list(reversed(items))})
        self.assertEqual(forward["new"], reverse["new"])

    def test_duplicate_keys_with_identical_tier_and_score_are_ordered_deterministically(self) -> None:
        items = [finding("dup", "medium", 50.0, "handlerB"), finding("dup", "medium", 50.0, "handlerA")]
        forward = compare_findings({"findings": []}, {"findings": items})
        reverse = compare_findings({"findings": []}, {"findings": list(reversed(items))})
        self.assertEqual(forward["summary"]["new"], 2)
        self.assertEqual([item["component"]["name"] for item in forward["new"]], [item["component"]["name"] for item in reverse["new"]])

    def test_duplicate_keys_are_surfaced_as_a_diagnostic(self) -> None:
        base = {"findings": [finding("dup", "medium", 50.0)]}
        head = {"findings": [finding("dup", "medium", 50.0), finding("dup", "high", 70.0), finding("unique", "low", 10.0)]}
        delta = compare_findings(base, head)
        self.assertEqual(delta["duplicate_keys"], [{"key": "dup", "base_count": 1, "head_count": 2}])
        self.assertEqual(pr_delta(delta)["duplicate_keys"], delta["duplicate_keys"])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "delta.md"
            write_delta_markdown(delta, out)
            self.assertIn("Ambiguous finding keys: `1`", out.read_text(encoding="utf-8"))

    def test_unique_keys_report_no_duplicate_diagnostic(self) -> None:
        delta = compare_findings({"findings": [finding("a", "high", 80.0)]}, {"findings": [finding("b", "low", 10.0)]})
        self.assertEqual(delta["duplicate_keys"], [])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "delta.md"
            write_delta_markdown(delta, out)
            self.assertNotIn("Ambiguous finding keys", out.read_text(encoding="utf-8"))

    def test_baseline_roundtrip_preserves_duplicate_keyed_findings(self) -> None:
        baseline = create_baseline({"findings": [finding("dup", "high", 80.0, "handlerA"), finding("dup", "low", 20.0, "handlerB")]})
        self.assertEqual(baseline["metadata"]["finding_count"], 2)
        delta = compare_findings(baseline_as_findings_json(baseline), {"findings": []})
        self.assertEqual(delta["summary"]["resolved"], 2)

    def test_cli_gate_fires_on_duplicate_keyed_new_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base.json"
            head = Path(tmp) / "head.json"
            delta = Path(tmp) / "delta.json"
            base.write_text(json.dumps({"findings": []}), encoding="utf-8")
            head.write_text(
                json.dumps({"findings": [finding("code|payments-api|js.taint|a0b2", "medium", 58.0, "handlerA"), finding("code|payments-api|js.taint|a0b2", "low", 23.0, "handlerB")]}),
                encoding="utf-8",
            )
            code = main(["compare", "--base-findings", str(base), "--head-findings", str(head), "--out", str(delta), "--fail-on-new-tier", "medium"])
            # Pre-fix this returned 0: only the `low` duplicate survived, so the gate passed.
            self.assertEqual(code, 10)
            data = json.loads(delta.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["new"], 2)


class LoadBaselineValidationTests(unittest.TestCase):
    """`load_baseline`'s four guards had no test; every guard could be deleted silently."""

    def _load(self, payload: Any) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return load_baseline(path)

    def test_rejects_non_object_root(self) -> None:
        with self.assertRaisesRegex(ValueError, "baseline artifact must be a JSON object"):
            self._load([])

    def test_rejects_wrong_kind(self) -> None:
        with self.assertRaisesRegex(ValueError, "baseline artifact kind must be"):
            self._load({"kind": "something-else"})

    def test_rejects_unsupported_schema_version(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported baseline schema_version"):
            self._load({"kind": BASELINE_KIND, "schema_version": "0.9"})

    def test_rejects_non_list_findings(self) -> None:
        with self.assertRaisesRegex(ValueError, "baseline artifact must contain a findings array"):
            self._load({"kind": BASELINE_KIND, "schema_version": BASELINE_SCHEMA_VERSION, "findings": {}})

    def test_accepts_a_well_formed_baseline(self) -> None:
        data = self._load(create_baseline({"findings": [finding("a", "high", 80.0)]}))
        self.assertEqual(data["kind"], BASELINE_KIND)
        self.assertEqual(len(data["findings"]), 1)

    def test_cli_compare_rejects_a_findings_report_used_as_a_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            not_a_baseline = Path(tmp) / "findings.json"
            head = Path(tmp) / "head.json"
            payload = {"metadata": {}, "findings": [finding("a", "high", 80.0)]}
            not_a_baseline.write_text(json.dumps(payload), encoding="utf-8")
            head.write_text(json.dumps(payload), encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(["compare", "--baseline", str(not_a_baseline), "--head-findings", str(head), "--fail-on-new-tier", "high"])
            self.assertEqual(code, 2)
            self.assertIn(f"error: baseline artifact kind must be {BASELINE_KIND!r}", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
