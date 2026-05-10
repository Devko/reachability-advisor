from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.compare import compare_findings, delta_fails
from reachability_advisor.outputs import explain_finding, load_findings_json
from reachability_advisor.policy import ExceptionRule, RuntimePolicy, apply_exceptions
from reachability_advisor.scoring import ScorePolicy
from reachability_advisor.models import Tier

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_version_command(self) -> None:
        self.assertEqual(main(["version"]), 0)

    def test_validate_command_success(self) -> None:
        code = main(["validate", "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"), "--vulns", str(ROOT / "samples/vulnerabilities.json")])
        self.assertEqual(code, 0)

    def test_validate_command_failure(self) -> None:
        code = main(["validate", "--sbom", "missing.json"])
        self.assertEqual(code, 2)

    def test_scan_writes_all_developer_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            code = main([
                "scan",
                "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                "--sbom", str(ROOT / "samples/sboms/notifier.cdx.json"),
                "--vulns", str(ROOT / "samples/vulnerabilities.json"),
                "--context", str(ROOT / "samples/context.json"),
                "--source-root", f"payments-api={ROOT / 'samples/source/payments-api'}",
                "--source-root", f"notifier={ROOT / 'samples/source/notifier'}",
                "--out", str(out / "findings.json"),
                "--sarif-out", str(out / "findings.sarif"),
                "--diagnostics-out", str(out / "diagnostics.json"),
                "--markdown-out", str(out / "summary.md"),
                "--annotations-out", str(out / "annotations.txt"),
                "--no-table",
            ])
            self.assertEqual(code, 0)
            for filename in ("findings.json", "findings.sarif", "diagnostics.json", "summary.md", "annotations.txt"):
                self.assertTrue((out / filename).exists(), filename)
            findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(findings["findings"]), 4)
            sarif = json.loads((out / "findings.sarif").read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            diagnostics = json.loads((out / "diagnostics.json").read_text(encoding="utf-8"))
            self.assertTrue(diagnostics["diagnostics"])
            self.assertIn("Reachability Advisor PR Summary", (out / "summary.md").read_text(encoding="utf-8"))
            self.assertIn("::error", (out / "annotations.txt").read_text(encoding="utf-8"))

    def test_scan_fail_on_high(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code = main([
                "scan",
                "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                "--vulns", str(ROOT / "samples/vulnerabilities.json"),
                "--context", str(ROOT / "samples/context.json"),
                "--source-root", f"payments-api={ROOT / 'samples/source/payments-api'}",
                "--out", str(Path(tmp) / "findings.json"),
                "--fail-on-tier", "high",
                "--no-table",
            ])
            self.assertEqual(code, 10)

    def test_init_policy_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            code = main(["init-policy", "--out", str(path)])
            self.assertEqual(code, 0)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["fail_on_tier"], "high")

    def test_explain_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings_path = Path(tmp) / "findings.json"
            explain_path = Path(tmp) / "explain.md"
            main([
                "scan",
                "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                "--vulns", str(ROOT / "samples/vulnerabilities.json"),
                "--context", str(ROOT / "samples/context.json"),
                "--source-root", f"payments-api={ROOT / 'samples/source/payments-api'}",
                "--out", str(findings_path),
                "--no-table",
            ])
            code = main(["explain", "--findings", str(findings_path), "--artifact", "payments-api", "--component", "log4j-core", "--vulnerability", "CVE-2021-44228", "--out", str(explain_path)])
            self.assertEqual(code, 0)
            self.assertIn("Explanation", explain_path.read_text(encoding="utf-8"))

    def test_compare_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base.json"
            head = Path(tmp) / "head.json"
            delta = Path(tmp) / "delta.json"
            base.write_text(json.dumps({"findings": []}), encoding="utf-8")
            main([
                "scan",
                "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                "--vulns", str(ROOT / "samples/vulnerabilities.json"),
                "--context", str(ROOT / "samples/context.json"),
                "--source-root", f"payments-api={ROOT / 'samples/source/payments-api'}",
                "--out", str(head),
                "--no-table",
            ])
            code = main(["compare", "--base-findings", str(base), "--head-findings", str(head), "--out", str(delta), "--fail-on-new-tier", "high"])
            self.assertEqual(code, 10)
            data = json.loads(delta.read_text(encoding="utf-8"))
            self.assertGreater(data["summary"]["new"], 0)


class OutputAndCompareTests(unittest.TestCase):
    def test_explain_finding_not_found(self) -> None:
        with self.assertRaises(ValueError):
            explain_finding({"findings": []}, key="missing")

    def test_load_findings_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.json"
            path.write_text(json.dumps({"findings": []}), encoding="utf-8")
            self.assertEqual(load_findings_json(path)["findings"], [])

    def test_compare_findings_new_resolved_improved_regressed(self) -> None:
        base = {"findings": [
            {"key": "same", "score": 50, "tier": "medium", "component": {"name": "a"}, "artifact": {"name": "app"}, "vulnerability": {"id": "CVE-A"}},
            {"key": "resolved", "score": 80, "tier": "high", "component": {"name": "b"}, "artifact": {"name": "app"}, "vulnerability": {"id": "CVE-B"}},
            {"key": "improved", "score": 80, "tier": "high", "component": {"name": "c"}, "artifact": {"name": "app"}, "vulnerability": {"id": "CVE-C"}},
        ]}
        head = {"findings": [
            {"key": "same", "score": 50, "tier": "medium", "component": {"name": "a"}, "artifact": {"name": "app"}, "vulnerability": {"id": "CVE-A"}},
            {"key": "new", "score": 90, "tier": "urgent", "component": {"name": "d"}, "artifact": {"name": "app"}, "vulnerability": {"id": "CVE-D"}},
            {"key": "improved", "score": 60, "tier": "medium", "component": {"name": "c"}, "artifact": {"name": "app"}, "vulnerability": {"id": "CVE-C"}},
            {"key": "regressed", "score": 65, "tier": "high", "component": {"name": "e"}, "artifact": {"name": "app"}, "vulnerability": {"id": "CVE-E"}},
        ]}
        delta = compare_findings(base, head)
        self.assertEqual(delta["summary"]["new"], 2)
        self.assertEqual(delta["summary"]["resolved"], 1)
        self.assertEqual(delta["summary"]["improved"], 1)
        self.assertTrue(delta_fails(delta, "high"))


class PolicyTests(unittest.TestCase):
    def test_apply_exception_marks_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "findings.json"
            main([
                "scan",
                "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                "--vulns", str(ROOT / "samples/vulnerabilities.json"),
                "--context", str(ROOT / "samples/context.json"),
                "--source-root", f"payments-api={ROOT / 'samples/source/payments-api'}",
                "--out", str(out),
                "--no-table",
            ])
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["findings"][0]["policy_status"], "active")

    def test_exception_rule_applies_and_expires(self) -> None:
        rule = ExceptionRule(vulnerability="CVE-X", artifact="app", component="lib", expires=None, reason="test")
        self.assertEqual(rule.reason, "test")

    def test_runtime_policy_defaults(self) -> None:
        policy = RuntimePolicy(score_policy=ScorePolicy())
        self.assertEqual(policy.fail_on_tier, Tier.HIGH)
        self.assertEqual(policy.exceptions, [])


if __name__ == "__main__":
    unittest.main()
