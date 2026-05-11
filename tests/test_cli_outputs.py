from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.compare import compare_findings, delta_fails
from reachability_advisor.models import Tier
from reachability_advisor.outputs import explain_finding, load_findings_json
from reachability_advisor.policy import ExceptionRule, RuntimePolicy
from reachability_advisor.scoring import ScorePolicy

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_version_command(self) -> None:
        self.assertEqual(main(["version"]), 0)

    def test_validate_command_success(self) -> None:
        code = main([
            "validate",
            "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
            "--vulns", str(ROOT / "samples/vulnerabilities.json"),
            "--policy", str(ROOT / "configs/policy.example.json"),
        ])
        self.assertEqual(code, 0)

    def test_validate_command_failure(self) -> None:
        code = main(["validate", "--sbom", "missing.json"])
        self.assertEqual(code, 2)

    def test_validate_command_checks_policy_and_reachability_rule_paths(self) -> None:
        code = main([
            "validate",
            "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
            "--policy", "missing-policy.json",
            "--reachability-rules", "missing-rules.json",
        ])
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
                "--html-out", str(out / "graph.html"),
                "--evidence-graph-out", str(out / "evidence-graph.json"),
                "--annotations-out", str(out / "annotations.txt"),
                "--no-table",
            ])
            self.assertEqual(code, 0)
            for filename in ("findings.json", "findings.sarif", "diagnostics.json", "summary.md", "graph.html", "evidence-graph.json", "annotations.txt"):
                self.assertTrue((out / filename).exists(), filename)
            findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(findings["findings"]), 4)
            self.assertIn("evidence_graph", findings)
            self.assertTrue(findings["findings"][0]["scoring"]["dimensions"])
            evidence_graph = json.loads((out / "evidence-graph.json").read_text(encoding="utf-8"))
            self.assertTrue(evidence_graph["assets"])
            self.assertTrue(evidence_graph["code_edges"])
            sarif = json.loads((out / "findings.sarif").read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            diagnostics = json.loads((out / "diagnostics.json").read_text(encoding="utf-8"))
            self.assertTrue(diagnostics["diagnostics"])
            self.assertIn("Reachability Advisor PR Summary", (out / "summary.md").read_text(encoding="utf-8"))
            html = (out / "graph.html").read_text(encoding="utf-8")
            self.assertIn("Reachability Advisor Visual Report", html)
            self.assertIn('id="graph"', html)
            self.assertIn("report-data", html)
            self.assertIn("asset-card", html)
            self.assertIn("vuln-card", html)
            self.assertIn("entry-card", html)
            self.assertIn("path-card", html)
            self.assertIn("Ingress path", html)
            self.assertIn("Network", html)
            self.assertIn("IAM:", html)
            embedded = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', html, flags=re.DOTALL)
            self.assertIsNotNone(embedded)
            report_data = json.loads(embedded.group(1)) if embedded else {}
            self.assertIn("evidenceGraph", report_data)
            self.assertGreaterEqual(len(report_data["assets"]), 2)
            self.assertGreaterEqual(len(report_data["networkPaths"]), 2)
            self.assertGreaterEqual(len(report_data["vulnerabilities"]), 2)
            self.assertEqual(len(report_data["links"]), len(report_data["vulnerabilities"]))
            self.assertIn("::error", (out / "annotations.txt").read_text(encoding="utf-8"))

    def test_scan_accepts_grype_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            vulns = out / "grype.json"
            vulns.write_text(
                json.dumps(
                    {
                        "matches": [
                            {
                                "vulnerability": {
                                    "id": "GHSA-35jh-r3h4-6jhm",
                                    "severity": "High",
                                    "description": "Prototype pollution in lodash.",
                                    "cvss": [{"metrics": {"baseScore": 7.4}}],
                                    "fix": {"versions": ["4.17.21"]},
                                },
                                "artifact": {
                                    "name": "lodash",
                                    "version": "4.17.20",
                                    "purl": "pkg:npm/lodash@4.17.20",
                                },
                                "relatedVulnerabilities": [{"id": "CVE-2021-23337"}],
                            },
                            {
                                "vulnerability": {
                                    "id": "GHSA-r5fr-rjxr-66jc",
                                    "severity": "Critical",
                                    "description": "Additional lodash advisory.",
                                    "cvss": [{"metrics": {"baseScore": 8.1}}],
                                    "fix": {"versions": ["4.17.21"]},
                                },
                                "artifact": {
                                    "name": "lodash",
                                    "version": "4.17.20",
                                    "purl": "pkg:npm/lodash@4.17.20",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            findings_path = out / "findings.json"
            code = main([
                "scan",
                "--sbom", str(ROOT / "samples/sboms/notifier.cdx.json"),
                "--vulns", str(vulns),
                "--source-root", f"notifier={ROOT / 'samples/source/notifier'}",
                "--out", str(findings_path),
                "--no-table",
            ])
            self.assertEqual(code, 0)
            data = json.loads(findings_path.read_text(encoding="utf-8"))
            self.assertEqual(data["metadata"]["vulnerability_records"], 2)
            self.assertEqual(data["metadata"]["remediation_groups"], 1)
            self.assertEqual(len(data["remediations"]), 1)
            self.assertEqual(data["remediations"][0]["vulnerability_count"], 2)
            self.assertEqual(data["remediations"][0]["suggested_fix"], "npm install lodash@4.17.21")
            self.assertEqual({finding["vulnerability"]["id"] for finding in data["findings"]}, {"GHSA-35jh-r3h4-6jhm", "GHSA-r5fr-rjxr-66jc"})
            self.assertIn("CVE-2021-23337", next(finding for finding in data["findings"] if finding["vulnerability"]["id"] == "GHSA-35jh-r3h4-6jhm")["vulnerability"]["aliases"])

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
            self.assertEqual(data["schema_version"], "1.0")
            self.assertEqual(data["fail_on_tier"], "high")

    def test_explain_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings_path = Path(tmp) / "findings.json"
            explain_path = Path(tmp) / "nested" / "explain.md"
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

    def test_scan_writes_baseline_and_compare_consumes_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            baseline = Path(tmp) / "baseline.json"
            head = Path(tmp) / "head.json"
            delta = Path(tmp) / "delta.json"
            markdown = Path(tmp) / "delta.md"
            scan_code = main([
                "scan",
                "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                "--vulns", str(ROOT / "samples/vulnerabilities.json"),
                "--context", str(ROOT / "samples/context.json"),
                "--source-root", f"payments-api={ROOT / 'samples/source/payments-api'}",
                "--out", str(head),
                "--baseline-out", str(baseline),
                "--no-table",
            ])
            self.assertEqual(scan_code, 0)
            baseline_data = json.loads(baseline.read_text(encoding="utf-8"))
            self.assertEqual(baseline_data["kind"], "reachability-advisor-baseline")
            compare_code = main(["compare", "--baseline", str(baseline), "--head-findings", str(head), "--out", str(delta), "--markdown-out", str(markdown), "--fail-on-new-tier", "high"])
            self.assertEqual(compare_code, 0)
            data = json.loads(delta.read_text(encoding="utf-8"))
            self.assertEqual(data["mode"], "new-or-worsened")
            self.assertEqual(data["summary"]["total"], 0)
            self.assertIn("Worsened findings", markdown.read_text(encoding="utf-8"))


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
