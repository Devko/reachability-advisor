from __future__ import annotations

import io
import json
import re
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reachability_advisor.cli import main
from reachability_advisor.compare import compare_findings, delta_fails
from reachability_advisor.models import Tier
from reachability_advisor.outputs import explain_finding, load_findings_json
from reachability_advisor.policy import ExceptionRule, RuntimePolicy
from reachability_advisor.scoring import ScorePolicy
from reachability_advisor.security_evidence import load_security_evidence

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_module_entrypoint_delegates_to_cli_main(self) -> None:
        with (
            patch("reachability_advisor.cli.main", return_value=0) as cli_main,
            self.assertRaises(SystemExit) as raised,
        ):
            runpy.run_module("reachability_advisor.__main__", run_name="__main__")

        self.assertEqual(raised.exception.code, 0)
        cli_main.assert_called_once_with()

    def test_version_command(self) -> None:
        self.assertEqual(main(["version"]), 0)

    def test_validate_command_success(self) -> None:
        code = main([
            "validate",
            "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
            "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
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
                "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
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
            self.assertIn("Reachability Advisor Evidence Report", html)
            self.assertIn('id="graph"', html)
            self.assertIn("report-data", html)
            self.assertIn("asset-card", html)
            self.assertIn("vuln-card", html)
            self.assertIn("entry-card", html)
            self.assertIn("path-card", html)
            self.assertIn("Network path", html)
            self.assertIn("Network", html)
            self.assertIn("IAM:", html)
            embedded = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', html, flags=re.DOTALL)
            self.assertIsNotNone(embedded)
            report_data = json.loads(embedded.group(1)) if embedded else {}
            self.assertIn("evidenceGraph", report_data)
            self.assertGreaterEqual(len(report_data["assets"]), 2)
            self.assertGreaterEqual(len(report_data["networkPaths"]), 1)
            self.assertTrue(any(path.get("assetIds") for path in report_data["networkPaths"]))
            self.assertGreaterEqual(len(report_data["vulnerabilities"]), 2)
            self.assertEqual(len(report_data["links"]), len(report_data["vulnerabilities"]))
            self.assertIn("::error", (out / "annotations.txt").read_text(encoding="utf-8"))

    def test_scan_imports_sast_and_dast_security_evidence_with_separate_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            sbom = out / "web-api.cdx.json"
            vulns = out / "vulns.json"
            context = out / "context.json"
            security = out / "security-evidence.json"
            findings_path = out / "findings.json"
            sarif_path = out / "findings.sarif"
            diagnostics_path = out / "diagnostics.json"
            source_coverage_path = out / "source-coverage.json"
            html_path = out / "graph.html"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {"component": {"name": "web-api", "properties": [{"name": "oci:image:ref", "value": "registry.example/web-api:1"}]}},
                        "components": [{"name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"}],
                    }
                ),
                encoding="utf-8",
            )
            vulns.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
            context.write_text(json.dumps({"artifacts": {"web-api": {"environment": "prod", "criticality": "high", "privilege": "limited"}}}), encoding="utf-8")
            security.write_text(
                json.dumps(
                    {
                        "security_evidence": [
                            {
                                "scanner_type": "sast",
                                "tool": "semgrep",
                                "artifact": "web-api",
                                "rule_id": "js.express.xss",
                                "weakness": "cross-site scripting",
                                "cwe": "CWE-79",
                                "severity": "high",
                                "confidence": "high",
                                "source": {"path": "src/routes/search.js", "line": 12, "column": 5, "snippet": "res.send(req.query.q)"},
                                "sink": {"function": "res.send"},
                                "evidence": {"dataflow": "req.query.q reaches res.send"},
                                "remediation": "Encode untrusted output before writing HTML responses.",
                            },
                            {
                                "scanner_type": "dast",
                                "tool": "zap",
                                "artifact": "web-api",
                                "rule_id": "dast.xss.reflected",
                                "weakness": "reflected xss",
                                "cwe": "79",
                                "severity": "medium",
                                "confidence": "high",
                                "method": "GET",
                                "url": "https://web-api.example/search?q=%3Cscript%3E",
                                "message": "Reflected payload was observed in the response body.",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            code = main([
                "scan",
                "--sbom", str(sbom),
                "--vuln-in", str(vulns),
                "--context", str(context),
                "--security-evidence-in", str(security),
                "--out", str(findings_path),
                "--sarif-out", str(sarif_path),
                "--diagnostics-out", str(diagnostics_path),
                "--source-coverage-out", str(source_coverage_path),
                "--html-out", str(html_path),
                "--no-table",
            ])

            self.assertEqual(code, 0)
            data = json.loads(findings_path.read_text(encoding="utf-8"))
            static_findings = [finding for finding in data["findings"] if finding["finding_type"] == "static_code_weakness"]
            runtime_findings = [finding for finding in data["findings"] if finding["finding_type"] == "dynamic_runtime_observation"]
            code_findings = [*static_findings, *runtime_findings]
            self.assertEqual(len(static_findings), 1)
            self.assertEqual(len(runtime_findings), 1)
            self.assertEqual(data["metadata"]["security_evidence_records"], 2)
            self.assertEqual(data["metadata"]["security_evidence_mapped"], 2)
            self.assertEqual({finding["weakness"]["scanner_type"] for finding in code_findings}, {"sast", "dast"})
            self.assertTrue(any(finding["context"]["exposure"] == "public" for finding in code_findings if finding["weakness"]["scanner_type"] == "dast"))
            self.assertEqual(runtime_findings[0]["runtime_evidence"]["state"], "vulnerability_observed")
            self.assertEqual(runtime_findings[0]["source_reachability"]["state"], "package_present")
            self.assertIn("source mapping unavailable", runtime_findings[0]["unknowns"])
            self.assertTrue(any(edge["kind"] == "scanner_reports_security_finding" for edge in data["evidence_graph"]["effective_exposure_graph"]["edges"]))
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
            self.assertTrue(any(result["properties"]["finding_type"] == "static_code_weakness" for result in sarif["runs"][0]["results"]))
            self.assertTrue(any(result["properties"]["finding_type"] == "dynamic_runtime_observation" for result in sarif["runs"][0]["results"]))
            diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
            self.assertEqual({diagnostic["finding_type"] for diagnostic in diagnostics["diagnostics"]}, {"static_code_weakness"})
            source_coverage = json.loads(source_coverage_path.read_text(encoding="utf-8"))
            self.assertEqual(source_coverage["security_evidence"]["mapped"], 2)
            self.assertEqual(source_coverage["security_evidence"]["summary"]["critical_profile_coverage"], 1.0)
            self.assertIn("sast-web-injection", source_coverage["security_evidence"]["profile_records"][0]["profiles"])
            html = html_path.read_text(encoding="utf-8")
            self.assertIn("runtime", html)

    def test_scan_security_profile_gate_rejects_uncovered_critical_weakness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            sbom = out / "web-api.cdx.json"
            vulns = out / "vulns.json"
            security = out / "security-evidence.json"
            coverage = out / "source-coverage.json"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {"component": {"name": "web-api"}},
                        "components": [{"name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"}],
                    }
                ),
                encoding="utf-8",
            )
            vulns.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
            security.write_text(
                json.dumps(
                    {
                        "security_evidence": [
                            {
                                "scanner_type": "sast",
                                "tool": "custom-sast",
                                "artifact": "web-api",
                                "rule_id": "custom.critical.unknown",
                                "weakness": "critical custom weakness",
                                "severity": "critical",
                                "confidence": "high",
                                "source": {"path": "src/app.js", "line": 1},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            code = main([
                "scan",
                "--sbom", str(sbom),
                "--vuln-in", str(vulns),
                "--security-evidence-in", str(security),
                "--source-coverage-out", str(coverage),
                "--min-critical-security-profile-coverage", "1.0",
                "--no-table",
            ])

            self.assertEqual(code, 10)
            report = json.loads(coverage.read_text(encoding="utf-8"))
            self.assertEqual(report["security_evidence"]["summary"]["critical_profile_coverage"], 0.0)
            self.assertEqual(report["security_evidence"]["summary"]["critical_records_missing_profile"], 1)

    def test_semgrep_json_can_be_loaded_as_security_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "semgrep.json"
            path.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "javascript.lang.security.audit.xss",
                                "path": "src/app.js",
                                "start": {"line": 9, "col": 3},
                                "extra": {
                                    "message": "Unsanitized output",
                                    "severity": "ERROR",
                                    "metadata": {"artifact": "web-api", "cwe": ["CWE-79"], "confidence": "high", "category": "xss"},
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            records = load_security_evidence([path])

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].scanner_type, "sast")
            self.assertEqual(records[0].tool, "semgrep")
            self.assertEqual(records[0].artifact, "web-api")
            self.assertEqual(records[0].cwe, "CWE-79")

    def test_zap_and_nuclei_are_loaded_as_runtime_evidence(self) -> None:
        zap = ROOT / "samples/demo/dast-zap.json"
        nuclei = ROOT / "samples/demo/dast-nuclei.jsonl"

        records = load_security_evidence([zap, nuclei], default_scanner_type="dast")

        self.assertGreaterEqual(len(records), 3)
        self.assertEqual({record.scanner_type for record in records}, {"dast"})
        self.assertTrue(any(record.tool == "zap" and record.cwe == "CWE-79" for record in records))
        self.assertTrue(any(record.tool == "nuclei" and record.cwe == "CWE-693" for record in records))

    def test_jsonl_without_nuclei_shape_loads_as_normalized_security_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "security-evidence.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "scanner_type": "dast",
                        "tool": "custom-dast",
                        "rule_id": "xss-reflected",
                        "weakness": "reflected xss",
                        "url": "https://shop.example.test/search?q=x",
                        "cwe": "CWE-79",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            records = load_security_evidence([path], default_scanner_type="dast")

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].tool, "custom-dast")
            self.assertEqual(records[0].scanner_type, "dast")
            self.assertEqual(records[0].rule_id, "xss-reflected")
            self.assertEqual(records[0].cwe, "CWE-79")

    def test_scan_aliases_correlation_and_runtime_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            findings_path = out / "findings.json"
            markdown_path = out / "summary.md"
            diagnostics_path = out / "diagnostics.json"
            sarif_path = out / "findings.sarif"
            html_path = out / "graph.html"

            code = main([
                "scan",
                "--sbom", str(ROOT / "samples/demo/sbom.cdx.json"),
                "--vuln-in", str(ROOT / "samples/demo/vulnerabilities.json"),
                "--sast-in", str(ROOT / "samples/demo/sast-semgrep.json"),
                "--dast-in", str(ROOT / "samples/demo/dast-zap.json"),
                "--kubernetes-manifest", str(ROOT / "samples/demo/kubernetes.yaml"),
                "--source-root", f"demo-api={ROOT / 'samples/demo/source'}",
                "--out", str(findings_path),
                "--markdown-out", str(markdown_path),
                "--diagnostics-out", str(diagnostics_path),
                "--sarif-out", str(sarif_path),
                "--html-out", str(html_path),
                "--no-table",
            ])

            self.assertEqual(code, 0)
            data = json.loads(findings_path.read_text(encoding="utf-8"))
            runtime = [finding for finding in data["findings"] if finding["finding_type"] == "dynamic_runtime_observation"]
            static = [finding for finding in data["findings"] if finding["finding_type"] == "static_code_weakness"]
            self.assertTrue(runtime)
            self.assertTrue(static)
            self.assertTrue(any(finding["artifact"]["name"] == "demo-api" for finding in runtime))
            self.assertTrue(any(item["correlation_type"] == "sast_dast_route_match" for finding in runtime + static for item in finding["correlated_evidence"]))
            self.assertTrue(any("source mapping unavailable" in finding["unknowns"] for finding in runtime))
            diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
            self.assertTrue(diagnostics["diagnostics"])
            self.assertTrue(all(not diagnostic["uri"].startswith("security-evidence://") for diagnostic in diagnostics["diagnostics"]))
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn("## Runtime scanner findings", markdown)
            self.assertIn("## Correlated findings", markdown)
            html = html_path.read_text(encoding="utf-8")
            self.assertIn("dynamic_runtime_observation", html)

    def test_dast_unmapped_remains_visible_and_does_not_invent_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            findings_path = out / "findings.json"
            diagnostics_path = out / "diagnostics.json"
            code = main([
                "scan",
                "--sbom", str(ROOT / "samples/demo/sbom.cdx.json"),
                "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                "--vuln-in", str(ROOT / "samples/demo/vulnerabilities.json"),
                "--dast-in", str(ROOT / "samples/demo/dast-zap.json"),
                "--out", str(findings_path),
                "--diagnostics-out", str(diagnostics_path),
                "--no-table",
            ])

            self.assertEqual(code, 0)
            data = json.loads(findings_path.read_text(encoding="utf-8"))
            unmapped = [finding for finding in data["findings"] if finding["artifact"]["name"].startswith("unmapped:")]
            self.assertTrue(unmapped)
            self.assertTrue(all(finding["source_reachability"]["state"] == "package_present" for finding in unmapped))
            diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
            self.assertEqual(diagnostics["diagnostics"], [])

    def test_demo_command_writes_multi_scanner_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "demo"
            code = main(["demo", "--output-dir", str(out)])

            self.assertEqual(code, 0)
            for name in ("findings.json", "summary.md", "reachability.sarif", "diagnostics.json", "reachability-graph.html", "mapping.json", "source-coverage.json", "kubernetes-coverage.json"):
                self.assertTrue((out / name).exists(), name)
            data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            self.assertTrue(any(finding["finding_type"] == "dynamic_runtime_observation" for finding in data["findings"]))
            self.assertTrue(any(finding["correlated_evidence"] for finding in data["findings"]))

    def test_semgrep_oss_sarif_sample_imports_as_static_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            sbom = out / "web-api.cdx.json"
            vulns = out / "vulns.json"
            findings_path = out / "findings.json"
            semgrep_sarif = ROOT / "samples/security-evidence/semgrep-ce-xss.sarif"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {"component": {"name": "web-api", "properties": [{"name": "oci:image:ref", "value": "registry.example/web-api:1"}]}},
                        "components": [{"name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"}],
                    }
                ),
                encoding="utf-8",
            )
            vulns.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")

            records = load_security_evidence([semgrep_sarif])
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].tool, "Semgrep OSS")
            self.assertEqual(records[0].cwe, "CWE-79")
            self.assertEqual(records[0].weakness, "cross_site_scripting_xss")

            code = main([
                "scan",
                "--sbom", str(sbom),
                "--vuln-in", str(vulns),
                "--security-evidence-in", str(semgrep_sarif),
                "--out", str(findings_path),
                "--no-table",
            ])

            self.assertEqual(code, 0)
            data = json.loads(findings_path.read_text(encoding="utf-8"))
            self.assertEqual(len(data["findings"]), 1)
            finding = data["findings"][0]
            self.assertEqual(finding["finding_type"], "static_code_weakness")
            self.assertEqual(finding["weakness"]["tool"], "Semgrep OSS")
            self.assertEqual(finding["weakness"]["cwe"], "CWE-79")
            self.assertEqual(finding["source_reachability"]["state"], "attacker_controlled")

    def test_real_world_nodejs_goof_sarif_imports_as_static_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            sbom = out / "nodejs-goof.cdx.json"
            vulns = out / "vulns.json"
            findings_path = out / "findings.json"
            sarif = ROOT / "samples/security-evidence/semgrep-nodejs-goof-command-injection.sarif"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {"component": {"name": "nodejs-goof", "properties": [{"name": "oci:image:ref", "value": "ghcr.io/snyk-labs/nodejs-goof:sample"}]}},
                        "components": [{"name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"}],
                    }
                ),
                encoding="utf-8",
            )
            vulns.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")

            code = main([
                "scan",
                "--sbom", str(sbom),
                "--vuln-in", str(vulns),
                "--security-evidence-in", str(sarif),
                "--out", str(findings_path),
                "--no-table",
            ])

            self.assertEqual(code, 0)
            data = json.loads(findings_path.read_text(encoding="utf-8"))
            self.assertEqual(len(data["findings"]), 1)
            finding = data["findings"][0]
            self.assertEqual(finding["artifact"]["name"], "nodejs-goof")
            self.assertEqual(finding["finding_type"], "static_code_weakness")
            self.assertEqual(finding["weakness"]["weakness"], "command_injection")
            self.assertEqual(finding["weakness"]["cwe"], "CWE-78")
            self.assertEqual(finding["source_reachability"]["state"], "attacker_controlled")
            self.assertEqual(finding["source_reachability"]["locations"][0]["path"].replace("\\", "/"), "routes/index.js")

    def test_scan_quality_gate_fails_on_low_artifact_mapping_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            mapping = out / "mapping.json"
            code = main([
                "scan",
                "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
                "--mapping-out", str(mapping),
                "--min-artifact-match-coverage", "1.0",
                "--no-table",
            ])

            self.assertEqual(code, 10)
            report = json.loads(mapping.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["artifact_match_coverage"], 0.0)
            self.assertGreater(report["summary"]["mapping_warnings_count"], 0)

    def test_scan_quality_gate_rejects_non_finite_threshold(self) -> None:
        code = main([
            "scan",
            "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
            "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
            "--min-artifact-match-coverage", "nan",
            "--no-table",
        ])

        self.assertEqual(code, 10)

    def test_scan_quality_gate_fails_on_unusable_external_source_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            sbom = out / "bom.json"
            vulns = out / "vulns.json"
            evidence = out / "source-evidence.json"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {"component": {"name": "app", "properties": [{"name": "oci:image:ref", "value": "repo/app:1"}]}},
                        "components": [{"name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0"}],
                    }
                ),
                encoding="utf-8",
            )
            vulns.write_text(json.dumps({"vulnerabilities": [{"id": "GHSA-leftpad", "package": {"name": "left-pad"}}]}), encoding="utf-8")
            evidence.write_text(json.dumps({"evidence": [{"artifact": "app", "state": "attacker_controlled", "confidence": "high"}]}), encoding="utf-8")

            code = main([
                "scan",
                "--sbom", str(sbom),
                "--vuln-in", str(vulns),
                "--source-evidence-in", str(evidence),
                "--min-external-evidence-usable-ratio", "1.0",
                "--no-table",
            ])

            self.assertEqual(code, 10)

    def test_scan_production_profile_requires_external_and_rendered_deployment_evidence(self) -> None:
        code = main([
            "scan",
            "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
            "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
            "--analysis-profile", "production",
            "--no-table",
        ])

        self.assertEqual(code, 10)

    def test_scan_production_profile_accepts_external_source_and_terraform_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            source = out / "src"
            source.mkdir()
            sbom = out / "bom.json"
            vulns = out / "vulns.json"
            evidence = out / "source-evidence.json"
            plan = out / "tfplan.json"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {
                            "component": {
                                "name": "app",
                                "properties": [{"name": "oci:image:ref", "value": "repo/app:1"}],
                            }
                        },
                        "components": [{"name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0"}],
                    }
                ),
                encoding="utf-8",
            )
            vulns.write_text(json.dumps({"vulnerabilities": [{"id": "GHSA-leftpad", "package": {"name": "left-pad"}}]}), encoding="utf-8")
            evidence.write_text(
                json.dumps(
                    {
                        "evidence": [
                            {
                                "artifact": "app",
                                "component": "left-pad",
                                "vulnerability": "GHSA-leftpad",
                                "state": "function_reachable",
                                "confidence": "high",
                                "tool": "semgrep",
                                "locations": [{"path": str(source / "index.js"), "line": 1}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (source / "index.js").write_text("require('left-pad');\n", encoding="utf-8")
            plan.write_text(
                json.dumps(
                    {
                        "planned_values": {
                            "root_module": {
                                "resources": [
                                    {
                                        "address": "aws_lambda_function.app",
                                        "type": "aws_lambda_function",
                                        "name": "app",
                                        "values": {"function_name": "app", "image_uri": "repo/app:1"},
                                    }
                                ]
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            code = main([
                "scan",
                "--sbom", str(sbom),
                "--vuln-in", str(vulns),
                "--source-root", f"app={source}",
                "--source-evidence-in", str(evidence),
                "--terraform-plan", str(plan),
                "--analysis-profile", "production",
                "--source-coverage-out", str(out / "source-coverage.json"),
                "--no-table",
            ])

            self.assertEqual(code, 0)
            coverage = json.loads((out / "source-coverage.json").read_text(encoding="utf-8"))
            self.assertEqual(coverage["production_readiness"]["status"], "ready")

    def test_production_profile_rejects_external_evidence_that_misses_critical_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            source = out / "src"
            source.mkdir()
            sbom = out / "bom.json"
            vulns = out / "vulns.json"
            evidence = out / "source-evidence.json"
            plan = out / "tfplan.json"
            coverage = out / "source-coverage.json"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {"component": {"name": "app", "properties": [{"name": "oci:image:ref", "value": "repo/app:1"}]}},
                        "components": [{"name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0"}],
                    }
                ),
                encoding="utf-8",
            )
            vulns.write_text(json.dumps({"vulnerabilities": [{"id": "GHSA-requests", "package": {"name": "requests"}, "severity": "critical", "cvss": 9.8}]}), encoding="utf-8")
            evidence.write_text(
                json.dumps(
                    {
                        "evidence": [
                            {
                                "component": "unrelated",
                                "vulnerability": "GHSA-unrelated",
                                "state": "function_reachable",
                                "confidence": "high",
                                "tool": "semgrep",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (source / "api.py").write_text(
                "from fastapi import FastAPI, Request\nimport requests\napp = FastAPI()\n@app.get('/x')\ndef x(request: Request):\n    return requests.get(request.query_params['url']).text\n",
                encoding="utf-8",
            )
            plan.write_text(
                json.dumps(
                    {
                        "planned_values": {
                            "root_module": {
                                "resources": [
                                    {
                                        "address": "aws_lambda_function.app",
                                        "type": "aws_lambda_function",
                                        "name": "app",
                                        "values": {"function_name": "app", "image_uri": "repo/app:1"},
                                    }
                                ]
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            code = main([
                "scan",
                "--sbom", str(sbom),
                "--vuln-in", str(vulns),
                "--source-root", f"app={source}",
                "--source-evidence-in", str(evidence),
                "--terraform-plan", str(plan),
                "--analysis-profile", "production",
                "--source-coverage-out", str(coverage),
                "--no-table",
            ])

            self.assertEqual(code, 10)
            report = json.loads(coverage.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["external_evidence_records"], 1)
            self.assertEqual(report["summary"]["critical_external_evidence_coverage"], 0.0)
            self.assertEqual(report["summary"]["critical_findings_missing_external_evidence"], 1)

    def test_production_profile_rejects_external_evidence_without_required_query_family(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            source = out / "src"
            source.mkdir()
            sbom = out / "bom.json"
            vulns = out / "vulns.json"
            evidence = out / "source-evidence.json"
            plan = out / "tfplan.json"
            coverage = out / "source-coverage.json"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {"component": {"name": "app", "properties": [{"name": "oci:image:ref", "value": "repo/app:1"}]}},
                        "components": [{"name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0"}],
                    }
                ),
                encoding="utf-8",
            )
            vulns.write_text(json.dumps({"vulnerabilities": [{"id": "GHSA-requests", "package": {"name": "requests"}, "severity": "critical", "cvss": 9.8}]}), encoding="utf-8")
            evidence.write_text(
                json.dumps(
                    {
                        "evidence": [
                            {
                                "artifact": "app",
                                "component": "requests",
                                "vulnerability": "GHSA-requests",
                                "state": "function_reachable",
                                "confidence": "high",
                                "tool": "semgrep",
                                "locations": [{"path": str(source / "api.py"), "line": 1}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (source / "api.py").write_text("import requests\nrequests.get('https://example.invalid')\n", encoding="utf-8")
            plan.write_text(
                json.dumps(
                    {
                        "planned_values": {
                            "root_module": {
                                "resources": [
                                    {
                                        "address": "aws_lambda_function.app",
                                        "type": "aws_lambda_function",
                                        "name": "app",
                                        "values": {"function_name": "app", "image_uri": "repo/app:1"},
                                    }
                                ]
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            code = main([
                "scan",
                "--sbom", str(sbom),
                "--vuln-in", str(vulns),
                "--source-root", f"app={source}",
                "--source-evidence-in", str(evidence),
                "--terraform-plan", str(plan),
                "--analysis-profile", "production",
                "--source-coverage-out", str(coverage),
                "--no-table",
            ])

            self.assertEqual(code, 10)
            report = json.loads(coverage.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["critical_external_evidence_coverage"], 1.0)
            self.assertEqual(report["summary"]["critical_query_family_coverage"], 0.0)
            self.assertEqual(report["summary"]["critical_proven_query_family_coverage"], 0.0)
            self.assertEqual(report["summary"]["critical_findings_missing_query_family"], 1)
            self.assertEqual(report["summary"]["critical_findings_missing_proven_query_family"], 1)
            self.assertEqual(report["artifacts"][0]["critical_packages"][0]["missing_query_families"], ["http-client"])

            evidence.write_text(
                json.dumps(
                    {
                        "evidence": [
                            {
                                "artifact": "app",
                                "component": "requests",
                                "vulnerability": "GHSA-requests",
                                "state": "function_reachable",
                                "confidence": "high",
                                "query_family": "http-client",
                                "tool": "semgrep",
                                "locations": [{"path": str(source / "api.py"), "line": 1}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            code = main([
                "scan",
                "--sbom", str(sbom),
                "--vuln-in", str(vulns),
                "--source-root", f"app={source}",
                "--source-evidence-in", str(evidence),
                "--terraform-plan", str(plan),
                "--analysis-profile", "production",
                "--source-coverage-out", str(coverage),
                "--no-table",
            ])

            self.assertEqual(code, 0)
            report = json.loads(coverage.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["critical_query_family_coverage"], 1.0)
            self.assertEqual(report["summary"]["critical_proven_query_family_coverage"], 1.0)
            self.assertEqual(report["artifacts"][0]["critical_packages"][0]["evidence_query_families"], ["http-client"])

    def test_production_profile_rejects_critical_dependency_only_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            source = out / "src"
            source.mkdir()
            sbom = out / "bom.json"
            vulns = out / "vulns.json"
            evidence = out / "source-evidence.json"
            plan = out / "tfplan.json"
            coverage = out / "source-coverage.json"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {"component": {"name": "app", "properties": [{"name": "oci:image:ref", "value": "repo/app:1"}]}},
                        "components": [{"name": "critical-lib", "version": "1.0.0", "purl": "pkg:npm/critical-lib@1.0.0"}],
                    }
                ),
                encoding="utf-8",
            )
            vulns.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "id": "GHSA-critical-lib",
                                "package": {"name": "critical-lib"},
                                "severity": "critical",
                                "cvss": 9.8,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            evidence.write_text(
                json.dumps(
                    {
                        "evidence": [
                            {
                                "artifact": "app",
                                "component": "critical-lib",
                                "vulnerability": "GHSA-critical-lib",
                                "state": "dependency_reachable",
                                "confidence": "medium",
                                "tool": "semgrep",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            plan.write_text(
                json.dumps(
                    {
                        "planned_values": {
                            "root_module": {
                                "resources": [
                                    {
                                        "address": "aws_lambda_function.app",
                                        "type": "aws_lambda_function",
                                        "name": "app",
                                        "values": {"function_name": "app", "image_uri": "repo/app:1"},
                                    }
                                ]
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            code = main([
                "scan",
                "--sbom", str(sbom),
                "--vuln-in", str(vulns),
                "--source-root", f"app={source}",
                "--source-evidence-in", str(evidence),
                "--terraform-plan", str(plan),
                "--analysis-profile", "production",
                "--source-coverage-out", str(coverage),
                "--no-table",
            ])

            self.assertEqual(code, 10)
            report = json.loads(coverage.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["critical_findings_with_dependency_only_source"], 1)

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
                "--vuln-in", str(vulns),
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
                "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
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

    def test_artifact_manifest_source_pack_and_iac_plan_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            manifest = out / "artifact-manifest.json"
            manifest_report = out / "artifact-manifest-report.json"
            pack = out / "pack"
            security_pack = out / "security-pack"
            iac_plan = out / "iac-plan.json"

            init_code = main([
                "artifact-manifest",
                "init",
                "--artifact",
                "api",
                "--image",
                "ghcr.io/acme/api:1",
                "--digest",
                "sha256:" + "a" * 64,
                "--git-sha",
                "abc123",
                "--sbom",
                "api.cdx.json",
                "--signed",
                "--out",
                str(manifest),
            ])
            validate_code = main(["artifact-manifest", "validate", "--manifest", str(manifest), "--out", str(manifest_report), "--fail-on-warning"])
            pack_code = main(["source-evidence-pack", "--output-dir", str(pack), "--language", "go"])
            security_pack_code = main(["security-evidence-pack", "--output-dir", str(security_pack)])
            iac_code = main(["rendered-iac-plan", "--terraform-dir", "infra", "--helm-chart", "charts/app", "--kustomize-dir", "deploy/prod", "--out-json", str(iac_plan)])

            self.assertEqual(init_code, 0)
            self.assertEqual(validate_code, 0)
            self.assertEqual(pack_code, 0)
            self.assertEqual(security_pack_code, 0)
            self.assertEqual(iac_code, 0)
            self.assertTrue((pack / "semgrep-reachability.yml").exists())
            self.assertTrue((pack / "source-evidence-pack.json").exists())
            self.assertTrue((security_pack / "security-evidence-pack.json").exists())
            self.assertTrue((security_pack / "semgrep" / "security.yml").exists())
            self.assertEqual(json.loads(manifest_report.read_text(encoding="utf-8"))["status"], "ready")
            commands = json.loads(iac_plan.read_text(encoding="utf-8"))["commands"]
            self.assertTrue(any(command["tool"] == "terraform" for command in commands))
            self.assertTrue(any(command["tool"] == "helm" for command in commands))

    def test_composite_action_exposes_readiness_gates(self) -> None:
        text = (ROOT / "action.yml").read_text(encoding="utf-8")

        self.assertIn("require-release-ready:", text)
        self.assertIn("fail-on-readiness-warnings:", text)
        self.assertIn("--require-release-ready", text)
        self.assertIn("--fail-on-readiness-warnings", text)

    def test_scan_can_enforce_release_readiness_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            code = main([
                "scan",
                "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
                "--source-root", f"payments-api={ROOT / 'samples/source/payments-api'}",
                "--mapping-out", str(out / "mapping.json"),
                "--source-coverage-out", str(out / "source-coverage.json"),
                "--readiness-out", str(out / "readiness.json"),
                "--require-release-ready",
                "--no-table",
            ])

            self.assertEqual(code, 10)
            readiness = json.loads((out / "readiness.json").read_text(encoding="utf-8"))
            self.assertEqual(readiness["status"], "blocked")
            self.assertTrue(any("Next step:" in blocker.get("next_step", "") or blocker.get("next_step") for blocker in readiness["blockers"]))

    def test_release_readiness_cli_error_names_blocker_and_next_step(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            err = io.StringIO()
            with patch("sys.stderr", err):
                code = main([
                    "scan",
                    "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                    "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
                    "--source-root", f"payments-api={ROOT / 'samples/source/payments-api'}",
                    "--mapping-out", str(out / "mapping.json"),
                    "--source-coverage-out", str(out / "source-coverage.json"),
                    "--readiness-out", str(out / "readiness.json"),
                    "--require-release-ready",
                    "--no-table",
                ])

            self.assertEqual(code, 10)
            text = err.getvalue()
            self.assertIn("release evidence is blocked", text)
            self.assertIn("Next step:", text)
            self.assertIn("no rendered deployment workload", text)

    def test_explain_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings_path = Path(tmp) / "findings.json"
            explain_path = Path(tmp) / "nested" / "explain.md"
            main([
                "scan",
                "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
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
                "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
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
                "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
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
                "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
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
