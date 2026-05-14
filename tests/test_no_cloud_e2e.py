from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "samples" / "e2e-no-cloud"


class NoCloudTerraformPlanE2ETests(unittest.TestCase):
    def test_scan_uses_synthetic_terraform_plan_without_cloud_account(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            code = main(
                [
                    "scan",
                    "--sbom",
                    str(FIXTURE / "app.cdx.json"),
                    "--vuln-in",
                    str(FIXTURE / "vulnerabilities.json"),
                    "--source-root",
                    f"no-cloud-app={FIXTURE / 'source'}",
                    "--terraform-plan",
                    str(FIXTURE / "tfplan.json"),
                    "--terraform-coverage-out",
                    str(out / "terraform-coverage.json"),
                    "--source-coverage-out",
                    str(out / "source-coverage.json"),
                    "--mapping-out",
                    str(out / "mapping.json"),
                    "--evidence-graph-out",
                    str(out / "evidence-graph.json"),
                    "--html-out",
                    str(out / "graph.html"),
                    "--out",
                    str(out / "findings.json"),
                    "--no-table",
                ]
            )
            self.assertEqual(code, 0)
            findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            terraform = json.loads((out / "terraform-coverage.json").read_text(encoding="utf-8"))
            source = json.loads((out / "source-coverage.json").read_text(encoding="utf-8"))
            mapping = json.loads((out / "mapping.json").read_text(encoding="utf-8"))
            evidence_graph = json.loads((out / "evidence-graph.json").read_text(encoding="utf-8"))
            html = (out / "graph.html").read_text(encoding="utf-8")

        self.assertEqual(terraform["summary"]["resource_accounting_coverage"], 1.0)
        self.assertEqual(terraform["summary"]["artifact_match_coverage"], 1.0)
        self.assertEqual(terraform["artifact_matches"][0]["match_method"], "exact-reference")
        self.assertEqual(terraform["artifact_matches"][0]["match_proof"]["candidate_strength"], "digest")
        self.assertEqual(mapping["summary"]["artifacts_with_strong_identity"], 1)
        self.assertFalse(mapping["artifacts"][0]["artifact_identity"]["warnings"])
        self.assertEqual(source["summary"]["source_evidence_coverage"], 1.0)
        self.assertEqual(source["summary"]["source_rule_coverage"], 1.0)

        finding = findings["findings"][0]
        self.assertEqual(finding["artifact"]["name"], "no-cloud-app")
        self.assertEqual(finding["source_reachability"]["state"], "attacker_controlled")
        self.assertEqual(finding["context"]["exposure"], "public")
        self.assertIn("network_control", finding["context"]["iam_impacts"])
        self.assertEqual(finding["tier"], "urgent")
        self.assertTrue(any(capability["effective_risk"] == "constrained_critical" for capability in finding["context"]["iam_capabilities"]))
        self.assertTrue(evidence_graph["network_paths"])
        self.assertTrue(evidence_graph["iam_edges"])
        self.assertIsNotNone(re.search(r'<script id="report-data" type="application/json">', html))


if __name__ == "__main__":
    unittest.main()
