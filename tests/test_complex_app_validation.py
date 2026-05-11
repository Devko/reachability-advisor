from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_complex_app_validation.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("run_complex_app_validation", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ComplexAppValidationScriptTests(unittest.TestCase):
    def test_merge_grype_reports_stamps_artifact_scope(self) -> None:
        module = _load_script()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            grype = root / "checkout.grype.json"
            grype.write_text(
                json.dumps(
                    {
                        "matches": [
                            {
                                "vulnerability": {"id": "CVE-1", "severity": "High"},
                                "artifact": {"name": "request", "version": "2.88.2", "purl": "pkg:npm/request@2.88.2"},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = root / "merged.json"
            summary = module._merge_grype_reports([{"artifact": "checkout", "status": "passed", "grype": str(grype)}], output)
            merged = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(summary["matches"], 1)
        self.assertEqual(merged["matches"][0]["reachability_advisor"]["artifact"], "checkout")

    def test_expectation_evaluation_reports_failures(self) -> None:
        module = _load_script()
        results = module._evaluate_expectations(
            {"sbom_count": 4, "finding_count": 2, "html_exists": True},
            {"min_sboms": 5, "min_findings": 1},
        )
        statuses = {row["id"]: row["status"] for row in results}
        self.assertEqual(statuses["min_sboms"], "failed")
        self.assertEqual(statuses["min_findings"], "passed")
        self.assertEqual(statuses["html_report"], "passed")

    def test_advisor_summary_separates_finding_and_remediation_tier_counts(self) -> None:
        module = _load_script()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings_path = root / "findings.json"
            coverage_path = root / "terraform-coverage.json"
            mapping_path = root / "mapping.json"
            findings_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {"tier": "medium", "artifact": {"name": "checkout"}},
                            {"tier": "medium", "artifact": {"name": "checkout"}},
                            {"tier": "low", "artifact": {"name": "catalog"}},
                        ],
                        "remediations": [
                            {"tier": "medium", "artifact": {"name": "checkout"}, "component": {"name": "request"}},
                            {"tier": "low", "artifact": {"name": "catalog"}, "component": {"name": "lodash"}},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            coverage_path.write_text(json.dumps({"summary": {}}), encoding="utf-8")
            mapping_path.write_text(json.dumps({"summary": {}, "warnings": []}), encoding="utf-8")

            summary = module._advisor_summary(
                {
                    "findings": str(findings_path),
                    "terraform_coverage": str(coverage_path),
                    "mapping": str(mapping_path),
                }
            )

        self.assertEqual(summary["finding_count"], 3)
        self.assertEqual(summary["tier_counts"], {"low": 1, "medium": 2})
        self.assertEqual(summary["remediation_count"], 2)
        self.assertEqual(summary["remediation_tier_counts"], {"low": 1, "medium": 1})

    def test_kubernetes_manifest_generates_public_and_internal_context(self) -> None:
        module = _load_script()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout = root / "checkout"
            checkout.mkdir()
            (checkout / "manifests.yaml").write_text(
                """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  labels:
    app: frontend
spec:
  selector:
    matchLabels:
      app: frontend
---
apiVersion: v1
kind: Service
metadata:
  name: frontend-external
spec:
  type: LoadBalancer
  selector:
    app: frontend
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: checkoutservice
spec:
  selector:
    matchLabels:
      app: checkoutservice
---
apiVersion: v1
kind: Service
metadata:
  name: checkoutservice
spec:
  type: ClusterIP
  selector:
    app: checkoutservice
""".strip(),
                encoding="utf-8",
            )
            summary = module._generate_kubernetes_context(
                {
                    "kubernetes_manifest": "manifests.yaml",
                    "infer_cluster_lateral_from_public_entry": True,
                    "workloads": [{"artifact": "frontend"}, {"artifact": "checkoutservice"}],
                },
                checkout,
                [{"artifact": "frontend", "status": "passed"}, {"artifact": "checkoutservice", "status": "passed"}],
                root / "out",
            )
            data = json.loads(Path(summary["path"]).read_text(encoding="utf-8"))

        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["exposure_counts"], {"internal": 1, "public": 1})
        self.assertEqual(data["artifacts"]["frontend"]["exposure"], "public")
        self.assertEqual(data["artifacts"]["checkoutservice"]["exposure"], "internal")
        self.assertIn("context network path: public", data["artifacts"]["frontend"]["evidence"][0])
        self.assertIn("frontend-external", data["artifacts"]["checkoutservice"]["evidence"][0])


if __name__ == "__main__":
    unittest.main()
