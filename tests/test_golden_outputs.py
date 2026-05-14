from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.visual_graph import visual_graph_model

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_ARTIFACTS = [
    "payments-api",
    "notifier",
    "orders-api",
    "audit-api",
    "inventory-api",
    "batch-worker",
    "reports-api",
]


def _count_by(items: list[dict[str, object]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key))
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


class GoldenOutputRegressionTests(unittest.TestCase):
    def test_main_sample_output_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            args = ["scan"]
            for artifact in SAMPLE_ARTIFACTS:
                args.extend(["--sbom", str(ROOT / "samples" / "sboms" / f"{artifact}.cdx.json")])
            args.extend([
                "--vuln-in",
                str(ROOT / "samples" / "vulnerabilities.json"),
                "--terraform-plan",
                str(ROOT / "samples" / "tfplan-multicloud.json"),
                "--terraform-coverage-out",
                str(out / "terraform-coverage.json"),
                "--kubernetes-manifest",
                str(ROOT / "samples" / "kubernetes-manifest.yaml"),
                "--kubernetes-coverage-out",
                str(out / "kubernetes-coverage.json"),
                "--source-coverage-out",
                str(out / "source-coverage.json"),
                "--mapping-out",
                str(out / "mapping.json"),
            ])
            for artifact in SAMPLE_ARTIFACTS:
                args.extend(["--source-root", f"{artifact}={ROOT / 'samples' / 'source' / artifact}"])
            args.extend([
                "--out",
                str(out / "findings.json"),
                "--baseline-out",
                str(out / "baseline.json"),
                "--html-out",
                str(out / "graph.html"),
                "--no-table",
            ])

            self.assertEqual(main(args), 0)

            findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            terraform = json.loads((out / "terraform-coverage.json").read_text(encoding="utf-8"))
            kubernetes = json.loads((out / "kubernetes-coverage.json").read_text(encoding="utf-8"))
            source = json.loads((out / "source-coverage.json").read_text(encoding="utf-8"))
            mapping = json.loads((out / "mapping.json").read_text(encoding="utf-8"))
            html = (out / "graph.html").read_text(encoding="utf-8")
            embedded = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', html, flags=re.DOTALL)
            self.assertIsNotNone(embedded)
            visual = json.loads(embedded.group(1)) if embedded else {}
            graph_model = visual_graph_model(visual)

        self.assertEqual(len(findings["findings"]), 16)
        self.assertEqual(len(findings["remediations"]), 16)
        self.assertEqual(_count_by(findings["findings"], "finding_type"), {"cloud_posture_finding": 6, "dependency_vulnerability": 10})
        self.assertEqual(_count_by(findings["findings"], "tier"), {"high": 4, "low": 2, "medium": 9, "urgent": 1})
        self.assertEqual(
            [(item["artifact"]["name"], item["component"]["name"], item["tier"], item["max_score"]) for item in findings["remediations"][:5]],
            [
                ("payments-api", "log4j-core", "urgent", 99.5),
                ("notifier", "aws_lambda_function_url.notifier", "high", 79.0),
                ("orders-api", "requests", "high", 76.5),
                ("audit-api", "jackson-databind", "high", 76.5),
                ("notifier", "lodash", "high", 74.5),
            ],
        )
        self.assertEqual(terraform["summary"]["total_resources"], 26)
        self.assertEqual(terraform["summary"]["artifact_match_coverage"], 1.0)
        self.assertEqual(kubernetes["summary"]["exposure_counts"], {"internal": 1, "public": 1})
        self.assertEqual(source["summary"]["states"], {"attacker_controlled": 5, "function_reachable": 2, "package_present": 3})
        self.assertEqual(mapping["summary"]["artifacts_with_terraform_matches"], 7)
        self.assertEqual({key: len(visual[key]) for key in ("assets", "vulnerabilities", "networkPaths", "links")}, {"assets": 12, "vulnerabilities": 16, "networkPaths": 12, "links": 16})
        self.assertTrue(all("pathType" in item for item in visual["networkPaths"]))
        effective = visual["evidenceGraph"]["effective_exposure_graph"]
        self.assertEqual(len(effective["paths"]), len(findings["findings"]))
        self.assertTrue(all({"evidence_layer", "confidence", "blocker_state"}.issubset(edge) for edge in effective["edges"]))
        self.assertFalse(graph_model["duplicateNodeIds"])
        edge_roles = {edge["role"] for edge in graph_model["edges"]}
        self.assertTrue({"entry-path", "path-asset", "asset-vulnerability"}.issubset(edge_roles))


if __name__ == "__main__":
    unittest.main()
