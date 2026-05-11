from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    Finding,
    Reachability,
    SourceEvidence,
    Tier,
    VulnerabilityRecord,
)
from reachability_advisor.sbom import SbomError, load_sbom
from reachability_advisor.source_external import (
    ExternalSourceEvidenceError,
    load_external_source_evidence,
)
from reachability_advisor.visual import render_html_report
from reachability_advisor.vulnerability import VulnerabilityError, load_vulnerabilities


class InputHardeningTests(unittest.TestCase):
    def test_sbom_loader_rejects_invalid_json_roots_and_ignores_malformed_component_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root_list = root / "root-list.json"
            root_list.write_text("[]", encoding="utf-8")
            with self.assertRaises(SbomError):
                load_sbom(root_list)

            malformed_components = root / "malformed-components.json"
            malformed_components.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {"component": {"name": "app"}},
                        "components": ["bad", {"version": "1.0.0"}, {"name": "safe", "properties": ["bad", {"name": "scope", "value": "runtime"}]}],
                    }
                ),
                encoding="utf-8",
            )
            sbom = load_sbom(malformed_components)

        self.assertEqual(sbom.artifact.name, "app")
        self.assertEqual([component.name for component in sbom.components], ["safe"])

    def test_vulnerability_loader_uses_controlled_errors_for_malformed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root_list = root / "root-list.json"
            root_list.write_text("[]", encoding="utf-8")
            with self.assertRaises(VulnerabilityError):
                load_vulnerabilities(root_list)

            malformed_grype = root / "grype.json"
            malformed_grype.write_text(json.dumps({"matches": ["bad", {"artifact": {}, "vulnerability": {}}]}), encoding="utf-8")
            self.assertEqual(load_vulnerabilities(malformed_grype), [])

    def test_external_source_evidence_reports_jsonl_line_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.jsonl"
            path.write_text('{"finding":{"osv":"GO-2024-0001"}}\n{"finding":\n', encoding="utf-8")
            with self.assertRaisesRegex(ExternalSourceEvidenceError, "line 2"):
                load_external_source_evidence([path])

    def test_visual_html_escapes_script_breakout_payloads(self) -> None:
        payload = '</script><img src=x onerror="alert(1)">'
        finding = Finding(
            key="malicious|component|CVE-1",
            artifact=Artifact(name="malicious-app"),
            component=Component(name="component", version="1.0.0"),
            vulnerability=VulnerabilityRecord(
                id="CVE-2099-0001",
                package_name="component",
                severity="high",
                summary=payload,
                references=[payload],
            ),
            source=SourceEvidence(reachability=Reachability.IMPORTED, confidence=Confidence.MEDIUM, reason=payload),
            context=ContextEvidence(exposure="public", privilege="limited", criticality="medium", evidence=[payload]),
            score=61.0,
            tier=Tier.HIGH,
            confidence=Confidence.MEDIUM,
            rationale=[payload],
        )

        html = render_html_report([finding])

        self.assertNotIn(payload, html)
        self.assertIn("\\u003c/script\\u003e", html)


if __name__ == "__main__":
    unittest.main()
