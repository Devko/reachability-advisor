from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.models import (
    Artifact,
    Confidence,
    ContextEvidence,
    SbomDocument,
    SourceLocation,
)
from reachability_advisor.scoring import ScorePolicy
from reachability_advisor.security_evidence import (
    generate_security_findings,
    load_security_evidence,
)
from reachability_advisor.security_evidence_model import (
    SecurityEvidenceError,
    SecurityEvidenceRecord,
)
from reachability_advisor.security_runtime import (
    context_for_security_record,
    runtime_for_security_record,
    source_for_security_record,
)


class SecurityEvidenceAdapterBoundaryTests(unittest.TestCase):
    def test_invalid_json_and_jsonl_raise_user_facing_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "bad.json"
            jsonl_path = Path(tmp) / "bad.jsonl"
            json_path.write_text("{", encoding="utf-8")
            jsonl_path.write_text("{\n", encoding="utf-8")

            with self.assertRaises(SecurityEvidenceError):
                load_security_evidence([json_path])
            with self.assertRaises(SecurityEvidenceError):
                load_security_evidence([jsonl_path])

    def test_single_plain_json_object_and_list_are_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            object_path = Path(tmp) / "finding.json"
            list_path = Path(tmp) / "findings.json"
            object_path.write_text(json.dumps({"rule_id": "xss", "tool": "scanner", "cwe": "79"}), encoding="utf-8")
            list_path.write_text(json.dumps([{"rule_id": "sqli", "tool": "scanner", "cwe": "89"}]), encoding="utf-8")

            records = load_security_evidence([object_path, list_path])

            self.assertEqual([record.rule_id for record in records], ["xss", "sqli"])
            self.assertEqual([record.cwe for record in records], ["CWE-79", "CWE-89"])

    def test_sarif_without_locations_stays_source_unmapped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scanner.sarif"
            path.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "codeql", "rules": [{"id": "js/xss", "properties": {"cwe": "CWE-79"}}]}},
                                "results": [{"ruleId": "js/xss", "message": {"text": "xss"}, "properties": {"scanner_type": "sast"}}],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            records = load_security_evidence([path])

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].tool, "codeql")
            self.assertIsNone(records[0].source)
            self.assertEqual(records[0].cwe, "CWE-79")


class SecurityRuntimeBoundaryTests(unittest.TestCase):
    def test_runtime_states_track_authentication_context(self) -> None:
        unauth = SecurityEvidenceRecord(scanner_type="dast", tool="zap", rule_id="xss", weakness="xss", authentication_context="unauthenticated")
        auth = SecurityEvidenceRecord(scanner_type="dast", tool="zap", rule_id="xss", weakness="xss", authentication_context="authenticated user")
        endpoint = SecurityEvidenceRecord(scanner_type="dast", tool="zap", rule_id="", weakness="")

        self.assertEqual(runtime_for_security_record(unauth).state.value, "unauthenticated_observed")
        self.assertEqual(runtime_for_security_record(auth).state.value, "authenticated_observed")
        self.assertEqual(runtime_for_security_record(endpoint).state.value, "endpoint_observed")

    def test_static_records_have_no_runtime_evidence_and_dataflow_strengthens_source(self) -> None:
        source = SourceLocation(path=Path("app.js"), line=12)
        record = SecurityEvidenceRecord(scanner_type="sast", tool="semgrep", rule_id="xss", weakness="xss", source=source, dataflow="trace")

        runtime = runtime_for_security_record(record)
        source_evidence = source_for_security_record(record)

        self.assertEqual(runtime.state.value, "not_observed")
        self.assertEqual(source_evidence.reachability.value, "attacker_controlled")
        self.assertEqual(source_evidence.language, "javascript")

    def test_dast_context_adds_dynamic_network_path(self) -> None:
        record = SecurityEvidenceRecord(scanner_type="dast", tool="zap", rule_id="xss", weakness="xss", url="https://shop.example.test/search", confidence=Confidence.HIGH)

        context = context_for_security_record(ContextEvidence(exposure="internal"), record, "shop")

        self.assertEqual(context.exposure, "public")
        self.assertEqual(context.confidence, Confidence.HIGH)
        self.assertEqual(context.network_paths[-1]["entry_kind"], "dast_probe")


class SecurityFindingGenerationBoundaryTests(unittest.TestCase):
    def test_unmapped_static_record_is_reported_without_guessing_artifact(self) -> None:
        sboms = [
            SbomDocument(path=Path("a.cdx.json"), artifact=Artifact(name="a"), components=[]),
            SbomDocument(path=Path("b.cdx.json"), artifact=Artifact(name="b"), components=[]),
        ]
        record = SecurityEvidenceRecord(scanner_type="sast", tool="semgrep", rule_id="xss", weakness="xss", artifact="missing")

        findings, report = generate_security_findings([record], sboms, {}, ScorePolicy())

        self.assertEqual(findings, [])
        self.assertEqual(report["unmapped"], 1)
        self.assertEqual(report["unmapped_records"][0]["mapping_confidence"], "low")

    def test_unmapped_dast_record_remains_visible_as_runtime_artifact(self) -> None:
        record = SecurityEvidenceRecord(scanner_type="dast", tool="zap", rule_id="xss", weakness="xss", url="https://unknown.example.test/search")

        findings, report = generate_security_findings([record], [], {}, ScorePolicy())

        self.assertEqual(len(findings), 1)
        self.assertEqual(report["unmapped"], 1)
        self.assertTrue(findings[0].artifact.name.startswith("unmapped:"))
        self.assertIn("artifact mapping unavailable or weak one-SBOM fallback", findings[0].unknowns)

    def test_remediation_and_source_summary_are_preserved(self) -> None:
        artifact = Artifact(name="api")
        source = SourceLocation(path=Path("app.py"), line=5)
        record = SecurityEvidenceRecord(
            scanner_type="sast",
            tool="semgrep",
            rule_id="py/sqli",
            weakness="sqli",
            artifact="api",
            source=source,
            remediation="parameterize query",
        )

        findings, _ = generate_security_findings([record], [SbomDocument(path=Path("api.cdx.json"), artifact=artifact, components=[])], {}, ScorePolicy())

        self.assertEqual(findings[0].fix_commands, ["parameterize query"])
        self.assertIn("Source location: app.py:5", findings[0].evidence_summary)
        self.assertEqual(findings[0].component.properties["finding_type"], "static_code_weakness")


if __name__ == "__main__":
    unittest.main()
