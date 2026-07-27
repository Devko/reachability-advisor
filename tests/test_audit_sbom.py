"""Regression tests for confirmed audit findings in the `sbom` group.

Covers:
  1. Deeply nested JSON must produce a clean domain error, not an uncaught RecursionError.
  2. Non-finite numbers in scanner evidence must be treated as absent, not crash on int().
  3. Scanner-declared `unknowns` must survive for every scanner type, not only CSPM.
"""

from __future__ import annotations

import json
import math
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.models import Artifact, SbomDocument
from reachability_advisor.sbom import SbomError, load_sbom
from reachability_advisor.scoring import ScorePolicy
from reachability_advisor.security_evidence import generate_security_findings
from reachability_advisor.security_evidence_adapters import load_security_evidence
from reachability_advisor.security_evidence_model import (
    SecurityEvidenceError,
    SecurityEvidenceRecord,
)

NESTING_DEPTH = 60000


def _deep_array(depth: int = NESTING_DEPTH) -> str:
    return "[" * depth + "]" * depth


class DeeplyNestedJsonTests(unittest.TestCase):
    """Finding 1: `json.loads` raises RecursionError, which is not a JSONDecodeError."""

    def test_deeply_nested_sbom_raises_sbom_error_not_recursion_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deep.cdx.json"
            path.write_text('{"bomFormat":"CycloneDX","components":' + _deep_array() + "}", encoding="utf-8")

            with self.assertRaises(SbomError) as caught:
                load_sbom(path)

        self.assertIn("nesting exceeds the supported depth", str(caught.exception))
        # SbomError is a ValueError, so cli.main maps it to the documented exit code 2.
        self.assertIsInstance(caught.exception, ValueError)
        self.assertIsInstance(caught.exception.__cause__, RecursionError)

    def test_deeply_nested_sbom_exits_two_through_the_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sbom_path = root / "deep.cdx.json"
            sbom_path.write_text('{"bomFormat":"CycloneDX","components":' + _deep_array() + "}", encoding="utf-8")
            vuln_path = root / "vulns.json"
            vuln_path.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")

            exit_code = main(
                [
                    "scan",
                    "--sbom",
                    str(sbom_path),
                    "--vuln-in",
                    str(vuln_path),
                    "--out",
                    str(root / "out"),
                    "--no-table",
                ]
            )

        self.assertEqual(exit_code, 2)

    def test_deeply_nested_security_evidence_raises_security_evidence_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deep.json"
            path.write_text('{"findings":' + _deep_array() + "}", encoding="utf-8")

            with self.assertRaises(SecurityEvidenceError) as caught:
                load_security_evidence([path])

        self.assertIn("nesting exceeds the supported depth", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, RecursionError)

    def test_deeply_nested_security_evidence_jsonl_line_raises_security_evidence_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deep.jsonl"
            path.write_text('{"findings":' + _deep_array() + "}\n", encoding="utf-8")

            with self.assertRaises(SecurityEvidenceError) as caught:
                load_security_evidence([path])

        message = str(caught.exception)
        self.assertIn("nesting exceeds the supported depth", message)
        self.assertIn(":1:", message)
        self.assertIsInstance(caught.exception.__cause__, RecursionError)


class NonFiniteEvidenceNumberTests(unittest.TestCase):
    """Finding 2: `Infinity`/`NaN`/`1e400` reached `int()` and raised OverflowError."""

    def _load_single(self, tmp: str, payload: str, name: str = "evidence.json") -> SecurityEvidenceRecord:
        path = Path(tmp) / name
        path.write_text(payload, encoding="utf-8")
        records = load_security_evidence([path])
        self.assertEqual(len(records), 1)
        return records[0]

    def test_infinite_line_and_cvss_are_treated_as_absent(self) -> None:
        payload = (
            '{"findings":[{"rule_id":"R1","tool":"semgrep","severity":"high","message":"x",'
            '"source":{"path":"src/app.py","line":Infinity},"cvss":Infinity}]}'
        )
        with tempfile.TemporaryDirectory() as tmp:
            record = self._load_single(tmp, payload)

        self.assertIsNotNone(record.source)
        assert record.source is not None
        self.assertEqual(record.source.line, 1)
        self.assertIsNone(record.cvss)

    def test_overflowing_literal_and_nan_are_treated_as_absent(self) -> None:
        payload = (
            '{"findings":[{"rule_id":"R1","tool":"semgrep","severity":"high","message":"x",'
            '"source":{"path":"src/app.py","line":1e400,"column":NaN},"cvss":1e400}]}'
        )
        with tempfile.TemporaryDirectory() as tmp:
            record = self._load_single(tmp, payload)

        assert record.source is not None
        self.assertEqual(record.source.line, 1)
        self.assertEqual(record.source.column, 1)
        self.assertIsNone(record.cvss)

    def test_infinite_sarif_region_and_security_severity_are_treated_as_absent(self) -> None:
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"name": "codeql"}},
                        "results": [
                            {
                                "ruleId": "js/xss",
                                "message": {"text": "xss"},
                                "properties": {"security-severity": "Infinity"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/app.js"},
                                            "region": {"startLine": float("inf"), "startColumn": float("inf")},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            record = self._load_single(tmp, payload, name="report.sarif.json")

        assert record.source is not None
        self.assertEqual(record.source.line, 1)
        self.assertEqual(record.source.column, 1)
        self.assertIsNone(record.cvss)

    def test_non_finite_values_never_reach_report_json(self) -> None:
        payload = (
            '{"findings":[{"rule_id":"R1","tool":"semgrep","severity":"high","message":"x",'
            '"artifact":"api","source":{"path":"src/app.py","line":1},"cvss":Infinity}]}'
        )
        with tempfile.TemporaryDirectory() as tmp:
            record = self._load_single(tmp, payload)

        sboms = [SbomDocument(path=Path("api.cdx.json"), artifact=Artifact(name="api"), components=[])]
        findings, _ = generate_security_findings([record], sboms, {}, ScorePolicy())

        self.assertEqual(len(findings), 1)
        serialized = json.dumps(findings[0].to_json(), default=str)
        self.assertNotIn("Infinity", serialized)
        self.assertNotIn("NaN", serialized)
        self.assertTrue(math.isfinite(findings[0].score))


class ScannerDeclaredUnknownsTests(unittest.TestCase):
    """Finding 3: `unknowns` declared by SAST/DAST scanners were dropped."""

    def _finding_unknowns(self, record: SecurityEvidenceRecord) -> tuple[list[str], list[str]]:
        sboms = [SbomDocument(path=Path("api.cdx.json"), artifact=Artifact(name="api"), components=[])]
        findings, _ = generate_security_findings([record], sboms, {}, ScorePolicy())
        self.assertEqual(len(findings), 1)
        decision = findings[0].score_details["graph_decision"]
        return findings[0].unknowns, list(decision["unknowns"])

    def test_sast_record_keeps_scanner_declared_unknowns(self) -> None:
        gap = "dataflow trace truncated: sink resolution incomplete"
        record = SecurityEvidenceRecord(
            scanner_type="sast",
            tool="semgrep",
            rule_id="py/sqli",
            weakness="sqli",
            artifact="api",
            unknowns=[gap],
        )

        finding_unknowns, decision_unknowns = self._finding_unknowns(record)

        self.assertIn(gap, finding_unknowns)
        self.assertIn(gap, decision_unknowns)

    def test_dast_record_keeps_scanner_declared_unknowns(self) -> None:
        gap = "authenticated crawl coverage incomplete"
        record = SecurityEvidenceRecord(
            scanner_type="dast",
            tool="zap",
            rule_id="xss",
            weakness="xss",
            artifact="api",
            url="https://api.example.test/search",
            unknowns=[gap],
        )

        finding_unknowns, decision_unknowns = self._finding_unknowns(record)

        self.assertIn(gap, finding_unknowns)
        self.assertIn(gap, decision_unknowns)

    def test_cspm_record_still_keeps_scanner_declared_unknowns(self) -> None:
        gap = "bucket policy evaluation incomplete"
        record = SecurityEvidenceRecord(
            scanner_type="cspm",
            tool="checkov",
            rule_id="CKV_AWS_20",
            weakness="public bucket",
            artifact="api",
            resource_id="aws_s3_bucket.public",
            unknowns=[gap],
        )

        finding_unknowns, _ = self._finding_unknowns(record)

        self.assertIn(gap, finding_unknowns)

    def test_scanner_unknowns_are_deduped_against_derived_unknowns(self) -> None:
        derived = "affected cloud resource unavailable"
        record = SecurityEvidenceRecord(
            scanner_type="cspm",
            tool="checkov",
            rule_id="CKV_AWS_20",
            weakness="public bucket",
            artifact="api",
            unknowns=[derived, derived],
        )

        finding_unknowns, _ = self._finding_unknowns(record)

        self.assertEqual(finding_unknowns.count(derived), 1)

    def test_unknowns_survive_the_full_evidence_load_path(self) -> None:
        gap = "sink resolution incomplete"
        payload = json.dumps(
            {
                "security_evidence": [
                    {
                        "scanner_type": "sast",
                        "tool": "semgrep",
                        "rule_id": "py/sqli",
                        "weakness": "sqli",
                        "severity": "high",
                        "artifact": "api",
                        "source": {"path": "src/app.py", "line": 12},
                        "unknowns": [gap],
                    }
                ]
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(payload, encoding="utf-8")
            records = load_security_evidence([path])

        self.assertEqual(records[0].unknowns, [gap])
        finding_unknowns, decision_unknowns = self._finding_unknowns(records[0])
        self.assertIn(gap, finding_unknowns)
        self.assertIn(gap, decision_unknowns)


if __name__ == "__main__":
    unittest.main()
