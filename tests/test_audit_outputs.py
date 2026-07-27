"""Regression tests for audit findings in `reachability_advisor.outputs`."""

from __future__ import annotations

import json
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from typing import Any

from reachability_advisor.models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    CorrelationEvidence,
    Finding,
    RuntimeEvidence,
    RuntimeEvidenceState,
    SourceEvidence,
    SourceLocation,
    Tier,
    VulnerabilityRecord,
)
from reachability_advisor.outputs import (
    render_table,
    write_diagnostics,
    write_json_findings,
    write_markdown_report,
    write_sarif,
)


def _reject_constant(name: str) -> float:
    raise AssertionError(f"non-standard JSON constant in artifact: {name}")


def _strict_json(text: str) -> Any:
    """Parse like a conforming RFC 8259 parser: bare NaN/Infinity are a hard error."""
    return json.loads(text, parse_constant=_reject_constant)


def _finding(**overrides: Any) -> Finding:
    finding = Finding(
        key="payments-api|lodash|CVE-2020-8203",
        artifact=Artifact(name="payments-api"),
        component=Component(name="lodash", version="4.17.20"),
        vulnerability=VulnerabilityRecord(
            id="CVE-2020-8203",
            package_name="lodash",
            affected_versions=["4.17.20"],
            severity="high",
            cvss=7.4,
            epss=0.5,
        ),
        source=SourceEvidence(),
        context=ContextEvidence(owner="team-payments"),
        score=72.0,
        tier=Tier.HIGH,
        confidence=Confidence.MEDIUM,
        rationale=["known exploited vulnerability"],
    )
    for name, value in overrides.items():
        setattr(finding, name, value)
    return finding


class NonFiniteNumberOutputTests(unittest.TestCase):
    """Finding 1/2: NaN and Infinity must never be written into an output artifact."""

    def test_write_json_findings_emits_rfc8259_json_for_non_finite_scores(self) -> None:
        finding = _finding()
        finding.vulnerability.cvss = float("nan")
        finding.vulnerability.epss = float("inf")
        finding.vulnerability.intelligence = {
            "cvss": {"value": float("nan"), "source": "hostile-feed"},
            "epss": {"score": float("-inf")},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.json"
            write_json_findings([finding], path)
            text = path.read_text(encoding="utf-8")

        self.assertNotIn("NaN", text)
        self.assertNotIn("Infinity", text)
        data = _strict_json(text)
        vulnerability = data["findings"][0]["vulnerability"]
        self.assertIsNone(vulnerability["cvss"])
        self.assertIsNone(vulnerability["epss"])
        self.assertIsNone(vulnerability["intelligence"]["cvss"]["value"])
        self.assertIsNone(vulnerability["intelligence"]["epss"]["score"])
        self.assertEqual(vulnerability["intelligence"]["cvss"]["source"], "hostile-feed")

    def test_write_sarif_security_severity_is_a_finite_number_for_nan_cvss(self) -> None:
        finding = _finding()
        finding.vulnerability.cvss = float("nan")
        finding.runtime_evidence = RuntimeEvidence(diagnostics=[{"score": float("inf")}])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.sarif"
            write_sarif([finding], path)
            text = path.read_text(encoding="utf-8")

        self.assertNotIn("NaN", text)
        self.assertNotIn("Infinity", text)
        data = _strict_json(text)
        severity = data["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
        self.assertEqual(severity, "7.2")
        self.assertEqual(float(severity), 7.2)
        diagnostics = data["runs"][0]["results"][0]["properties"]["runtime_evidence"]["diagnostics"]
        self.assertIsNone(diagnostics[0]["score"])

    def test_write_diagnostics_emits_rfc8259_json_for_non_finite_evidence(self) -> None:
        finding = _finding()
        finding.source.locations = [SourceLocation(Path("src/app.js"), 12, 3, snippet="require('lodash')")]
        finding.posture_evidence.diagnostics = [{"value": float("nan")}]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "diagnostics.json"
            write_diagnostics([finding], path)
            text = path.read_text(encoding="utf-8")

        self.assertNotIn("NaN", text)
        data = _strict_json(text)
        self.assertIsNone(data["diagnostics"][0]["evidence"]["posture_evidence"]["diagnostics"][0]["value"])


class MarkdownInjectionTests(unittest.TestCase):
    """Finding 3: scanner-supplied text must not break out of the Markdown report."""

    def test_snippet_cannot_inject_headings_html_or_comments(self) -> None:
        payload = (
            "x\n\n## ALL CLEAR\n\nNo security findings were detected. "
            "<img src=x onerror=alert(1)>\n\n<!--"
        )
        finding = _finding()
        finding.source.locations = [SourceLocation(Path("app.js"), 7, 1, snippet=payload)]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.md"
            write_markdown_report([finding], path)
            markdown = path.read_text(encoding="utf-8")

        lines = markdown.splitlines()
        self.assertNotIn("<!--", markdown)
        self.assertNotIn("<img", markdown)
        self.assertNotIn("## ALL CLEAR", lines)
        snippet_lines = [line for line in lines if "app.js:7" in line]
        self.assertEqual(len(snippet_lines), 1)
        self.assertIn("ALL CLEAR", snippet_lines[0])

    def test_rationale_and_unknowns_cannot_inject_markdown_structure(self) -> None:
        finding = _finding()
        finding.rationale = ["ok\n\n## INJECTED HEADING\n\n<!--"]
        finding.unknowns = ["gap\n## SECOND HEADING"]
        finding.source.reason = "reason\n## THIRD HEADING"
        finding.correlated_evidence = [
            CorrelationEvidence(
                correlation_type="dast_to_sca",
                related_finding_key="other",
                reason="corr\n## FOURTH HEADING",
            )
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.md"
            write_markdown_report([finding], path)
            markdown = path.read_text(encoding="utf-8")

        headings = [line for line in markdown.splitlines() if line.startswith("#")]
        for injected in ("## INJECTED HEADING", "## SECOND HEADING", "## THIRD HEADING", "## FOURTH HEADING"):
            self.assertNotIn(injected, headings)
        self.assertNotIn("<!--", markdown)

    def test_component_name_cannot_break_out_of_a_code_span(self) -> None:
        finding = _finding()
        finding.component = Component(name="lodash` <script>alert(1)</script> `", version="4.17.20")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.md"
            write_markdown_report([finding], path)
            markdown = path.read_text(encoding="utf-8")

        component_lines = [line for line in markdown.splitlines() if line.startswith("- Component:")]
        self.assertEqual(len(component_lines), 1)
        self.assertEqual(component_lines[0].count("`"), 2)

    def test_render_table_rows_stay_single_line(self) -> None:
        finding = _finding()
        finding.component = Component(name="lodash\nEVIL | injected", version="4.17.20")
        table = render_table([finding])
        self.assertEqual(len(table.splitlines()), 3)


class SarifPositionTests(unittest.TestCase):
    """Finding 4: emitted positions must satisfy the SARIF and LSP schemas."""

    def test_sarif_region_and_lsp_range_are_clamped(self) -> None:
        finding = _finding()
        finding.source.locations = [SourceLocation(Path("src/app.js"), -7, -3, snippet="boom")]
        with tempfile.TemporaryDirectory() as tmp:
            sarif_path = Path(tmp) / "findings.sarif"
            diagnostics_path = Path(tmp) / "diagnostics.json"
            write_sarif([finding], sarif_path)
            write_diagnostics([finding], diagnostics_path)
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
            diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))

        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region, {"startLine": 1, "startColumn": 1})
        entry = diagnostics["diagnostics"][0]["range"]
        self.assertEqual(entry["start"], {"line": 0, "character": 0})
        self.assertEqual(entry["end"], {"line": 0, "character": 1})


class SarifUriTests(unittest.TestCase):
    """Finding 5: artifactLocation.uri must be a valid, repo-relative URI reference."""

    def test_artifact_uri_is_percent_encoded(self) -> None:
        finding = _finding()
        finding.source.locations = [SourceLocation(Path("src/my app/a#b?c.js"), 3, 1)]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.sarif"
            write_sarif([finding], path)
            sarif = json.loads(path.read_text(encoding="utf-8"))

        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        parts = urllib.parse.urlsplit(uri)
        self.assertEqual(parts.fragment, "")
        self.assertEqual(parts.query, "")
        self.assertEqual(urllib.parse.unquote(parts.path), "src/my app/a#b?c.js")

    def test_artifact_uri_is_relative_to_the_source_root(self) -> None:
        finding = _finding()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            (root / "src").mkdir(parents=True)
            finding.source.locations = [SourceLocation(root / "src" / "app.js", 3, 1)]
            path = Path(tmp) / "findings.sarif"
            write_sarif([finding], path, source_roots={"payments-api": root})
            sarif = json.loads(path.read_text(encoding="utf-8"))

        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "src/app.js")

    def test_artifact_uri_outside_every_root_stays_absolute_and_encoded(self) -> None:
        finding = _finding()
        finding.source.locations = [SourceLocation(Path("/elsewhere/od d/app.js"), 3, 1)]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.sarif"
            write_sarif([finding], path, source_roots={"payments-api": Path(tmp)})
            sarif = json.loads(path.read_text(encoding="utf-8"))

        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "/elsewhere/od%20d/app.js")

    def test_synthetic_uris_encode_untrusted_names(self) -> None:
        dependency = _finding()
        dependency.artifact = Artifact(name="payments api")
        dependency.component = Component(name="lo dash#frag", version="1.0.0")
        dynamic = _finding(
            key="payments-api|dast|DAST-1",
            finding_type="dynamic_runtime_observation",
            runtime_evidence=RuntimeEvidence(
                state=RuntimeEvidenceState.ENDPOINT_OBSERVED,
                url="https://example.test/a path?q=1",
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.sarif"
            write_sarif([dependency, dynamic], path)
            sarif = json.loads(path.read_text(encoding="utf-8"))

        results = sarif["runs"][0]["results"]
        sbom_uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(sbom_uri, "sbom://payments%20api/lo%20dash%23frag")
        self.assertEqual(urllib.parse.urlsplit(sbom_uri).fragment, "")
        dast_uri = results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(dast_uri, "https://example.test/a%20path?q=1")


if __name__ == "__main__":
    unittest.main()
