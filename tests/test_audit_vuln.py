"""Regression tests for confirmed audit findings in the ``vuln`` group.

Covers the OSV severity/CVSS adapter, non-finite score handling, deep-nesting
loader hardening, vulnerability match indexing, and correlation fan-out bounds.
"""

from __future__ import annotations

import json
import math
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from reachability_advisor import correlation as correlation_module
from reachability_advisor import vulnerability as vulnerability_module
from reachability_advisor import vulnerability_intelligence as vulnerability_intelligence_module
from reachability_advisor.correlation import apply_correlations
from reachability_advisor.models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    Reachability,
    RuntimeEvidence,
    RuntimeEvidenceState,
    SbomDocument,
    SourceEvidence,
    VulnerabilityRecord,
)
from reachability_advisor.numeric import finite_float_or_none, safe_float
from reachability_advisor.purl import package_match
from reachability_advisor.scoring import ScorePolicy, score_finding
from reachability_advisor.vulnerability import (
    VulnerabilityError,
    cvss_base_score_from_vector,
    load_vulnerabilities,
    matching_vulnerabilities,
)
from reachability_advisor.vulnerability_intelligence import normalize_local_vulnerability


def _load(document: dict[str, Any], name: str = "vulns.json") -> list[VulnerabilityRecord]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return load_vulnerabilities(path)


def _osv_document(vulnerability: dict[str, Any], *, name: str = "lodash", purl: str = "pkg:npm/lodash@4.17.15") -> dict[str, Any]:
    return {"results": [{"packages": [{"package": {"name": name, "purl": purl}, "vulnerabilities": [vulnerability]}]}]}


class OsvSeverityAdapterTests(unittest.TestCase):
    """OSV ``severity[].type`` is a CVSS version tag and ``score`` is a vector string."""

    def test_cvss_vector_is_scored_and_version_tag_is_never_the_severity_label(self) -> None:
        records = _load(
            _osv_document(
                {
                    "id": "GHSA-p6mc-m468-83gg",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                }
            )
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].cvss, 9.8)
        self.assertEqual(records[0].severity, "critical")

    def test_highest_scoreable_cvss_version_wins_across_severity_and_affected(self) -> None:
        records = _load(
            _osv_document(
                {
                    "id": "UBUNTU-CVE-2021-44228",
                    "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:M/Au:N/C:P/I:P/A:P"}],
                    "affected": [{"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]}],
                }
            )
        )

        self.assertEqual(records[0].cvss, 10.0)
        self.assertEqual(records[0].severity, "critical")

    def test_reading_affected_severity_does_not_mutate_the_parsed_document(self) -> None:
        vulnerability = {
            "id": "GHSA-mutation",
            "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:M/Au:N/C:P/I:P/A:P"}],
            "affected": [{"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}],
        }
        document = _osv_document(vulnerability)

        _load(document)

        self.assertEqual(len(vulnerability["severity"]), 1)

    def test_unscoreable_cvss_v4_vector_stays_unknown_instead_of_bottom_bucket(self) -> None:
        records = _load(
            _osv_document(
                {
                    "id": "GHSA-v4-only",
                    "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
                }
            )
        )

        self.assertIsNone(records[0].cvss)
        self.assertEqual(records[0].severity, "unknown")

    def test_database_specific_severity_and_numeric_score_remain_supported(self) -> None:
        records = _load(
            _osv_document(
                {
                    "id": "GHSA-35jh-r3h4-6jhm",
                    "severity": [{"type": "CVSS_V3", "score": "7.2"}],
                    "database_specific": {"severity": "HIGH"},
                }
            )
        )

        self.assertEqual(records[0].cvss, 7.2)
        self.assertEqual(records[0].severity, "high")

    def test_base_score_matches_published_reference_vectors(self) -> None:
        expected = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H": 7.2,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L": 1.8,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
            "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C": 10.0,
            "AV:N/AC:M/Au:N/C:P/I:N/A:N": 4.3,
        }
        for vector, score in expected.items():
            with self.subTest(vector=vector):
                self.assertEqual(cvss_base_score_from_vector(vector), score)

    def test_non_vector_and_v4_input_never_produces_a_guessed_score(self) -> None:
        for vector in ("", "not a vector", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"):
            with self.subTest(vector=vector):
                self.assertIsNone(cvss_base_score_from_vector(vector))


class NonFiniteScoreTests(unittest.TestCase):
    """``json.loads`` accepts bare NaN/Infinity, which must never become a score."""

    def test_non_finite_cvss_does_not_override_the_declared_severity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vulns.json"
            path.write_text(
                '{"vulnerabilities": ['
                '{"id": "CVE-NAN", "package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.15"}, "severity": "critical", "cvss": NaN},'
                '{"id": "CVE-INF", "package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.15"}, "severity": "low", "cvss": Infinity},'
                '{"id": "CVE-NEG", "package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.15"}, "severity": "critical", "cvss": -5.0}]}',
                encoding="utf-8",
            )
            records = {record.id: record for record in load_vulnerabilities(path)}

        self.assertIsNone(records["CVE-NAN"].cvss)
        self.assertEqual(records["CVE-NAN"].severity, "critical")
        self.assertIsNone(records["CVE-INF"].cvss)
        self.assertEqual(records["CVE-INF"].severity, "low")
        self.assertIsNone(records["CVE-NEG"].cvss)
        self.assertEqual(records["CVE-NEG"].severity, "critical")

    def test_out_of_range_and_non_finite_epss_is_rejected(self) -> None:
        records = _load(
            {
                "vulnerabilities": [
                    {"id": "CVE-A", "package": {"name": "lodash"}, "epss": 5.0},
                    {"id": "CVE-B", "package": {"name": "lodash"}, "epss": -0.5},
                    {"id": "CVE-C", "package": {"name": "lodash"}, "epss": "NaN"},
                    {"id": "CVE-D", "package": {"name": "lodash"}, "epss": 0.42},
                ]
            }
        )
        scores = {record.id: record.epss for record in records}

        self.assertIsNone(scores["CVE-A"])
        self.assertIsNone(scores["CVE-B"])
        self.assertIsNone(scores["CVE-C"])
        self.assertEqual(scores["CVE-D"], 0.42)

    def test_grype_cvss_outside_the_defined_range_is_rejected(self) -> None:
        records = _load(
            {
                "matches": [
                    {
                        "vulnerability": {"id": "CVE-BIG", "severity": "critical", "cvss": [{"metrics": {"baseScore": 99.0}}]},
                        "artifact": {"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
                    }
                ]
            }
        )

        self.assertIsNone(records[0].cvss)
        self.assertEqual(records[0].severity, "critical")

    def test_parsed_records_are_rfc8259_serializable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vulns.json"
            path.write_text(
                '{"vulnerabilities": [{"id": "CVE-NAN", "package": {"name": "lodash"}, "severity": "critical", "cvss": NaN, "epss": Infinity}]}',
                encoding="utf-8",
            )
            record = load_vulnerabilities(path)[0]

        payload = {"cvss": record.cvss, "epss": record.epss}
        self.assertEqual(json.dumps(payload, allow_nan=False), '{"cvss": null, "epss": null}')

    def test_safe_float_rejects_non_finite_and_overflowing_values(self) -> None:
        self.assertEqual(safe_float(float("nan")), 0.0)
        self.assertEqual(safe_float(float("inf")), 0.0)
        self.assertEqual(safe_float("NaN"), 0.0)
        self.assertEqual(safe_float("-Infinity"), 0.0)
        self.assertEqual(safe_float(10**400), 0.0)
        self.assertEqual(safe_float("1e400"), 0.0)
        self.assertEqual(safe_float(7.5), 7.5)
        self.assertEqual(safe_float("7.5"), 7.5)
        self.assertTrue(math.isfinite(safe_float(float("nan"), 1.0)))


class DeepNestingLoaderTests(unittest.TestCase):
    def test_deeply_nested_vulnerability_json_raises_a_controlled_loader_error(self) -> None:
        depth = 200_000
        payload = '{"vulnerabilities":[{"id":"CVE-X","package":{"name":"lodash"},"intelligence":' + "[" * depth + "]" * depth + "}]}"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deep.json"
            path.write_text(payload, encoding="utf-8")
            with self.assertRaises(VulnerabilityError) as caught:
                load_vulnerabilities(path)

        self.assertIn("invalid JSON", str(caught.exception))


class MatchIndexTests(unittest.TestCase):
    """The candidate index must be a superset prefilter, never a semantic change."""

    RECORDS = [
        VulnerabilityRecord(id="CVE-SAME-PURL", package_name="org.apache.logging.log4j:log4j-core", package_purl="pkg:npm/lodash@4.17.15"),
        VulnerabilityRecord(id="CVE-NS-CONFLICT", package_name="foo", package_purl="pkg:npm/b/foo@1.0.0"),
        VulnerabilityRecord(id="CVE-NS-ABSENT", package_name="foo", package_purl="pkg:npm/foo@1.0.0"),
        VulnerabilityRecord(id="CVE-CROSS-ECOSYSTEM", package_name="foo", package_purl="pkg:pypi/foo@1.0.0"),
        VulnerabilityRecord(id="CVE-NAME-ONLY", package_name="Some_Lib"),
        VulnerabilityRecord(id="CVE-TYPE-ONLY", package_name="ptype-only", package_purl="pkg:golang"),
        VulnerabilityRecord(id="CVE-UNRELATED", package_name="unrelated"),
    ]

    COMPONENTS = [
        Component(name="lodash", version=None, purl="pkg:npm/lodash@4.17.15"),
        Component(name="foo", version=None, purl="pkg:npm/a/foo@1.0.0"),
        Component(name="foo", version=None, purl="pkg:npm/foo@1.0.0"),
        Component(name="foo", version=None, purl="pkg:pypi/foo@1.0.0"),
        Component(name="some-lib", version=None, purl=None),
        Component(name="ptype-only", version=None, purl="pkg:golang?download_url=x"),
        Component(name="nothing", version=None, purl="pkg:npm/nothing@1.0.0"),
    ]

    def _brute_force(self, component: Component) -> list[str]:
        return [
            record.id
            for record in self.RECORDS
            if package_match(component.name, component.purl, record.package_name, record.package_purl)
        ]

    def test_index_returns_exactly_the_unindexed_package_match_result(self) -> None:
        for component in self.COMPONENTS:
            with self.subTest(component=component.purl or component.name):
                matched = [record.id for record in matching_vulnerabilities(component, list(self.RECORDS))]
                self.assertEqual(matched, self._brute_force(component))

    def test_matching_does_not_test_every_record_against_every_component(self) -> None:
        records = [VulnerabilityRecord(id=f"CVE-{index}", package_name=f"pkg-{index}", package_purl=f"pkg:npm/pkg-{index}@1.0.0") for index in range(200)]
        components = [Component(name=f"pkg-{index}", version="1.0.0", purl=f"pkg:npm/pkg-{index}@1.0.0") for index in range(200)]

        with mock.patch("reachability_advisor.vulnerability.package_match", side_effect=package_match) as spy:
            matched = [matching_vulnerabilities(component, records)[0].id for component in components]

        self.assertEqual(matched, [f"CVE-{index}" for index in range(200)])
        self.assertLessEqual(spy.call_count, 400)

    def test_index_is_rebuilt_when_the_record_list_changes(self) -> None:
        component = Component(name="lodash", version=None, purl="pkg:npm/lodash@4.17.15")
        first = [VulnerabilityRecord(id="CVE-1", package_name="lodash")]
        second = [VulnerabilityRecord(id="CVE-2", package_name="lodash")]

        self.assertEqual([record.id for record in matching_vulnerabilities(component, first)], ["CVE-1"])
        self.assertEqual([record.id for record in matching_vulnerabilities(component, second)], ["CVE-2"])
        second.append(VulnerabilityRecord(id="CVE-3", package_name="lodash"))
        self.assertEqual([record.id for record in matching_vulnerabilities(component, second)], ["CVE-2", "CVE-3"])


def _finding(key: str, artifact: str, finding_type: str, *, route: str | None = None, cwe: str | None = None, exposure: str = "public"):
    weakness: dict[str, Any] = {}
    if route:
        weakness["route"] = route
    if cwe:
        weakness["cwe"] = cwe
    finding = score_finding(
        SbomDocument(path=Path("app.cdx.json"), artifact=Artifact(name=artifact), components=[]),
        Component(name="lib", version="1.0.0", purl="pkg:npm/lib@1.0.0"),
        VulnerabilityRecord(id=key, package_name="lib", severity="high"),
        SourceEvidence(reachability=Reachability.PACKAGE_PRESENT, confidence=Confidence.LOW),
        ContextEvidence(exposure=exposure, confidence=Confidence.HIGH),
        ScorePolicy(),
    )
    finding.key = key
    finding.finding_type = finding_type
    finding.weakness = weakness
    if finding_type == "dynamic_runtime_observation":
        finding.runtime_evidence = RuntimeEvidence(state=RuntimeEvidenceState.VULNERABILITY_OBSERVED, confidence=Confidence.HIGH, tool="zap")
    return finding


class CorrelationFanOutTests(unittest.TestCase):
    def test_pairing_is_not_quadratic_across_unrelated_artifacts(self) -> None:
        findings = []
        for index in range(100):
            findings.append(_finding(f"sca-{index}", f"app-{index}", "dependency_vulnerability"))
            findings.append(_finding(f"sast-{index}", f"app-{index}", "static_code_weakness", cwe=f"CWE-{index}"))

        with mock.patch(
            "reachability_advisor.correlation._correlate",
            side_effect=correlation_module._correlate,
        ) as spy:
            apply_correlations(findings)

        # The all-pairs scan evaluated 19,900 pairs for this input.
        self.assertLessEqual(spy.call_count, 500)

    def test_artifact_only_correlations_are_capped_and_the_gap_is_reported(self) -> None:
        limit = correlation_module.max_correlations_per_relation()
        peers = limit + 15
        findings = [_finding(f"sca-{index}", "monolith", "dependency_vulnerability") for index in range(peers)]
        findings.extend(_finding(f"dast-{index}", "monolith", "dynamic_runtime_observation", route=f"/r{index}") for index in range(peers))

        apply_correlations(findings)

        for finding in findings:
            with self.subTest(key=finding.key):
                same_artifact = [item for item in finding.correlated_evidence if item.correlation_type == "sca_dast_same_artifact"]
                self.assertEqual(len(same_artifact), limit)
                self.assertTrue(
                    any("correlation coverage incomplete" in unknown for unknown in finding.unknowns),
                    finding.unknowns,
                )

    def test_correlations_below_the_cap_are_untouched(self) -> None:
        findings = [
            _finding("sca-1", "app", "dependency_vulnerability"),
            _finding("dast-1", "app", "dynamic_runtime_observation", route="/search"),
            _finding("dast-2", "app", "dynamic_runtime_observation", route="/other"),
        ]

        apply_correlations(findings)

        by_key = {finding.key: finding for finding in findings}
        self.assertEqual([item.related_finding_key for item in by_key["sca-1"].correlated_evidence], ["dast-1", "dast-2"])
        self.assertEqual([item.correlation_type for item in by_key["dast-1"].correlated_evidence], ["sca_dast_same_artifact"])
        self.assertEqual(by_key["sca-1"].unknowns, [])

    def test_cross_artifact_sast_dast_route_match_survives_bucketing(self) -> None:
        findings = [
            _finding("sast-1", "checkout", "static_code_weakness", route="/search", cwe="CWE-79"),
            _finding("dast-1", "unmapped:https://app.example", "dynamic_runtime_observation", route="/search", cwe="CWE-79"),
        ]

        apply_correlations(findings)

        by_key = {finding.key: finding for finding in findings}
        self.assertEqual(
            [(item.correlation_type, item.confidence.value) for item in by_key["sast-1"].correlated_evidence],
            [("sast_dast_route_match", "high")],
        )
        self.assertEqual(
            [(item.correlation_type, item.confidence.value) for item in by_key["dast-1"].correlated_evidence],
            [("sast_dast_route_match", "high")],
        )

    def test_cross_artifact_cwe_only_match_survives_bucketing(self) -> None:
        findings = [
            _finding("sast-1", "checkout", "static_code_weakness", route="/a", cwe="CWE-89"),
            _finding("dast-1", "unmapped:https://app.example", "dynamic_runtime_observation", route="/b", cwe="CWE-89"),
        ]

        apply_correlations(findings)

        by_key = {finding.key: finding for finding in findings}
        self.assertEqual([item.correlation_type for item in by_key["sast-1"].correlated_evidence], ["multi_tool_same_cwe"])

    def test_cloud_posture_findings_still_correlate_within_an_artifact(self) -> None:
        findings = [
            _finding("cspm-1", "app", "cloud_posture_finding"),
            _finding("cspm-2", "app", "cloud_posture_finding"),
            _finding("sca-1", "app", "dependency_vulnerability"),
        ]

        apply_correlations(findings)

        by_key = {finding.key: finding for finding in findings}
        self.assertEqual(
            sorted(item.related_finding_key for item in by_key["cspm-1"].correlated_evidence),
            ["cspm-2", "sca-1"],
        )
        self.assertEqual(
            sorted(item.related_finding_key for item in by_key["sca-1"].correlated_evidence),
            ["cspm-1", "cspm-2"],
        )
        self.assertEqual({item.correlation_type for item in by_key["sca-1"].correlated_evidence}, {"cspm_deployment_match"})

    def test_repeated_application_does_not_duplicate_correlation_evidence(self) -> None:
        findings = [
            _finding("sca-1", "app", "dependency_vulnerability"),
            _finding("dast-1", "app", "dynamic_runtime_observation", route="/search"),
        ]

        apply_correlations(findings)
        apply_correlations(findings)

        self.assertEqual(len(findings[0].correlated_evidence), 1)
        self.assertEqual(len(findings[1].correlated_evidence), 1)


class SharedFiniteFloatHelperTests(unittest.TestCase):
    """The two scanner ingest paths must reject non-finite scores identically.

    ``_float_or_none`` was duplicated in ``vulnerability`` and
    ``vulnerability_intelligence``. The copies drifted -- only one guarded
    ``math.isfinite`` -- which left a live NaN ingest path that blanked the HTML
    report. Both now delegate to ``numeric.finite_float_or_none``; these tests fail
    if either module reintroduces a private copy.
    """

    def test_no_module_keeps_a_private_float_parser(self) -> None:
        for module in (vulnerability_module, vulnerability_intelligence_module):
            with self.subTest(module=module.__name__):
                self.assertFalse(
                    hasattr(module, "_float_or_none"),
                    f"{module.__name__} reintroduced a private float parser; use "
                    "numeric.finite_float_or_none so the isfinite guard cannot drift",
                )
                self.assertIs(module.finite_float_or_none, finite_float_or_none)

    def test_non_finite_and_unusable_values_become_none(self) -> None:
        for value in (
            math.nan,
            math.inf,
            -math.inf,
            "NaN",
            "Infinity",
            10**400,  # int too large to convert to float -> OverflowError
            None,
            "",
            "not-a-number",
            object(),
        ):
            with self.subTest(value=repr(value)[:40]):
                self.assertIsNone(finite_float_or_none(value))

    def test_absence_is_not_coerced_to_zero(self) -> None:
        # safe_float() has a 0.0 default; this helper must not, or a missing CVSS
        # would be indistinguishable from a genuine score of 0.0.
        self.assertIsNone(finite_float_or_none(None))
        self.assertEqual(finite_float_or_none(0), 0.0)
        self.assertEqual(finite_float_or_none("7.5"), 7.5)

    def test_intelligence_epss_rejects_non_finite_score(self) -> None:
        record = normalize_local_vulnerability(
            {"id": "CVE-NONFINITE", "package_name": "demo", "epss": {"score": math.inf}}
        )
        self.assertIsNone(json.loads(json.dumps(record, allow_nan=False)).get("epss", {}).get("value"))


if __name__ == "__main__":
    unittest.main()
