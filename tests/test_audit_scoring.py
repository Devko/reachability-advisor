"""Regression tests for audited scoring defects (group `scoring`).

Each test pins a decision that was wrong before the fix:

* missing impact evidence was scored identically to a vendor-rated Low;
* CSPM findings with unresolved network exposure ranked below proven-isolated ones;
* any blocker anywhere on the asset - including a `constrains`-only WAF and
  blockers on unrelated paths - stripped URGENT from an exploited public finding.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

from reachability_advisor.finding_types import CLOUD_POSTURE_FINDING
from reachability_advisor.models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    Finding,
    PostureEvidence,
    Reachability,
    SbomDocument,
    SourceEvidence,
    Tier,
    VulnerabilityRecord,
)
from reachability_advisor.risk_graph_scoring import TIER_RANK
from reachability_advisor.scoring import ScorePolicy, apply_graph_score, score_finding

KEV = VulnerabilityRecord(id="CVE-2020-8203", package_name="lodash", cvss=9.8, epss=0.94, known_exploited=True)
ATTACKER_CONTROLLED = SourceEvidence(reachability=Reachability.ATTACKER_CONTROLLED, confidence=Confidence.HIGH)


def scored(vulnerability: VulnerabilityRecord, source: SourceEvidence, context: ContextEvidence) -> Finding:
    return score_finding(
        SbomDocument(path=Path("app.cdx.json"), artifact=Artifact(name="payments-api"), components=[]),
        Component(name="lodash", version="4.17.15", purl="pkg:npm/lodash@4.17.15"),
        vulnerability,
        source,
        context,
        ScorePolicy(),
    )


def decision(finding: Finding) -> dict[str, Any]:
    graph_decision = finding.score_details["graph_decision"]
    assert isinstance(graph_decision, dict)
    return graph_decision


def dimension(finding: Finding, name: str) -> str:
    return next(str(item["value"]) for item in finding.score_details["dimensions"] if item["name"] == name)


def posture_finding(exposure: str) -> Finding:
    finding = Finding(
        key=f"posture:{exposure}",
        artifact=Artifact(name="payments-api"),
        component=Component(name="aws_s3_bucket.payments", scope="posture"),
        vulnerability=VulnerabilityRecord(id="CKV_AWS_20", package_name="aws_s3_bucket", severity="critical", cvss=9.8),
        source=SourceEvidence(reachability=Reachability.PACKAGE_PRESENT, confidence=Confidence.MEDIUM),
        context=ContextEvidence(exposure=exposure, confidence=Confidence.LOW),
        score=0.0,
        tier=Tier.LOW,
        confidence=Confidence.MEDIUM,
        rationale=[],
        finding_type=CLOUD_POSTURE_FINDING,
        posture_evidence=PostureEvidence(
            scanner="cspm",
            tool="checkov",
            rule_id="CKV_AWS_20",
            resource_id="aws_s3_bucket.payments",
            confidence=Confidence.MEDIUM,
        ),
    )
    apply_graph_score(finding)
    return finding


class MissingImpactEvidenceTests(unittest.TestCase):
    """Absence of impact evidence must never be scored as a vendor-rated Low."""

    def _public_reachable(self, severity: str) -> Finding:
        return scored(
            VulnerabilityRecord(id="CVE-2026-0001", package_name="lodash", severity=severity),
            ATTACKER_CONTROLLED,
            ContextEvidence(exposure="public", privilege="admin", criticality="high", confidence=Confidence.HIGH),
        )

    def test_vendor_low_severity_is_not_reported_as_unknown_impact(self) -> None:
        for severity, expected in (("low", "low"), ("negligible", "low"), ("note", "low")):
            with self.subTest(severity=severity):
                self.assertEqual(dimension(self._public_reachable(severity), "vulnerability_impact"), expected)

    def test_unresolved_severity_stays_unknown_and_becomes_a_visibility_gap(self) -> None:
        finding = self._public_reachable("unknown")

        self.assertEqual(dimension(finding, "vulnerability_impact"), "unknown")
        self.assertIn("vulnerability impact unknown", decision(finding)["unknowns"])
        self.assertIn("vulnerability impact unknown", decision(finding)["visibility_gaps"])

    def test_unknown_impact_on_a_reachable_public_path_raises_potential_tier(self) -> None:
        unknown = self._public_reachable("unknown")
        low = self._public_reachable("low")

        self.assertEqual(low.score_details["graph_decision"]["potential_tier"], Tier.LOW.value)
        self.assertEqual(decision(unknown)["potential_tier"], Tier.HIGH.value)
        self.assertGreater(TIER_RANK[Tier(decision(unknown)["potential_tier"])], TIER_RANK[unknown.tier])

    def test_unknown_impact_is_not_scored_identically_to_vendor_low(self) -> None:
        unknown = self._public_reachable("unknown")
        low = self._public_reachable("low")

        self.assertNotEqual(
            (unknown.tier, decision(unknown)["potential_tier"], unknown.score),
            (low.tier, decision(low)["potential_tier"], low.score),
        )

    def test_unknown_impact_without_reachable_path_still_reports_the_gap(self) -> None:
        finding = scored(
            VulnerabilityRecord(id="CVE-2026-0002", package_name="lodash", severity="unknown"),
            SourceEvidence(reachability=Reachability.PACKAGE_PRESENT, confidence=Confidence.LOW),
            ContextEvidence(exposure="internal", confidence=Confidence.MEDIUM),
        )

        self.assertIn("vulnerability impact unknown", decision(finding)["unknowns"])
        self.assertEqual(decision(finding)["potential_tier"], finding.tier.value)

    def test_vendor_important_severity_is_high_impact(self) -> None:
        finding = self._public_reachable("important")

        self.assertEqual(dimension(finding, "vulnerability_impact"), "high")
        self.assertNotIn("vulnerability impact unknown", decision(finding)["unknowns"])


class PostureExposureMonotonicityTests(unittest.TestCase):
    """Unresolved exposure must never rank below a proven no-ingress path."""

    def test_unknown_exposure_is_not_ranked_below_proven_isolated_paths(self) -> None:
        unknown = posture_finding("unknown")
        for exposure in ("none", "isolated", "private", "internal"):
            with self.subTest(exposure=exposure):
                known = posture_finding(exposure)
                self.assertGreaterEqual(TIER_RANK[unknown.tier], TIER_RANK[known.tier])
                self.assertGreaterEqual(unknown.score, known.score)

    def test_unknown_exposure_posture_reaches_medium_and_keeps_reporting_the_gap(self) -> None:
        finding = posture_finding("unknown")

        self.assertEqual(finding.tier, Tier.MEDIUM)
        self.assertIn("deployment exposure not proven", decision(finding)["visibility_gaps"])

    def test_low_confidence_posture_evidence_still_caps_at_low(self) -> None:
        finding = posture_finding("unknown")
        finding.posture_evidence = PostureEvidence(
            scanner="cspm",
            tool="checkov",
            rule_id="CKV_AWS_20",
            resource_id="aws_s3_bucket.payments",
            confidence=Confidence.LOW,
        )
        apply_graph_score(finding)

        self.assertEqual(finding.tier, Tier.LOW)
        self.assertIn("posture finding lacks enough mapping evidence", decision(finding)["matched_rule"])


def _context(**network: Any) -> ContextEvidence:
    return ContextEvidence(
        exposure="public",
        environment="prod",
        privilege="admin",
        criticality="high",
        confidence=Confidence.HIGH,
        **network,
    )


class NetworkBlockerScopeTests(unittest.TestCase):
    """Only blockers on the selected path, and only hard ones, can strip urgent."""

    def test_constraining_waf_does_not_strip_urgent_from_an_exploited_public_finding(self) -> None:
        blocker = {"kind": "waf_or_firewall_policy", "effect": "constrains"}
        context = _context(
            network_paths=[{"exposure": "public", "confidence": "high", "blockers": [blocker]}],
            effective_exposure=[{"decision": "reachable", "network": {"exposure": "public", "confidence": "high", "blockers": [blocker]}}],
        )

        finding = scored(KEV, ATTACKER_CONTROLLED, context)

        self.assertEqual(finding.tier, Tier.URGENT)
        self.assertEqual(decision(finding)["matched_rule"], "exploit intelligence plus confirmed public reachable source path")
        self.assertEqual(decision(finding)["blockers"], ["waf_or_firewall_policy"])
        self.assertTrue(any(gate["name"] == "network_blocker" for gate in finding.score_details["gates"]))

    def test_blocker_on_an_unselected_path_does_not_demote_the_exposed_path(self) -> None:
        context = _context(
            network_paths=[
                {"exposure": "public", "confidence": "high", "blockers": []},
                {"exposure": "internal", "confidence": "high", "blockers": [{"kind": "public_network_disabled", "effect": "blocks"}]},
            ],
            effective_exposure=[{"decision": "reachable", "network": {"exposure": "public", "confidence": "high", "blockers": []}}],
        )

        finding = scored(KEV, ATTACKER_CONTROLLED, context)

        self.assertEqual(finding.tier, Tier.URGENT)
        self.assertEqual(decision(finding)["blockers"], [])

    def test_hard_blocker_on_the_selected_path_still_caps_an_exploited_finding(self) -> None:
        blocker = {"kind": "public_network_disabled", "effect": "blocks"}
        context = _context(
            effective_exposure=[{"decision": "blocked", "network": {"exposure": "public", "confidence": "high", "blockers": [blocker]}}],
        )

        finding = scored(KEV, ATTACKER_CONTROLLED, context)

        self.assertLessEqual(TIER_RANK[finding.tier], TIER_RANK[Tier.HIGH])
        self.assertIn("public_network_disabled", decision(finding)["blockers"])

    def test_blocker_without_declared_semantics_stays_conservative(self) -> None:
        context = _context(
            effective_exposure=[{"decision": "reachable", "network": {"exposure": "public", "confidence": "high", "blockers": [{"kind": "unlabelled_control"}]}}],
        )

        finding = scored(KEV, ATTACKER_CONTROLLED, context)

        self.assertNotEqual(finding.tier, Tier.URGENT)
        self.assertIn("unlabelled_control", decision(finding)["blockers"])

    def test_constraining_blocker_still_keeps_a_non_exploited_finding_below_urgent(self) -> None:
        context = ContextEvidence(
            exposure="public",
            environment="prod",
            privilege="sensitive",
            confidence=Confidence.MEDIUM,
            network_paths=[{"confidence": "medium", "blockers": [{"kind": "auth_required", "effect": "constrains"}]}],
        )

        finding = scored(VulnerabilityRecord(id="GHSA-router", package_name="router", cvss=9.8), ATTACKER_CONTROLLED, context)

        self.assertEqual(finding.tier, Tier.HIGH)
        self.assertIn("provider blocker constrains confirmed graph path", decision(finding)["matched_rule"])

    def test_network_paths_are_used_when_no_effective_exposure_record_exists(self) -> None:
        context = _context(network_paths=[{"exposure": "public", "confidence": "high", "blockers": [{"kind": "auth_required", "effect": "constrains"}]}])

        finding = scored(VulnerabilityRecord(id="GHSA-router", package_name="router", cvss=9.8), ATTACKER_CONTROLLED, context)

        self.assertEqual(decision(finding)["blockers"], ["auth_required"])


if __name__ == "__main__":
    unittest.main()
