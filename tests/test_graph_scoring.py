from __future__ import annotations

import unittest
from pathlib import Path

from reachability_advisor.models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    CorrelationEvidence,
    Reachability,
    RuntimeEvidence,
    RuntimeEvidenceState,
    SbomDocument,
    SourceEvidence,
    SourceLocation,
    Tier,
    VulnerabilityRecord,
)
from reachability_advisor.scoring import ScorePolicy, apply_graph_score, score_finding


def scored(
    *,
    vulnerability: VulnerabilityRecord | None = None,
    source: SourceEvidence | None = None,
    context: ContextEvidence | None = None,
):
    return score_finding(
        SbomDocument(path=Path("app.cdx.json"), artifact=Artifact(name="app"), components=[]),
        Component(name="lib", version="1.0.0", purl="pkg:npm/lib@1.0.0"),
        vulnerability or VulnerabilityRecord(id="CVE-X", package_name="lib", cvss=9.8),
        source or SourceEvidence(reachability=Reachability.ATTACKER_CONTROLLED, confidence=Confidence.HIGH),
        context or ContextEvidence(exposure="public", privilege="sensitive", criticality="high", confidence=Confidence.HIGH),
        ScorePolicy(),
    )


class GraphScoringTests(unittest.TestCase):
    def test_public_confirmed_dependency_path_is_graph_urgent(self) -> None:
        finding = scored(vulnerability=VulnerabilityRecord(id="CVE-X", package_name="lib", cvss=9.8, known_exploited=True))

        decision = finding.score_details["graph_decision"]

        self.assertEqual(finding.tier, Tier.URGENT)
        self.assertEqual(decision["matched_rule"], "exploit intelligence plus confirmed public reachable source path")
        self.assertIn("graph_decision", finding.score_details)
        self.assertTrue(all(dimension["points"] == 0.0 for dimension in finding.score_details["dimensions"]))

    def test_dast_runtime_observed_unknown_source_has_runtime_priority_not_source_proof(self) -> None:
        finding = scored(
            vulnerability=VulnerabilityRecord(id="dast-xss", package_name="first-party-code", severity="high"),
            source=SourceEvidence(reachability=Reachability.PACKAGE_PRESENT, confidence=Confidence.LOW),
            context=ContextEvidence(exposure="public", confidence=Confidence.HIGH),
        )
        finding.finding_type = "dynamic_runtime_observation"
        finding.runtime_evidence = RuntimeEvidence(
            state=RuntimeEvidenceState.UNAUTHENTICATED_OBSERVED,
            confidence=Confidence.HIGH,
            tool="zap",
            url="https://app.example/search?q=x",
        )
        finding.unknowns = ["source mapping unavailable"]
        apply_graph_score(finding)

        decision = finding.score_details["graph_decision"]

        self.assertEqual(finding.source.reachability, Reachability.PACKAGE_PRESENT)
        self.assertEqual(finding.tier, Tier.HIGH)
        self.assertIn("runtime-observed vulnerability", decision["matched_rule"])
        self.assertIn("runtime finding has no source mapping", decision["visibility_gaps"])

    def test_sast_location_only_without_deployment_stays_below_high(self) -> None:
        finding = scored(
            vulnerability=VulnerabilityRecord(id="sast-xss", package_name="first-party-code", severity="high"),
            source=SourceEvidence(
                reachability=Reachability.IMPORTED,
                confidence=Confidence.MEDIUM,
                locations=[SourceLocation(path=Path("app.js"), line=10)],
            ),
            context=ContextEvidence(exposure="unknown", confidence=Confidence.LOW),
        )
        finding.finding_type = "static_code_weakness"
        apply_graph_score(finding)

        self.assertEqual(finding.tier, Tier.MEDIUM)
        self.assertEqual(finding.score_details["graph_decision"]["matched_rule"], "static location-only evidence")

    def test_blocked_public_path_caps_confirmed_priority_but_keeps_potential(self) -> None:
        finding = scored(
            context=ContextEvidence(
                exposure="public",
                confidence=Confidence.HIGH,
                network_paths=[
                    {
                        "exposure": "public",
                        "confidence": "high",
                        "blockers": [{"kind": "waf_auth", "effect": "blocks"}],
                    }
                ],
                effective_exposure=[
                    {
                        "decision": "blocked",
                        "network": {
                            "exposure": "public",
                            "confidence": "high",
                            "blockers": [{"kind": "waf_auth", "effect": "blocks"}],
                        },
                    }
                ],
            )
        )

        self.assertEqual(finding.tier, Tier.MEDIUM)
        self.assertEqual(finding.score_details["graph_decision"]["potential_tier"], "high")
        self.assertIn("blocked network path caps confirmed priority", finding.score_details["graph_decision"]["matched_rule"])

    def test_unknown_context_scores_above_private_and_records_potential_tier(self) -> None:
        vulnerability = VulnerabilityRecord(id="CVE-X", package_name="lib", cvss=7.5)
        source = SourceEvidence(reachability=Reachability.ATTACKER_CONTROLLED, confidence=Confidence.HIGH)
        unknown = scored(vulnerability=vulnerability, source=source, context=ContextEvidence(exposure="unknown", privilege="unknown", confidence=Confidence.LOW))
        private = scored(vulnerability=vulnerability, source=source, context=ContextEvidence(exposure="private", privilege="none", confidence=Confidence.MEDIUM))

        self.assertGreater(unknown.score, private.score)
        self.assertIn(unknown.score_details["graph_decision"]["potential_tier"], {"high", "urgent"})
        self.assertIn("deployment exposure not proven", unknown.score_details["graph_decision"]["visibility_gaps"])

    def test_weak_same_artifact_correlation_does_not_raise_to_high(self) -> None:
        finding = scored(
            vulnerability=VulnerabilityRecord(id="CVE-X", package_name="lib", cvss=8.0),
            source=SourceEvidence(reachability=Reachability.PACKAGE_PRESENT, confidence=Confidence.LOW),
            context=ContextEvidence(exposure="internal", confidence=Confidence.MEDIUM),
        )
        finding.correlated_evidence.append(
            CorrelationEvidence(
                correlation_type="sca_dast_same_artifact",
                related_finding_key="runtime",
                confidence=Confidence.LOW,
                reason="same artifact only",
            )
        )
        apply_graph_score(finding)

        self.assertEqual(finding.tier, Tier.MEDIUM)
        self.assertTrue(any(item["name"] == "corroboration" and item["adjustment"] == 0.5 for item in finding.score_details["graph_decision"]["band_adjustments"]))


if __name__ == "__main__":
    unittest.main()
