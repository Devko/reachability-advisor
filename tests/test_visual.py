from __future__ import annotations

import unittest

from reachability_advisor.models import Artifact, Component, Confidence, ContextEvidence, Finding, Reachability, SourceEvidence, Tier, VulnerabilityRecord
from reachability_advisor.visual import _visual_payload


def finding_for_visual(
    asset: str,
    exposure: str,
    evidence: list[str],
    *,
    tier: Tier = Tier.HIGH,
    score: float = 80.0,
    reachability: Reachability = Reachability.ATTACKER_CONTROLLED,
) -> Finding:
    return Finding(
        key=f"{asset}|demo|1.0|CVE-DEMO",
        artifact=Artifact(name=asset, reference=f"repo/{asset}:1.0"),
        component=Component(name="demo", version="1.0", purl="pkg:npm/demo@1.0"),
        vulnerability=VulnerabilityRecord(id="CVE-DEMO", package_name="demo", severity="high", cvss=8.0, summary="demo vulnerability"),
        source=SourceEvidence(reachability=reachability, confidence=Confidence.HIGH, reason="test evidence"),
        context=ContextEvidence(
            environment="prod",
            exposure=exposure,
            privilege="limited",
            criticality="high",
            owner="@team",
            confidence=Confidence.MEDIUM,
            evidence=evidence,
        ),
        score=score,
        tier=tier,
        confidence=Confidence.HIGH,
        rationale=["test rationale"],
    )


class VisualPayloadTests(unittest.TestCase):
    def test_public_network_path_becomes_entry_and_ingress_path(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_lb_target_group.api -> aws_ecs_service.api"],
                tier=Tier.URGENT,
                score=99.0,
            )
        ])

        path = payload["networkPaths"][0]
        self.assertEqual(path["entryLabel"], "Internet / attacker")
        self.assertEqual(path["entrySubtitle"], "direct public route")
        self.assertEqual(path["label"], "aws_lb.edge public load balancer")
        self.assertEqual(path["steps"][1], "aws_lb_target_group.api")
        self.assertEqual(path["tier"], "urgent")

    def test_internal_path_is_rendered_as_lateral_movement_entry(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "worker",
                "internal",
                ["terraform network path: internal via aws_security_group.app allows traffic from sg-web -> sg-app reaches aws_instance.worker"],
            )
        ])

        path = payload["networkPaths"][0]
        self.assertEqual(path["entryLabel"], "Internal pivot")
        self.assertEqual(path["entrySubtitle"], "requires a reachable internal foothold")
        self.assertEqual(path["exposure"], "internal")

    def test_internal_cidr_path_is_rendered_as_internal_network_entry(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "reports",
                "internal",
                ["terraform network path: internal via aws_security_group.reports_internal internal ingress -> sg-reports-internal reaches aws_ecs_service.reports"],
            )
        ])

        path = payload["networkPaths"][0]
        self.assertEqual(path["entryLabel"], "Internal network")
        self.assertEqual(path["entrySubtitle"], "private network ingress only")
        self.assertEqual(path["label"], "aws_security_group.reports_internal internal ingress")

    def test_external_exposure_inference_has_fallback_path_card(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "gateway",
                "external",
                ["terraform exposure inference: external via azurerm_application_gateway.gateway"],
            )
        ])

        path = payload["networkPaths"][0]
        self.assertEqual(path["entryLabel"], "External source")
        self.assertEqual(path["label"], "external exposure")
        self.assertEqual(path["steps"], ["azurerm_application_gateway.gateway"])

    def test_private_asset_without_path_evidence_is_marked_no_external_entry(self) -> None:
        payload = _visual_payload([finding_for_visual("batch", "private", [])])

        path = payload["networkPaths"][0]
        self.assertEqual(path["entryLabel"], "No external entry")
        self.assertEqual(path["label"], "Isolated/private network")
        self.assertEqual(path["summary"], "No direct or lateral ingress path was observed in the supplied context.")

    def test_unknown_asset_without_context_keeps_uncertainty_visible(self) -> None:
        payload = _visual_payload([finding_for_visual("unknown", "unknown", [])])

        path = payload["networkPaths"][0]
        self.assertEqual(path["entryLabel"], "Unknown entry")
        self.assertEqual(path["label"], "Unresolved network path")
        self.assertEqual(path["summary"], "The supplied context does not prove a network entry path.")

    def test_code_exposure_labels_are_visible_on_assets_and_vulnerabilities(self) -> None:
        payload = _visual_payload([
            finding_for_visual("api", "public", [], reachability=Reachability.ATTACKER_CONTROLLED, tier=Tier.URGENT, score=95.0),
            finding_for_visual("job", "private", [], reachability=Reachability.FUNCTION_REACHABLE, tier=Tier.MEDIUM, score=55.0),
            finding_for_visual("unused", "private", [], reachability=Reachability.PACKAGE_PRESENT, tier=Tier.LOW, score=25.0),
            finding_for_visual("worker", "private", [], reachability=Reachability.UNKNOWN_DUE_TO_NO_RULE, tier=Tier.MEDIUM, score=45.0),
        ])

        assets = {asset["name"]: asset for asset in payload["assets"]}
        self.assertIn("covered", assets["api"]["codeExposures"])
        self.assertIn("reachable sink", assets["job"]["codeExposures"])
        self.assertIn("not observed", assets["unused"]["codeExposures"])
        self.assertIn("no rule", assets["worker"]["codeExposures"])
        vulns = {vuln["assetId"]: vuln for vuln in payload["vulnerabilities"]}
        self.assertEqual(vulns["asset:api"]["codeExposure"], "covered")
        self.assertEqual(vulns["asset:job"]["codeExposure"], "reachable sink")
        self.assertEqual(vulns["asset:unused"]["codeExposure"], "not observed")
        self.assertEqual(vulns["asset:worker"]["codeExposure"], "no rule")
        self.assertIn("No package-specific source rule", vulns["asset:worker"]["codeExposureDetail"])


if __name__ == "__main__":
    unittest.main()
