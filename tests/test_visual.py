from __future__ import annotations

import unittest

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
from reachability_advisor.visual import _visual_graph_model, _visual_payload, render_html_report


def finding_for_visual(
    asset: str,
    exposure: str,
    evidence: list[str],
    *,
    tier: Tier = Tier.HIGH,
    score: float = 80.0,
    reachability: Reachability = Reachability.ATTACKER_CONTROLLED,
    component: str = "demo",
    vulnerability: str = "CVE-DEMO",
) -> Finding:
    return Finding(
        key=f"{asset}|{component}|1.0|{vulnerability}",
        artifact=Artifact(name=asset, reference=f"repo/{asset}:1.0"),
        component=Component(name=component, version="1.0", purl=f"pkg:npm/{component}@1.0"),
        vulnerability=VulnerabilityRecord(id=vulnerability, package_name=component, severity="high", cvss=8.0, summary="demo vulnerability"),
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

    def test_context_network_path_prefix_is_rendered(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "frontend",
                "public",
                ["context network path: public via kubernetes_service.frontend-external LoadBalancer -> kubernetes_deployment.frontend"],
                tier=Tier.HIGH,
                score=71.0,
            )
        ])

        path = payload["networkPaths"][0]
        self.assertEqual(path["entryLabel"], "Internet / attacker")
        self.assertEqual(path["label"], "kubernetes_service.frontend-external LoadBalancer")
        self.assertEqual(path["steps"][1], "kubernetes_deployment.frontend")

    def test_internal_path_through_public_kubernetes_entry_shows_attacker_entry(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "paymentservice",
                "internal",
                [
                    (
                        "context network path: internal via kubernetes_service.frontend-external LoadBalancer"
                        " -> kubernetes_deployment.frontend -> kubernetes_service.paymentservice ClusterIP"
                        " -> kubernetes_deployment.paymentservice"
                    )
                ],
            )
        ])

        path = payload["networkPaths"][0]
        self.assertEqual(path["entryLabel"], "Internet / attacker")
        self.assertEqual(path["entrySubtitle"], "public ingress then internal hop")
        self.assertEqual(path["exposure"], "internal")

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
        self.assertIn("request-controlled path", assets["api"]["codeExposures"])
        self.assertIn("reachable vulnerable API", assets["job"]["codeExposures"])
        self.assertIn("SBOM only", assets["unused"]["codeExposures"])
        self.assertIn("no source rule", assets["worker"]["codeExposures"])
        vulns = {vuln["assetId"]: vuln for vuln in payload["vulnerabilities"]}
        self.assertEqual(vulns["asset:api"]["codeExposure"], "request-controlled path")
        self.assertEqual(vulns["asset:job"]["codeExposure"], "reachable vulnerable API")
        self.assertEqual(vulns["asset:unused"]["codeExposure"], "SBOM only")
        self.assertEqual(vulns["asset:worker"]["codeExposure"], "no source rule")
        self.assertIn("No package-specific source rule", vulns["asset:worker"]["codeExposureDetail"])

    def test_html_uses_explicit_priority_score_labels_and_fan_edges(self) -> None:
        html = render_html_report([
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_ecs_service.api"],
                tier=Tier.HIGH,
                score=80.0,
            )
        ])

        self.assertIn("function fanEdgePath", html)
        self.assertIn("priority ${value || \"unknown\"}", html)
        self.assertIn("network ${value || \"unknown\"}", html)
        self.assertIn("dataset.edgeSource", html)
        self.assertIn("dataset.edgeTarget", html)
        self.assertIn("dataset.nodeId", html)
        self.assertIn("const assetById = new Map", html)
        self.assertIn("const vulnerabilityByFindingKey = new Map", html)
        self.assertIn("const vulnerabilitiesByAssetId = new Map", html)
        self.assertIn("const networkPathsByAssetId = new Map", html)

    def test_graph_model_connects_network_paths_assets_and_vulnerabilities(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_ecs_service.api"],
                tier=Tier.URGENT,
                score=98.0,
                component="express",
                vulnerability="CVE-PUBLIC",
            ),
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_ecs_service.api"],
                tier=Tier.HIGH,
                score=76.0,
                component="lodash",
                vulnerability="CVE-PUBLIC-SECOND",
            ),
            finding_for_visual(
                "worker",
                "internal",
                ["terraform network path: internal via aws_security_group.api allows traffic from sg-public -> sg-worker reaches aws_ecs_service.worker"],
                tier=Tier.MEDIUM,
                score=54.0,
                component="requests",
                vulnerability="CVE-LATERAL",
            ),
        ])

        graph = _visual_graph_model(payload)
        node_ids = {node["id"] for node in graph["nodes"]}
        self.assertFalse(graph["duplicateNodeIds"])
        self.assertEqual(len(graph["edges"]), len(payload["networkPaths"]) * 2 + len(payload["vulnerabilities"]))
        self.assertTrue(all(edge["source"] in node_ids for edge in graph["edges"]))
        self.assertTrue(all(edge["target"] in node_ids for edge in graph["edges"]))

        edge_pairs = {(edge["source"], edge["target"], edge["role"]) for edge in graph["edges"]}
        for path in payload["networkPaths"]:
            self.assertIn((f"{path['id']}:entry", path["id"], "entry-path"), edge_pairs)
            self.assertIn((path["id"], path["assetId"], "path-asset"), edge_pairs)
        for vulnerability_node in payload["vulnerabilities"]:
            self.assertIn((vulnerability_node["assetId"], vulnerability_node["id"], "asset-vulnerability"), edge_pairs)

    def test_large_graph_layout_keeps_cards_bounded_and_ordered(self) -> None:
        findings: list[Finding] = []
        exposures = ["public", "external", "internal", "private"]
        for asset_index in range(12):
            asset = f"service-{asset_index:02d}"
            exposure = exposures[asset_index % len(exposures)]
            evidence = [
                (
                    f"context network path: {exposure} via ingress-{asset_index}"
                    f" -> service-{asset_index} -> deployment-{asset_index}"
                )
            ]
            for vuln_index in range(6):
                findings.append(
                    finding_for_visual(
                        asset,
                        exposure,
                        evidence,
                        tier=Tier.HIGH if vuln_index == 0 else Tier.MEDIUM,
                        score=80.0 - vuln_index,
                        component=f"pkg-{vuln_index}",
                        vulnerability=f"CVE-{asset_index:02d}-{vuln_index:02d}",
                    )
                )

        payload = _visual_payload(findings)
        graph = _visual_graph_model(payload)
        node_ids = {node["id"] for node in graph["nodes"]}
        self.assertEqual(len(payload["assets"]), 12)
        self.assertEqual(len(payload["vulnerabilities"]), 72)
        self.assertEqual(graph["bounds"]["maxVulnerabilityCount"], 6)
        self.assertGreater(graph["bounds"]["height"], 7000)
        self.assertGreaterEqual(graph["bounds"]["width"], 1480)
        self.assertFalse(graph["duplicateNodeIds"])
        self.assertEqual(len(graph["edges"]), len(payload["networkPaths"]) * 2 + len(payload["vulnerabilities"]))
        self.assertTrue(all(edge["source"] in node_ids and edge["target"] in node_ids for edge in graph["edges"]))

        positions = graph["positions"]
        for node in graph["nodes"]:
            position = node["position"]
            self.assertGreaterEqual(position["x"], 0)
            self.assertGreaterEqual(position["y"], 0)
            self.assertLessEqual(position["x"] + position["width"], graph["bounds"]["width"])
            self.assertLessEqual(position["y"] + position["height"], graph["bounds"]["height"])
        for asset in payload["assets"]:
            asset_position = positions[asset["id"]]
            path = next(path for path in payload["networkPaths"] if path["assetId"] == asset["id"])
            self.assertLess(positions[f"{path['id']}:entry"]["x"], positions[path["id"]]["x"])
            self.assertLess(positions[path["id"]]["x"], asset_position["x"])
            for vulnerability_node in [item for item in payload["vulnerabilities"] if item["assetId"] == asset["id"]]:
                self.assertGreater(positions[vulnerability_node["id"]]["x"], asset_position["x"])

    def test_graph_model_tolerates_sparse_payloads_and_reports_duplicate_nodes(self) -> None:
        self.assertEqual(_visual_graph_model({"assets": "not-a-list"})["nodes"], [])

        graph = _visual_graph_model({
            "assets": [
                {"id": ""},
                {"id": "asset:pathless"},
                {"id": "asset:missing-path-id"},
                {"id": "asset:duplicate-vuln"},
            ],
            "networkPaths": [
                {"assetId": "asset:missing-path-id", "score": "not numeric"},
                {
                    "id": "network:asset:duplicate-vuln:0",
                    "assetId": "asset:duplicate-vuln",
                    "exposure": "unknown",
                    "tier": "low",
                    "score": False,
                },
            ],
            "vulnerabilities": [
                {
                    "id": "vulnerability:duplicate",
                    "assetId": "asset:duplicate-vuln",
                    "tier": "medium",
                    "score": "not numeric",
                    "label": "first",
                },
                {
                    "id": "vulnerability:duplicate",
                    "assetId": "asset:duplicate-vuln",
                    "tier": "low",
                    "score": 10,
                    "label": "second",
                },
                {"assetId": "asset:duplicate-vuln", "tier": "low"},
            ],
        })

        self.assertIn("vulnerability:duplicate", graph["duplicateNodeIds"])
        self.assertIn("asset:pathless", graph["positions"])
        self.assertIn("asset:missing-path-id", graph["positions"])
        self.assertFalse(any("missing-path-id:entry" in node_id for node_id in graph["positions"]))
        self.assertEqual(len([edge for edge in graph["edges"] if edge["role"] == "asset-vulnerability"]), 2)


if __name__ == "__main__":
    unittest.main()
