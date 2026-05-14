from __future__ import annotations

import unittest
from pathlib import Path

from reachability_advisor.attack_path_view import build_attack_paths
from reachability_advisor.models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    Finding,
    Reachability,
    RuntimeEvidence,
    RuntimeEvidenceState,
    SourceEvidence,
    SourceLocation,
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
    finding_type: str = "dependency_vulnerability",
    weakness: dict[str, object] | None = None,
    runtime_evidence: RuntimeEvidence | None = None,
    unknowns: list[str] | None = None,
    source_locations: list[SourceLocation] | None = None,
    privilege: str = "limited",
    criticality: str = "high",
    iam_impacts: list[str] | None = None,
    effective_access: list[dict[str, object]] | None = None,
    rationale: list[str] | None = None,
    score_details: dict[str, object] | None = None,
    evidence_summary: list[str] | None = None,
    fix_commands: list[str] | None = None,
) -> Finding:
    return Finding(
        key=f"{asset}|{component}|1.0|{vulnerability}",
        artifact=Artifact(name=asset, reference=f"repo/{asset}:1.0"),
        component=Component(name=component, version="1.0", purl=f"pkg:npm/{component}@1.0"),
        vulnerability=VulnerabilityRecord(id=vulnerability, package_name=component, severity="high", cvss=8.0, summary="demo vulnerability"),
        source=SourceEvidence(
            reachability=reachability,
            confidence=Confidence.HIGH,
            reason="test evidence",
            locations=source_locations or [],
        ),
        context=ContextEvidence(
            environment="prod",
            exposure=exposure,
            privilege=privilege,
            criticality=criticality,
            iam_impacts=iam_impacts if iam_impacts is not None else ["secrets:read"],
            effective_access=effective_access or [],
            owner="@team",
            confidence=Confidence.MEDIUM,
            evidence=evidence,
        ),
        score=score,
        tier=tier,
        confidence=Confidence.HIGH,
        rationale=rationale if rationale is not None else ["test rationale"],
        finding_type=finding_type,
        weakness=weakness or {},
        fix_commands=fix_commands or [],
        score_details=score_details or {},
        runtime_evidence=runtime_evidence or RuntimeEvidence(),
        unknowns=unknowns or [],
        evidence_summary=evidence_summary or [],
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
        self.assertTrue(payload["evidenceGraph"]["network_paths"])
        typed_nodes = {node["label"]: node["kind"] for node in payload["evidenceGraph"]["network_nodes"]}
        typed_edges = payload["evidenceGraph"]["network_edges"]
        self.assertEqual(typed_nodes["Internet / attacker"], "internet")
        self.assertEqual(typed_nodes["aws_lb.edge public load balancer"], "load_balancer")
        self.assertTrue(any(edge["target"] == "asset:api" and edge["kind"] == "network_path_asset" for edge in typed_edges))
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
        self.assertEqual(path["steps"], ["kubernetes_service.frontend-external LoadBalancer"])

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

    def test_fallback_paths_are_used_when_graph_has_no_network_paths(self) -> None:
        payload = _visual_payload(
            [
                finding_for_visual("public-api", "public", [], tier=Tier.HIGH, score=80.0),
                finding_for_visual("partner-api", "external", [], tier=Tier.MEDIUM, score=60.0),
                finding_for_visual("internal-api", "internal", [], tier=Tier.MEDIUM, score=55.0),
                finding_for_visual("batch", "private", [], tier=Tier.LOW, score=30.0),
                finding_for_visual("unknown", "unknown", [], tier=Tier.LOW, score=20.0),
            ],
            evidence_graph={"network_paths": []},
        )

        paths = {path["assetId"]: path for path in payload["networkPaths"]}
        self.assertEqual(paths["asset:public-api"]["entryLabel"], "Internet / attacker")
        self.assertEqual(paths["asset:public-api"]["label"], "Public ingress")
        self.assertEqual(paths["asset:public-api"]["summary"], "Public exposure is reported, but no linked Terraform path evidence was emitted.")
        self.assertEqual(paths["asset:partner-api"]["entryLabel"], "External source")
        self.assertEqual(paths["asset:partner-api"]["label"], "External ingress")
        self.assertEqual(paths["asset:partner-api"]["summary"], "External exposure is reported, but the exact ingress path is not linked.")
        self.assertEqual(paths["asset:internal-api"]["entryLabel"], "Internal network")
        self.assertEqual(paths["asset:internal-api"]["summary"], "Reachable only through an internal network path inferred from the supplied context.")
        self.assertEqual(paths["asset:batch"]["entrySubtitle"], "no linked network route observed")
        self.assertEqual(paths["asset:unknown"]["entrySubtitle"], "insufficient IaC evidence")

    def test_sparse_graph_network_paths_are_normalized(self) -> None:
        payload = _visual_payload(
            [finding_for_visual("api", "external", [])],
            evidence_graph={
                "network_paths": [
                    "not an object",
                    {},
                    {"asset_id": "asset:api", "exposure": "external", "steps": "not a list"},
                ]
            },
        )

        path = payload["networkPaths"][0]
        self.assertEqual(path["entryLabel"], "External source")
        self.assertEqual(path["entrySubtitle"], "restricted public CIDR or external source")
        self.assertEqual(path["label"], "External ingress")
        self.assertEqual(path["summary"], "External exposure is reported, but the exact ingress path is not linked.")
        self.assertEqual(path["steps"], [])

    def test_architecture_view_places_public_ingress_through_edge_and_asset_zone(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_lb_target_group.api -> aws_ecs_service.api"],
                tier=Tier.URGENT,
                score=99.0,
            )
        ])

        architecture = payload["architecture"]
        zones = {zone["id"]: zone for zone in architecture["zones"]}
        assets = {asset["id"]: asset for asset in architecture["assets"]}
        hops = {hop["label"]: hop for hop in architecture["hops"]}
        self.assertEqual(assets["asset:api"]["zoneId"], "zone:public")
        self.assertIn("asset:api", zones["zone:public"]["assetIds"])
        self.assertEqual(hops["Ingress edge"]["zoneId"], "zone:edge-ingress")
        self.assertEqual(hops["Ingress edge"]["provider"], "AWS")
        self.assertTrue(any(edge["target"] == "asset:api" and edge["role"] == "hop-asset" for edge in architecture["edges"]))

    def test_attack_path_view_builds_per_finding_dependency_story(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_lb_target_group.api -> aws_ecs_service.api"],
                tier=Tier.URGENT,
                score=99.0,
            )
        ])

        attack_paths = payload["attackPaths"]
        self.assertEqual(len(attack_paths), 1)
        path = attack_paths[0]
        self.assertEqual(path["findingKey"], "api|demo|1.0|CVE-DEMO")
        self.assertEqual(path["findingType"], "dependency_vulnerability")
        self.assertEqual(path["findingTypeLabel"], "dependency vulnerability")
        self.assertEqual(path["artifact"]["name"], "api")
        self.assertEqual(path["provider"], "AWS")
        self.assertEqual(path["tier"], "urgent")
        self.assertIn("SBOM", path["evidenceLayers"])
        self.assertIn("Source", path["evidenceLayers"])
        self.assertIn("Terraform", path["evidenceLayers"])
        node_types = [node["type"] for node in path["nodes"]]
        for expected_type in ["entry", "ingress", "workload", "artifact", "source", "vulnerability", "identity", "data"]:
            self.assertIn(expected_type, node_types)
        node_ids = {node["id"] for node in path["nodes"]}
        self.assertTrue(all(edge["from"] in node_ids and edge["to"] in node_ids for edge in path["edges"]))
        self.assertTrue(path["id"].startswith("attack:path:"))

    def test_attack_path_view_uses_one_story_per_finding_even_on_shared_network_path(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_lb_target_group.shared -> aws_ecs_service.api"],
                component="express",
                vulnerability="CVE-API",
            ),
            finding_for_visual(
                "worker",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_lb_target_group.shared -> aws_ecs_service.worker"],
                component="requests",
                vulnerability="CVE-WORKER",
            ),
        ])

        self.assertEqual(len(payload["attackPaths"]), 2)
        self.assertEqual({path["artifact"]["name"] for path in payload["attackPaths"]}, {"api", "worker"})
        self.assertEqual({path["findingKey"] for path in payload["attackPaths"]}, {"api|express|1.0|CVE-API", "worker|requests|1.0|CVE-WORKER"})
        self.assertTrue(all(any(node["type"] == "ingress" for node in path["nodes"]) for path in payload["attackPaths"]))

    def test_risk_scenario_maps_urgent_to_critical_without_cve_title(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_ecs_service.api"],
                tier=Tier.URGENT,
                score=99.0,
                vulnerability="CVE-CRITICAL-DEMO",
            )
        ])

        scenario = payload["riskScenarios"][0]
        self.assertEqual(scenario["priorityLabel"], "Critical")
        self.assertNotIn("CVE-CRITICAL-DEMO", scenario["title"])
        self.assertGreaterEqual(scenario["categoryCounts"]["vulnerabilities"], 1)

    def test_risk_scenario_collapses_multiple_cves_on_same_asset_path(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_ecs_service.api"],
                component="express",
                vulnerability="CVE-API-1",
            ),
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_ecs_service.api"],
                component="lodash",
                vulnerability="CVE-API-2",
            ),
        ])

        self.assertEqual(len(payload["riskScenarios"]), 1)
        scenario = payload["riskScenarios"][0]
        self.assertEqual(scenario["totalFindings"], 2)
        self.assertEqual(set(scenario["findingKeys"]), {"api|express|1.0|CVE-API-1", "api|lodash|1.0|CVE-API-2"})

    def test_attack_path_groups_reuse_shared_route_for_multiple_assets(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_lb_target_group.shared -> aws_ecs_service.api"],
                component="express",
                vulnerability="CVE-API",
            ),
            finding_for_visual(
                "worker",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_lb_target_group.shared -> aws_ecs_service.worker"],
                component="requests",
                vulnerability="CVE-WORKER",
            ),
        ])

        self.assertEqual(len(payload["attackPathGroups"]), 1)
        group = payload["attackPathGroups"][0]
        self.assertEqual(set(group["assetIds"]), {"asset:api", "asset:worker"})
        self.assertEqual(group["assetCount"], 2)
        self.assertEqual(set(group["scenarioIds"]), {scenario["id"] for scenario in payload["riskScenarios"]})
        self.assertTrue(group["routeNodes"])

    def test_risk_scenario_category_counts_cover_issue_buckets(self) -> None:
        path = ["context network path: public via kubernetes_ingress.edge -> kubernetes_deployment.search-api"]
        payload = _visual_payload([
            finding_for_visual("search-api", "public", path, component="requests", vulnerability="CVE-DEP"),
            finding_for_visual(
                "search-api",
                "public",
                path,
                finding_type="static_code_weakness",
                component="semgrep",
                vulnerability="semgrep.xss",
                weakness={"scanner_type": "sast", "tool": "Semgrep", "cwe": "CWE-79", "weakness": "reflected XSS"},
                source_locations=[SourceLocation(Path("app/search.py"), 42)],
            ),
            finding_for_visual(
                "search-api",
                "public",
                path,
                reachability=Reachability.PACKAGE_PRESENT,
                finding_type="dynamic_runtime_observation",
                component="zap",
                vulnerability="ZAP-10016",
                weakness={"scanner_type": "dast", "tool": "ZAP", "weakness": "reflected XSS"},
                runtime_evidence=RuntimeEvidence(state=RuntimeEvidenceState.VULNERABILITY_OBSERVED, confidence=Confidence.MEDIUM, tool="ZAP"),
            ),
            finding_for_visual(
                "search-api",
                "public",
                path,
                finding_type="cloud_posture_finding",
                component="cspm",
                vulnerability="cspm.public-ingress",
                weakness={"scanner_type": "cspm", "tool": "CSPM", "weakness": "public ingress"},
            ),
        ])

        scenario = payload["riskScenarios"][0]
        self.assertEqual(scenario["categoryCounts"]["vulnerabilities"], 2)
        self.assertEqual(scenario["categoryCounts"]["events"], 1)
        self.assertEqual(scenario["categoryCounts"]["insecure_configuration"], 1)
        self.assertGreaterEqual(scenario["categoryCounts"]["identity_data_access"], 1)
        self.assertGreaterEqual(scenario["categoryCounts"]["visibility_gaps"], 1)

    def test_attack_path_view_models_sast_as_static_source_evidence(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "search-api",
                "public",
                ["context network path: public via kubernetes_ingress.edge -> kubernetes_deployment.search-api"],
                finding_type="static_code_weakness",
                component="semgrep",
                vulnerability="semgrep.xss",
                weakness={"scanner_type": "sast", "tool": "Semgrep", "cwe": "CWE-79", "weakness": "reflected XSS"},
                source_locations=[SourceLocation(Path("app/search.py"), 42, snippet="return request.args['q']")],
            )
        ])

        path = payload["attackPaths"][0]
        node_types = [node["type"] for node in path["nodes"]]
        self.assertEqual(path["findingType"], "static_code_weakness")
        self.assertIn("SAST", path["evidenceLayers"])
        self.assertIn("source", node_types)
        self.assertIn("weakness", node_types)
        self.assertNotIn("runtime", node_types)

    def test_attack_path_view_models_dast_as_runtime_observation_with_source_unknown(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "search-api",
                "public",
                ["context network path: public via kubernetes_ingress.edge -> kubernetes_deployment.search-api"],
                reachability=Reachability.PACKAGE_PRESENT,
                finding_type="dynamic_runtime_observation",
                component="zap",
                vulnerability="ZAP-10016",
                weakness={"scanner_type": "dast", "tool": "ZAP", "cwe": "CWE-79", "weakness": "reflected XSS"},
                runtime_evidence=RuntimeEvidence(
                    state=RuntimeEvidenceState.VULNERABILITY_OBSERVED,
                    confidence=Confidence.MEDIUM,
                    tool="ZAP",
                    url="https://api.example.test/search?q=x",
                    method="GET",
                    parameter="q",
                    evidence_source="zap",
                ),
            )
        ])

        path = payload["attackPaths"][0]
        node_types = [node["type"] for node in path["nodes"]]
        self.assertEqual(path["findingType"], "dynamic_runtime_observation")
        self.assertIn("DAST", path["evidenceLayers"])
        self.assertIn("runtime", node_types)
        self.assertIn("weakness", node_types)
        self.assertIn("unknown", node_types)
        self.assertNotIn("source", node_types)
        self.assertIn("source mapping unavailable", path["unknowns"])

    def test_attack_path_builder_keeps_unmapped_runtime_observation_conservative(self) -> None:
        finding = finding_for_visual(
            "orphan-api",
            "unknown",
            [],
            reachability=Reachability.PACKAGE_PRESENT,
            finding_type="dynamic_runtime_observation",
            component="zap",
            vulnerability="ZAP-40012",
            weakness={"scanner_type": "dast", "tool": "ZAP", "weakness": "SQL injection"},
            runtime_evidence=RuntimeEvidence(state=RuntimeEvidenceState.VULNERABILITY_OBSERVED, confidence=Confidence.LOW, tool="ZAP"),
            privilege="unknown",
            criticality="unknown",
            iam_impacts=[],
            rationale=[],
            evidence_summary=["DAST scanner observed a vulnerable endpoint"],
        )

        path = build_attack_paths([finding], [], [], [None, {"findings": ["not-a-dict"], "suggested_fix": "unused"}])[0]
        node_types = [node["type"] for node in path["nodes"]]
        self.assertEqual(path["provider"], "Context")
        self.assertEqual(path["shortReason"], "vulnerability_observed by ZAP")
        self.assertIn("network path unavailable", path["unknowns"])
        self.assertIn("source mapping unavailable", path["unknowns"])
        self.assertIn("unknown", node_types)
        self.assertNotIn("identity", node_types)
        self.assertNotIn("data", node_types)
        runtime_nodes = [node for node in path["nodes"] if node["type"] == "runtime"]
        self.assertEqual(runtime_nodes[0]["label"], "vulnerability_observed")

    def test_attack_path_builder_shows_blockers_effective_access_and_remediation(self) -> None:
        finding = finding_for_visual(
            "payments",
            "external",
            ["context network path: external via azurerm_application_gateway.edge -> azurerm_linux_web_app.payments"],
            reachability=Reachability.UNKNOWN_DUE_TO_NO_RULE,
            component="jackson-databind",
            vulnerability="GHSA-demo",
            effective_access=[{"principal": "payments-mi", "action": "secrets/get", "decision": "allow", "resource": "keyvault", "confidence": "medium"}],
            iam_impacts=[],
            criticality="",
            rationale=[],
            score_details={"graph_decision": {"drivers": ["public app gateway"], "blockers": ["application gateway auth required"]}},
        )
        network_path = {
            "id": "network:payments:0",
            "assetIds": ["asset:payments"],
            "label": "azurerm_application_gateway.edge",
            "entryLabel": "External source",
            "entrySubtitle": "partner CIDR",
            "pathType": "external exposure",
            "exposure": "external",
            "confidence": "medium",
            "evidence": "context network path: external via azurerm_application_gateway.edge",
            "provider": "Azure",
            "steps": ["azurerm_application_gateway.edge", "azurerm_linux_web_app.payments"],
            "blockers": [{"kind": "auth", "reason": "application gateway authorizer"}],
            "summary": "External gateway reaches payments.",
            "tier": "high",
            "score": 75.0,
        }
        visual_vulnerability = {
            "findingKey": finding.key,
            "severity": "critical",
        }
        remediation = {
            "suggested_fix": "Upgrade jackson-databind",
            "fix_commands": ["mvn versions:use-latest-releases"],
            "findings": [{"key": finding.key}],
        }

        path = build_attack_paths([finding], [network_path], [visual_vulnerability], [remediation])[0]
        node_types = [node["type"] for node in path["nodes"]]
        blocker_labels = [node["label"] for node in path["nodes"] if node["type"] == "blocker"]
        self.assertEqual(path["provider"], "Azure")
        self.assertEqual(path["remediation"][0], "Upgrade jackson-databind")
        self.assertIn("public app gateway", path["why"])
        self.assertIn("auth", blocker_labels)
        self.assertIn("application gateway auth required", blocker_labels)
        self.assertIn("identity", node_types)
        self.assertIn("no source rule", path["unknowns"])
        self.assertIn("Terraform", path["evidenceLayers"])

    def test_attack_path_builder_handles_context_and_provider_fallbacks(self) -> None:
        findings = [
            finding_for_visual("aws-api", "public", ["context network path: public via aws_lb.edge -> aws_ecs_service.api"], rationale=[]),
            finding_for_visual("gcp-api", "public", ["context network path: public via google_compute_forwarding_rule.edge -> google_cloud_run_service.api"], rationale=[]),
            finding_for_visual("k8s-api", "public", ["context network path: public via kubernetes_ingress.edge -> kubernetes_deployment.api"], rationale=[]),
            finding_for_visual("private-job", "private", [], rationale=[], privilege="unknown", criticality="", iam_impacts=[]),
        ]
        payload = _visual_payload(findings)
        providers = {path["artifact"]["name"]: path["provider"] for path in payload["attackPaths"]}
        short_reasons = {path["artifact"]["name"]: path["shortReason"] for path in payload["attackPaths"]}
        self.assertEqual(providers["aws-api"], "AWS")
        self.assertEqual(providers["gcp-api"], "GCP")
        self.assertEqual(providers["k8s-api"], "Kubernetes")
        self.assertEqual(providers["private-job"], "Context")
        self.assertIn("aws_lb.edge", short_reasons["aws-api"])
        self.assertIn("No direct or lateral ingress path", short_reasons["private-job"])

    def test_architecture_view_shows_internal_lateral_path_and_private_asset(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "worker",
                "internal",
                ["terraform network path: internal via aws_security_group.app allows traffic from sg-web -> sg-app reaches aws_instance.worker"],
            )
        ])

        architecture = payload["architecture"]
        assets = {asset["id"]: asset for asset in architecture["assets"]}
        entry_hops = [hop for hop in architecture["hops"] if hop["kind"] == "entry"]
        self.assertEqual(assets["asset:worker"]["zoneId"], "zone:private-internal")
        self.assertTrue(any(hop["label"] == "Internal pivot" for hop in entry_hops))
        self.assertTrue(any(hop["kind"] == "policy" for hop in architecture["hops"]))

    def test_architecture_view_keeps_unknown_and_private_boundaries_distinct(self) -> None:
        payload = _visual_payload([
            finding_for_visual("batch", "private", []),
            finding_for_visual("unknown", "unknown", []),
        ])

        assets = {asset["id"]: asset for asset in payload["architecture"]["assets"]}
        self.assertEqual(assets["asset:batch"]["zoneId"], "zone:private-internal")
        self.assertEqual(assets["asset:unknown"]["zoneId"], "zone:unknown")

    def test_architecture_view_reuses_shared_ingress_for_multiple_assets(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_lb_target_group.shared -> aws_ecs_service.api"],
                component="express",
                vulnerability="CVE-API",
            ),
            finding_for_visual(
                "worker",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_lb_target_group.shared -> aws_ecs_service.worker"],
                component="requests",
                vulnerability="CVE-WORKER",
            ),
        ])

        hops = payload["architecture"]["hops"]
        shared_hops = [hop for hop in hops if hop["label"] == "Ingress edge"]
        self.assertEqual(len(shared_hops), 1)
        self.assertEqual(set(shared_hops[0]["assetIds"]), {"asset:api", "asset:worker"})

    def test_architecture_view_infers_provider_labels_for_major_platforms(self) -> None:
        payload = _visual_payload([
            finding_for_visual("aws-api", "public", ["context network path: public via aws_lb.edge -> aws_ecs_service.api"]),
            finding_for_visual("azure-api", "external", ["context network path: external via azurerm_application_gateway.edge -> azurerm_linux_web_app.api"]),
            finding_for_visual("gcp-api", "public", ["context network path: public via google_compute_forwarding_rule.edge -> google_cloud_run_service.api"]),
            finding_for_visual("k8s-api", "public", ["context network path: public via kubernetes_ingress.edge -> kubernetes_deployment.api"]),
            finding_for_visual("manual-api", "unknown", ["context network path: unknown via manual gateway -> manual service"]),
        ])

        providers = {asset["name"]: asset["provider"] for asset in payload["architecture"]["assets"]}
        self.assertEqual(providers["aws-api"], "AWS")
        self.assertEqual(providers["azure-api"], "Azure")
        self.assertEqual(providers["gcp-api"], "GCP")
        self.assertEqual(providers["k8s-api"], "Kubernetes")
        self.assertEqual(providers["manual-api"], "Context")

    def test_code_exposure_labels_are_visible_on_assets_and_vulnerabilities(self) -> None:
        payload = _visual_payload([
            finding_for_visual("api", "public", [], reachability=Reachability.ATTACKER_CONTROLLED, tier=Tier.URGENT, score=95.0),
            finding_for_visual("job", "private", [], reachability=Reachability.FUNCTION_REACHABLE, tier=Tier.MEDIUM, score=55.0),
            finding_for_visual("unused", "private", [], reachability=Reachability.PACKAGE_PRESENT, tier=Tier.LOW, score=25.0),
            finding_for_visual("worker", "private", [], reachability=Reachability.UNKNOWN_DUE_TO_NO_RULE, tier=Tier.MEDIUM, score=45.0),
            finding_for_visual("importer", "private", [], reachability=Reachability.IMPORTED, tier=Tier.LOW, score=35.0),
            finding_for_visual("dependency", "private", [], reachability=Reachability.DEPENDENCY_REACHABLE, tier=Tier.LOW, score=34.0),
            finding_for_visual("absent", "private", [], reachability=Reachability.ABSENT, tier=Tier.LOW, score=5.0),
        ])

        assets = {asset["name"]: asset for asset in payload["assets"]}
        self.assertIn("request-controlled path", assets["api"]["codeExposures"])
        self.assertIn("reachable vulnerable API", assets["job"]["codeExposures"])
        self.assertIn("SBOM only", assets["unused"]["codeExposures"])
        self.assertIn("no source rule", assets["worker"]["codeExposures"])
        vulns = {vuln["assetId"]: vuln for vuln in payload["vulnerabilities"]}
        self.assertEqual(vulns["asset:api"]["codeExposure"], "request-controlled path")
        self.assertEqual(vulns["asset:api"]["effectivePath"]["order"][0], "asset")
        self.assertEqual(vulns["asset:job"]["codeExposure"], "reachable vulnerable API")
        self.assertEqual(vulns["asset:unused"]["codeExposure"], "SBOM only")
        self.assertEqual(vulns["asset:worker"]["codeExposure"], "no source rule")
        self.assertIn("No package-specific source rule", vulns["asset:worker"]["codeExposureDetail"])
        self.assertIn("package is imported", vulns["asset:importer"]["codeExposureDetail"])
        self.assertIn("dependency graph", vulns["asset:dependency"]["codeExposureDetail"])
        self.assertIn("absent", vulns["asset:absent"]["codeExposureDetail"])

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
        self.assertIn("Attack Paths</button>", html)
        self.assertIn("Architecture</button>", html)
        self.assertIn("Evidence Paths</button>", html)
        self.assertIn("Risk</button>", html)
        self.assertNotIn("Findings</button>", html)
        self.assertIn('id="riskTab" type="button" class="active" data-view="risk"', html)
        self.assertIn('let viewMode = "risk"', html)
        self.assertIn("function layoutAttackPaths", html)
        self.assertIn("function layoutRiskScenarios", html)
        self.assertIn("function renderRiskBoard", html)
        self.assertIn("function renderRiskRow", html)
        self.assertIn("function openScenarioAttackPath", html)
        self.assertIn("Attack Path", html)
        self.assertIn("Open path", html)
        self.assertIn("risk-path-link", html)
        self.assertIn("function renderAttackPathCard", html)
        self.assertIn("function renderAttackScenarioCard", html)
        self.assertIn("function renderAttackSummary", html)
        self.assertIn("function renderAttackNodeCard", html)
        self.assertIn("function nodeIcon", html)
        self.assertIn("function rawDisclosure", html)
        self.assertIn("function appendCategoryPanels", html)
        self.assertIn("function appendNodeLinks", html)
        self.assertIn("detail-link-button", html)
        self.assertIn("const overviewLimit", html)
        self.assertIn("function compactRouteNodes", html)
        self.assertIn("function renderAttackOverviewLane", html)
        self.assertIn("attack-overview-lane", html)
        self.assertIn("risk-board", html)
        self.assertIn("Issue categories", html)
        self.assertIn("shown on map", html)
        self.assertIn("Why this is prioritized", html)
        self.assertIn("Unknowns / visibility gaps", html)
        self.assertIn("Recommended next steps", html)
        self.assertIn("Path nodes", html)
        self.assertIn("Raw evidence", html)
        self.assertIn("attack-list-card", html)
        self.assertIn("attack-node-card", html)
        self.assertIn("function layoutArchitecture", html)
        self.assertIn("function renderArchitectureAsset", html)
        self.assertIn("zone-panel", html)
        self.assertIn("function renderLaneLabels", html)
        self.assertIn("function renderEdgeDefs", html)
        self.assertIn("function compactComponent", html)
        self.assertIn("priority ${value || \"unknown\"}", html)
        self.assertIn("network ${value || \"unknown\"}", html)
        self.assertIn("dataset.edgeSource", html)
        self.assertIn("dataset.edgeTarget", html)
        self.assertIn("dataset.nodeId", html)
        self.assertIn("title-main", html)
        self.assertIn("overflow-wrap: anywhere", html)
        self.assertIn("marker-end: url(#edge-arrow)", html)
        self.assertIn("const assetById = new Map", html)
        self.assertIn("const vulnerabilityByFindingKey = new Map", html)
        self.assertIn("const vulnerabilitiesByAssetId = new Map", html)
        self.assertIn("const networkPathsByAssetId = new Map", html)
        self.assertIn("function effectivePathLabels", html)
        self.assertIn('id="topLimit"', html)
        self.assertIn('id="highestPerAsset"', html)
        self.assertIn('id="findingType"', html)
        self.assertIn('id="confidence"', html)
        self.assertIn('id="evidenceLayer"', html)
        self.assertIn("pre.textContent = JSON.stringify", html)
        self.assertIn("card.tabIndex = 0", html)
        self.assertIn("top per asset", html)

    def test_attack_path_html_escapes_scanner_controlled_text(self) -> None:
        html = render_html_report([
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge -> aws_ecs_service.api"],
                component="pkg<script>alert(1)</script>",
                vulnerability="CVE-<script>alert(1)</script>",
            )
        ])

        self.assertNotIn("CVE-<script>alert(1)</script>", html)
        self.assertIn("CVE-\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", html)

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
            self.assertIn((path["entryNodeId"], path["id"], "entry-path"), edge_pairs)
            for asset_id in path.get("assetIds") or [path["assetId"]]:
                self.assertIn((path["id"], asset_id, "path-asset"), edge_pairs)
        for vulnerability_node in payload["vulnerabilities"]:
            self.assertIn((vulnerability_node["assetId"], vulnerability_node["id"], "asset-vulnerability"), edge_pairs)

    def test_shared_network_path_collapses_to_one_graph_node_for_multiple_assets(self) -> None:
        payload = _visual_payload([
            finding_for_visual(
                "api",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_lb_target_group.shared -> aws_ecs_service.api"],
                tier=Tier.HIGH,
                score=80.0,
                component="express",
                vulnerability="CVE-API",
            ),
            finding_for_visual(
                "worker",
                "public",
                ["terraform network path: public via aws_lb.edge public load balancer -> aws_lb_target_group.shared -> aws_ecs_service.worker"],
                tier=Tier.MEDIUM,
                score=60.0,
                component="requests",
                vulnerability="CVE-WORKER",
            ),
        ])

        self.assertEqual(len(payload["networkPaths"]), 1)
        path = payload["networkPaths"][0]
        self.assertEqual(path["steps"], ["aws_lb.edge public load balancer", "aws_lb_target_group.shared"])
        self.assertEqual(set(path["assetIds"]), {"asset:api", "asset:worker"})
        self.assertEqual(path["assetCount"], 2)

        graph = _visual_graph_model(payload)
        node_ids = {node["id"] for node in graph["nodes"]}
        edge_pairs = {(edge["source"], edge["target"], edge["role"]) for edge in graph["edges"]}
        self.assertFalse(graph["duplicateNodeIds"])
        self.assertIn(path["id"], node_ids)
        self.assertIn(path["entryNodeId"], node_ids)
        self.assertIn((path["entryNodeId"], path["id"], "entry-path"), edge_pairs)
        self.assertIn((path["id"], "asset:api", "path-asset"), edge_pairs)
        self.assertIn((path["id"], "asset:worker", "path-asset"), edge_pairs)
        self.assertEqual(len([edge for edge in graph["edges"] if edge["role"] == "entry-path"]), 1)

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
            path = next(path for path in payload["networkPaths"] if asset["id"] in (path.get("assetIds") or [path.get("assetId")]))
            self.assertLess(positions[path["entryNodeId"]]["x"], positions[path["id"]]["x"])
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
