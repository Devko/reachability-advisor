from __future__ import annotations

import unittest
from pathlib import Path

from reachability_advisor.effective_exposure import (
    enrich_context_with_effective_exposure,
    evaluate_effective_exposure,
)
from reachability_advisor.effective_graph import (
    build_effective_exposure_graph,
    effective_exposure_path,
    scoring_path_summary,
)
from reachability_advisor.models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    Reachability,
    SbomDocument,
    SourceEvidence,
    VulnerabilityRecord,
)
from reachability_advisor.provider_evaluators import evaluator_for_context
from reachability_advisor.scoring import ScorePolicy, score_finding


def _scored_finding(
    *,
    artifact_name: str = "api",
    component: Component | None = None,
    vulnerability: VulnerabilityRecord | None = None,
    source: SourceEvidence | None = None,
    context: ContextEvidence | None = None,
):
    return score_finding(
        SbomDocument(path=Path(f"{artifact_name}.cdx.json"), artifact=Artifact(name=artifact_name), components=[]),
        component or Component(name="requests", version="2.0.0", purl="pkg:pypi/requests@2.0.0"),
        vulnerability or VulnerabilityRecord(id="CVE-TEST", package_name="requests", cvss=8.8),
        source or SourceEvidence(reachability=Reachability.FUNCTION_REACHABLE, confidence=Confidence.MEDIUM),
        context or ContextEvidence(),
        ScorePolicy(),
    )


class EffectiveExposureEngineTests(unittest.TestCase):
    def test_aws_public_path_with_auth_and_scoped_identity_is_constrained(self) -> None:
        context = ContextEvidence(
            exposure="public",
            privilege="sensitive",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "aws",
                    "exposure": "public",
                    "path_type": "public_load_balancer",
                    "entry": "internet",
                    "steps": ["aws_lb.public", "aws_lb_listener.https", "aws_ecs_service.api"],
                    "confidence": "high",
                    "blockers": [{"kind": "auth_required", "evidence": "listener requires OIDC"}],
                    "source": "terraform-plan",
                }
            ],
            effective_access=[
                {
                    "provider": "aws",
                    "identity": "api-role",
                    "action": "secretsmanager:GetSecretValue",
                    "impact": "data_access",
                    "effect": "allow",
                    "resource_scope": "scoped",
                    "condition_keys": ["aws:ResourceTag/app"],
                    "decision": "allowed",
                    "confidence": "medium",
                    "blockers": [{"kind": "scoped_resource"}, {"kind": "condition"}],
                    "source": "terraform-plan",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]

        self.assertEqual(record["provider"], "aws")
        self.assertEqual(record["evaluator"], "aws.effective_exposure")
        self.assertEqual(record["decision"], "constrained")
        self.assertEqual(record["network"]["decision"], "constrained")
        self.assertEqual(record["identity"]["decision"], "constrained_allow")
        self.assertEqual({item["effect"] for item in record["blockers"]}, {"constrains"})
        self.assertTrue(all(edge["provider"] == "aws" for edge in record["edges"]))

    def test_azure_private_endpoint_blocks_public_effective_path(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.MEDIUM,
            network_paths=[
                {
                    "provider": "azure",
                    "exposure": "public",
                    "path_type": "public_gateway",
                    "entry": "internet",
                    "steps": ["azurerm_application_gateway.app", "azurerm_linux_web_app.api"],
                    "confidence": "medium",
                    "blockers": [{"kind": "public_network_disabled", "evidence": "public network access disabled"}],
                    "source": "terraform-plan",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]

        self.assertEqual(record["provider"], "azure")
        self.assertEqual(record["decision"], "blocked")
        self.assertEqual(record["network"]["decision"], "blocked")
        self.assertEqual(record["blockers"][0]["effect"], "blocks")

    def test_effective_exposure_uses_reachable_path_when_first_candidate_is_blocked(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "aws",
                    "exposure": "public",
                    "path_type": "public_load_balancer",
                    "entry": "internet",
                    "steps": ["internet", "aws_vpc_endpoint.api", "aws_ecs_service.api"],
                    "confidence": "high",
                    "blockers": [{"kind": "vpc_endpoint_only", "effect": "blocks", "evidence": "endpoint only"}],
                    "source": "terraform-plan",
                },
                {
                    "provider": "aws",
                    "exposure": "public",
                    "path_type": "public_load_balancer",
                    "entry": "internet",
                    "steps": ["internet", "aws_lb.public", "aws_ecs_service.api"],
                    "confidence": "high",
                    "source": "terraform-plan",
                },
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]

        self.assertEqual(record["decision"], "reachable")
        self.assertEqual(record["network"]["decision"], "reachable")
        self.assertEqual(record["network"]["steps"], ["internet", "aws_lb.public", "aws_ecs_service.api"])

    def test_effective_exposure_prefers_constrained_path_over_blocked_path(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "aws",
                    "exposure": "public",
                    "path_type": "public_load_balancer",
                    "entry": "internet",
                    "steps": ["internet", "aws_vpc_endpoint.api", "aws_ecs_service.api"],
                    "confidence": "high",
                    "blockers": [{"kind": "vpc_endpoint_only", "effect": "blocks", "evidence": "endpoint only"}],
                    "source": "terraform-plan",
                },
                {
                    "provider": "aws",
                    "exposure": "public",
                    "path_type": "public_load_balancer",
                    "entry": "internet",
                    "steps": ["internet", "aws_lb.public", "aws_wafv2_web_acl.edge", "aws_ecs_service.api"],
                    "confidence": "high",
                    "blockers": [{"kind": "waf_or_firewall_policy", "effect": "constrains", "evidence": "WAF attached"}],
                    "source": "terraform-plan",
                },
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]

        self.assertEqual(record["decision"], "constrained")
        self.assertEqual(record["network"]["decision"], "constrained")
        self.assertIn("waf_or_firewall_policy", {blocker["kind"] for blocker in record["network"]["blockers"]})
        self.assertNotIn("vpc_endpoint_only", {blocker["kind"] for blocker in record["network"]["blockers"]})

    def test_effective_exposure_keeps_blocked_decision_when_all_paths_are_blocked(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "aws",
                    "exposure": "public",
                    "path_type": "public_load_balancer",
                    "entry": "internet",
                    "steps": ["internet", "aws_vpc_endpoint.api", "aws_ecs_service.api"],
                    "confidence": "high",
                    "blockers": [{"kind": "vpc_endpoint_only", "effect": "blocks", "evidence": "endpoint only"}],
                    "source": "terraform-plan",
                },
                {
                    "provider": "aws",
                    "exposure": "internal",
                    "path_type": "internal_ingress",
                    "entry": "private_network",
                    "steps": ["private_network", "aws_security_group.closed", "aws_ecs_service.api"],
                    "confidence": "high",
                    "blockers": [{"kind": "security_group_no_ingress", "effect": "blocks", "evidence": "no ingress"}],
                    "source": "terraform-plan",
                },
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]

        self.assertEqual(record["decision"], "blocked")
        self.assertEqual(record["network"]["decision"], "blocked")
        self.assertIn("vpc_endpoint_only", {blocker["kind"] for blocker in record["network"]["blockers"]})

    def test_effective_exposure_prefers_reachable_internal_path_over_blocked_public_path(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "aws",
                    "exposure": "public",
                    "path_type": "public_load_balancer",
                    "entry": "internet",
                    "steps": ["internet", "aws_vpc_endpoint.api", "aws_ecs_service.api"],
                    "confidence": "high",
                    "blockers": [{"kind": "vpc_endpoint_only", "effect": "blocks", "evidence": "endpoint only"}],
                    "source": "terraform-plan",
                },
                {
                    "provider": "aws",
                    "exposure": "internal",
                    "path_type": "internal_ingress",
                    "entry": "private_network",
                    "steps": ["private_network", "aws_lb.internal", "aws_ecs_service.api"],
                    "confidence": "high",
                    "source": "terraform-plan",
                },
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]

        self.assertEqual(record["decision"], "reachable")
        self.assertEqual(record["exposure"], "internal")
        self.assertEqual(record["network"]["steps"], ["private_network", "aws_lb.internal", "aws_ecs_service.api"])

    def test_provider_layer_selects_identity_provider_when_network_provider_is_unknown(self) -> None:
        context = ContextEvidence(
            exposure="internal",
            source="context:test",
            confidence=Confidence.MEDIUM,
            network_paths=[
                {
                    "provider": "unknown",
                    "exposure": "internal",
                    "path_type": "internal_ingress",
                    "entry": "internal_network",
                    "steps": ["subnet:private", "aws_ecs_service.api"],
                    "confidence": "medium",
                    "source": "context:test",
                }
            ],
            effective_access=[
                {
                    "provider": "aws",
                    "identity": "aws_iam_role.api",
                    "action": "s3:PutObject",
                    "impact": "data_access",
                    "effect": "allow",
                    "decision": "allowed",
                    "confidence": "medium",
                    "blockers": [{"kind": "permission_boundary"}],
                }
            ],
        )

        self.assertEqual(evaluator_for_context(context).provider, "aws")
        record = evaluate_effective_exposure("api", context)[0]

        self.assertEqual(record["provider"], "aws")
        self.assertEqual(record["identity"]["decision"], "denied")
        self.assertEqual(record["decision"], "reachable_without_effective_identity")
        self.assertTrue(any(blocker["kind"] == "permission_boundary" and blocker["effect"] == "blocks" for blocker in record["identity"]["blockers"]))

    def test_aws_evaluator_interprets_scp_source_group_and_waf_evidence(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "aws",
                    "exposure": "public",
                    "path_type": "public_load_balancer",
                    "entry": "internet",
                    "steps": ["aws_lb.edge", "aws_security_group_rule.api source_security_group_id=sg-edge", "aws_ecs_service.api"],
                    "source_security_group_id": "sg-edge",
                    "web_acl_id": "aws_wafv2_web_acl.edge",
                    "confidence": "high",
                    "source": "terraform-plan",
                }
            ],
            effective_access=[
                {
                    "provider": "aws",
                    "identity": "aws_iam_role.api",
                    "action": "s3:GetObject",
                    "impact": "data_access",
                    "effect": "allow",
                    "decision": "allowed",
                    "resource_scope": "scoped",
                    "condition_keys": ["aws:PrincipalTag/team"],
                    "policy_layer": "service_control_policy",
                    "confidence": "high",
                    "source": "terraform-plan",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]
        network_kinds = {blocker["kind"] for blocker in record["network"]["blockers"]}
        identity_kinds = {blocker["kind"] for blocker in record["identity"]["blockers"]}

        self.assertEqual(record["decision"], "constrained")
        self.assertIn("source_security_group_restriction", network_kinds)
        self.assertIn("waf_or_firewall_policy", network_kinds)
        self.assertIn("scp_scope", identity_kinds)
        self.assertIn("scoped_resource", identity_kinds)
        self.assertIn("condition", identity_kinds)
        self.assertTrue(record["network"]["decision_basis"].startswith("constrained_by:"))
        self.assertTrue(record["identity"]["provider_decision_basis"].startswith("constrained_by:"))
        self.assertIn("network:", record["decision_basis"])

    def test_aws_evaluator_covers_api_vpce_resource_policy_and_trust_policy(self) -> None:
        network_context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "aws",
                    "exposure": "public",
                    "path_type": "public_serverless_url",
                    "entry": "internet",
                    "steps": ["aws_lambda_function_url.api"],
                    "authorization_type": "AWS_IAM",
                    "condition": {"aws:SourceVpce": "vpce-123"},
                    "cidr_blocks": ["10.0.0.0/8"],
                    "authorizer_id": "authz",
                    "private_link": True,
                    "confidence": "high",
                    "source": "terraform-plan",
                }
            ],
        )
        network_record = evaluate_effective_exposure("api", network_context)[0]
        network_kinds = {blocker["kind"] for blocker in network_record["network"]["blockers"]}

        self.assertEqual(network_record["decision"], "blocked")
        self.assertIn("lambda_function_url_aws_iam", network_kinds)
        self.assertIn("source_vpce_condition", network_kinds)
        self.assertIn("source_cidr_restriction", network_kinds)
        self.assertIn("api_authorizer", network_kinds)
        self.assertIn("vpc_endpoint_only", network_kinds)

        resource_policy_context = ContextEvidence(
            exposure="internal",
            confidence=Confidence.HIGH,
            network_paths=[{"provider": "aws", "exposure": "internal", "steps": ["aws_vpc.private", "aws_ecs_service.api"], "confidence": "high"}],
            effective_access=[
                {
                    "provider": "aws",
                    "identity": "aws_iam_role.api",
                    "action": "s3:GetObject",
                    "impact": "data_access",
                    "effect": "deny",
                    "decision": "denied_by_explicit_deny",
                    "decision_basis": "explicit_deny_precedence",
                    "policy_layer": "resource_policy",
                    "session_policy": True,
                    "confidence": "high",
                }
            ],
        )
        resource_policy_record = evaluate_effective_exposure("api", resource_policy_context)[0]
        identity_kinds = {blocker["kind"] for blocker in resource_policy_record["identity"]["blockers"]}

        self.assertIn("explicit_deny_precedence", identity_kinds)
        self.assertIn("resource_policy_deny", identity_kinds)
        self.assertIn("session_policy", identity_kinds)

        trust_context = ContextEvidence(
            exposure="internal",
            confidence=Confidence.HIGH,
            network_paths=[{"provider": "aws", "exposure": "internal", "steps": ["aws_vpc.private", "aws_ecs_service.api"], "confidence": "high"}],
            effective_access=[
                {
                    "provider": "aws",
                    "identity": "aws_iam_role.api",
                    "action": "sts:AssumeRole",
                    "impact": "iam_escalation",
                    "effect": "allow",
                    "decision": "allowed",
                    "policy_layer": "trust_policy",
                    "condition_keys": ["aws:PrincipalArn"],
                    "confidence": "high",
                }
            ],
        )
        trust_record = evaluate_effective_exposure("api", trust_context)[0]

        self.assertTrue(any(blocker["kind"] == "trust_policy_condition" for blocker in trust_record["identity"]["blockers"]))

    def test_aws_structured_network_evaluation_blocks_route_sg_and_nacl(self) -> None:
        route_context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "aws",
                    "exposure": "public",
                    "routes": [{"destination_cidr_block": "10.0.0.0/16", "gateway_id": "local", "state": "active"}],
                    "security_groups": [{"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "type": "ingress"}]}],
                    "network_acls": [{"rule_number": 100, "rule_action": "allow", "egress": False, "cidr_block": "0.0.0.0/0"}],
                }
            ],
        )
        route_record = evaluate_effective_exposure("api", route_context)[0]
        self.assertEqual(route_record["network"]["decision"], "blocked")
        self.assertIn("no_public_route", {blocker["kind"] for blocker in route_record["network"]["blockers"]})

        sg_context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "aws",
                    "exposure": "public",
                    "routes": [{"destination_cidr_block": "0.0.0.0/0", "gateway_id": "igw-123", "state": "active"}],
                    "security_groups": [{"ingress": [{"cidr_blocks": ["10.0.0.0/8"], "type": "ingress"}]}],
                }
            ],
        )
        sg_record = evaluate_effective_exposure("api", sg_context)[0]
        self.assertEqual(sg_record["network"]["decision"], "constrained")
        self.assertIn("source_cidr_restriction", {blocker["kind"] for blocker in sg_record["network"]["blockers"]})

        nacl_context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "aws",
                    "exposure": "public",
                    "routes": [{"destination_cidr_block": "0.0.0.0/0", "gateway_id": "igw-123", "state": "active"}],
                    "security_groups": [{"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "type": "ingress"}]}],
                    "network_acls": [
                        {"rule_number": 90, "rule_action": "deny", "egress": False, "cidr_block": "0.0.0.0/0"},
                        {"rule_number": 100, "rule_action": "allow", "egress": False, "cidr_block": "0.0.0.0/0"},
                    ],
                }
            ],
        )
        nacl_record = evaluate_effective_exposure("api", nacl_context)[0]
        self.assertEqual(nacl_record["network"]["decision"], "blocked")
        self.assertIn("network_acl_deny", {blocker["kind"] for blocker in nacl_record["network"]["blockers"]})

    def test_aws_resource_graph_builder_selects_nacl_precedence(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "aws",
                    "exposure": "public",
                    "entry": "internet",
                    "target": "aws_ecs_service.api",
                    "routes": [{"id": "route-public", "destination_cidr_block": "0.0.0.0/0", "gateway_id": "igw-123"}],
                    "network_acls": [
                        {
                            "id": "acl-api",
                            "ingress": [
                                {"id": "acl-deny", "rule_number": 90, "rule_action": "deny", "cidr_block": "0.0.0.0/0"},
                                {"id": "acl-allow", "rule_number": 100, "rule_action": "allow", "cidr_block": "0.0.0.0/0"},
                            ],
                        }
                    ],
                    "security_groups": [{"id": "sg-api", "ingress": [{"id": "sg-public", "cidr_blocks": ["0.0.0.0/0"]}]}],
                    "source": "terraform-plan",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]
        graph = record["network"]["network_graph"]
        acl_edge = next(edge for edge in graph["edges"] if edge["type"] == "network_acl")

        self.assertEqual(record["network"]["decision"], "blocked")
        self.assertEqual(acl_edge["precedence"], 90)
        self.assertIn("lowest numbered", acl_edge["precedence_reason"])
        self.assertTrue(graph["resource_graph"]["evaluated"])
        self.assertIn("network_acl_deny", {blocker["kind"] for blocker in record["network"]["blockers"]})

    def test_azure_resource_graph_builder_selects_lowest_priority_nsg_rule(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "azure",
                    "exposure": "public",
                    "entry": "internet",
                    "target": "azurerm_linux_web_app.api",
                    "network_security_rules": [
                        {"id": "nsg-deny", "priority": 100, "access": "Deny", "source_address_prefix": "*"},
                        {"id": "nsg-allow", "priority": 200, "access": "Allow", "source_address_prefix": "*"},
                    ],
                    "source": "terraform-plan",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]
        graph = record["network"]["network_graph"]
        nsg_edge = next(edge for edge in graph["edges"] if edge["type"] == "network_security_group")

        self.assertEqual(record["network"]["decision"], "blocked")
        self.assertEqual(nsg_edge["precedence"], 100)
        self.assertIn("lowest priority", nsg_edge["precedence_reason"])
        self.assertIn("nsg_deny", {blocker["kind"] for blocker in record["network"]["blockers"]})

    def test_gcp_resource_graph_builder_selects_lowest_priority_firewall_rule(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "gcp",
                    "exposure": "public",
                    "entry": "internet",
                    "target": "google_cloud_run_v2_service.api",
                    "firewall_rules": [
                        {"id": "fw-deny", "priority": 900, "action": "deny", "direction": "INGRESS", "source_ranges": ["0.0.0.0/0"]},
                        {"id": "fw-allow", "priority": 1000, "action": "allow", "direction": "INGRESS", "source_ranges": ["0.0.0.0/0"]},
                    ],
                    "source": "terraform-plan",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]
        graph = record["network"]["network_graph"]
        firewall_edge = next(edge for edge in graph["edges"] if edge["type"] == "firewall")

        self.assertEqual(record["network"]["decision"], "blocked")
        self.assertEqual(firewall_edge["precedence"], 900)
        self.assertIn("lowest priority", firewall_edge["precedence_reason"])
        self.assertIn("firewall_deny", {blocker["kind"] for blocker in record["network"]["blockers"]})

    def test_kubernetes_resource_graph_builder_applies_deny_policy_precedence(self) -> None:
        context = ContextEvidence(
            exposure="public",
            source="kubernetes-manifest",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "kubernetes",
                    "exposure": "public",
                    "entry": "internet",
                    "target": "kubernetes_deployment.api",
                    "ingresses": [{"id": "ingress-public", "class": "nginx"}],
                    "services": [{"id": "service-api"}],
                    "network_policies": [
                        {"id": "np-deny", "policy": "deny all ingress"},
                        {"id": "np-allow", "policy": "allow frontend"},
                    ],
                    "authorization_policies": [{"id": "mesh-deny", "action": "DENY"}],
                    "source": "kubernetes-manifest",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]
        graph = record["network"]["network_graph"]
        policy_edge = next(edge for edge in graph["edges"] if edge["type"] == "network_policy")

        self.assertEqual(record["network"]["decision"], "blocked")
        self.assertEqual(policy_edge["precedence"], 0)
        self.assertIn("NetworkPolicy", policy_edge["precedence_reason"])
        self.assertIn("network_policy_deny_all", {blocker["kind"] for blocker in record["network"]["blockers"]})

    def test_effective_access_prefers_explicit_deny_over_allow_records(self) -> None:
        context = ContextEvidence(
            exposure="internal",
            confidence=Confidence.HIGH,
            network_paths=[{"provider": "aws", "exposure": "internal", "confidence": "high", "steps": ["aws_vpc.private", "aws_ecs_service.api"]}],
            effective_access=[
                {
                    "provider": "aws",
                    "identity": "aws_iam_role.api",
                    "action": "secretsmanager:GetSecretValue",
                    "impact": "data_access",
                    "effect": "allow",
                    "decision": "allowed",
                    "policy_layer": "identity_policy",
                    "confidence": "high",
                },
                {
                    "provider": "aws",
                    "identity": "aws_iam_role.api",
                    "action": "secretsmanager:GetSecretValue",
                    "impact": "data_access",
                    "effect": "deny",
                    "decision": "denied_by_explicit_deny",
                    "policy_layer": "resource_policy",
                    "confidence": "high",
                },
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]

        self.assertEqual(record["identity"]["decision"], "denied")
        self.assertEqual(record["decision"], "reachable_without_effective_identity")
        self.assertEqual(record["identity"]["policy_layer"], "resource_policy")
        self.assertEqual(record["identity"]["evaluation_order"][0]["state"], "matched")
        self.assertEqual(record["identity"]["effective_access_model"]["authorization_model"], "aws_iam")
        self.assertTrue(record["identity"]["effective_access_model"]["explicit_deny_precedence"])
        self.assertEqual(record["identity"]["effective_access_model"]["resource_policy"], "blocks")

    def test_structured_policy_documents_drive_provider_effective_access(self) -> None:
        cases = [
            (
                "aws",
                {
                    "provider": "aws",
                    "identity": "aws_iam_role.api",
                    "action": "s3:GetObject",
                    "impact": "data_access",
                    "resource": "arn:aws:s3:::tenant-data/private.json",
                    "identity_policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::tenant-data/*",
                            }
                        ]
                    },
                    "permissions_boundary": {
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::tenant-data/private.json",
                            }
                        ]
                    },
                    "confidence": "medium",
                },
                "permission_boundary",
                "aws.structured_policy",
            ),
            (
                "azure",
                {
                    "provider": "azure",
                    "identity": "principal:api",
                    "action": "Microsoft.KeyVault/vaults/secrets/read",
                    "impact": "data_access",
                    "resource": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/v/secrets/api",
                    "role_definition": {
                        "permissions": [{"actions": ["Microsoft.KeyVault/vaults/secrets/read"]}],
                        "assignableScopes": ["/subscriptions/sub-a"],
                    },
                    "role_assignment": {"scope": "/subscriptions/sub-a/resourceGroups/rg-a"},
                    "deny_assignment": {
                        "permissions": [{"actions": ["Microsoft.KeyVault/vaults/secrets/read"]}],
                        "scope": "/subscriptions/sub-a/resourceGroups/rg-a",
                    },
                    "confidence": "medium",
                },
                "deny_assignment",
                "azure.structured_policy",
            ),
            (
                "gcp",
                {
                    "provider": "gcp",
                    "identity": "serviceAccount:api@prod.iam.gserviceaccount.com",
                    "action": "secretmanager.versions.access",
                    "impact": "data_access",
                    "resource": "projects/prod/secrets/api",
                    "iam_policy": {
                        "bindings": [
                            {
                                "permissions": ["secretmanager.versions.access"],
                                "resources": ["projects/prod/secrets/api"],
                                "condition": {"expression": "request.time < timestamp('2026-01-01T00:00:00Z')"},
                            }
                        ]
                    },
                    "deny_policy": {
                        "rules": [
                            {
                                "deniedPermissions": ["secretmanager.versions.access"],
                                "resources": ["projects/prod/secrets/api"],
                            }
                        ]
                    },
                    "confidence": "medium",
                },
                "deny_policy",
                "gcp.structured_policy",
            ),
            (
                "kubernetes",
                {
                    "provider": "kubernetes",
                    "identity": "system:serviceaccount:payments:api",
                    "action": "get secrets",
                    "impact": "data_access",
                    "resource": "secrets",
                    "namespace": "payments",
                    "rules": [
                        {"effect": "Deny", "verbs": ["get"], "resources": ["secrets"]},
                        {"verbs": ["get"], "resources": ["secrets"], "resourceNames": ["api-secret"]},
                    ],
                    "confidence": "medium",
                },
                "rbac_deny",
                "kubernetes.structured_policy",
            ),
        ]

        for provider, access_record, expected_blocker, expected_engine in cases:
            with self.subTest(provider=provider):
                context = ContextEvidence(
                    exposure="internal",
                    confidence=Confidence.HIGH,
                    network_paths=[{"provider": provider, "exposure": "internal", "confidence": "high", "steps": ["private-network", "api"]}],
                    effective_access=[access_record],
                )

                record = evaluate_effective_exposure("api", context)[0]
                identity = record["identity"]
                model = identity["effective_access_model"]
                blocker_kinds = {blocker["kind"] for blocker in identity["blockers"]}

                self.assertEqual(identity["decision"], "denied")
                self.assertEqual(model["policy_engine"], expected_engine)
                self.assertEqual(model["policy_evaluation"]["decision"], "denied")
                self.assertIn(expected_blocker, blocker_kinds)
                self.assertTrue(any(step["step"].startswith("policy:") for step in identity["evaluation_order"]))

    def test_structured_policy_documents_capture_trust_and_workload_identity_constraints(self) -> None:
        aws_context = ContextEvidence(
            exposure="internal",
            confidence=Confidence.HIGH,
            network_paths=[{"provider": "aws", "exposure": "internal", "confidence": "high", "steps": ["aws_vpc.private", "aws_ecs_service.api"]}],
            effective_access=[
                {
                    "provider": "aws",
                    "identity": "arn:aws:iam::111111111111:role/cicd",
                    "action": "sts:AssumeRole",
                    "impact": "iam_escalation",
                    "resource": "arn:aws:iam::222222222222:role/prod-api",
                    "trust_policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRole",
                                "Resource": "arn:aws:iam::222222222222:role/prod-api",
                                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-prod"}},
                            }
                        ]
                    },
                }
            ],
        )
        aws_record = evaluate_effective_exposure("api", aws_context)[0]
        aws_kinds = {blocker["kind"] for blocker in aws_record["identity"]["blockers"]}

        self.assertEqual(aws_record["identity"]["decision"], "constrained_allow")
        self.assertIn("trust_policy_condition", aws_kinds)
        self.assertEqual(aws_record["identity"]["effective_access_model"]["policy_engine"], "aws.structured_policy")

        gcp_context = ContextEvidence(
            exposure="internal",
            confidence=Confidence.HIGH,
            network_paths=[{"provider": "gcp", "exposure": "internal", "confidence": "high", "steps": ["gke", "cloud-run-api"]}],
            effective_access=[
                {
                    "provider": "gcp",
                    "identity": "principal://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/gke/subject/ns/api/sa/api",
                    "action": "iam.serviceAccounts.actAs",
                    "impact": "iam_escalation",
                    "resource": "projects/prod/serviceAccounts/api@prod.iam.gserviceaccount.com",
                    "iam_policy": {
                        "bindings": [
                            {
                                "permissions": ["iam.serviceAccounts.actAs"],
                                "resources": ["projects/prod/serviceAccounts/api@prod.iam.gserviceaccount.com"],
                                "workload_identity": "iam.gke.io/gcp-service-account=api@prod.iam.gserviceaccount.com",
                                "condition": {"expression": "resource.name.startsWith('projects/prod/')"},
                            }
                        ]
                    },
                }
            ],
        )
        gcp_record = evaluate_effective_exposure("api", gcp_context)[0]
        gcp_kinds = {blocker["kind"] for blocker in gcp_record["identity"]["blockers"]}

        self.assertEqual(gcp_record["identity"]["decision"], "constrained_allow")
        self.assertIn("workload_identity_condition", gcp_kinds)
        self.assertIn("service_account_impersonation", gcp_kinds)
        self.assertEqual(gcp_record["identity"]["effective_access_model"]["policy_engine"], "gcp.structured_policy")

    def test_structured_policy_documents_expand_common_azure_and_gcp_roles(self) -> None:
        azure_context = ContextEvidence(
            exposure="internal",
            confidence=Confidence.HIGH,
            network_paths=[{"provider": "azure", "exposure": "internal", "confidence": "high", "steps": ["vnet", "app"]}],
            effective_access=[
                {
                    "provider": "azure",
                    "identity": "principal:api",
                    "action": "Microsoft.KeyVault/vaults/secrets/read",
                    "impact": "data_access",
                    "resource": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/v/secrets/api",
                    "role_definition": {
                        "roleName": "Key Vault Secrets User",
                        "assignableScopes": ["/subscriptions/sub-a/resourceGroups/rg-a"],
                    },
                    "role_assignment": {"scope": "/subscriptions/sub-a/resourceGroups/rg-a"},
                }
            ],
        )
        azure_record = evaluate_effective_exposure("api", azure_context)[0]

        self.assertEqual(azure_record["identity"]["decision"], "constrained_allow")
        self.assertEqual(azure_record["identity"]["effective_access_model"]["policy_engine"], "azure.structured_policy")
        self.assertEqual(azure_record["identity"]["policy_evaluation"]["decision"], "constrained_allow")

        gcp_context = ContextEvidence(
            exposure="internal",
            confidence=Confidence.HIGH,
            network_paths=[{"provider": "gcp", "exposure": "internal", "confidence": "high", "steps": ["vpc", "run"]}],
            effective_access=[
                {
                    "provider": "gcp",
                    "identity": "serviceAccount:api@prod.iam.gserviceaccount.com",
                    "action": "secretmanager.versions.access",
                    "impact": "data_access",
                    "resource": "projects/prod/secrets/api",
                    "iam_policy": {
                        "bindings": [
                            {
                                "role": "roles/secretmanager.secretAccessor",
                                "resources": ["projects/prod/secrets/api"],
                                "condition": {"expression": "resource.name.startsWith('projects/prod/')"},
                            }
                        ]
                    },
                }
            ],
        )
        gcp_record = evaluate_effective_exposure("api", gcp_context)[0]

        self.assertEqual(gcp_record["identity"]["decision"], "constrained_allow")
        self.assertEqual(gcp_record["identity"]["effective_access_model"]["policy_engine"], "gcp.structured_policy")
        self.assertEqual(gcp_record["identity"]["policy_evaluation"]["decision"], "constrained_allow")

    def test_provider_iam_deny_precedence_over_high_impact_allow_across_clouds(self) -> None:
        cases = [
            (
                "azure",
                {
                    "provider": "azure",
                    "identity": "principal",
                    "action": "Microsoft.KeyVault/vaults/secrets/read",
                    "impact": "data_access",
                    "effect": "deny",
                    "decision": "denied",
                    "policy_layer": "deny_assignment",
                    "resource": "secret:api",
                    "confidence": "high",
                },
                "azure_rbac",
            ),
            (
                "gcp",
                {
                    "provider": "gcp",
                    "identity": "serviceAccount:api",
                    "action": "secretmanager.versions.access",
                    "impact": "data_access",
                    "effect": "deny",
                    "decision": "denied",
                    "policy_layer": "deny_policy",
                    "resource": "secret:api",
                    "confidence": "high",
                },
                "gcp_iam",
            ),
            (
                "kubernetes",
                {
                    "provider": "kubernetes",
                    "identity": "system:serviceaccount:api:api",
                    "action": "get secrets",
                    "impact": "data_access",
                    "effect": "deny",
                    "decision": "denied",
                    "policy_layer": "kubernetes_rbac",
                    "resource": "secret:api",
                    "confidence": "high",
                },
                "kubernetes_rbac",
            ),
        ]

        for provider, deny_record, model_name in cases:
            with self.subTest(provider=provider):
                context = ContextEvidence(
                    exposure="internal",
                    confidence=Confidence.HIGH,
                    network_paths=[{"provider": provider, "exposure": "internal", "confidence": "high", "steps": ["network", "api"]}],
                    effective_access=[
                        {
                            "provider": provider,
                            "identity": "runtime",
                            "action": deny_record["action"],
                            "impact": "data_access",
                            "effect": "allow",
                            "decision": "allowed",
                            "policy_layer": "identity_policy",
                            "resource": "secret:api",
                            "confidence": "high",
                        },
                        deny_record,
                    ],
                )

                record = evaluate_effective_exposure("api", context)[0]

                self.assertEqual(record["identity"]["decision"], "denied")
                self.assertEqual(record["decision"], "reachable_without_effective_identity")
                self.assertEqual(record["identity"]["effective_access_model"]["authorization_model"], model_name)
                self.assertTrue(record["identity"]["effective_access_model"]["deny_observed"])

    def test_provider_iam_unrelated_low_impact_deny_does_not_hide_admin_allow(self) -> None:
        for provider in ("aws", "azure", "gcp", "kubernetes"):
            with self.subTest(provider=provider):
                context = ContextEvidence(
                    exposure="internal",
                    confidence=Confidence.HIGH,
                    network_paths=[{"provider": provider, "exposure": "internal", "confidence": "high", "steps": ["network", "api"]}],
                    effective_access=[
                        {
                            "provider": provider,
                            "identity": "runtime",
                            "action": "*",
                            "impact": "admin_control",
                            "effect": "allow",
                            "decision": "allowed",
                            "policy_layer": "identity_policy",
                            "resource": "*",
                            "confidence": "high",
                        },
                        {
                            "provider": provider,
                            "identity": "runtime",
                            "action": "read_metadata",
                            "impact": "limited_access",
                            "effect": "deny",
                            "decision": "denied",
                            "policy_layer": "resource_policy",
                            "resource": "metadata:debug",
                            "confidence": "high",
                        },
                    ],
                )

                record = evaluate_effective_exposure("api", context)[0]

                self.assertEqual(record["identity"]["decision"], "allowed")
                self.assertEqual(record["identity"]["impact"], "admin_control")
                self.assertFalse(record["identity"]["effective_access_model"]["deny_observed"])

    def test_non_aws_iam_models_expose_provider_layer_states(self) -> None:
        azure = evaluate_effective_exposure(
            "api",
            ContextEvidence(
                exposure="internal",
                confidence=Confidence.HIGH,
                network_paths=[{"provider": "azure", "exposure": "internal", "confidence": "high", "steps": ["vnet", "app"]}],
                effective_access=[
                    {
                        "provider": "azure",
                        "identity": "managed_identity.api",
                        "action": "Microsoft.KeyVault/vaults/secrets/read",
                        "impact": "data_access",
                        "effect": "allow",
                        "decision": "allowed",
                        "policy_layer": "role_assignment",
                        "resource": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/payments",
                        "condition_keys": ["@Resource[Microsoft.KeyVault/vaults:name]"],
                        "assignable_scopes": ["/subscriptions/sub/resourceGroups/rg"],
                        "evidence": "PIM eligible role assignment with condition",
                        "confidence": "high",
                    }
                ],
            ),
        )[0]
        gcp = evaluate_effective_exposure(
            "api",
            ContextEvidence(
                exposure="internal",
                confidence=Confidence.HIGH,
                network_paths=[{"provider": "gcp", "exposure": "internal", "confidence": "high", "steps": ["vpc", "run"]}],
                effective_access=[
                    {
                        "provider": "gcp",
                        "identity": "serviceAccount:gke-api",
                        "action": "iam.serviceAccounts.actAs",
                        "impact": "iam_escalation",
                        "effect": "allow",
                        "decision": "allowed",
                        "policy_layer": "principal_access_boundary",
                        "resource": "projects/prod/serviceAccounts/runtime",
                        "condition_keys": ["resource.name"],
                        "evidence": "workload_identity principal_access_boundary organization_policy",
                        "confidence": "high",
                    }
                ],
            ),
        )[0]
        k8s = evaluate_effective_exposure(
            "api",
            ContextEvidence(
                exposure="internal",
                confidence=Confidence.HIGH,
                network_paths=[{"provider": "kubernetes", "exposure": "internal", "confidence": "high", "steps": ["svc", "deploy"]}],
                effective_access=[
                    {
                        "provider": "kubernetes",
                        "identity": "system:serviceaccount:payments:api",
                        "action": "impersonate users",
                        "impact": "iam_escalation",
                        "effect": "allow",
                        "decision": "allowed",
                        "policy_layer": "cluster_role_binding",
                        "resource_scope": "global",
                        "verbs": ["get", "impersonate"],
                        "resources": ["secrets", "users"],
                        "non_resource_urls": ["/metrics"],
                        "aggregation_rule": {"clusterRoleSelectors": []},
                        "confidence": "high",
                    }
                ],
            ),
        )[0]

        azure_model = azure["identity"]["effective_access_model"]
        self.assertEqual(azure_model["authorization_model"], "azure_rbac")
        self.assertEqual(azure_model["scope_level"], "resource_group")
        self.assertEqual(azure_model["conditions_and_scope"], "constrains")
        self.assertEqual(azure_model["role_definition_scope"], "constrains")
        self.assertEqual(azure_model["pim"], "constrains")

        gcp_model = gcp["identity"]["effective_access_model"]
        self.assertEqual(gcp_model["authorization_model"], "gcp_iam")
        self.assertEqual(gcp_model["principal_access_boundary"], "constrains")
        self.assertEqual(gcp_model["organization_policy"], "constrains")
        self.assertTrue(gcp_model["workload_identity_mapping"])
        self.assertTrue(gcp_model["service_account_impersonation"])

        k8s_model = k8s["identity"]["effective_access_model"]
        self.assertEqual(k8s_model["authorization_model"], "kubernetes_rbac")
        self.assertTrue(k8s_model["cluster_scope"])
        self.assertTrue(k8s_model["non_resource_url_scope"])
        self.assertTrue(k8s_model["aggregation_rule_scope"])
        self.assertEqual(k8s_model["privilege_escalation_verbs"], ["impersonate"])

    def test_provider_evaluators_classify_route_firewall_and_ingress_auth_uncertainty(self) -> None:
        aws = evaluate_effective_exposure(
            "api",
            ContextEvidence(
                exposure="public",
                confidence=Confidence.HIGH,
                network_paths=[
                    {
                        "provider": "aws",
                        "exposure": "public",
                        "steps": ["aws_lb_listener.authenticate_oidc", "aws_network_acl.api", "aws_route_table.public"],
                        "authenticate_oidc": True,
                        "network_acl": [{"rule_action": "allow"}],
                        "route_table": "aws_route_table.public",
                    }
                ],
            ),
        )[0]
        azure = evaluate_effective_exposure(
            "api",
            ContextEvidence(
                exposure="public",
                confidence=Confidence.HIGH,
                network_paths=[
                    {
                        "provider": "azure",
                        "exposure": "public",
                        "steps": ["azurerm_application_gateway.edge auth", "azurerm_network_security_rule.allow", "azurerm_route_table.app"],
                    }
                ],
            ),
        )[0]
        gcp = evaluate_effective_exposure(
            "api",
            ContextEvidence(
                exposure="public",
                confidence=Confidence.HIGH,
                network_paths=[
                    {
                        "provider": "gcp",
                        "exposure": "public",
                        "steps": ["google_compute_firewall.priority=1000", "google_compute_route.default"],
                        "priority": 1000,
                    }
                ],
            ),
        )[0]
        k8s = evaluate_effective_exposure(
            "api",
            ContextEvidence(
                exposure="public",
                confidence=Confidence.HIGH,
                network_paths=[
                    {
                        "provider": "kubernetes",
                        "exposure": "public",
                        "steps": ["ingress nginx.ingress.kubernetes.io/auth-url", "securityContext"],
                    }
                ],
            ),
        )[0]

        self.assertIn("elb_listener_auth", {blocker["kind"] for blocker in aws["network"]["blockers"]})
        self.assertIn("nacl_rule_order_unknown", {blocker["kind"] for blocker in aws["network"]["blockers"]})
        self.assertIn("application_gateway_auth", {blocker["kind"] for blocker in azure["network"]["blockers"]})
        self.assertIn("nsg_priority_unknown", {blocker["kind"] for blocker in azure["network"]["blockers"]})
        self.assertIn("firewall_priority_unknown", {blocker["kind"] for blocker in gcp["network"]["blockers"]})
        self.assertIn("route_precedence_unknown", {blocker["kind"] for blocker in gcp["network"]["blockers"]})
        self.assertIn("ingress_controller_auth", {blocker["kind"] for blocker in k8s["network"]["blockers"]})
        self.assertIn("pod_security_boundary", {blocker["kind"] for blocker in k8s["network"]["blockers"]})

    def test_provider_network_graph_solves_typed_edges(self) -> None:
        aws = evaluate_effective_exposure(
            "api",
            ContextEvidence(
                exposure="public",
                confidence=Confidence.HIGH,
                network_paths=[
                    {
                        "provider": "aws",
                        "exposure": "public",
                        "entry": "internet",
                        "target": "aws_ecs_service.api",
                        "network_graph": {
                            "edges": [
                                {
                                    "from": "internet",
                                    "to": "aws_route.public",
                                    "type": "route",
                                    "destination_cidr_block": "0.0.0.0/0",
                                    "gateway_id": "igw-123",
                                },
                                {
                                    "from": "aws_route.public",
                                    "to": "aws_security_group.api",
                                    "type": "security_group",
                                    "cidr_blocks": ["10.0.0.0/8"],
                                },
                                {"from": "aws_security_group.api", "to": "aws_ecs_service.api", "type": "load_balancer"},
                            ]
                        },
                    }
                ],
            ),
        )[0]
        azure = evaluate_effective_exposure(
            "api",
            ContextEvidence(
                exposure="public",
                confidence=Confidence.HIGH,
                network_paths=[
                    {
                        "provider": "azure",
                        "exposure": "public",
                        "entry": "internet",
                        "target": "azurerm_linux_web_app.api",
                        "network_graph": {
                            "edges": [
                                {"from": "internet", "to": "azurerm_application_gateway.edge", "type": "gateway"},
                                {
                                    "from": "azurerm_application_gateway.edge",
                                    "to": "azurerm_network_security_rule.deny",
                                    "type": "network_security_group",
                                    "access": "Deny",
                                    "priority": 100,
                                },
                                {"from": "azurerm_network_security_rule.deny", "to": "azurerm_linux_web_app.api", "type": "service"},
                            ]
                        },
                    }
                ],
            ),
        )[0]
        gcp = evaluate_effective_exposure(
            "api",
            ContextEvidence(
                exposure="public",
                confidence=Confidence.HIGH,
                network_paths=[
                    {
                        "provider": "gcp",
                        "exposure": "public",
                        "entry": "internet",
                        "target": "google_cloud_run_v2_service.api",
                        "network_graph": {
                            "edges": [
                                {
                                    "from": "internet",
                                    "to": "google_compute_firewall.public",
                                    "type": "firewall",
                                    "source_ranges": ["0.0.0.0/0"],
                                    "priority": 1000,
                                },
                                {"from": "google_compute_firewall.public", "to": "google_cloud_run_v2_service.api", "type": "gateway"},
                            ]
                        },
                    }
                ],
            ),
        )[0]
        k8s = evaluate_effective_exposure(
            "api",
            ContextEvidence(
                exposure="public",
                confidence=Confidence.HIGH,
                network_paths=[
                    {
                        "provider": "kubernetes",
                        "exposure": "public",
                        "entry": "internet",
                        "target": "deployment/api",
                        "network_graph": {
                            "edges": [
                                {"from": "internet", "to": "ingress/api", "type": "ingress"},
                                {"from": "ingress/api", "to": "networkpolicy/default-deny", "type": "network_policy", "policy": "deny all ingress"},
                                {"from": "networkpolicy/default-deny", "to": "deployment/api", "type": "service"},
                            ]
                        },
                    }
                ],
            ),
        )[0]

        self.assertEqual(aws["network"]["network_graph"]["decision"], "constrained")
        self.assertEqual(aws["network"]["decision"], "constrained")
        self.assertIn("source_cidr_restriction", {blocker["kind"] for blocker in aws["network"]["blockers"]})
        self.assertEqual(azure["network"]["network_graph"]["decision"], "blocked")
        self.assertEqual(azure["network"]["decision"], "blocked")
        self.assertIn("nsg_deny", {blocker["kind"] for blocker in azure["network"]["blockers"]})
        self.assertEqual(gcp["network"]["network_graph"]["decision"], "constrained")
        self.assertIn("firewall_priority_unknown", {blocker["kind"] for blocker in gcp["network"]["blockers"]})
        self.assertEqual(k8s["network"]["network_graph"]["decision"], "blocked")
        self.assertIn("network_policy_deny_all", {blocker["kind"] for blocker in k8s["network"]["blockers"]})

    def test_network_graph_requires_connected_path_to_target(self) -> None:
        record = evaluate_effective_exposure(
            "api",
            ContextEvidence(
                exposure="public",
                confidence=Confidence.HIGH,
                network_paths=[
                    {
                        "provider": "aws",
                        "exposure": "public",
                        "entry": "internet",
                        "target": "aws_ecs_service.api",
                        "network_graph": {
                            "edges": [
                                {"from": "internet", "to": "aws_route.public", "type": "route", "destination_cidr_block": "0.0.0.0/0", "gateway_id": "igw-123"},
                                {"from": "aws_security_group.other", "to": "aws_ecs_service.api", "type": "security_group", "cidr_blocks": ["0.0.0.0/0"]},
                            ]
                        },
                    }
                ],
            ),
        )[0]

        self.assertEqual(record["network"]["decision"], "blocked")
        self.assertEqual(record["network"]["network_graph"]["evaluation_order"][0]["state"], "no_path")
        self.assertIn("unconnected_network_graph", {blocker["kind"] for blocker in record["network"]["blockers"]})

    def test_gcp_iap_and_cloud_armor_are_provider_constraints(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "gcp",
                    "exposure": "public",
                    "path_type": "public_gateway",
                    "entry": "internet",
                    "steps": ["google_compute_backend_service.api with IAP", "cloud_armor security_policy"],
                    "confidence": "high",
                    "source": "terraform-plan",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]
        blocker_kinds = {blocker["kind"] for blocker in record["network"]["blockers"]}

        self.assertEqual(record["provider"], "gcp")
        self.assertEqual(record["network"]["decision"], "constrained")
        self.assertIn("iap_required", blocker_kinds)
        self.assertIn("cloud_armor_policy", blocker_kinds)

    def test_azure_evaluator_applies_private_endpoint_and_deny_assignment(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "azure",
                    "exposure": "public",
                    "path_type": "public_gateway",
                    "entry": "internet",
                    "steps": ["azurerm_application_gateway.edge", "azurerm_private_endpoint.api", "azurerm_linux_web_app.api"],
                    "private_endpoint": "azurerm_private_endpoint.api",
                    "auth_settings": [{"enabled": True}],
                    "confidence": "high",
                    "source": "terraform-plan",
                }
            ],
            effective_access=[
                {
                    "provider": "azure",
                    "identity": "azurerm_user_assigned_identity.api",
                    "action": "Microsoft.KeyVault/vaults/secrets/read",
                    "impact": "data_access",
                    "effect": "deny",
                    "decision": "denied",
                    "policy_layer": "deny_assignment",
                    "confidence": "high",
                    "source": "terraform-plan",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]

        self.assertEqual(record["decision"], "blocked")
        self.assertTrue(any(blocker["kind"] == "private_endpoint" and blocker["effect"] == "blocks" for blocker in record["network"]["blockers"]))
        self.assertTrue(any(blocker["kind"] == "deny_assignment" and blocker["effect"] == "blocks" for blocker in record["identity"]["blockers"]))
        self.assertEqual(record["decision_basis"], "network:blocked_by:private_endpoint")
        self.assertEqual(record["identity"]["effective_access_model"]["authorization_model"], "azure_rbac")
        self.assertTrue(record["identity"]["effective_access_model"]["deny_assignment"])

    def test_azure_evaluator_covers_access_restrictions_waf_scope_and_policy_deny(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "azure",
                    "exposure": "public",
                    "path_type": "public_gateway",
                    "entry": "internet",
                    "steps": ["azurerm_frontdoor_endpoint.edge", "azurerm_linux_web_app.api"],
                    "access_restriction": [{"action": "Deny"}],
                    "network_security_rule": [{"access": "Deny"}],
                    "web_application_firewall_policy_link_id": "waf",
                    "confidence": "high",
                    "source": "terraform-plan",
                }
            ],
            effective_access=[
                {
                    "provider": "azure",
                    "identity": "principal",
                    "action": "Microsoft.KeyVault/vaults/secrets/read",
                    "impact": "data_access",
                    "effect": "deny",
                    "decision": "denied",
                    "decision_basis": "resource_policy_deny",
                    "policy_layer": "resource_policy",
                    "resource": "/providers/Microsoft.Management/managementGroups/prod",
                    "evidence": "PIM eligible assignment",
                    "confidence": "high",
                    "source": "terraform-plan",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]
        network_kinds = {blocker["kind"] for blocker in record["network"]["blockers"]}
        identity_kinds = {blocker["kind"] for blocker in record["identity"]["blockers"]}

        self.assertIn("access_restriction_deny", network_kinds)
        self.assertIn("nsg_deny", network_kinds)
        self.assertIn("front_door_waf", network_kinds)
        self.assertIn("management_group_scope", identity_kinds)
        self.assertIn("pim_eligible_only", identity_kinds)
        self.assertIn("resource_policy_deny", identity_kinds)

    def test_gcp_evaluator_interprets_conditional_workload_identity(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "gcp",
                    "exposure": "public",
                    "path_type": "public_gateway",
                    "entry": "internet",
                    "steps": ["google_compute_backend_service.api with IAP", "cloud_armor security_policy"],
                    "confidence": "high",
                    "source": "terraform-plan",
                }
            ],
            effective_access=[
                {
                    "provider": "gcp",
                    "identity": "serviceAccount:gke-api",
                    "action": "secretmanager.versions.access",
                    "impact": "data_access",
                    "effect": "allow",
                    "decision": "allowed",
                    "resource_scope": "scoped",
                    "condition_keys": ["request.time"],
                    "policy_layer": "resource_policy",
                    "evidence": "workload_identity binding with condition",
                    "confidence": "medium",
                    "source": "terraform-plan",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]
        identity_kinds = {blocker["kind"] for blocker in record["identity"]["blockers"]}

        self.assertEqual(record["provider"], "gcp")
        self.assertEqual(record["decision"], "constrained")
        self.assertIn("conditional_iam_binding", identity_kinds)
        self.assertIn("workload_identity_condition", identity_kinds)
        self.assertTrue(record["identity"]["provider_decision_basis"].startswith("constrained_by:"))

    def test_gcp_evaluator_covers_private_service_connect_internal_ingress_and_deny_policy(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "gcp",
                    "exposure": "public",
                    "path_type": "public_gateway",
                    "entry": "internet",
                    "steps": ["google_compute_backend_service.api", "private_service_connect endpoint"],
                    "ingress": "INGRESS_INTERNAL_ONLY",
                    "vpc_access_connector": "projects/p/locations/l/connectors/c",
                    "egress": "ALL_TRAFFIC",
                    "confidence": "high",
                    "source": "terraform-plan",
                }
            ],
            effective_access=[
                {
                    "provider": "gcp",
                    "identity": "serviceAccount:api",
                    "action": "secretmanager.versions.access",
                    "impact": "data_access",
                    "effect": "deny",
                    "decision": "denied",
                    "policy_layer": "deny_policy",
                    "resource": "organizations/123/folders/456/secrets/api",
                    "confidence": "high",
                    "source": "terraform-plan",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]
        network_kinds = {blocker["kind"] for blocker in record["network"]["blockers"]}
        identity_kinds = {blocker["kind"] for blocker in record["identity"]["blockers"]}

        self.assertEqual(record["decision"], "blocked")
        self.assertIn("private_endpoint", network_kinds)
        self.assertIn("ingress_internal_only", network_kinds)
        self.assertIn("serverless_vpc_connector_egress_only", network_kinds)
        self.assertIn("deny_policy", identity_kinds)
        self.assertIn("organization_scope", identity_kinds)
        self.assertIn("folder_scope", identity_kinds)
        self.assertEqual(record["identity"]["effective_access_model"]["authorization_model"], "gcp_iam")
        self.assertTrue(record["identity"]["effective_access_model"]["deny_policy"])
        self.assertEqual(record["identity"]["effective_access_model"]["scope_level"], "organization")

    def test_kubernetes_service_mesh_policy_is_provider_constraint(self) -> None:
        context = ContextEvidence(
            exposure="internal",
            source="kubernetes-manifest",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "kubernetes",
                    "exposure": "internal",
                    "path_type": "internal_ingress",
                    "entry": "internal_network",
                    "steps": ["kubernetes_service.api", "AuthorizationPolicy strict mTLS"],
                    "confidence": "high",
                    "source": "kubernetes-manifest",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]

        self.assertEqual(record["provider"], "kubernetes")
        self.assertEqual(record["network"]["decision"], "constrained")
        self.assertTrue(any(blocker["kind"] == "service_mesh_policy" for blocker in record["network"]["blockers"]))

    def test_kubernetes_evaluator_interprets_network_policy_and_rbac_scope(self) -> None:
        context = ContextEvidence(
            exposure="internal",
            source="kubernetes-manifest",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "kubernetes",
                    "exposure": "internal",
                    "path_type": "internal_ingress",
                    "entry": "internal_network",
                    "steps": ["Service api", "NetworkPolicy allow frontend", "PeerAuthentication STRICT mTLS"],
                    "confidence": "high",
                    "source": "kubernetes-manifest",
                }
            ],
            effective_access=[
                {
                    "provider": "kubernetes",
                    "identity": "system:serviceaccount:payments:api",
                    "action": "get secrets",
                    "impact": "data_access",
                    "effect": "allow",
                    "decision": "allowed",
                    "resource_scope": "scoped",
                    "condition_keys": [],
                    "policy_layer": "kubernetes_rbac",
                    "resource_names": ["payments-secret"],
                    "namespace": "payments",
                    "confidence": "high",
                    "source": "kubernetes-manifest",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]
        network_kinds = {blocker["kind"] for blocker in record["network"]["blockers"]}
        identity_kinds = {blocker["kind"] for blocker in record["identity"]["blockers"]}

        self.assertEqual(record["decision"], "constrained")
        self.assertIn("network_policy_allow_list", network_kinds)
        self.assertIn("service_mesh_mtls_strict", network_kinds)
        self.assertIn("rbac_resource_names", identity_kinds)
        self.assertIn("service_account_scope", identity_kinds)
        self.assertIn("namespace_scope", identity_kinds)
        self.assertEqual(record["identity"]["effective_access_model"]["authorization_model"], "kubernetes_rbac")
        self.assertTrue(record["identity"]["effective_access_model"]["resource_names_scope"])
        self.assertEqual(record["identity"]["effective_access_model"]["scope_level"], "resource_names")

    def test_kubernetes_evaluator_covers_deny_all_internal_ingress_and_rbac_deny(self) -> None:
        context = ContextEvidence(
            exposure="public",
            source="kubernetes-manifest",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "kubernetes",
                    "exposure": "public",
                    "path_type": "public_ingress",
                    "entry": "internet",
                    "steps": ["Ingress ingress_class internal", "NetworkPolicy deny all ingress", "AuthorizationPolicy DENY"],
                    "confidence": "high",
                    "source": "kubernetes-manifest",
                }
            ],
            effective_access=[
                {
                    "provider": "kubernetes",
                    "identity": "system:serviceaccount:default:api",
                    "action": "get secrets",
                    "impact": "data_access",
                    "effect": "deny",
                    "decision": "denied",
                    "policy_layer": "kubernetes_rbac",
                    "evidence": "forbidden by RBAC",
                    "confidence": "high",
                    "source": "kubernetes-manifest",
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]
        network_kinds = {blocker["kind"] for blocker in record["network"]["blockers"]}
        identity_kinds = {blocker["kind"] for blocker in record["identity"]["blockers"]}

        self.assertEqual(record["decision"], "blocked")
        self.assertIn("network_policy_deny_all", network_kinds)
        self.assertIn("ingress_class_internal", network_kinds)
        self.assertIn("authorization_policy_deny", network_kinds)
        self.assertIn("rbac_deny", identity_kinds)

    def test_kubernetes_network_policy_deny_all_becomes_blocked_effective_path(self) -> None:
        context = ContextEvidence(
            exposure="private",
            source="kubernetes-manifest",
            confidence=Confidence.HIGH,
            evidence=[
                "context network policy: private via kubernetes_deployment.api; selected NetworkPolicy resources deny all ingress",
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]

        self.assertEqual(record["provider"], "kubernetes")
        self.assertEqual(record["decision"], "blocked")
        self.assertEqual(record["network"]["blockers"][0]["kind"], "network_policy_deny_all")
        self.assertEqual(record["network"]["blockers"][0]["effect"], "blocks")

    def test_unknown_provider_records_uncertainty_instead_of_confirmed_reachability(self) -> None:
        context = ContextEvidence(exposure="unknown", source="context:test", confidence=Confidence.LOW)

        record = evaluate_effective_exposure("api", context)[0]

        self.assertEqual(record["provider"], "unknown")
        self.assertEqual(record["decision"], "unknown")
        self.assertIn("network exposure is unresolved", record["unknowns"])
        self.assertIn("no identity/effective-access evidence", record["unknowns"])

    def test_scoring_uses_effective_exposure_blockers_even_when_raw_path_has_no_effect(self) -> None:
        context = enrich_context_with_effective_exposure(
            "api",
            ContextEvidence(
                exposure="public",
                privilege="sensitive",
                confidence=Confidence.HIGH,
                network_paths=[
                    {
                        "provider": "aws",
                        "exposure": "public",
                        "path_type": "public_load_balancer",
                        "entry": "internet",
                        "steps": ["aws_lb.public", "aws_ecs_service.api"],
                        "confidence": "high",
                        "blockers": [{"kind": "auth_required", "evidence": "OIDC auth"}],
                        "source": "terraform-plan",
                    }
                ],
            ),
        )
        finding = score_finding(
            SbomDocument(path=Path("api.cdx.json"), artifact=Artifact(name="api"), components=[]),
            Component(name="requests", version="2.0.0", purl="pkg:pypi/requests@2.0.0"),
            VulnerabilityRecord(id="CVE-TEST", package_name="requests", cvss=9.8),
            SourceEvidence(reachability=Reachability.ATTACKER_CONTROLLED, confidence=Confidence.HIGH),
            context,
            ScorePolicy(),
        )

        self.assertEqual(finding.tier.value, "high")
        self.assertTrue(any(gate["name"] == "network_blocker" for gate in finding.score_details["gates"]))
        self.assertEqual(finding.context.effective_exposure[0]["decision"], "constrained")

    def test_effective_graph_uses_effective_access_when_exposure_record_has_no_identity(self) -> None:
        context = ContextEvidence(
            exposure="external",
            privilege="sensitive",
            source="terraform:aws",
            confidence=Confidence.MEDIUM,
            effective_exposure=[
                {
                    "decision": "reachable",
                    "network": {
                        "source": "terraform:aws",
                        "provider": "aws",
                        "exposure": "external",
                        "path_type": "restricted_external_ingress",
                        "entry": "external_cidr",
                        "steps": ["10.0.0.0/8", "aws_security_group_rule.allow_partner", "aws_ecs_service.api"],
                        "confidence": "medium",
                    },
                }
            ],
            effective_access=[
                {
                    "provider": "aws",
                    "identity": "aws_iam_role.api",
                    "action": "s3:GetObject",
                    "impact": "data_access",
                    "resource": "arn:aws:s3:::tenant-data/*",
                    "decision": "allowed",
                    "confidence": "high",
                    "source": "terraform:aws",
                    "blockers": [{"kind": "condition", "evidence": "aws:PrincipalTag/team"}],
                    "unknowns": ["trust policy condition not fully evaluated"],
                }
            ],
        )

        path = effective_exposure_path(_scored_finding(context=context))
        identity = next(node for node in path["nodes"] if node["kind"] == "identity")

        self.assertEqual(identity["label"], "aws_iam_role.api")
        self.assertEqual(identity["decision"], "allowed")
        self.assertEqual(identity["provider"], "aws")
        self.assertEqual(identity["blockers"][0]["kind"], "condition")
        self.assertIn("trust policy condition not fully evaluated", identity["unknowns"])

    def test_effective_graph_uses_iam_capability_when_no_effective_access_exists(self) -> None:
        context = ContextEvidence(
            exposure="internal",
            privilege="admin",
            source="terraform:gcp",
            confidence=Confidence.HIGH,
            effective_exposure=[
                {
                    "decision": "reachable",
                    "network": {
                        "source": "terraform:gcp",
                        "provider": "gcp",
                        "exposure": "internal",
                        "path_type": "internal_ingress",
                        "entry": "internal_network",
                        "steps": ["google_compute_network.shared", "google_cloud_run_v2_service.api"],
                        "confidence": "high",
                    },
                }
            ],
            iam_capabilities=[
                {
                    "provider": "gcp",
                    "action": "iam.serviceAccounts.actAs",
                    "impact": "iam_escalation",
                    "access": "write",
                    "resource_scope": "unknown",
                    "source": "terraform:gcp",
                }
            ],
        )

        graph = build_effective_exposure_graph([_scored_finding(artifact_name="worker", context=context)])
        identity = next(node for node in graph["nodes"] if node["kind"] == "identity")

        self.assertEqual(identity["label"], "iam.serviceAccounts.actAs")
        self.assertEqual(identity["provider"], "gcp")
        self.assertEqual(identity["resource_scope"], "unknown")
        self.assertIn("IAM resource scope unknown", identity["unknowns"])
        self.assertIn("IAM conditions not observed", identity["unknowns"])

    def test_effective_graph_parses_context_network_evidence_and_summary_identity(self) -> None:
        context = ContextEvidence(
            exposure="internal",
            privilege="unknown",
            source="context_json",
            confidence=Confidence.LOW,
            evidence=["context network path: internal via source:partner-vpn -> subnet:private -> service:api"],
            effective_exposure=[{"decision": "unknown"}],
        )

        path = effective_exposure_path(_scored_finding(artifact_name="internal-api", context=context))
        network = next(node for node in path["nodes"] if node["kind"] == "network_path")
        identity = next(node for node in path["nodes"] if node["kind"] == "identity")

        self.assertEqual(network["entry_kind"], "internal")
        self.assertEqual(network["path_type"], "internal_ingress")
        self.assertEqual(network["steps"], ["source:partner-vpn", "subnet:private", "service:api"])
        self.assertEqual(identity["label"], "unknown identity")
        self.assertIn("no effective identity or IAM capability evidence", identity["unknowns"])

    def test_effective_graph_parses_exposure_inference_and_score_summary(self) -> None:
        context = ContextEvidence(
            exposure="public",
            privilege="limited",
            source="context",
            confidence=Confidence.MEDIUM,
            evidence=["context exposure inference: public via internet-facing load balancer"],
            effective_exposure=[{"decision": "unknown"}],
        )
        finding = _scored_finding(
            context=context,
            component=Component(name="mystery-lib", version=None),
            vulnerability=VulnerabilityRecord(id="CVE-NO-PURL", package_name="other-lib", cvss=9.0, affected_versions=[]),
            source=SourceEvidence(reachability=Reachability.PACKAGE_PRESENT, confidence=Confidence.LOW),
        )

        path = effective_exposure_path(finding)
        network = next(node for node in path["nodes"] if node["kind"] == "network_path")
        vulnerability_edge = next(edge for edge in path["edges"] if edge["kind"] == "package_has_vulnerability")
        summary = scoring_path_summary(finding)

        self.assertEqual(network["entry_kind"], "internet")
        self.assertEqual(network["path_type"], "public_load_balancer")
        self.assertEqual(vulnerability_edge["confidence"], "low")
        self.assertIn("component has no package URL", vulnerability_edge["unknowns"])
        self.assertEqual(summary["path_id"], path["id"])


if __name__ == "__main__":
    unittest.main()
