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
