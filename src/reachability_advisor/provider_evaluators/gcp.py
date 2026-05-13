"""GCP effective exposure evaluator."""

from __future__ import annotations

from typing import Any, ClassVar

from reachability_advisor.models import ContextEvidence

from .base import (
    ProviderEvaluator,
    ProviderExposurePolicy,
    dedupe_objects,
    jsonish,
    matched_blocker_state,
    strongest_provider_effective_access,
)
from .policy_engine import evaluate_gcp_policy_records


class GcpExposureEvaluator(ProviderEvaluator):
    policy: ClassVar[ProviderExposurePolicy] = ProviderExposurePolicy(
        provider="gcp",
        blocking_network_kinds=frozenset(
            {
                "disabled_firewall",
                "egress_firewall",
                "ingress_internal_only",
                "internal_ingress_only",
                "internal_only_endpoint",
                "private_endpoint",
                "public_network_disabled",
                "serverless_vpc_connector_egress_only",
            }
        ),
        constraining_network_kinds=frozenset(
            {
                "api_authorizer",
                "auth_required",
                "cloud_armor_policy",
                "firewall_priority_unknown",
                "iap_required",
                "route_precedence_unknown",
                "source_cidr_restriction",
                "waf_or_firewall_policy",
            }
        ),
        blocking_identity_kinds=frozenset(
            {
                "deny_policy",
                "explicit_deny",
                "explicit_deny_precedence",
                "organization_policy_deny",
                "principal_access_boundary_deny",
                "resource_policy_deny",
            }
        ),
        constraining_identity_kinds=frozenset(
            {
                "condition",
                "conditional_iam_binding",
                "folder_scope",
                "organization_scope",
                "organization_policy_constraint",
                "principal_access_boundary_scope",
                "project_scope",
                "resource_policy_condition",
                "scoped_resource",
                "service_account_impersonation",
                "unknown_resource_scope",
                "workload_identity_condition",
            }
        ),
        unknown_network_notes=("GCP hierarchical firewall and route precedence require fully rendered provider evidence.",),
    )

    def augment_network_blockers(
        self,
        network: dict[str, Any],
        blockers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        text = jsonish(network).lower()
        augmented = list(blockers)
        if "iap" in text:
            augmented.append(
                {
                    "kind": "iap_required",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "GCP IAP evidence is linked to the ingress path",
                }
            )
        if "cloud_armor" in text or "security_policy" in text:
            augmented.append(
                {
                    "kind": "cloud_armor_policy",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "GCP Cloud Armor or backend security policy is linked to the path",
                }
            )
        if "priority" in text and ("firewall" in text or "hierarchical" in text):
            augmented.append(
                {
                    "kind": "firewall_priority_unknown",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "GCP firewall priority evidence is present and must be evaluated with hierarchy",
                }
            )
        if "google_compute_route" in text or "route" in text:
            augmented.append(
                {
                    "kind": "route_precedence_unknown",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "GCP route evidence is present; route precedence needs rendered confirmation",
                }
            )
        exposure = str(network.get("exposure") or "").lower()
        if exposure in {"public", "external"} and ("private_service_connect" in text or "psc" in text):
            augmented.append(
                {
                    "kind": "private_endpoint",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "GCP Private Service Connect evidence restricts the path to private endpoints",
                }
            )
        if "ingress_internal" in text or "ingress=internal" in text or "internal-and-cloud-load-balancing" in text:
            augmented.append(
                {
                    "kind": "ingress_internal_only",
                    "effect": "blocks" if exposure in {"public", "external"} else "constrains",
                    "provider": self.provider,
                    "evidence": "GCP serverless ingress is restricted to internal traffic",
                }
            )
        if "vpc_access_connector" in text and "egress" in text and "all_traffic" in text:
            augmented.append(
                {
                    "kind": "serverless_vpc_connector_egress_only",
                    "effect": "blocks" if exposure in {"public", "external"} else "constrains",
                    "provider": self.provider,
                    "evidence": "GCP serverless VPC connector indicates private-network routing evidence",
                }
            )
        return dedupe_objects(augmented)

    def select_effective_access(self, context: ContextEvidence) -> dict[str, Any] | None:
        records = [dict(item) for item in context.effective_access if isinstance(item, dict)]
        records = evaluate_gcp_policy_records(records)
        return strongest_provider_effective_access(records, denies=_gcp_record_denies, layer_rank=_gcp_policy_layer_rank)

    def effective_identity_decision(self, record: dict[str, Any], blockers: list[dict[str, Any]]) -> str:
        if _gcp_record_denies(record) or any(item.get("effect") == "blocks" for item in blockers):
            return "denied"
        if any(item.get("effect") == "constrains" for item in blockers):
            return "constrained_allow"
        return "allowed"

    def identity_evaluation_order(
        self,
        record: dict[str, Any],
        blockers: list[dict[str, Any]],
        decision: str,
    ) -> list[dict[str, str]]:
        blocking = {str(item.get("kind") or "unknown") for item in blockers if item.get("effect") == "blocks"}
        constraining = {str(item.get("kind") or "unknown") for item in blockers if item.get("effect") == "constrains"}
        return [
            {"step": "deny_policy", "state": "matched" if _gcp_record_denies(record) or "deny_policy" in blocking else "not_observed"},
            {"step": "allow_binding", "state": "matched" if str(record.get("effect") or "allow").lower() != "deny" else "not_observed"},
            {"step": "principal_access_boundary", "state": matched_blocker_state(blocking, constraining, {"principal_access_boundary_deny", "principal_access_boundary_scope"})},
            {"step": "organization_policy", "state": matched_blocker_state(blocking, constraining, {"organization_policy_deny", "organization_policy_constraint"})},
            {"step": "resource_policy", "state": matched_blocker_state(blocking, constraining, {"resource_policy_deny", "resource_policy_condition"})},
            {"step": "scope_inheritance", "state": _gcp_scope_level(record)},
            {"step": "conditions", "state": "matched" if {"condition", "conditional_iam_binding"} & constraining else "not_observed"},
            {"step": "workload_identity", "state": "matched" if "workload_identity_condition" in constraining else "not_observed"},
            {"step": "effective_decision", "state": decision},
        ]

    def identity_decision_detail(
        self,
        record: dict[str, Any],
        blockers: list[dict[str, Any]],
        decision: str,
    ) -> dict[str, Any]:
        detail = super().identity_decision_detail(record, blockers, decision)
        blocking = {str(item.get("kind") or "unknown") for item in blockers if item.get("effect") == "blocks"}
        constraining = {str(item.get("kind") or "unknown") for item in blockers if item.get("effect") == "constrains"}
        detail.update(
            {
                "authorization_model": "gcp_iam",
                "scope_level": _gcp_scope_level(record),
                "deny_policy": _gcp_record_denies(record) or "deny_policy" in blocking,
                "deny_policy_state": matched_blocker_state(blocking, constraining, {"deny_policy"}),
                "allow_binding": str(record.get("effect") or "allow").lower() != "deny",
                "allow_binding_state": "matched" if str(record.get("effect") or "allow").lower() != "deny" else "not_observed",
                "principal_access_boundary": matched_blocker_state(blocking, constraining, {"principal_access_boundary_deny", "principal_access_boundary_scope"}),
                "organization_policy": matched_blocker_state(blocking, constraining, {"organization_policy_deny", "organization_policy_constraint"}),
                "resource_policy": matched_blocker_state(blocking, constraining, {"resource_policy_deny", "resource_policy_condition"}),
                "conditions_and_scope": matched_blocker_state(
                    blocking,
                    constraining,
                    {
                        "condition",
                        "conditional_iam_binding",
                        "organization_scope",
                        "folder_scope",
                        "project_scope",
                        "scoped_resource",
                        "unknown_resource_scope",
                    },
                ),
                "conditional_binding": "conditional_iam_binding" in constraining or "condition" in constraining,
                "workload_identity_mapping": "workload_identity_condition" in constraining,
                "service_account_impersonation": "service_account_impersonation" in constraining,
                "organization_inheritance": "organization_scope" in constraining,
                "folder_inheritance": "folder_scope" in constraining,
                "project_scope": "project_scope" in constraining,
                "policy_layer_authority": str(record.get("policy_layer") or "unknown").lower(),
            }
        )
        return detail

    def augment_identity_blockers(
        self,
        record: dict[str, Any],
        blockers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        augmented = super().augment_identity_blockers(record, blockers)
        text = jsonish(record).lower()
        policy_layer = str(record.get("policy_layer") or "").lower()
        effect = str(record.get("effect") or "allow").lower()
        decision = str(record.get("decision") or "").lower()
        denied = effect == "deny" or decision.startswith("denied")

        if "deny_policy" in text or policy_layer == "deny_policy":
            augmented.append(
                {
                    "kind": "deny_policy",
                    "effect": "blocks" if denied else "constrains",
                    "provider": self.provider,
                    "evidence": "GCP IAM deny policy participates in the effective decision",
                }
            )
        if "principal_access_boundary" in text or "principal access boundary" in text or policy_layer == "principal_access_boundary":
            augmented.append(
                {
                    "kind": "principal_access_boundary_deny" if denied else "principal_access_boundary_scope",
                    "effect": "blocks" if denied else "constrains",
                    "provider": self.provider,
                    "evidence": "GCP principal access boundary participates in the effective decision",
                }
            )
        if "organization_policy" in text or "org_policy" in text or policy_layer == "organization_policy":
            augmented.append(
                {
                    "kind": "organization_policy_deny" if denied else "organization_policy_constraint",
                    "effect": "blocks" if denied else "constrains",
                    "provider": self.provider,
                    "evidence": "GCP organization policy constraint participates in the effective decision",
                }
            )
        if policy_layer == "resource_policy":
            augmented.append(
                {
                    "kind": "resource_policy_deny" if denied else "resource_policy_condition",
                    "effect": "blocks" if denied else "constrains",
                    "provider": self.provider,
                    "evidence": "GCP resource IAM policy participates in the effective decision",
                }
            )
        if "condition" in text or record.get("condition_keys"):
            augmented.append(
                {
                    "kind": "conditional_iam_binding",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "GCP IAM binding has conditions",
                }
            )
        if "workload_identity" in text or "iam.gke.io/gcp-service-account" in text:
            augmented.append(
                {
                    "kind": "workload_identity_condition",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "GCP Workload Identity mapping affects the effective identity",
                }
            )
        if "organizations/" in text or "organization" in text:
            augmented.append(
                {
                    "kind": "organization_scope",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "GCP IAM evidence is scoped or inherited at organization level",
                }
            )
        if "folders/" in text or "folder" in text:
            augmented.append(
                {
                    "kind": "folder_scope",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "GCP IAM evidence is scoped or inherited at folder level",
                }
            )
        elif "projects/" in text or "project" in text:
            augmented.append(
                {
                    "kind": "project_scope",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "GCP IAM evidence is scoped or inherited at project level",
                }
            )
        action = str(record.get("action") or "").lower()
        if "serviceaccounts.actas" in action or "iamcredentials." in action or "service_account_impersonation" in text:
            augmented.append(
                {
                    "kind": "service_account_impersonation",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "GCP service-account impersonation or actAs permission affects blast radius",
                }
            )
        return dedupe_objects(augmented)

    def network_unknowns(self, network: dict[str, Any], exposure: str) -> list[str]:
        unknowns = super().network_unknowns(network, exposure)
        if exposure in {"public", "external", "internal"}:
            text = jsonish(network).lower()
            if "hierarchical" not in text and "firewall_policy" not in text:
                unknowns.append("GCP hierarchical firewall policy precedence was not proven.")
            if "google_compute_route" not in text and "route" not in text:
                unknowns.append("GCP route precedence was not proven by linked route evidence.")
        return unknowns


def _gcp_record_denies(record: dict[str, Any]) -> bool:
    effect = str(record.get("effect") or "allow").lower()
    decision = str(record.get("decision") or "").lower()
    decision_basis = str(record.get("decision_basis") or "").lower()
    policy_layer = str(record.get("policy_layer") or "").lower()
    text = jsonish(record).lower()
    return effect == "deny" or decision.startswith("denied") or "deny_policy" in decision_basis or policy_layer == "deny_policy" or "denypolicy" in text


def _gcp_policy_layer_rank(layer: str) -> int:
    return {
        "deny_policy": 7,
        "principal_access_boundary": 6,
        "resource_policy": 6,
        "iam_binding": 5,
        "iam_member": 5,
        "organization_policy": 4,
        "organization_iam_binding": 4,
        "organization_iam_member": 4,
        "folder_policy": 3,
        "folder_iam_binding": 3,
        "folder_iam_member": 3,
        "project_policy": 2,
        "project_iam_binding": 2,
        "project_iam_member": 2,
        "service_account_iam_binding": 2,
        "service_account_iam_member": 2,
    }.get(layer.lower(), 1)


def _gcp_scope_level(record: dict[str, Any]) -> str:
    text = jsonish(record).lower()
    if "organizations/" in text or "organization" in text:
        return "organization"
    if "folders/" in text or "folder" in text:
        return "folder"
    if "projects/" in text or "project" in text:
        return "project"
    if str(record.get("resource_scope") or "").lower() == "scoped":
        return "resource"
    return "unknown"
