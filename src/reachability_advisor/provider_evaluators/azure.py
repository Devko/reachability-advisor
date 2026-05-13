"""Azure effective exposure evaluator."""

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
from .policy_engine import evaluate_azure_policy_records


class AzureExposureEvaluator(ProviderEvaluator):
    policy: ClassVar[ProviderExposurePolicy] = ProviderExposurePolicy(
        provider="azure",
        blocking_network_kinds=frozenset(
            {
                "access_restriction_deny",
                "deny_inbound",
                "internal_ingress_only",
                "internal_only_endpoint",
                "nsg_deny",
                "private_endpoint",
                "private_link_only",
                "public_network_disabled",
            }
        ),
        constraining_network_kinds=frozenset(
            {
                "api_authorizer",
                "app_service_auth",
                "auth_required",
                "application_gateway_auth",
                "firewall_policy",
                "front_door_waf",
                "nsg_priority_unknown",
                "private_endpoint_egress_only",
                "route_table_precedence_unknown",
                "source_cidr_restriction",
                "waf_or_firewall_policy",
            }
        ),
        blocking_identity_kinds=frozenset(
            {
                "deny_assignment",
                "explicit_deny",
                "explicit_deny_precedence",
                "resource_policy_deny",
            }
        ),
        constraining_identity_kinds=frozenset(
            {
                "condition",
                "access_restriction_scope",
                "management_group_scope",
                "pim_eligible_only",
                "resource_group_scope",
                "resource_policy_condition",
                "role_assignment_condition",
                "role_definition_scope",
                "scoped_resource",
                "subscription_scope",
                "unknown_resource_scope",
            }
        ),
        unknown_network_notes=("Azure NSG priority conflicts and App Gateway auth semantics are modeled only from rendered evidence.",),
    )

    def augment_network_blockers(
        self,
        network: dict[str, Any],
        blockers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        text = jsonish(network).lower()
        augmented = list(blockers)
        if "auth_settings" in text or "easy_auth" in text:
            augmented.append(
                {
                    "kind": "app_service_auth",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure App Service authentication settings are present",
                }
            )
        exposure = str(network.get("exposure") or "").lower()
        if "private_endpoint" in text or "privatelink" in text:
            if "private_endpoint_egress_only" in text:
                augmented.append(
                    {
                        "kind": "private_endpoint_egress_only",
                        "effect": "constrains",
                        "provider": self.provider,
                        "evidence": "Azure Private Endpoint evidence is outbound/dependency traffic, not public ingress",
                    }
                )
            else:
                augmented.append(
                    {
                        "kind": "private_endpoint",
                        "effect": "blocks" if exposure in {"public", "external"} else "constrains",
                        "provider": self.provider,
                        "evidence": "Azure Private Endpoint evidence is linked to the path",
                    }
                )
        if "access_restriction" in text and "deny" in text:
            augmented.append(
                {
                    "kind": "access_restriction_deny",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "Azure App Service access restriction deny rule is linked to the path",
                }
            )
        elif "access_restriction" in text or "ip_restriction" in text:
            augmented.append(
                {
                    "kind": "access_restriction_scope",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure App Service access restrictions scope ingress",
                }
            )
        if "deny_inbound" in text or ("network_security_rule" in text and "deny" in text):
            augmented.append(
                {
                    "kind": "nsg_deny",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "Azure NSG deny rule is linked to the path",
                }
            )
        if "front_door" in text or "web_application_firewall_policy" in text:
            augmented.append(
                {
                    "kind": "front_door_waf",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure Front Door or Application Gateway WAF evidence is linked to the path",
                }
            )
        if "application_gateway" in text and ("authentication" in text or "auth" in text):
            augmented.append(
                {
                    "kind": "application_gateway_auth",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure Application Gateway authentication evidence is linked to the path",
                }
            )
        if "precedence_evaluated" not in text and ("network_security_rule" in text or "nsg" in text):
            augmented.append(
                {
                    "kind": "nsg_priority_unknown",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure NSG evidence is present; priority order must be evaluated",
                }
            )
        if "precedence_evaluated" not in text and ("route_table" in text or "azurerm_route" in text):
            augmented.append(
                {
                    "kind": "route_table_precedence_unknown",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure route-table evidence is present; route precedence needs rendered confirmation",
                }
            )
        return dedupe_objects(augmented)

    def select_effective_access(self, context: ContextEvidence) -> dict[str, Any] | None:
        records = [dict(item) for item in context.effective_access if isinstance(item, dict)]
        records = evaluate_azure_policy_records(records)
        return strongest_provider_effective_access(records, denies=_azure_record_denies, layer_rank=_azure_policy_layer_rank)

    def effective_identity_decision(self, record: dict[str, Any], blockers: list[dict[str, Any]]) -> str:
        if _azure_record_denies(record) or any(item.get("effect") == "blocks" for item in blockers):
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
            {"step": "deny_assignment", "state": "matched" if _azure_record_denies(record) or "deny_assignment" in blocking else "not_observed"},
            {"step": "role_assignment_allow", "state": "matched" if str(record.get("effect") or "allow").lower() != "deny" else "not_observed"},
            {"step": "resource_policy", "state": matched_blocker_state(blocking, constraining, {"resource_policy_deny", "resource_policy_condition"})},
            {"step": "role_definition_scope", "state": matched_blocker_state(blocking, constraining, {"role_definition_scope"})},
            {"step": "scope_inheritance", "state": _azure_scope_level(record)},
            {"step": "conditions", "state": "matched" if {"condition", "role_assignment_condition"} & constraining else "not_observed"},
            {"step": "pim_activation", "state": "required" if "pim_eligible_only" in constraining else "not_observed"},
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
                "authorization_model": "azure_rbac",
                "scope_level": _azure_scope_level(record),
                "deny_assignment": _azure_record_denies(record) or "deny_assignment" in blocking,
                "deny_assignment_state": matched_blocker_state(blocking, constraining, {"deny_assignment"}),
                "role_assignment_allow": str(record.get("effect") or "allow").lower() != "deny",
                "role_assignment": "matched" if str(record.get("effect") or "allow").lower() != "deny" else "not_observed",
                "role_definition_scope": matched_blocker_state(blocking, constraining, {"role_definition_scope"}),
                "resource_policy": matched_blocker_state(blocking, constraining, {"resource_policy_deny", "resource_policy_condition"}),
                "conditions_and_scope": matched_blocker_state(
                    blocking,
                    constraining,
                    {
                        "condition",
                        "role_assignment_condition",
                        "management_group_scope",
                        "subscription_scope",
                        "resource_group_scope",
                        "scoped_resource",
                        "unknown_resource_scope",
                    },
                ),
                "pim_activation_required": "pim_eligible_only" in constraining,
                "pim": matched_blocker_state(blocking, constraining, {"pim_eligible_only"}),
                "conditional_access": bool({"condition", "role_assignment_condition"} & constraining),
                "management_group_inheritance": "management_group_scope" in constraining,
                "subscription_scope": "subscription_scope" in constraining,
                "resource_group_scope": "resource_group_scope" in constraining,
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
        decision_basis = str(record.get("decision_basis") or "").lower()
        effect = str(record.get("effect") or "allow").lower()
        decision = str(record.get("decision") or "").lower()
        denied = effect == "deny" or decision.startswith("denied") or "deny" in decision_basis

        if "deny_assignment" in text or "denyassignment" in text or policy_layer == "deny_assignment":
            augmented.append(
                {
                    "kind": "deny_assignment",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "Azure deny assignment affects the effective action",
                }
            )
        if "management_group" in text or "/providers/microsoft.management/managementgroups/" in text:
            augmented.append(
                {
                    "kind": "management_group_scope",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure role assignment is inherited or scoped at management-group level",
                }
            )
        elif "/resourcegroups/" in text or "resource_group" in text:
            augmented.append(
                {
                    "kind": "resource_group_scope",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure role assignment is scoped at resource-group level",
                }
            )
        elif "/subscriptions/" in text or "subscription" in text:
            augmented.append(
                {
                    "kind": "subscription_scope",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure role assignment is scoped or inherited at subscription level",
                }
            )
        if "assignable_scopes" in text or "assignablescopes" in text:
            augmented.append(
                {
                    "kind": "role_definition_scope",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure custom role definition has assignable scope constraints",
                }
            )
        if "condition" in text or record.get("condition_keys"):
            augmented.append(
                {
                    "kind": "role_assignment_condition",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure role assignment includes conditions",
                }
            )
        if "pim" in text or "eligible" in text:
            augmented.append(
                {
                    "kind": "pim_eligible_only",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure PIM eligibility requires activation before effective access",
                }
            )
        if policy_layer == "resource_policy" and denied:
            augmented.append(
                {
                    "kind": "resource_policy_deny",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "Azure resource policy denies the effective action",
                }
            )
        elif policy_layer == "resource_policy":
            augmented.append(
                {
                    "kind": "resource_policy_condition",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure resource policy participates in the effective action",
                }
            )
        return dedupe_objects(augmented)

    def network_unknowns(self, network: dict[str, Any], exposure: str) -> list[str]:
        unknowns = super().network_unknowns(network, exposure)
        if exposure in {"public", "external", "internal"}:
            text = jsonish(network).lower()
            if "network_security_rule" not in text and "nsg" not in text:
                unknowns.append("Azure NSG rule ordering was not proven by linked rule evidence.")
            if "route_table" not in text and "azurerm_route" not in text:
                unknowns.append("Azure route-table precedence was not proven by linked route evidence.")
        return unknowns


def _azure_record_denies(record: dict[str, Any]) -> bool:
    effect = str(record.get("effect") or "allow").lower()
    decision = str(record.get("decision") or "").lower()
    decision_basis = str(record.get("decision_basis") or "").lower()
    policy_layer = str(record.get("policy_layer") or "").lower()
    text = jsonish(record).lower()
    return (
        effect == "deny"
        or decision.startswith("denied")
        or "deny_assignment" in decision_basis
        or policy_layer == "deny_assignment"
        or "denyassignment" in text
    )


def _azure_policy_layer_rank(layer: str) -> int:
    return {
        "deny_assignment": 7,
        "resource_policy": 6,
        "role_assignment": 5,
        "management_group": 4,
        "subscription": 3,
        "resource_group": 2,
    }.get(layer.lower(), 1)


def _azure_scope_level(record: dict[str, Any]) -> str:
    text = jsonish(record).lower()
    if "managementgroups" in text or "management_group" in text:
        return "management_group"
    if "/subscriptions/" in text and "/resourcegroups/" in text:
        return "resource_group"
    if "/subscriptions/" in text:
        return "subscription"
    if str(record.get("resource_scope") or "").lower() == "scoped":
        return "resource"
    return "unknown"
