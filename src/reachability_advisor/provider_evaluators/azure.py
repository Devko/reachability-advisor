"""Azure effective exposure evaluator."""

from __future__ import annotations

from typing import Any, ClassVar

from .base import ProviderEvaluator, ProviderExposurePolicy, dedupe_objects, jsonish


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
                "scoped_resource",
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
        if "network_security_rule" in text or "nsg" in text:
            augmented.append(
                {
                    "kind": "nsg_priority_unknown",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure NSG evidence is present; priority order must be evaluated",
                }
            )
        if "route_table" in text or "azurerm_route" in text:
            augmented.append(
                {
                    "kind": "route_table_precedence_unknown",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Azure route-table evidence is present; route precedence needs rendered confirmation",
                }
            )
        return dedupe_objects(augmented)

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
