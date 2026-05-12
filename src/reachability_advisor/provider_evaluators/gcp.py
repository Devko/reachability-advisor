"""GCP effective exposure evaluator."""

from __future__ import annotations

from typing import Any, ClassVar

from .base import ProviderEvaluator, ProviderExposurePolicy, dedupe_objects, jsonish


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
                "iap_required",
                "source_cidr_restriction",
                "waf_or_firewall_policy",
            }
        ),
        blocking_identity_kinds=frozenset(
            {
                "deny_policy",
                "explicit_deny",
                "explicit_deny_precedence",
                "resource_policy_deny",
            }
        ),
        constraining_identity_kinds=frozenset(
            {
                "condition",
                "conditional_iam_binding",
                "folder_scope",
                "organization_scope",
                "scoped_resource",
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
