"""Kubernetes effective exposure evaluator."""

from __future__ import annotations

from typing import Any, ClassVar

from .base import ProviderEvaluator, ProviderExposurePolicy, dedupe_objects, jsonish


class KubernetesExposureEvaluator(ProviderEvaluator):
    policy: ClassVar[ProviderExposurePolicy] = ProviderExposurePolicy(
        provider="kubernetes",
        blocking_network_kinds=frozenset(
            {
                "authorization_policy_deny",
                "ingress_class_internal",
                "internal_ingress_only",
                "network_policy_deny_all",
                "private_endpoint",
                "service_mesh_deny",
            }
        ),
        constraining_network_kinds=frozenset(
            {
                "auth_required",
                "ingress_auth_required",
                "ingress_controller_auth",
                "network_policy_allow_list",
                "pod_security_boundary",
                "service_mesh_mtls_strict",
                "service_mesh_policy",
            }
        ),
        blocking_identity_kinds=frozenset({"explicit_deny", "rbac_deny"}),
        constraining_identity_kinds=frozenset(
            {
                "namespace_scope",
                "rbac_resource_names",
                "scoped_resource",
                "service_account_scope",
                "unknown_resource_scope",
            }
        ),
        unknown_network_notes=("Service mesh policy is only enforced when rendered policy evidence is present.",),
    )

    def augment_network_blockers(
        self,
        network: dict[str, Any],
        blockers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        text = jsonish(network).lower()
        augmented = list(blockers)
        exposure = str(network.get("exposure") or "").lower()
        if "deny all ingress" in text and not any(item.get("kind") == "network_policy_deny_all" for item in augmented):
            augmented.append(
                {
                    "kind": "network_policy_deny_all",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "Rendered NetworkPolicy denies all ingress",
                }
            )
        if "ingress_class" in text and "internal" in text:
            augmented.append(
                {
                    "kind": "ingress_class_internal",
                    "effect": "blocks" if exposure in {"public", "external"} else "constrains",
                    "provider": self.provider,
                    "evidence": "Kubernetes ingress class is internal",
                }
            )
        if "authorizationpolicy" in text and "deny" in text:
            augmented.append(
                {
                    "kind": "authorization_policy_deny",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "Rendered service-mesh AuthorizationPolicy denies the path",
                }
            )
        elif "mtls" in text or "authorizationpolicy" in text:
            augmented.append(
                {
                    "kind": "service_mesh_policy",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Rendered service mesh policy evidence is linked to the path",
                }
            )
        if "mtls" in text and ("strict" in text or "permissive" not in text):
            augmented.append(
                {
                    "kind": "service_mesh_mtls_strict",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Rendered service-mesh mTLS policy is strict",
                }
            )
        if "networkpolicy" in text and "deny all ingress" not in text and "allow" in text:
            augmented.append(
                {
                    "kind": "network_policy_allow_list",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Rendered NetworkPolicy allow-list constrains ingress",
                }
            )
        if "nginx.ingress.kubernetes.io/auth" in text or "oauth2-proxy" in text or "external-auth" in text:
            augmented.append(
                {
                    "kind": "ingress_controller_auth",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Ingress controller authentication annotation is linked to the path",
                }
            )
        if "podsecuritypolicy" in text or "pod_security" in text or "securitycontext" in text:
            augmented.append(
                {
                    "kind": "pod_security_boundary",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Pod security evidence constrains runtime behavior but does not prove network isolation",
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
        effect = str(record.get("effect") or "allow").lower()
        decision = str(record.get("decision") or "").lower()
        if effect == "deny" or decision.startswith("denied") or "forbidden" in text:
            augmented.append(
                {
                    "kind": "rbac_deny",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "Kubernetes RBAC decision denies the action",
                }
            )
        if "resource_names" in text or "resourcenames" in text:
            augmented.append(
                {
                    "kind": "rbac_resource_names",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Kubernetes RBAC rule is scoped to resourceNames",
                }
            )
        if "serviceaccount" in text or "service_account" in text:
            augmented.append(
                {
                    "kind": "service_account_scope",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Kubernetes access is scoped to a service account binding",
                }
            )
        if "namespace" in text and "clusterrole" not in text:
            augmented.append(
                {
                    "kind": "namespace_scope",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Kubernetes RBAC access is namespace scoped",
                }
            )
        return dedupe_objects(augmented)

    def network_unknowns(self, network: dict[str, Any], exposure: str) -> list[str]:
        unknowns = super().network_unknowns(network, exposure)
        if exposure in {"public", "external", "internal"}:
            text = jsonish(network).lower()
            if "networkpolicy" not in text and "network_policy" not in text:
                unknowns.append("Kubernetes NetworkPolicy coverage was not proven by rendered policy evidence.")
            if "authorizationpolicy" not in text and "service_mesh" not in text:
                unknowns.append("Kubernetes service-mesh authorization was not proven by rendered policy evidence.")
        return unknowns
