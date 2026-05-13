"""Kubernetes effective exposure evaluator."""

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
from .policy_engine import evaluate_kubernetes_policy_records


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
                "service_mesh_authz_no_allow",
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
                "aggregation_rule_scope",
                "namespace_scope",
                "non_resource_url_scope",
                "privilege_escalation_verb",
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

    def select_effective_access(self, context: ContextEvidence) -> dict[str, Any] | None:
        records = [dict(item) for item in context.effective_access if isinstance(item, dict)]
        records = evaluate_kubernetes_policy_records(records)
        return strongest_provider_effective_access(records, denies=_kubernetes_record_denies, layer_rank=_kubernetes_policy_layer_rank)

    def effective_identity_decision(self, record: dict[str, Any], blockers: list[dict[str, Any]]) -> str:
        if _kubernetes_record_denies(record) or any(item.get("effect") == "blocks" for item in blockers):
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
            {"step": "rbac_deny", "state": "matched" if _kubernetes_record_denies(record) or "rbac_deny" in blocking else "not_observed"},
            {"step": "role_binding_allow", "state": "matched" if str(record.get("effect") or "allow").lower() != "deny" else "not_observed"},
            {"step": "scope", "state": _kubernetes_scope_level(record)},
            {"step": "resource_names", "state": "matched" if "rbac_resource_names" in constraining else "not_observed"},
            {"step": "service_account", "state": "matched" if "service_account_scope" in constraining else "not_observed"},
            {"step": "non_resource_urls", "state": "matched" if "non_resource_url_scope" in constraining else "not_observed"},
            {"step": "privilege_escalation_verbs", "state": "matched" if "privilege_escalation_verb" in constraining else "not_observed"},
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
                "authorization_model": "kubernetes_rbac",
                "scope_level": _kubernetes_scope_level(record),
                "rbac_deny": _kubernetes_record_denies(record) or "rbac_deny" in blocking,
                "rbac_deny_state": matched_blocker_state(blocking, constraining, {"rbac_deny"}),
                "role_binding_allow": str(record.get("effect") or "allow").lower() != "deny",
                "role_binding_state": "matched" if str(record.get("effect") or "allow").lower() != "deny" else "not_observed",
                "cluster_scope": _kubernetes_scope_level(record) == "cluster",
                "namespace_scope": "namespace_scope" in constraining,
                "service_account_scope": "service_account_scope" in constraining,
                "resource_names_scope": "rbac_resource_names" in constraining,
                "scope_constraints": matched_blocker_state(
                    blocking,
                    constraining,
                    {
                        "aggregation_rule_scope",
                        "namespace_scope",
                        "non_resource_url_scope",
                        "rbac_resource_names",
                        "scoped_resource",
                        "service_account_scope",
                        "unknown_resource_scope",
                    },
                ),
                "non_resource_url_scope": "non_resource_url_scope" in constraining,
                "aggregation_rule_scope": "aggregation_rule_scope" in constraining,
                "privilege_escalation_verbs": _kubernetes_privilege_escalation_verbs(record),
                "verbs": _strings_from_record(record, "verbs"),
                "resources": _strings_from_record(record, "resources"),
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
        if "nonresourceurls" in text or "non_resource_urls" in text:
            augmented.append(
                {
                    "kind": "non_resource_url_scope",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Kubernetes RBAC rule is scoped to non-resource URLs",
                }
            )
        if "aggregationrule" in text or "aggregation_rule" in text:
            augmented.append(
                {
                    "kind": "aggregation_rule_scope",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Kubernetes ClusterRole aggregation rule affects effective RBAC permissions",
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
        if _kubernetes_privilege_escalation_verbs(record):
            augmented.append(
                {
                    "kind": "privilege_escalation_verb",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "Kubernetes RBAC grants impersonate, bind, escalate, or pod exec style verbs",
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


def _kubernetes_record_denies(record: dict[str, Any]) -> bool:
    effect = str(record.get("effect") or "allow").lower()
    decision = str(record.get("decision") or "").lower()
    decision_basis = str(record.get("decision_basis") or "").lower()
    text = jsonish(record).lower()
    return effect == "deny" or decision.startswith("denied") or "forbidden" in text or "rbac_deny" in decision_basis


def _kubernetes_policy_layer_rank(layer: str) -> int:
    return {
        "cluster_role_binding": 5,
        "clusterrolebinding": 5,
        "cluster_role": 4,
        "clusterrole": 4,
        "cluster_role_v1": 4,
        "role_binding": 3,
        "rolebinding": 3,
        "role_binding_v1": 3,
        "role": 2,
        "role_v1": 2,
        "kubernetes_rbac": 1,
    }.get(layer.lower(), 1)


def _kubernetes_scope_level(record: dict[str, Any]) -> str:
    text = jsonish(record).lower()
    if "clusterrole" in text or "cluster_role" in text or str(record.get("resource_scope") or "").lower() == "global":
        return "cluster"
    if "resourcenames" in text or "resource_names" in text:
        return "resource_names"
    if "serviceaccount" in text or "service_account" in text:
        return "service_account"
    if "namespace" in text or str(record.get("resource_scope") or "").lower() == "scoped":
        return "namespace"
    return "unknown"


def _kubernetes_privilege_escalation_verbs(record: dict[str, Any]) -> list[str]:
    verbs = set(_strings_from_record(record, "verbs"))
    action = str(record.get("action") or "").lower()
    for marker in ("impersonate", "bind", "escalate", "pods/exec", "create pods/exec"):
        if marker in action:
            verbs.add(marker)
    return sorted(verbs & {"impersonate", "bind", "escalate", "pods/exec", "create pods/exec"})


def _strings_from_record(record: dict[str, Any], key: str) -> list[str]:
    raw = record.get(key)
    if isinstance(raw, list):
        return sorted({str(item).lower() for item in raw if str(item)})
    value = str(raw or "").lower()
    return [value] if value else []
