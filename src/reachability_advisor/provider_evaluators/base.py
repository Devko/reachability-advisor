"""Shared provider evaluator contract for effective exposure decisions."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar

from reachability_advisor.iam_capabilities import (
    capability_risk_multiplier,
    dedupe_iam_capabilities,
)
from reachability_advisor.models import ContextEvidence
from reachability_advisor.terraform_exposure import exposure_rank

from .network_engine import evaluate_provider_network_graph


@dataclass(frozen=True)
class ProviderExposurePolicy:
    provider: str
    blocking_network_kinds: frozenset[str]
    constraining_network_kinds: frozenset[str]
    blocking_identity_kinds: frozenset[str]
    constraining_identity_kinds: frozenset[str]
    unknown_network_notes: tuple[str, ...] = ()


class ProviderEvaluator:
    """Provider-specific authority for normalized network and identity decisions."""

    policy: ClassVar[ProviderExposurePolicy] = ProviderExposurePolicy(
        provider="unknown",
        blocking_network_kinds=frozenset({"public_network_disabled", "internal_only_endpoint", "internal_ingress_only"}),
        constraining_network_kinds=frozenset({"auth_required", "api_key_required", "api_authorizer", "waf_or_firewall_policy"}),
        blocking_identity_kinds=frozenset({"explicit_deny", "explicit_deny_precedence"}),
        constraining_identity_kinds=frozenset({"condition", "scoped_resource", "unknown_resource_scope"}),
        unknown_network_notes=("Provider-specific precedence could not be selected.",),
    )

    @property
    def provider(self) -> str:
        return self.policy.provider

    def evaluate(
        self,
        artifact_name: str,
        context: ContextEvidence,
        *,
        selected_network: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        network = selected_network or select_network_path(context)
        network_eval = self.evaluate_network(context, network)
        identity_eval = self.evaluate_identity(context)
        decision = self.combined_decision(network_eval, identity_eval)
        confidence = combine_confidence(
            str(network_eval["confidence"]),
            str(identity_eval["confidence"]),
            context.confidence.value,
        )
        blockers = dedupe_objects([*objects(network_eval.get("blockers")), *objects(identity_eval.get("blockers"))])
        unknowns = dedupe_strings([*strings(network_eval.get("unknowns")), *strings(identity_eval.get("unknowns"))])
        record_id = f"effective-exposure:{artifact_name}:{stable_token(jsonish(network_eval) + jsonish(identity_eval))}"
        decision_basis = self.combined_decision_basis(network_eval, identity_eval, decision)
        return {
            "id": record_id,
            "schema_version": "1.0",
            "artifact": artifact_name,
            "provider": self.provider,
            "evaluator": f"{self.provider}.effective_exposure",
            "decision": decision,
            "decision_basis": decision_basis,
            "exposure": network_eval["exposure"],
            "entry": network_eval["entry"],
            "path_type": network_eval["path_type"],
            "confidence": confidence,
            "network": network_eval,
            "identity": identity_eval,
            "blockers": blockers,
            "unknowns": unknowns,
            "edges": effective_edges(artifact_name, record_id, self.provider, network_eval, identity_eval, confidence),
        }

    def evaluate_network(self, context: ContextEvidence, network: dict[str, Any]) -> dict[str, Any]:
        exposure = str(network.get("exposure") or context.exposure or "unknown").lower()
        graph_eval = self.evaluate_network_graph(network, exposure)
        blockers = self.normalize_blockers([*objects(network.get("blockers")), *objects(graph_eval.get("blockers"))], is_identity=False)
        network_for_augment = dict(network)
        if graph_eval.get("evaluated"):
            network_for_augment["provider_network_graph"] = graph_eval
        blockers = self.normalize_blockers(self.augment_network_blockers(network_for_augment, blockers), is_identity=False)
        effects = {str(item.get("effect") or "") for item in blockers}
        unknowns = [*strings(network.get("unknowns")), *strings(graph_eval.get("unknowns"))]
        path_type = str(network.get("path_type") or path_type_for_exposure(exposure))
        entry = str(network.get("entry") or network.get("entry_kind") or entry_for_exposure(exposure))
        graph_path = strings(graph_eval.get("path"))
        steps = graph_path or strings(network.get("steps"))
        if not steps and exposure not in {"private", "isolated", "none", "unknown"}:
            unknowns.append("provider path exists as a label but has no hop sequence")
        if exposure == "unknown":
            unknowns.append("network exposure is unresolved")
        unknowns.extend(self.network_unknowns(network, exposure))
        if "blocks" in effects:
            decision = "blocked"
        elif exposure in {"private", "isolated", "none"}:
            decision = "isolated"
        elif "constrains" in effects:
            decision = "constrained"
        elif exposure == "unknown":
            decision = "unknown"
        else:
            decision = "reachable"
        decision_basis = self.network_decision_basis(network, blockers, unknowns, decision)
        result: dict[str, Any] = {
            "provider": self.provider,
            "decision": decision,
            "decision_basis": decision_basis,
            "exposure": exposure,
            "entry": entry,
            "path_type": path_type,
            "steps": steps,
            "confidence": confidence_value(network.get("confidence"), context.confidence.value),
            "blockers": blockers,
            "unknowns": dedupe_strings(unknowns),
            "source": str(network.get("source") or context.source or "context"),
            "evidence_layer": evidence_layer(str(network.get("source") or context.source or "context")),
        }
        if graph_eval.get("evaluated"):
            result["network_graph"] = graph_eval
        return result

    def evaluate_network_graph(self, network: dict[str, Any], exposure: str) -> dict[str, Any]:
        return evaluate_provider_network_graph(self.provider, network, exposure)

    def evaluate_identity(self, context: ContextEvidence) -> dict[str, Any]:
        access = self.select_effective_access(context)
        if access:
            blockers = self.normalize_blockers(access.get("blockers"), is_identity=True)
            blockers = self.normalize_blockers(self.augment_identity_blockers(access, blockers), is_identity=True)
            decision = self.effective_identity_decision(access, blockers)
            decision_basis = str(access.get("decision_basis") or "unknown")
            provider_decision_basis = self.identity_decision_basis(access, blockers, decision, decision_basis)
            evaluation_order = merge_policy_evaluation_order(self.identity_evaluation_order(access, blockers, decision), access)
            return {
                "provider": str(access.get("provider") or self.provider),
                "decision": decision,
                "identity": access.get("identity"),
                "action": access.get("action"),
                "impact": access.get("impact"),
                "access": access.get("access"),
                "resource": access.get("resource"),
                "target_resources": access.get("target_resources", []),
                "policy_layer": access.get("policy_layer", "unknown"),
                "decision_basis": decision_basis,
                "provider_decision_basis": provider_decision_basis,
                "confidence": confidence_value(access.get("confidence"), context.confidence.value),
                "blockers": blockers,
                "unknowns": self.identity_unknowns(access, has_capability=True),
                "source": str(access.get("source") or context.source or "context"),
                "evidence_layer": "iam",
                "evaluation_order": evaluation_order,
                "effective_access_model": self.identity_decision_detail(access, blockers, decision),
                "policy_evaluation": access.get("policy_evaluation"),
            }
        capability = strongest_capability(context)
        if capability:
            blockers = self.normalize_blockers(capability_blockers(capability), is_identity=True)
            blockers = self.normalize_blockers(self.augment_identity_blockers(capability, blockers), is_identity=True)
            decision = "constrained_allow" if blockers else "allowed"
            provider_decision_basis = self.identity_decision_basis(capability, blockers, decision, "capability_summary")
            return {
                "provider": str(capability.get("provider") or self.provider),
                "decision": decision,
                "identity": capability.get("identity"),
                "action": capability.get("action"),
                "impact": capability.get("impact"),
                "access": capability.get("access"),
                "resource_scope": capability.get("resource_scope", "unknown"),
                "condition_keys": capability.get("condition_keys", []),
                "risk_multiplier": capability_risk_multiplier(capability),
                "decision_basis": "capability_summary",
                "provider_decision_basis": provider_decision_basis,
                "confidence": "medium" if blockers else "high",
                "blockers": blockers,
                "unknowns": self.identity_unknowns(capability, has_capability=True),
                "source": str(capability.get("source") or context.source or "context"),
                "evidence_layer": "iam",
                "evaluation_order": self.identity_evaluation_order(capability, blockers, decision),
                "effective_access_model": self.identity_decision_detail(capability, blockers, decision),
            }
        unknowns = [] if context.privilege not in {"", "unknown"} or context.iam_impacts else ["no identity/effective-access evidence"]
        return {
            "provider": self.provider,
            "decision": "unknown" if unknowns else "summary_only",
            "decision_basis": "no_effective_identity" if unknowns else "context_summary",
            "provider_decision_basis": "no_effective_identity" if unknowns else "context_summary",
            "privilege": context.privilege,
            "impacts": context.iam_impacts,
            "confidence": context.confidence.value if not unknowns else "low",
            "blockers": [],
            "unknowns": unknowns,
            "source": context.source,
            "evidence_layer": "iam",
        }

    def select_effective_access(self, context: ContextEvidence) -> dict[str, Any] | None:
        return strongest_effective_access(context)

    def effective_identity_decision(self, record: dict[str, Any], blockers: list[dict[str, Any]]) -> str:
        decision = str(record.get("decision") or ("denied" if str(record.get("effect") or "allow").lower() == "deny" else "allowed"))
        effect = str(record.get("effect") or "allow").lower()
        if effect == "deny" or decision.startswith("denied") or any(item.get("effect") == "blocks" for item in blockers):
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
        steps = [
            {"step": "explicit_deny", "state": "matched" if any(item.get("effect") == "blocks" for item in blockers) else "not_observed"},
            {"step": "allow", "state": "matched" if str(record.get("effect") or "allow").lower() != "deny" else "not_observed"},
        ]
        if any(item.get("effect") == "constrains" for item in blockers):
            steps.append({"step": "constraints", "state": "matched"})
        steps.append({"step": "effective_decision", "state": decision})
        return steps

    def identity_decision_detail(
        self,
        record: dict[str, Any],
        blockers: list[dict[str, Any]],
        decision: str,
    ) -> dict[str, Any]:
        """Return a normalized identity/resource/action decision model for graph consumers."""

        condition_keys = record.get("condition_keys")
        conditions = [str(item) for item in condition_keys if str(item)] if isinstance(condition_keys, list) else []
        effect = str(record.get("effect") or "allow").lower()
        detail = {
            "provider": str(record.get("provider") or self.provider),
            "identity": record.get("identity"),
            "action": record.get("action"),
            "resource": record.get("resource"),
            "target_resources": record.get("target_resources", []),
            "policy_layer": record.get("policy_layer", "unknown"),
            "effect": effect,
            "decision": decision,
            "allow_observed": effect != "deny",
            "deny_observed": effect == "deny" or decision == "denied" or bool(blocker_kinds(blockers, "blocks")),
            "blocking_reasons": blocker_kinds(blockers, "blocks"),
            "constraints": blocker_kinds(blockers, "constrains"),
            "resource_scope": str(record.get("resource_scope") or "unknown").lower(),
            "conditions": conditions,
            "confidence": confidence_value(record.get("confidence")),
        }
        policy_evaluation = record.get("policy_evaluation")
        if isinstance(policy_evaluation, dict):
            detail["policy_evaluation"] = policy_evaluation
            detail["policy_engine"] = policy_evaluation.get("engine")
            detail["policy_matched_statements"] = policy_evaluation.get("matched_statements", [])
        return detail

    def normalize_blockers(self, value: Any, *, is_identity: bool) -> list[dict[str, Any]]:
        blockers: list[dict[str, Any]] = []
        raw_items = value if isinstance(value, list) else []
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            blocker = {str(key): item for key, item in raw.items()}
            kind = str(blocker.get("kind") or "unknown").lower()
            explicit_effect = str(blocker.get("effect") or "").lower()
            if explicit_effect in {"blocks", "constrains"}:
                effect = explicit_effect
            elif is_identity and kind in self.policy.blocking_identity_kinds:
                effect = "blocks"
            elif is_identity and kind in self.policy.constraining_identity_kinds:
                effect = "constrains"
            elif not is_identity and kind in self.policy.blocking_network_kinds:
                effect = "blocks"
            elif not is_identity and kind in self.policy.constraining_network_kinds:
                effect = "constrains"
            else:
                effect = "unknown"
            blocker["kind"] = kind
            blocker["effect"] = effect
            blocker.setdefault("provider", self.provider)
            blockers.append(blocker)
        return dedupe_objects(blockers)

    def augment_network_blockers(
        self,
        _network: dict[str, Any],
        blockers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return blockers

    def augment_identity_blockers(
        self,
        record: dict[str, Any],
        blockers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        augmented = list(blockers)
        effect = str(record.get("effect") or "allow").lower()
        decision = str(record.get("decision") or "").lower()
        if effect == "deny" or decision.startswith("denied"):
            augmented.append({"kind": "explicit_deny", "evidence": "effective-access record is denied"})
        scope = str(record.get("resource_scope") or "").lower()
        if scope == "unknown":
            augmented.append({"kind": "unknown_resource_scope", "evidence": "identity resource scope is unresolved"})
        elif scope == "scoped":
            augmented.append({"kind": "scoped_resource", "evidence": "identity resource scope is constrained"})
        condition_keys = record.get("condition_keys")
        for key in condition_keys if isinstance(condition_keys, list) else []:
            augmented.append({"kind": "condition", "evidence": f"condition key {key}"})
        return dedupe_objects(augmented)

    def network_decision_basis(
        self,
        network: dict[str, Any],
        blockers: list[dict[str, Any]],
        _unknowns: list[str],
        decision: str,
    ) -> str:
        blocking = blocker_kinds(blockers, "blocks")
        constraining = blocker_kinds(blockers, "constrains")
        if blocking:
            return "blocked_by:" + ",".join(blocking)
        if constraining:
            return "constrained_by:" + ",".join(constraining)
        exposure = str(network.get("exposure") or "").lower()
        if decision == "isolated" or exposure in {"private", "isolated", "none"}:
            return "no_observed_ingress"
        if decision == "unknown":
            return "unknown_network_path"
        return f"linked_{str(network.get('path_type') or path_type_for_exposure(exposure))}"

    def identity_decision_basis(
        self,
        _record: dict[str, Any],
        blockers: list[dict[str, Any]],
        decision: str,
        default: str,
    ) -> str:
        blocking = blocker_kinds(blockers, "blocks")
        constraining = blocker_kinds(blockers, "constrains")
        if blocking:
            return "blocked_by:" + ",".join(blocking)
        if constraining:
            return "constrained_by:" + ",".join(constraining)
        if default and default != "unknown":
            return default
        return decision or "unknown"

    def combined_decision_basis(self, network: dict[str, Any], identity: dict[str, Any], decision: str) -> str:
        network_basis = str(network.get("decision_basis") or "unknown_network_path")
        identity_basis = str(identity.get("provider_decision_basis") or identity.get("decision_basis") or "unknown_identity")
        if decision in {"blocked", "isolated", "unknown"}:
            return f"network:{network_basis}"
        if decision == "reachable_without_effective_identity":
            return f"identity:{identity_basis}"
        if decision == "constrained":
            return f"network:{network_basis}; identity:{identity_basis}"
        return f"network:{network_basis}; identity:{identity_basis}"

    def network_unknowns(self, network: dict[str, Any], exposure: str) -> list[str]:
        if exposure in {"private", "isolated", "none"}:
            return []
        unknowns = list(self.policy.unknown_network_notes)
        if str(network.get("confidence") or "").lower() == "low":
            unknowns.append("provider network path is low confidence")
        return unknowns

    def identity_unknowns(self, record: dict[str, Any], *, has_capability: bool) -> list[str]:
        unknowns: list[str] = []
        if has_capability and str(record.get("resource_scope") or "unknown").lower() == "unknown":
            unknowns.append("identity resource scope is unresolved")
        if has_capability and not record.get("condition_keys"):
            unknowns.append("identity conditions are not fully known")
        return unknowns

    def combined_decision(self, network: dict[str, Any], identity: dict[str, Any]) -> str:
        network_decision = str(network.get("decision") or "unknown")
        identity_decision = str(identity.get("decision") or "unknown")
        if network_decision in {"blocked", "isolated"}:
            return network_decision
        if network_decision == "unknown":
            return "unknown"
        if identity_decision == "denied":
            return "reachable_without_effective_identity"
        if network_decision == "constrained" or identity_decision == "constrained_allow":
            return "constrained"
        return "reachable"


def candidate_network_paths(context: ContextEvidence) -> list[dict[str, Any]]:
    paths = [dict(item) for item in context.network_paths if isinstance(item, dict)]
    if paths:
        return paths
    return [network_path_from_evidence(context)]


def select_network_path(context: ContextEvidence) -> dict[str, Any]:
    paths = candidate_network_paths(context)
    return max(
        paths,
        key=lambda item: (
            exposure_rank(str(item.get("exposure") or context.exposure or "unknown")),
            confidence_rank(str(item.get("confidence") or context.confidence.value)),
        ),
    )


def network_path_from_evidence(context: ContextEvidence) -> dict[str, Any]:
    evidence_text = "\n".join(context.evidence).lower()
    blockers: list[dict[str, str]] = []
    if "network policy" in evidence_text and "deny all ingress" in evidence_text:
        blockers.append(
            {
                "kind": "network_policy_deny_all",
                "effect": "blocks",
                "evidence": "rendered NetworkPolicy denies all ingress",
            }
        )
    for needle, kind, effect, evidence in (
        ("public network disabled", "public_network_disabled", "blocks", "public network access is disabled"),
        ("private endpoint", "private_endpoint", "blocks", "private endpoint evidence restricts public access"),
        ("privatelink", "private_link_only", "blocks", "PrivateLink-only access is reported"),
        ("vpc endpoint", "vpc_endpoint_only", "blocks", "VPC endpoint-only access is reported"),
        ("internal ingress only", "internal_ingress_only", "blocks", "ingress is internal only"),
        ("deny inbound", "deny_inbound", "blocks", "deny inbound rule is reported"),
        ("explicit deny", "explicit_deny", "blocks", "explicit deny is reported"),
        ("waf", "waf_or_firewall_policy", "constrains", "WAF/firewall policy is linked to the path"),
        ("authorizer", "api_authorizer", "constrains", "API authorizer is linked to the path"),
        ("authentication required", "auth_required", "constrains", "authentication is required on the path"),
        ("source cidr", "source_cidr_restriction", "constrains", "source CIDR restriction is reported"),
        ("source security group", "source_security_group_restriction", "constrains", "source security group restriction is reported"),
    ):
        if needle in evidence_text:
            blockers.append({"kind": kind, "effect": effect, "evidence": evidence})
    exposure = str(context.exposure or "unknown").lower()
    return {
        "source": context.source,
        "provider": provider_from_source(context.source),
        "exposure": exposure,
        "path_type": path_type_for_exposure(exposure),
        "entry": entry_for_exposure(exposure),
        "steps": evidence_network_steps(context.evidence),
        "confidence": context.confidence.value,
        "blockers": blockers,
        "unknowns": ["no typed provider network path record"] if exposure not in {"private", "isolated", "none"} else [],
    }


def provider_from_source(source: str) -> str:
    value = str(source or "").lower()
    for provider in ("aws", "azure", "gcp", "kubernetes"):
        if provider in value:
            return provider
    return "unknown"


def strongest_effective_access(context: ContextEvidence) -> dict[str, Any] | None:
    records = [dict(item) for item in context.effective_access if isinstance(item, dict)]
    if not records:
        return None
    return max(
        records,
        key=lambda item: (
            identity_decision_rank(item),
            impact_rank(str(item.get("impact") or "")),
            confidence_rank(str(item.get("confidence") or "")),
        ),
    )


def merge_policy_evaluation_order(
    provider_order: list[dict[str, str]],
    record: dict[str, Any],
) -> list[dict[str, str]]:
    policy_evaluation = record.get("policy_evaluation")
    if not isinstance(policy_evaluation, dict):
        return provider_order
    policy_order = policy_evaluation.get("evaluation_order")
    if not isinstance(policy_order, list):
        return provider_order
    normalized = [
        {"step": f"policy:{str(item.get('step') or 'unknown')}", "state": str(item.get("state") or "unknown")}
        for item in policy_order
        if isinstance(item, dict)
    ]
    if not normalized:
        return provider_order
    seen = {item["step"] for item in normalized}
    return [*normalized, *[item for item in provider_order if item.get("step") not in seen]]


def strongest_provider_effective_access(
    records: list[dict[str, Any]],
    *,
    denies: Callable[[dict[str, Any]], bool],
    layer_rank: Callable[[str], int],
) -> dict[str, Any] | None:
    if not records:
        return None
    deny_records = [record for record in records if denies(record)]
    allow_records = [record for record in records if not denies(record)]
    strongest_allow = _strongest_by_layer_impact_confidence(allow_records, layer_rank)
    if not deny_records:
        return strongest_allow
    if strongest_allow is None:
        return _strongest_by_layer_impact_confidence(deny_records, layer_rank)
    applicable_denies = [
        record
        for record in deny_records
        if _deny_applies_to_candidate(record, strongest_allow)
        or impact_rank(str(record.get("impact") or "")) >= impact_rank(str(strongest_allow.get("impact") or ""))
    ]
    if applicable_denies:
        return _strongest_by_layer_impact_confidence(applicable_denies, layer_rank)
    return strongest_allow


def _strongest_by_layer_impact_confidence(
    records: list[dict[str, Any]],
    layer_rank: Callable[[str], int],
) -> dict[str, Any] | None:
    if not records:
        return None
    return max(
        records,
        key=lambda item: (
            layer_rank(str(item.get("policy_layer") or "")),
            impact_rank(str(item.get("impact") or "")),
            confidence_rank(str(item.get("confidence") or "")),
        ),
    )


def _deny_applies_to_candidate(deny_record: dict[str, Any], candidate: dict[str, Any]) -> bool:
    deny_action = str(deny_record.get("action") or "").lower()
    candidate_action = str(candidate.get("action") or "").lower()
    if not deny_action or not candidate_action:
        return False
    if deny_action not in {"*", candidate_action}:
        return False
    deny_resources = _effective_access_resource_tokens(deny_record)
    candidate_resources = _effective_access_resource_tokens(candidate)
    if not deny_resources or not candidate_resources:
        return True
    return "*" in deny_resources or bool(deny_resources & candidate_resources)


def _effective_access_resource_tokens(record: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for key in ("resource", "resource_scope"):
        value = str(record.get(key) or "").lower()
        if value and value != "unknown":
            tokens.add(value)
    for key in ("target_resources", "resource_refs"):
        raw = record.get(key)
        if isinstance(raw, list):
            tokens.update(str(item).lower() for item in raw if str(item))
    return tokens


def strongest_capability(context: ContextEvidence) -> dict[str, Any] | None:
    capabilities = dedupe_iam_capabilities([dict(item) for item in context.iam_capabilities if isinstance(item, dict)])
    if not capabilities:
        return None
    return max(capabilities, key=lambda item: (impact_rank(str(item.get("impact") or "")), capability_risk_multiplier(item)))


def identity_decision_rank(item: dict[str, Any]) -> int:
    decision = str(item.get("decision") or "").lower()
    effect = str(item.get("effect") or "allow").lower()
    if effect == "deny" or decision.startswith("denied"):
        return 4
    if decision in {"allowed", "allow"}:
        return 3
    return 1


def capability_blockers(capability: dict[str, Any]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    if str(capability.get("resource_scope") or "unknown").lower() == "unknown":
        blockers.append({"kind": "unknown_resource_scope", "evidence": "capability resource scope is unknown"})
    elif str(capability.get("resource_scope") or "").lower() == "scoped":
        blockers.append({"kind": "scoped_resource", "evidence": "capability is scoped to specific resources"})
    condition_keys = capability.get("condition_keys")
    for key in condition_keys if isinstance(condition_keys, list) else []:
        blockers.append({"kind": "condition", "evidence": f"condition key {key}"})
    return blockers


def effective_edges(
    artifact_name: str,
    record_id: str,
    provider: str,
    network: dict[str, Any],
    identity: dict[str, Any],
    confidence: str,
) -> list[dict[str, Any]]:
    asset_id = f"asset:{artifact_name}"
    network_id = f"effective-network:{stable_token(record_id + ':network')}"
    identity_id = f"effective-identity:{stable_token(record_id + ':identity')}"
    return [
        effective_edge(asset_id, network_id, "asset_effective_network_path", provider, network),
        effective_edge(network_id, identity_id, "network_path_effective_identity", provider, identity),
        {
            "from": identity_id,
            "to": f"asset-runtime:{artifact_name}",
            "kind": "identity_runs_asset_runtime",
            "provider": provider,
            "evidence_layer": "iam",
            "source": str(identity.get("source") or "context"),
            "confidence": confidence,
            "blockers": objects(identity.get("blockers")),
            "unknowns": strings(identity.get("unknowns")),
            "state": str(identity.get("decision") or "unknown"),
        },
    ]


def effective_edge(
    source: str,
    target: str,
    kind: str,
    provider: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    return {
        "from": source,
        "to": target,
        "kind": kind,
        "provider": provider,
        "evidence_layer": str(data.get("evidence_layer") or "context"),
        "source": str(data.get("source") or "context"),
        "confidence": confidence_value(data.get("confidence")),
        "blockers": objects(data.get("blockers")),
        "unknowns": strings(data.get("unknowns")),
        "state": str(data.get("decision") or "unknown"),
    }


def path_type_for_exposure(exposure: str) -> str:
    return {
        "public": "direct_public",
        "external": "restricted_external_ingress",
        "internal": "internal_ingress",
        "private": "no_observed_ingress",
        "isolated": "no_observed_ingress",
        "none": "no_observed_ingress",
    }.get(exposure, "unresolved")


def entry_for_exposure(exposure: str) -> str:
    return {
        "public": "internet",
        "external": "external_cidr",
        "internal": "internal_network",
        "private": "isolated_network",
        "isolated": "isolated_network",
        "none": "isolated_network",
    }.get(exposure, "unknown")


def evidence_network_steps(evidence: list[str]) -> list[str]:
    steps: list[str] = []
    for item in evidence:
        text = str(item)
        marker = " via "
        if "network path:" in text and marker in text:
            steps.extend(part.strip() for part in text.split(marker, 1)[1].split(" -> ") if part.strip())
    return steps


def evidence_layer(source: str) -> str:
    value = source.lower()
    if "terraform" in value:
        return "terraform"
    if "kubernetes" in value or "k8s" in value:
        return "kubernetes"
    if "context" in value:
        return "context"
    return value or "context"


def combine_confidence(network: str, identity: str, default: str) -> str:
    values = [confidence_value(network, default), confidence_value(identity, default), confidence_value(default)]
    return min(values, key=confidence_rank)


def confidence_value(value: Any, default: str = "low") -> str:
    candidate = str(value or default).lower()
    return candidate if candidate in {"high", "medium", "low"} else default


def confidence_rank(value: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(str(value).lower(), 1)


def decision_rank(value: str) -> int:
    return {
        "blocked": 0,
        "isolated": 1,
        "unknown": 2,
        "reachable_without_effective_identity": 3,
        "constrained": 4,
        "reachable": 5,
    }.get(value, 2)


def impact_rank(value: str) -> int:
    return {
        "admin_control": 6,
        "iam_escalation": 5,
        "network_control": 5,
        "compute_control": 4,
        "data_access": 4,
        "limited_access": 1,
    }.get(value.lower(), 0)


def objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def dedupe_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    for value in values:
        if value and value not in deduped:
            deduped.append(value)
    return deduped


def dedupe_objects(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        token = json.dumps(value, sort_keys=True, default=str)
        if token in seen:
            continue
        seen.add(token)
        deduped.append(value)
    return deduped


def blocker_kinds(blockers: list[dict[str, Any]], effect: str) -> list[str]:
    return sorted({str(item.get("kind") or "unknown") for item in blockers if str(item.get("effect") or "") == effect})


def matched_blocker_state(blocking: set[str], constraining: set[str], kinds: set[str]) -> str:
    if blocking & kinds:
        return "blocks"
    if constraining & kinds:
        return "constrains"
    return "not_observed"


def stable_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def jsonish(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)
