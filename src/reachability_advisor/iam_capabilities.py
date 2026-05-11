"""Normalized IAM capability helpers.

The rest of the scanner can keep provider-specific evidence, but scoring and
graph output need a small common vocabulary for action, access, impact, and
resource references.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

CRITICAL_CAPABILITY_IMPACTS = {"admin_control", "iam_escalation", "network_control", "compute_control", "data_access"}
CAPABILITY_ACCESS_BY_IMPACT = {
    "admin_control": "admin",
    "iam_escalation": "privilege_escalation",
    "network_control": "network_mutation",
    "compute_control": "compute_mutation",
    "data_access": "sensitive_data",
    "limited_access": "limited",
}
CAPABILITY_IMPACT_RANK = {
    "unknown": 0,
    "limited_access": 1,
    "data_access": 2,
    "compute_control": 3,
    "network_control": 4,
    "iam_escalation": 5,
    "admin_control": 6,
}


def normalize_iam_capability(raw: dict[str, Any]) -> dict[str, Any]:
    impact = str(raw.get("impact") or "limited_access").lower()
    action = str(raw.get("action") or "unknown")
    refs = raw.get("resource_refs")
    resource_refs = sorted(str(ref) for ref in refs) if isinstance(refs, list) else []
    condition_keys = raw.get("condition_keys")
    normalized: dict[str, Any] = {
        "action": action,
        "impact": impact,
        "access": str(raw.get("access") or CAPABILITY_ACCESS_BY_IMPACT.get(impact, "limited")).lower(),
        "effect": str(raw.get("effect") or "allow").lower(),
        "resource_refs": resource_refs,
        "resource_scope": str(raw.get("resource_scope") or _resource_scope(resource_refs)).lower(),
        "source": str(raw.get("source") or "unknown"),
        "evidence": str(raw.get("evidence") or ""),
    }
    if isinstance(condition_keys, list):
        normalized["condition_keys"] = sorted(str(key) for key in condition_keys)
    provider = raw.get("provider")
    if provider:
        normalized["provider"] = str(provider).lower()
    catalog = raw.get("catalog")
    if catalog:
        normalized["catalog"] = str(catalog)
    normalized["effective_risk"] = capability_effective_risk(normalized)
    normalized["risk_multiplier"] = capability_risk_multiplier(normalized)
    return normalized


def dedupe_iam_capabilities(capabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str, tuple[str, ...], str, str, tuple[str, ...]]] = set()
    result: list[dict[str, Any]] = []
    for item in capabilities:
        if not isinstance(item, dict):
            continue
        capability = normalize_iam_capability(item)
        key = (
            capability["action"],
            capability["impact"],
            capability["access"],
            capability["effect"],
            tuple(capability["resource_refs"]),
            capability["resource_scope"],
            capability["source"],
            tuple(capability.get("condition_keys", [])),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(capability)
    return result


def _resource_scope(resource_refs: list[str]) -> str:
    if not resource_refs:
        return "unknown"
    if any(ref in {"*", "*:*"} or ref.lower().startswith("not:") for ref in resource_refs):
        return "wildcard"
    return "scoped"


def capability_risk_multiplier(capability: Mapping[str, Any]) -> float:
    scope = str(capability.get("resource_scope") or "unknown").lower()
    condition_keys = capability.get("condition_keys")
    has_conditions = bool(condition_keys) if isinstance(condition_keys, list) else False
    if scope == "scoped" and has_conditions:
        return 0.6
    if scope == "scoped":
        return 0.75
    if has_conditions:
        return 0.85
    return 1.0


def capability_effective_risk(capability: Mapping[str, Any]) -> str:
    impact = str(capability.get("impact") or "limited_access").lower()
    multiplier = capability_risk_multiplier(capability)
    if impact in CRITICAL_CAPABILITY_IMPACTS and multiplier >= 0.95:
        return "critical"
    if impact in CRITICAL_CAPABILITY_IMPACTS:
        return "constrained_critical"
    if impact == "limited_access":
        return "limited"
    return "moderate"


def strongest_capability(capabilities: list[dict[str, Any]]) -> dict[str, Any] | None:
    normalized = dedupe_iam_capabilities(capabilities)
    if not normalized:
        return None
    return max(normalized, key=lambda item: CAPABILITY_IMPACT_RANK.get(str(item.get("impact") or "unknown"), 0))


__all__ = [
    "CAPABILITY_ACCESS_BY_IMPACT",
    "CAPABILITY_IMPACT_RANK",
    "CRITICAL_CAPABILITY_IMPACTS",
    "capability_effective_risk",
    "capability_risk_multiplier",
    "dedupe_iam_capabilities",
    "normalize_iam_capability",
    "strongest_capability",
]
