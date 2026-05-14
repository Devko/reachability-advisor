"""Scenario-oriented view model for the visual HTML report."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .finding_types import (
    CLOUD_POSTURE_FINDING,
    CORRELATED_SECURITY_FINDING,
    DEPENDENCY_VULNERABILITY,
    DYNAMIC_RUNTIME_OBSERVATION,
    STATIC_CODE_WEAKNESS,
    canonical_finding_type,
)
from .models import Finding, Reachability, RuntimeEvidenceState, reachability_label
from .numeric import safe_float
from .visual_layout import EXPOSURE_RANK, TIER_RANK

ISSUE_CATEGORIES: list[dict[str, str]] = [
    {"id": "vulnerabilities", "label": "Vulnerabilities", "shortLabel": "Vuln"},
    {"id": "insecure_configuration", "label": "Insecure Configuration", "shortLabel": "Config"},
    {"id": "events", "label": "Events", "shortLabel": "Events"},
    {"id": "identity_data_access", "label": "Identity/Data Access", "shortLabel": "IAM"},
    {"id": "visibility_gaps", "label": "Visibility Gaps", "shortLabel": "Gaps"},
]


def build_scenario_view(
    findings: list[Finding],
    network_paths: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
    attack_paths: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build risk scenarios and shared attack-path groups for the visual report."""

    paths_by_asset = _network_paths_by_asset(network_paths)
    vulnerability_by_key = {str(item.get("findingKey") or ""): item for item in vulnerabilities if isinstance(item, dict)}
    attack_path_by_key = {str(item.get("findingKey") or ""): item for item in attack_paths if isinstance(item, dict)}
    scenarios: dict[str, dict[str, Any]] = {}

    for finding in findings:
        asset_id = f"asset:{finding.artifact.name}"
        network_path = _primary_network_path(paths_by_asset.get(asset_id, []))
        path_id = str((network_path or {}).get("id") or f"network:path:{_stable_token(asset_id)}")
        scenario_id = f"scenario:{_stable_token(path_id + '|' + asset_id)}"
        scenario = scenarios.setdefault(scenario_id, _new_scenario(scenario_id, asset_id, finding, network_path))
        _add_finding_to_scenario(
            scenario,
            finding,
            network_path,
            vulnerability_by_key.get(finding.key, {}),
            attack_path_by_key.get(finding.key, {}),
        )

    finalized_scenarios = [_finalize_scenario(scenario) for scenario in scenarios.values()]
    finalized_scenarios.sort(key=lambda item: (-TIER_RANK.get(str(item.get("tier") or "informational"), 0), -safe_float(item.get("score")), str(item.get("title") or "")))
    groups = _attack_path_groups(network_paths, finalized_scenarios)
    return {
        "issueCategories": ISSUE_CATEGORIES,
        "riskScenarios": finalized_scenarios,
        "attackPathGroups": groups,
    }


def _new_scenario(scenario_id: str, asset_id: str, finding: Finding, network_path: dict[str, Any] | None) -> dict[str, Any]:
    path = network_path or {}
    path_id = str(path.get("id") or f"network:path:{_stable_token(asset_id)}")
    return {
        "id": scenario_id,
        "scenarioKind": "scenario",
        "attackKind": "scenario",
        "assetId": asset_id,
        "assetName": finding.artifact.name,
        "assetReference": finding.artifact.reference,
        "owner": finding.context.owner,
        "networkPathId": path_id,
        "attackPathGroupId": f"attack-group:{_stable_token(path_id)}",
        "pathLabel": path.get("label") or "Unresolved network path",
        "pathSummary": path.get("summary") or "",
        "pathSteps": path.get("steps") if isinstance(path.get("steps"), list) else [],
        "entryLabel": path.get("entryLabel") or _entry_label(finding.context.exposure),
        "entrySubtitle": path.get("entrySubtitle") or "",
        "provider": _provider_for_path(path),
        "exposure": path.get("exposure") or finding.context.exposure or "unknown",
        "confidence": finding.confidence.value,
        "tier": finding.tier.value,
        "score": round(finding.score, 2),
        "priorityLabel": _priority_label(finding.tier.value),
        "findingKeys": [],
        "findingTypes": [],
        "policyStatuses": [],
        "categories": _empty_categories(),
        "sourceStates": [],
        "codeExposures": [],
        "vulnerabilitySeverities": [],
        "unknowns": [],
        "blockers": [],
        "evidenceSummary": [],
        "contextSignals": [],
        "inUseCount": 0,
        "status": "Open",
    }


def _add_finding_to_scenario(
    scenario: dict[str, Any],
    finding: Finding,
    network_path: dict[str, Any] | None,
    vulnerability: dict[str, Any],
    attack_path: dict[str, Any],
) -> None:
    finding_type = canonical_finding_type(finding.finding_type)
    scenario["tier"] = _stronger_tier(scenario.get("tier"), finding.tier.value)
    scenario["score"] = max(safe_float(scenario.get("score")), safe_float(finding.score))
    scenario["confidence"] = _stronger_confidence(scenario.get("confidence"), finding.confidence.value)
    scenario["owner"] = scenario.get("owner") or finding.context.owner
    _append_unique(scenario["findingKeys"], finding.key)
    _append_unique(scenario["findingTypes"], finding_type)
    _append_unique(scenario["policyStatuses"], finding.policy_status or "active")
    _append_unique(scenario["sourceStates"], finding.source.reachability.value)
    _append_unique(scenario["codeExposures"], reachability_label(finding.source.reachability))
    _append_unique(scenario["vulnerabilitySeverities"], finding.vulnerability.severity or "unknown")
    for value in finding.unknowns:
        _append_unique(scenario["unknowns"], value)
    for value in finding.evidence_summary:
        _append_unique(scenario["evidenceSummary"], value)
    for value in finding.context.evidence[:4]:
        _append_unique(scenario["evidenceSummary"], value)

    if _is_in_use(finding):
        scenario["inUseCount"] += 1

    finding_item = _finding_item(finding, vulnerability, attack_path)
    if finding_type in {DEPENDENCY_VULNERABILITY, STATIC_CODE_WEAKNESS, CORRELATED_SECURITY_FINDING}:
        _append_category_item(scenario, "vulnerabilities", finding_item)
    if finding_type == CLOUD_POSTURE_FINDING:
        _append_category_item(scenario, "insecure_configuration", finding_item)
    if finding_type == DYNAMIC_RUNTIME_OBSERVATION or finding.runtime_evidence.state != RuntimeEvidenceState.NOT_OBSERVED:
        _append_category_item(scenario, "events", finding_item)

    for item in _identity_items(finding):
        _append_category_item(scenario, "identity_data_access", item)
        _append_unique(scenario["contextSignals"], item["label"])

    for item in _visibility_items(finding, network_path):
        _append_category_item(scenario, "visibility_gaps", item)

    for blocker in _path_blockers(network_path):
        _append_unique(scenario["blockers"], blocker)
        _append_category_item(
            scenario,
            "insecure_configuration",
            {
                "key": f"blocker:{_stable_token(json.dumps(blocker, sort_keys=True, default=str))}",
                "label": _blocker_label(blocker),
                "detail": _blocker_detail(blocker),
                "tier": finding.tier.value,
                "score": round(finding.score, 2),
                "findingKey": finding.key,
                "findingType": "network_control",
            },
        )


def _finalize_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    categories = scenario["categories"]
    category_list = []
    category_counts: dict[str, int] = {}
    for category in ISSUE_CATEGORIES:
        value = categories[category["id"]]
        value["count"] = len(value["items"])
        value["findingCount"] = len(value["findingKeys"])
        category_counts[category["id"]] = value["count"]
        category_list.append(value)
    scenario["categoryList"] = category_list
    scenario["categoryCounts"] = category_counts
    scenario["categorySummary"] = [
        {"id": category["id"], "label": category["label"], "shortLabel": category["shortLabel"], "count": category_counts[category["id"]]}
        for category in ISSUE_CATEGORIES
        if category_counts[category["id"]]
    ]
    scenario["totalFindings"] = len(scenario["findingKeys"])
    scenario["priorityLabel"] = _priority_label(str(scenario.get("tier") or "informational"))
    scenario["status"] = _status_label(scenario["policyStatuses"])
    scenario["title"] = _scenario_title(scenario)
    scenario["searchText"] = " ".join(
        str(value)
        for value in [
            scenario["title"],
            scenario.get("assetName"),
            scenario.get("pathLabel"),
            scenario.get("provider"),
            scenario.get("exposure"),
            *scenario.get("codeExposures", []),
            *scenario.get("contextSignals", []),
            *[item["label"] for category in category_list for item in category.get("items", [])],
        ]
        if value
    ).lower()
    return scenario


def _attack_path_groups(network_paths: list[dict[str, Any]], scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scenarios_by_path: dict[str, list[dict[str, Any]]] = {}
    for scenario in scenarios:
        scenarios_by_path.setdefault(str(scenario.get("networkPathId") or ""), []).append(scenario)

    groups: list[dict[str, Any]] = []
    for path in network_paths:
        path_id = str(path.get("id") or "")
        if not path_id:
            continue
        linked = scenarios_by_path.get(path_id, [])
        if not linked:
            continue
        group_id = f"attack-group:{_stable_token(path_id)}"
        category_counts = {category["id"]: 0 for category in ISSUE_CATEGORIES}
        finding_keys: list[str] = []
        for scenario in linked:
            for category_id, count in scenario.get("categoryCounts", {}).items():
                category_counts[category_id] = category_counts.get(category_id, 0) + int(count or 0)
            for key in scenario.get("findingKeys", []):
                _append_unique(finding_keys, key)
        tier = "informational"
        score = 0.0
        for scenario in linked:
            tier = _stronger_tier(tier, scenario.get("tier"))
            score = max(score, safe_float(scenario.get("score")))
        groups.append(
            {
                "id": group_id,
                "attackKind": "group",
                "networkPathId": path_id,
                "title": _group_title(path),
                "summary": path.get("summary") or path.get("evidence") or "",
                "entryLabel": path.get("entryLabel") or "Unknown entry",
                "entrySubtitle": path.get("entrySubtitle") or "",
                "pathLabel": path.get("label") or "Network path",
                "pathType": path.get("pathType") or "unresolved",
                "provider": _provider_for_path(path),
                "exposure": path.get("exposure") or "unknown",
                "confidence": path.get("confidence") or "low",
                "tier": tier,
                "score": round(score, 2),
                "priorityLabel": _priority_label(tier),
                "assetIds": [scenario["assetId"] for scenario in linked],
                "assetNames": [scenario["assetName"] for scenario in linked],
                "assetCount": len(linked),
                "findingKeys": finding_keys,
                "findingCount": len(finding_keys),
                "scenarioIds": [scenario["id"] for scenario in linked],
                "assets": [_scenario_summary(scenario) for scenario in linked],
                "categoryCounts": category_counts,
                "categorySummary": [
                    {"id": category["id"], "label": category["label"], "shortLabel": category["shortLabel"], "count": category_counts.get(category["id"], 0)}
                    for category in ISSUE_CATEGORIES
                    if category_counts.get(category["id"], 0)
                ],
                "routeNodes": _route_nodes_for_path(path, group_id),
                "blockers": path.get("blockers") if isinstance(path.get("blockers"), list) else [],
                "evidence": path.get("evidence") or "",
                "steps": path.get("steps") if isinstance(path.get("steps"), list) else [],
            }
        )
    return sorted(groups, key=lambda item: (-TIER_RANK.get(str(item.get("tier") or "informational"), 0), -safe_float(item.get("score")), str(item.get("title") or "")))


def _scenario_summary(scenario: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": scenario["id"],
        "scenarioKind": "scenario",
        "attackKind": "scenario",
        "assetId": scenario["assetId"],
        "assetName": scenario["assetName"],
        "title": scenario["title"],
        "tier": scenario["tier"],
        "score": scenario["score"],
        "priorityLabel": scenario["priorityLabel"],
        "findingKeys": scenario["findingKeys"],
        "totalFindings": scenario["totalFindings"],
        "inUseCount": scenario["inUseCount"],
        "categoryCounts": scenario["categoryCounts"],
        "categorySummary": scenario["categorySummary"],
        "status": scenario["status"],
        "networkPathId": scenario["networkPathId"],
        "attackPathGroupId": scenario["attackPathGroupId"],
    }


def _empty_categories() -> dict[str, dict[str, Any]]:
    return {
        category["id"]: {
            "id": category["id"],
            "label": category["label"],
            "shortLabel": category["shortLabel"],
            "items": [],
            "findingKeys": [],
            "count": 0,
            "findingCount": 0,
        }
        for category in ISSUE_CATEGORIES
    }


def _append_category_item(scenario: dict[str, Any], category_id: str, item: dict[str, Any]) -> None:
    category = scenario["categories"][category_id]
    key = str(item.get("key") or item.get("findingKey") or item.get("label") or "")
    if key and any(str(existing.get("key") or existing.get("findingKey") or existing.get("label") or "") == key for existing in category["items"]):
        return
    category["items"].append(item)
    if item.get("findingKey"):
        _append_unique(category["findingKeys"], item["findingKey"])


def _finding_item(finding: Finding, vulnerability: dict[str, Any], attack_path: dict[str, Any]) -> dict[str, Any]:
    finding_type = canonical_finding_type(finding.finding_type)
    weakness = finding.weakness or {}
    if finding_type == DEPENDENCY_VULNERABILITY:
        label = f"{finding.vulnerability.id} in {finding.component.display_name}"
    else:
        label = str(weakness.get("weakness") or finding.vulnerability.summary or finding.vulnerability.id)
    return {
        "key": finding.key,
        "findingKey": finding.key,
        "findingType": finding_type,
        "label": label,
        "detail": _first_nonempty(
            [
                finding.vulnerability.summary,
                weakness.get("cwe"),
                weakness.get("tool"),
                attack_path.get("shortReason") if isinstance(attack_path, dict) else "",
            ]
        ),
        "advisoryId": finding.vulnerability.id,
        "component": finding.component.display_name,
        "severity": vulnerability.get("severity") or finding.vulnerability.severity or "unknown",
        "tier": finding.tier.value,
        "score": round(finding.score, 2),
    }


def _identity_items(finding: Finding) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if finding.context.privilege and finding.context.privilege not in {"unknown", "none"}:
        items.append(
            {
                "key": f"{finding.key}:privilege:{finding.context.privilege}",
                "findingKey": finding.key,
                "findingType": "identity_context",
                "label": f"{finding.context.privilege} privilege",
                "detail": ", ".join(finding.context.iam_impacts[:4]),
                "tier": finding.tier.value,
                "score": round(finding.score, 2),
            }
        )
    for impact in finding.context.iam_impacts:
        items.append(
            {
                "key": f"{finding.key}:iam-impact:{impact}",
                "findingKey": finding.key,
                "findingType": "identity_context",
                "label": str(impact),
                "detail": "IAM impact on the reachable asset",
                "tier": finding.tier.value,
                "score": round(finding.score, 2),
            }
        )
    for index, access in enumerate(finding.context.effective_access[:4]):
        label = str(access.get("identity") or access.get("principal") or access.get("action") or "effective access")
        detail = " ".join(str(access.get(key) or "") for key in ("action", "decision", "resource")).strip()
        items.append(
            {
                "key": f"{finding.key}:effective-access:{index}",
                "findingKey": finding.key,
                "findingType": "identity_context",
                "label": label,
                "detail": detail,
                "tier": finding.tier.value,
                "score": round(finding.score, 2),
            }
        )
    return items


def _visibility_items(finding: Finding, network_path: dict[str, Any] | None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if finding.source.reachability in {Reachability.UNKNOWN_DUE_TO_NO_RULE, Reachability.PACKAGE_PRESENT, Reachability.ABSENT}:
        items.append(
            {
                "key": f"{finding.key}:source:{finding.source.reachability.value}",
                "findingKey": finding.key,
                "findingType": "visibility_gap",
                "label": reachability_label(finding.source.reachability),
                "detail": finding.source.reason,
                "tier": finding.tier.value,
                "score": round(finding.score, 2),
            }
        )
    if not network_path:
        items.append(
            {
                "key": f"{finding.key}:network-path-missing",
                "findingKey": finding.key,
                "findingType": "visibility_gap",
                "label": "network path unavailable",
                "detail": "No linked network path is available for this asset.",
                "tier": finding.tier.value,
                "score": round(finding.score, 2),
            }
        )
    elif str(network_path.get("confidence") or "low") == "low" or str(network_path.get("exposure") or "unknown") == "unknown":
        items.append(
            {
                "key": f"{finding.key}:network-confidence",
                "findingKey": finding.key,
                "findingType": "visibility_gap",
                "label": "network path confidence is low or unresolved",
                "detail": str(network_path.get("summary") or network_path.get("evidence") or ""),
                "tier": finding.tier.value,
                "score": round(finding.score, 2),
            }
        )
    for index, unknown in enumerate(finding.unknowns[:4]):
        items.append(
            {
                "key": f"{finding.key}:unknown:{index}",
                "findingKey": finding.key,
                "findingType": "visibility_gap",
                "label": str(unknown),
                "detail": "Visibility gap",
                "tier": finding.tier.value,
                "score": round(finding.score, 2),
            }
        )
    return items


def _scenario_title(scenario: dict[str, Any]) -> str:
    exposure = str(scenario.get("exposure") or "unknown").lower()
    exposure_label = {
        "public": "Public exposed",
        "external": "Externally reachable",
        "internal": "Internally reachable",
        "private": "Private",
        "isolated": "Isolated",
    }.get(exposure, "Unresolved")
    asset_kind = _asset_kind(scenario)
    counts = scenario.get("categoryCounts") or {}
    has_vulnerability = counts.get("vulnerabilities", 0) > 0
    has_config = counts.get("insecure_configuration", 0) > 0
    has_event = counts.get("events", 0) > 0
    has_identity = counts.get("identity_data_access", 0) > 0
    has_gaps = counts.get("visibility_gaps", 0) > 0
    severity = _max_severity(scenario.get("vulnerabilitySeverities") or [])
    source_states = {str(value) for value in scenario.get("sourceStates") or []}

    if has_event and has_vulnerability:
        issue = "with runtime event and reachable exploit"
    elif has_vulnerability and severity == "critical":
        issue = "with critical reachable network exploit"
    elif has_vulnerability and "attacker_controlled" in source_states:
        issue = "with request-controlled exploit path"
    elif has_vulnerability:
        issue = "with reachable vulnerability exposure"
    elif has_config and has_identity:
        issue = "with insecure configuration and privileged control"
    elif has_config:
        issue = "with insecure configuration"
    elif has_event:
        issue = "with runtime security event"
    elif has_identity:
        issue = "with privileged access path"
    elif has_gaps:
        issue = "with visibility gaps"
    else:
        issue = "with security findings"

    if has_identity and "privileged" not in issue and "identity" not in issue:
        issue = f"{issue} and privileged control"
    hop_count = len(scenario.get("pathSteps") or [])
    hop_text = f" reachable in {hop_count} hops" if hop_count >= 4 else ""
    return f"{exposure_label} {asset_kind}{hop_text} {issue}"


def _asset_kind(scenario: dict[str, Any]) -> str:
    text = " ".join(
        str(value)
        for value in [
            scenario.get("assetName"),
            scenario.get("assetReference"),
            scenario.get("pathLabel"),
            *(scenario.get("pathSteps") or []),
        ]
        if value
    ).lower()
    if "s3" in text or "bucket" in text or "storage" in text:
        return "storage asset"
    if "ec2" in text or "aws_instance" in text or "virtual_machine" in text:
        return "EC2 workload"
    if "kubernetes" in text or "deployment" in text or "clusterip" in text:
        return "Kubernetes workload"
    if "ecs" in text or "fargate" in text:
        return "ECS service"
    if "lambda" in text or "function" in text:
        return "Lambda function"
    if "cloud_run" in text or "cloud run" in text:
        return "Cloud Run service"
    if "container_app" in text or "container app" in text:
        return "container app"
    if "app_service" in text or "web_app" in text or "web app" in text:
        return "web app"
    return "workload"


def _route_nodes_for_path(path: dict[str, Any], group_id: str) -> list[dict[str, Any]]:
    token = _stable_token(group_id)
    nodes = [
        {
            "id": f"{group_id}:route:entry",
            "type": "entry",
            "label": path.get("entryLabel") or "Unknown entry",
            "subtitle": path.get("entrySubtitle") or path.get("exposure") or "",
            "confidence": path.get("confidence") or "low",
            "evidenceLayer": _network_layer(path),
            "state": "unknown" if str(path.get("exposure") or "unknown") == "unknown" else "normal",
        }
    ]
    path_steps = path.get("steps")
    raw_steps = path_steps if isinstance(path_steps, list) else []
    steps = [str(step) for step in raw_steps if step]
    if not steps and path.get("label"):
        steps = [str(path.get("label"))]
    seen: set[str] = set()
    for index, step in enumerate(steps[:7]):
        key = step.lower()
        if key in seen:
            continue
        seen.add(key)
        nodes.append(
            {
                "id": f"{group_id}:route:{token}:{index}",
                "type": _route_node_type(step),
                "label": step,
                "subtitle": path.get("pathType") or path.get("exposure") or "",
                "confidence": path.get("confidence") or "low",
                "evidenceLayer": _network_layer(path),
                "state": "normal",
            }
        )
    return nodes


def _route_node_type(label: str) -> str:
    lowered = label.lower()
    if "load balancer" in lowered or "_lb" in lowered or "ingress" in lowered or "gateway" in lowered:
        return "ingress"
    if "security_group" in lowered or "firewall" in lowered or "network_policy" in lowered or "nsg" in lowered:
        return "policy"
    if "service" in lowered or "target_group" in lowered or "clusterip" in lowered:
        return "service"
    return "hop"


def _group_title(path: dict[str, Any]) -> str:
    entry = str(path.get("entryLabel") or "Entry")
    label = str(path.get("label") or path.get("pathType") or "network path")
    return f"{entry} to {label}"


def _network_paths_by_asset(network_paths: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for path in network_paths:
        if not isinstance(path, dict):
            continue
        for asset_id in _path_asset_ids(path):
            grouped.setdefault(asset_id, []).append(path)
    return grouped


def _primary_network_path(paths: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not paths:
        return None
    return sorted(
        paths,
        key=lambda item: (
            -EXPOSURE_RANK.get(str(item.get("exposure") or "unknown"), 0),
            -TIER_RANK.get(str(item.get("tier") or "informational"), 0),
            -safe_float(item.get("score")),
            str(item.get("id") or ""),
        ),
    )[0]


def _path_asset_ids(path: dict[str, Any]) -> list[str]:
    asset_ids = path.get("assetIds")
    if isinstance(asset_ids, list):
        return [str(asset_id) for asset_id in asset_ids if asset_id]
    asset_id = path.get("assetId")
    return [str(asset_id)] if asset_id else []


def _path_blockers(network_path: dict[str, Any] | None) -> list[Any]:
    if not network_path or not isinstance(network_path.get("blockers"), list):
        return []
    return list(network_path.get("blockers") or [])


def _provider_for_path(path: dict[str, Any]) -> str:
    provider = path.get("provider") if isinstance(path, dict) else None
    if provider:
        return str(provider)
    text = " ".join([str(path.get("label") or ""), str(path.get("evidence") or ""), " ".join(str(step) for step in path.get("steps") or [])]).lower() if isinstance(path, dict) else ""
    if "aws_" in text or "amazon" in text:
        return "AWS"
    if "azurerm_" in text or "azure" in text:
        return "Azure"
    if "google_" in text or "gcp" in text:
        return "GCP"
    if "kubernetes" in text:
        return "Kubernetes"
    return "Context"


def _network_layer(path: dict[str, Any]) -> str:
    provider = _provider_for_path(path).lower()
    evidence = str(path.get("evidence") or "").lower()
    if provider in {"aws", "azure", "gcp"} or evidence.startswith("terraform"):
        return "Terraform"
    if provider == "kubernetes" or "kubernetes" in evidence:
        return "Kubernetes"
    return "Context"


def _entry_label(exposure: str) -> str:
    exposure = str(exposure or "unknown").lower()
    if exposure == "public":
        return "Internet / attacker"
    if exposure == "external":
        return "External source"
    if exposure == "internal":
        return "Internal network"
    if exposure in {"private", "isolated"}:
        return "No external entry"
    return "Unknown entry"


def _is_in_use(finding: Finding) -> bool:
    return finding.source.reachability in {
        Reachability.DEPENDENCY_REACHABLE,
        Reachability.IMPORTED,
        Reachability.FUNCTION_REACHABLE,
        Reachability.ATTACKER_CONTROLLED,
    }


def _max_severity(values: list[Any]) -> str:
    order = {"unknown": 0, "low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}
    best = "unknown"
    for value in values:
        candidate = str(value or "unknown").lower()
        if order.get(candidate, 0) > order.get(best, 0):
            best = candidate
    return best


def _stronger_tier(first: Any, second: Any) -> str:
    first_value = str(first or "informational")
    second_value = str(second or "informational")
    return first_value if TIER_RANK.get(first_value, 0) >= TIER_RANK.get(second_value, 0) else second_value


def _stronger_confidence(first: Any, second: Any) -> str:
    rank = {"low": 0, "medium": 1, "high": 2}
    first_value = str(first or "low")
    second_value = str(second or "low")
    return first_value if rank.get(first_value, 0) >= rank.get(second_value, 0) else second_value


def _priority_label(tier: str) -> str:
    if tier == "urgent":
        return "Critical"
    return str(tier or "informational").replace("_", " ").title()


def _status_label(statuses: list[Any]) -> str:
    normalized = {str(status or "active").lower() for status in statuses}
    if not normalized or normalized == {"active"}:
        return "Open"
    if normalized == {"excepted"}:
        return "Excepted"
    return "Mixed"


def _blocker_label(blocker: Any) -> str:
    if isinstance(blocker, dict):
        return str(blocker.get("kind") or blocker.get("type") or "network constraint")
    return str(blocker)


def _blocker_detail(blocker: Any) -> str:
    if isinstance(blocker, dict):
        return str(blocker.get("evidence") or blocker.get("reason") or blocker.get("detail") or "")
    return ""


def _first_nonempty(values: list[Any]) -> str:
    for value in values:
        if value:
            return str(value)
    return ""


def _append_unique(items: list[Any], value: Any) -> None:
    if value in (None, "", [], {}):
        return
    if value not in items:
        items.append(value)


def _stable_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


__all__ = ["ISSUE_CATEGORIES", "build_scenario_view"]
