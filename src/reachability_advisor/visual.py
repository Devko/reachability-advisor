"""Self-contained visual HTML report renderer."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .attack_path_view import build_attack_paths
from .evidence_graph import build_evidence_graph
from .finding_types import canonical_finding_type
from .models import Finding, reachability_label
from .numeric import safe_float
from .remediation import build_remediation_groups
from .scenario_view import build_scenario_view
from .visual_graph import visual_graph_model
from .visual_layout import EXPOSURE_RANK, TIER_RANK
from .visual_template import HTML_TEMPLATE

_visual_graph_model = visual_graph_model


def write_html_report(findings: list[Finding], path: str | Path, metadata: dict[str, Any] | None = None, evidence_graph: dict[str, Any] | None = None) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html_report(findings, metadata=metadata, evidence_graph=evidence_graph), encoding="utf-8")


def render_html_report(findings: list[Finding], metadata: dict[str, Any] | None = None, evidence_graph: dict[str, Any] | None = None) -> str:
    payload = _visual_payload(findings, metadata=metadata, evidence_graph=evidence_graph)
    data_json = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return HTML_TEMPLATE.replace("__REPORT_DATA__", data_json)


def _visual_payload(findings: list[Finding], metadata: dict[str, Any] | None = None, evidence_graph: dict[str, Any] | None = None) -> dict[str, Any]:
    finding_rows = [finding.to_json() for finding in findings]
    graph = evidence_graph or build_evidence_graph(findings, metadata=metadata)
    graph_paths_by_asset = _graph_network_paths_by_asset(graph)
    effective_paths_by_key = _effective_paths_by_key(graph)
    assets: dict[str, dict[str, Any]] = {}
    vulnerabilities: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []

    for finding in finding_rows:
        artifact = finding["artifact"]
        component = finding["component"]
        vulnerability = finding["vulnerability"]
        weakness = finding.get("weakness") if isinstance(finding.get("weakness"), dict) else {}
        finding_type = str(finding.get("finding_type") or "dependency_vulnerability")
        canonical_type = canonical_finding_type(finding_type)
        source = finding["source_reachability"]
        context = finding.get("context") or {}
        artifact_name = str(artifact.get("name") or "unknown-artifact")
        asset_id = f"asset:{artifact_name}"
        asset = assets.setdefault(
            asset_id,
            {
                "id": asset_id,
                "name": artifact_name,
                "reference": artifact.get("reference"),
                "owner": context.get("owner"),
                "tier": "informational",
                "score": 0.0,
                "findingKeys": [],
                "exposures": [],
                "privileges": [],
                "criticalities": [],
                "environments": [],
                "iamImpacts": [],
                "effectiveAccess": [],
                "sourceStates": [],
                "codeExposures": [],
                "evidence": [],
                "networkPaths": [],
            },
        )
        _raise_asset(asset, finding)

        vuln_id = f"vulnerability:{finding['key']}"
        vulnerability_node = {
            "id": vuln_id,
            "assetId": asset_id,
            "findingKey": finding["key"],
            "kind": "vulnerability" if canonical_type == "dependency_vulnerability" else canonical_type,
            "findingType": finding_type,
            "weakness": weakness,
            "runtimeEvidence": finding.get("runtime_evidence") or {},
            "correlatedEvidence": finding.get("correlated_evidence") or [],
            "unknowns": finding.get("unknowns") or [],
            "evidenceSummary": finding.get("evidence_summary") or [],
            "label": str(vulnerability.get("id") or "unknown-vulnerability"),
            "tier": finding.get("tier") or "informational",
            "score": safe_float(finding.get("score")),
            "component": str(component.get("display_name") or component.get("name") or "unknown-component"),
            "componentVersion": component.get("version") or "unknown",
            "severity": vulnerability.get("severity") or "unknown",
            "cvss": vulnerability.get("cvss"),
            "knownExploited": bool(vulnerability.get("known_exploited")),
            "reachability": source.get("state") or "unknown",
            "codeExposure": _code_exposure_label(source),
            "codeExposureDetail": _code_exposure_detail(source.get("state") or "unknown"),
            "exposure": context.get("exposure") or "unknown",
            "privilege": context.get("privilege") or "unknown",
            "criticality": context.get("criticality") or "unknown",
            "iamImpacts": context.get("iam_impacts") or [],
            "effectiveAccess": context.get("effective_access") or [],
            "summary": vulnerability.get("summary") or "",
            "rationale": finding.get("rationale") or [],
            "fixCommands": finding.get("fix_commands") or [],
            "policyStatus": finding.get("policy_status") or "active",
            "sourceReason": source.get("reason") or "",
            "sourceLocations": source.get("locations") or [],
            "contextEvidence": context.get("evidence") or [],
            "effectivePath": (finding.get("scoring") or {}).get("effective_exposure_path") or effective_paths_by_key.get(finding["key"], {}),
        }
        vulnerabilities.append(vulnerability_node)
        links.append(
            {
                "id": f"{asset_id}->{vuln_id}",
                "source": asset_id,
                "target": vuln_id,
                "findingKey": finding["key"],
                "tier": finding.get("tier") or "informational",
            }
        )

    ordered_assets = sorted(assets.values(), key=lambda asset: (-TIER_RANK.get(asset["tier"], 0), -safe_float(asset["score"]), asset["name"]))
    for asset in ordered_assets:
        paths = graph_paths_by_asset.get(asset["id"])
        if paths:
            asset["networkPaths"] = paths
    network_paths = _finalize_network_paths(ordered_assets)
    vulnerabilities.sort(key=lambda item: (item["assetId"], -TIER_RANK.get(item["tier"], 0), -safe_float(item["score"]), item["label"]))
    architecture = _architecture_view(ordered_assets, network_paths, vulnerabilities)
    remediations = build_remediation_groups(findings)
    attack_paths = build_attack_paths(findings, network_paths, vulnerabilities, remediations)
    scenario_view = build_scenario_view(findings, network_paths, vulnerabilities, attack_paths)
    return {
        "metadata": {
            "tool": "reachability-advisor",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **(metadata or {}),
        },
        "stats": _stats(finding_rows),
        "remediations": remediations,
        "evidenceGraph": graph,
        "findings": finding_rows,
        "assets": ordered_assets,
        "networkPaths": network_paths,
        "architecture": architecture,
        "attackPaths": attack_paths,
        "riskScenarios": scenario_view["riskScenarios"],
        "attackPathGroups": scenario_view["attackPathGroups"],
        "attackSurfaces": scenario_view["attackSurfaces"],
        "issueCategories": scenario_view["issueCategories"],
        "vulnerabilities": vulnerabilities,
        "links": links,
    }


def _raise_asset(asset: dict[str, Any], finding: dict[str, Any]) -> None:
    context = finding.get("context") or {}
    source = finding.get("source_reachability") or {}
    key = finding["key"]
    if key not in asset["findingKeys"]:
        asset["findingKeys"].append(key)
    asset["score"] = max(safe_float(asset["score"]), safe_float(finding.get("score")))
    if TIER_RANK.get(finding.get("tier", "informational"), 0) > TIER_RANK.get(asset["tier"], 0):
        asset["tier"] = finding.get("tier") or "informational"
    if context.get("owner") and not asset.get("owner"):
        asset["owner"] = context.get("owner")
    _append_unique(asset["exposures"], context.get("exposure") or "unknown")
    _append_unique(asset["privileges"], context.get("privilege") or "unknown")
    _append_unique(asset["criticalities"], context.get("criticality") or "unknown")
    _append_unique(asset["environments"], context.get("environment") or "unknown")
    _append_unique(asset["sourceStates"], source.get("state") or "unknown")
    _append_unique(asset["codeExposures"], _code_exposure_label(source))
    for impact in context.get("iam_impacts") or []:
        _append_unique(asset["iamImpacts"], impact)
    for access in context.get("effective_access") or []:
        if len(asset["effectiveAccess"]) < 8:
            _append_unique(asset["effectiveAccess"], access)
    for item in context.get("evidence") or []:
        if len(asset["evidence"]) < 8:
            _append_unique(asset["evidence"], item)


def _graph_network_paths_by_asset(graph: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    paths_by_asset: dict[str, list[dict[str, Any]]] = {}
    for raw_path in graph.get("network_paths", []) if isinstance(graph.get("network_paths"), list) else []:
        if not isinstance(raw_path, dict):
            continue
        asset_id = str(raw_path.get("asset_id") or "")
        if not asset_id:
            continue
        path: dict[str, Any] = {
            "id": str(raw_path.get("id") or ""),
            "assetId": asset_id,
            "entryId": f"entry:{raw_path.get('entry_kind') or _entry_kind(str(raw_path.get('exposure') or 'unknown'))}",
            "entryLabel": raw_path.get("entry_label") or _entry_label(str(raw_path.get("exposure") or "unknown")),
            "entrySubtitle": raw_path.get("entry_subtitle") or _entry_subtitle(str(raw_path.get("exposure") or "unknown")),
            "exposure": str(raw_path.get("exposure") or "unknown"),
            "pathType": raw_path.get("path_type") or "unresolved",
            "provider": raw_path.get("provider"),
            "confidence": raw_path.get("confidence") or "low",
            "blockers": raw_path.get("blockers") if isinstance(raw_path.get("blockers"), list) else [],
            "tier": "informational",
            "score": 0.0,
            "label": raw_path.get("label") or _fallback_path_label(str(raw_path.get("exposure") or "unknown")),
            "summary": raw_path.get("summary") or _fallback_path_summary(str(raw_path.get("exposure") or "unknown")),
            "steps": raw_path.get("steps") if isinstance(raw_path.get("steps"), list) else [],
            "evidence": raw_path.get("evidence") or "",
            "owner": raw_path.get("owner"),
        }
        paths_by_asset.setdefault(asset_id, []).append(path)
    return paths_by_asset


def _effective_paths_by_key(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    effective = graph.get("effective_exposure_graph") if isinstance(graph, dict) else None
    paths = effective.get("paths") if isinstance(effective, dict) else None
    if not isinstance(paths, list):
        return {}
    by_key: dict[str, dict[str, Any]] = {}
    for path in paths:
        if not isinstance(path, dict):
            continue
        key = str(path.get("finding_key") or "")
        if key:
            by_key[key] = path
    return by_key


def _finalize_network_paths(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    shared_paths: dict[str, dict[str, Any]] = {}
    for asset in assets:
        paths = asset.get("networkPaths") or []
        if not paths:
            paths = [_fallback_network_path(asset)]
            asset["networkPaths"] = paths
        paths.sort(key=lambda item: (-EXPOSURE_RANK.get(item.get("exposure", "unknown"), 0), -TIER_RANK.get(item.get("tier", "informational"), 0), item.get("label", "")))
        linked_paths: list[dict[str, Any]] = []
        for index, path in enumerate(paths):
            shared = _shared_network_path(shared_paths, asset, path, index)
            linked_paths.append(shared)
        asset["networkPaths"] = linked_paths
    return sorted(
        shared_paths.values(),
        key=lambda item: (
            -EXPOSURE_RANK.get(item.get("exposure", "unknown"), 0),
            -TIER_RANK.get(item.get("tier", "informational"), 0),
            item.get("label", ""),
            item.get("id", ""),
        ),
    )


def _shared_network_path(shared_paths: dict[str, dict[str, Any]], asset: dict[str, Any], path: dict[str, Any], index: int) -> dict[str, Any]:
    original_id = str(path.get("id") or f"{asset['id']}:{index}")
    path["tier"] = _stronger_tier(asset.get("tier"), path.get("tier"))
    path["score"] = max(safe_float(path.get("score")), safe_float(asset.get("score")))
    path["assetId"] = asset["id"]
    shared_id = f"network:path:{_stable_token(_network_path_signature(path))}"
    shared = shared_paths.get(shared_id)
    if not shared:
        shared = {
            **path,
            "id": shared_id,
            "sourcePathIds": [],
            "entryNodeId": f"network:entry:{_stable_token(_entry_signature(path))}",
            "assetIds": [],
            "assetNames": [],
            "findingKeys": [],
            "steps": _shared_network_steps(path),
            "assetCount": 0,
        }
        shared_paths[shared_id] = shared
    _append_unique(shared["sourcePathIds"], original_id)
    _append_unique(shared["assetIds"], asset["id"])
    _append_unique(shared["assetNames"], asset.get("name"))
    for finding_key in asset.get("findingKeys") or []:
        _append_unique(shared["findingKeys"], finding_key)
    shared["tier"] = _stronger_tier(shared.get("tier"), path.get("tier"))
    shared["score"] = max(safe_float(shared.get("score")), safe_float(path.get("score")))
    shared["assetCount"] = len(shared["assetIds"])
    return shared


def _stronger_tier(first: Any, second: Any) -> str:
    first_value = str(first or "informational")
    second_value = str(second or "informational")
    return first_value if TIER_RANK.get(first_value, 0) >= TIER_RANK.get(second_value, 0) else second_value


def _network_path_signature(path: dict[str, Any]) -> str:
    return json.dumps(
        {
            "entry": path.get("entryLabel") or "",
            "entry_subtitle": path.get("entrySubtitle") or "",
            "exposure": path.get("exposure") or "unknown",
            "path_type": path.get("pathType") or "unresolved",
            "provider": path.get("provider") or "",
            "label": path.get("label") or "",
            "steps": _shared_network_steps(path),
            "blockers": path.get("blockers") or [],
        },
        sort_keys=True,
        default=str,
    )


def _entry_signature(path: dict[str, Any]) -> str:
    return json.dumps(
        {
            "entry": path.get("entryLabel") or "",
            "entry_subtitle": path.get("entrySubtitle") or "",
            "exposure": path.get("exposure") or "unknown",
        },
        sort_keys=True,
    )


def _shared_network_steps(path: dict[str, Any]) -> list[str]:
    raw_steps = path.get("steps")
    steps = [str(step) for step in raw_steps if str(step)] if isinstance(raw_steps, list) else []
    if len(steps) <= 1:
        return steps
    asset_id = str(path.get("assetId") or "")
    asset_name = asset_id.removeprefix("asset:")
    tail = steps[-1].lower()
    workload_tokens = (
        "ecs_service",
        "aws_instance",
        "lambda",
        "cloud_run",
        "container_app",
        "virtual_machine",
        "kubernetes_deployment",
        "deployment.",
        " reaches ",
    )
    if asset_name and asset_name.lower() in tail:
        return steps[:-1]
    if any(token in tail for token in workload_tokens):
        return steps[:-1]
    return steps


def _architecture_view(assets: list[dict[str, Any]], network_paths: list[dict[str, Any]], vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
    zones: list[dict[str, Any]] = [
        {
            "id": "zone:internet-external",
            "label": "Internet / External",
            "summary": "Attacker, partner, or external network entry points.",
            "order": 0,
            "assetIds": [],
            "hopIds": [],
        },
        {
            "id": "zone:edge-ingress",
            "label": "Edge / Ingress",
            "summary": "Load balancers, gateways, ingress controllers, listeners, and API edges.",
            "order": 1,
            "assetIds": [],
            "hopIds": [],
        },
        {
            "id": "zone:public",
            "label": "Public",
            "summary": "Workloads with confirmed or inferred public/external ingress.",
            "order": 2,
            "assetIds": [],
            "hopIds": [],
        },
        {
            "id": "zone:private-internal",
            "label": "Private / Internal",
            "summary": "Workloads reachable only through private or lateral paths.",
            "order": 3,
            "assetIds": [],
            "hopIds": [],
        },
        {
            "id": "zone:data-identity",
            "label": "Data / Identity",
            "summary": "Assets with sensitive data, admin, identity, or scoped access context.",
            "order": 4,
            "assetIds": [],
            "hopIds": [],
        },
        {
            "id": "zone:unknown",
            "label": "Unknown / Unresolved",
            "summary": "Assets without enough rendered network evidence for placement.",
            "order": 5,
            "assetIds": [],
            "hopIds": [],
        },
    ]
    zone_by_id: dict[str, dict[str, Any]] = {str(zone["id"]): zone for zone in zones}
    asset_by_id = {str(asset.get("id") or ""): asset for asset in assets if asset.get("id")}
    paths_by_asset: dict[str, list[dict[str, Any]]] = {}
    for path in network_paths:
        for asset_id in _path_asset_ids(path):
            paths_by_asset.setdefault(asset_id, []).append(path)
    finding_counts_by_asset: dict[str, dict[str, int]] = {}
    for vulnerability in vulnerabilities:
        asset_id = str(vulnerability.get("assetId") or "")
        if not asset_id:
            continue
        counts = finding_counts_by_asset.setdefault(asset_id, {"dependency_vulnerability": 0, "static_code_weakness": 0, "dynamic_runtime_observation": 0, "cloud_posture_finding": 0})
        finding_type = canonical_finding_type(str(vulnerability.get("findingType") or "dependency_vulnerability"))
        counts[finding_type] = counts.get(finding_type, 0) + 1

    arch_assets: list[dict[str, Any]] = []
    for asset in assets:
        asset_id = str(asset.get("id") or "")
        if not asset_id:
            continue
        paths = paths_by_asset.get(asset_id, [])
        zone_id = _asset_zone_id(asset, paths)
        zone_by_id[zone_id]["assetIds"].append(asset_id)
        arch_assets.append({
            "id": asset_id,
            "zoneId": zone_id,
            "name": asset.get("name"),
            "reference": asset.get("reference"),
            "provider": _provider_for_asset(asset, paths),
            "tier": asset.get("tier") or "informational",
            "score": safe_float(asset.get("score")),
            "owner": asset.get("owner"),
            "findingCount": len(asset.get("findingKeys") or []),
            "findingTypeCounts": finding_counts_by_asset.get(asset_id, {"dependency_vulnerability": 0, "static_code_weakness": 0, "dynamic_runtime_observation": 0, "cloud_posture_finding": 0}),
            "exposures": asset.get("exposures") or [],
            "privileges": asset.get("privileges") or [],
            "criticalities": asset.get("criticalities") or [],
            "iamImpacts": asset.get("iamImpacts") or [],
            "codeExposures": asset.get("codeExposures") or [],
            "networkPathIds": [path["id"] for path in paths if path.get("id")],
        })

    hops: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for path in network_paths:
        path_id = str(path.get("id") or "")
        provider = _provider_for_path(path)
        entry_id = _architecture_entry_hop(path)
        entry_exposure = str(path.get("exposure") or "unknown")
        hops.setdefault(
            entry_id,
            {
                "id": entry_id,
                "zoneId": "zone:internet-external",
                "label": path.get("entryLabel") or "Unknown entry",
                "summary": path.get("entrySubtitle") or path.get("summary") or "",
                "provider": provider,
                "kind": "entry",
                "exposure": entry_exposure,
                "tier": path.get("tier") or "informational",
                "score": safe_float(path.get("score")),
                "pathIds": [],
                "assetIds": [],
                "blockers": [],
                "confidence": path.get("confidence") or "low",
                "evidence": path.get("evidence") or "",
            },
        )
        _append_unique(hops[entry_id]["pathIds"], path_id)
        for asset_id in _path_asset_ids(path):
            _append_unique(hops[entry_id]["assetIds"], asset_id)
        previous_id = entry_id
        edge_steps = _architecture_steps(path)
        if not edge_steps:
            edge_steps = [_fallback_architecture_hop_label(path)]
        for step in edge_steps:
            hop_kind = _hop_kind(step)
            hop_zone = _hop_zone_id(step, entry_exposure)
            hop_id = f"arch:hop:{_stable_token(json.dumps({'provider': provider, 'kind': hop_kind, 'zone': hop_zone, 'step': step}, sort_keys=True))}"
            hop = hops.setdefault(
                hop_id,
                {
                    "id": hop_id,
                    "zoneId": hop_zone,
                    "label": step,
                    "summary": path.get("summary") or "",
                    "provider": provider,
                    "kind": hop_kind,
                    "exposure": entry_exposure,
                    "tier": path.get("tier") or "informational",
                    "score": safe_float(path.get("score")),
                    "pathIds": [],
                    "assetIds": [],
                    "blockers": path.get("blockers") or [],
                    "confidence": path.get("confidence") or "low",
                    "evidence": path.get("evidence") or "",
                },
            )
            _append_unique(hop["pathIds"], path_id)
            for asset_id in _path_asset_ids(path):
                _append_unique(hop["assetIds"], asset_id)
            hop["tier"] = _stronger_tier(hop.get("tier"), path.get("tier"))
            hop["score"] = max(safe_float(hop.get("score")), safe_float(path.get("score")))
            edges.append({"source": previous_id, "target": hop_id, "role": "route-hop", "pathId": path_id, "tier": path.get("tier") or "informational"})
            previous_id = hop_id
        for asset_id in _path_asset_ids(path):
            if asset_id not in asset_by_id:
                continue
            edges.append({"source": previous_id, "target": asset_id, "role": "hop-asset", "pathId": path_id, "tier": path.get("tier") or "informational"})

    for hop in hops.values():
        zone_by_id.get(str(hop.get("zoneId") or "zone:unknown"), zone_by_id["zone:unknown"])["hopIds"].append(hop["id"])
    return {
        "zones": zones,
        "hops": sorted(hops.values(), key=lambda item: (str(item.get("zoneId")), str(item.get("label")), str(item.get("id")))),
        "assets": arch_assets,
        "edges": edges,
    }


def _path_asset_ids(path: dict[str, Any]) -> list[str]:
    asset_ids = path.get("assetIds")
    if isinstance(asset_ids, list):
        return [str(asset_id) for asset_id in asset_ids if asset_id]
    asset_id = path.get("assetId")
    return [str(asset_id)] if asset_id else []


def _asset_zone_id(asset: dict[str, Any], paths: list[dict[str, Any]]) -> str:
    exposure = _strongest_exposure([str(path.get("exposure") or "unknown") for path in paths] or [str(value) for value in asset.get("exposures") or []])
    if exposure in {"public", "external"}:
        return "zone:public"
    if exposure in {"internal", "private", "isolated"}:
        if _has_data_or_identity_context(asset):
            return "zone:data-identity"
        return "zone:private-internal"
    return "zone:unknown"


def _has_data_or_identity_context(asset: dict[str, Any]) -> bool:
    values = [str(value).lower() for value in (asset.get("privileges") or []) + (asset.get("iamImpacts") or [])]
    return any(value in {"admin", "sensitive", "data_access", "iam_escalation", "network_control"} for value in values)


def _provider_for_asset(asset: dict[str, Any], paths: list[dict[str, Any]]) -> str:
    for path in paths:
        provider = _provider_for_path(path)
        if provider != "Context":
            return provider
    for evidence in asset.get("evidence") or []:
        provider = _provider_for_text(str(evidence))
        if provider != "Context":
            return provider
    return "Context"


def _provider_for_path(path: dict[str, Any]) -> str:
    provider = str(path.get("provider") or "")
    if provider:
        return _provider_label(provider)
    text = " ".join([str(path.get("label") or ""), str(path.get("evidence") or ""), " ".join(str(step) for step in path.get("steps") or [])])
    return _provider_for_text(text)


def _provider_for_text(text: str) -> str:
    lowered = text.lower()
    if "aws_" in lowered or "amazon" in lowered:
        return "AWS"
    if "azurerm_" in lowered or "azure" in lowered:
        return "Azure"
    if "google_" in lowered or "gcp" in lowered or "cloud_run" in lowered:
        return "GCP"
    if "kubernetes_" in lowered or "k8s" in lowered or "ingress" in lowered or "clusterip" in lowered:
        return "Kubernetes"
    return "Context"


def _provider_label(provider: str) -> str:
    value = provider.lower()
    if value == "aws":
        return "AWS"
    if value in {"azure", "azurerm"}:
        return "Azure"
    if value in {"gcp", "google"}:
        return "GCP"
    if value in {"kubernetes", "k8s"}:
        return "Kubernetes"
    return provider or "Context"


def _architecture_entry_hop(path: dict[str, Any]) -> str:
    signature = json.dumps(
        {
            "entry": path.get("entryLabel") or "",
            "subtitle": path.get("entrySubtitle") or "",
            "exposure": path.get("exposure") or "unknown",
        },
        sort_keys=True,
    )
    return f"arch:entry:{_stable_token(signature)}"


def _architecture_steps(path: dict[str, Any]) -> list[str]:
    steps = [str(step) for step in path.get("steps") or [] if str(step)]
    boundary_steps = [_architecture_step_label(step) for step in steps if _is_architecture_boundary_step(step)]
    deduped: list[str] = []
    for step in boundary_steps:
        if step not in deduped:
            deduped.append(step)
    if deduped:
        return deduped[:2]
    label = str(path.get("label") or "")
    return [_architecture_step_label(label)] if label and _is_architecture_boundary_step(label) else []


def _architecture_step_label(step: str) -> str:
    value = str(step).strip()
    lowered = value.lower()
    if "security_group" in lowered or "network_security_group" in lowered or "firewall" in lowered or "network_policy" in lowered:
        return "Network policy"
    if "load balancer" in lowered or "_lb" in lowered or "application_gateway" in lowered or "frontdoor" in lowered:
        return "Ingress edge"
    if "api_gateway" in lowered or "apigateway" in lowered or "gateway" in lowered:
        return "API gateway"
    if "ingress" in lowered or "loadbalancer" in lowered:
        return "Ingress"
    if "function_url" in lowered or "cloud_run" in lowered:
        return "Serverless edge"
    return value


def _compact_resource_label(value: str, fallback: str) -> str:
    parts = value.split()
    first = parts[0] if parts else value
    if len(first) > 64:
        first = f"{first[:30]}...{first[-26:]}"
    return first or fallback


def _is_architecture_boundary_step(step: str) -> bool:
    lowered = str(step).lower()
    include_tokens = (
        "load balancer",
        "_lb",
        "listener",
        "gateway",
        "ingress",
        "security_group",
        "network_security_group",
        "firewall",
        "network_policy",
        "function_url",
        "cloud_run",
        "frontdoor",
    )
    exclude_tokens = (
        "task_definition",
        "ecs_service",
        "kubernetes_deployment",
        "deployment.",
        "aws_instance",
        "container_app",
        "virtual_machine",
    )
    if any(token in lowered for token in exclude_tokens):
        return False
    return any(token in lowered for token in include_tokens)


def _fallback_architecture_hop_label(path: dict[str, Any]) -> str:
    exposure = str(path.get("exposure") or "unknown").lower()
    provider = _provider_for_path(path)
    if exposure in {"internal", "private", "isolated"}:
        return f"{provider} private/internal network"
    if exposure == "external":
        return f"{provider} restricted ingress"
    if exposure == "public":
        return f"{provider} public ingress"
    return f"{provider} unresolved path"


def _hop_zone_id(label: str, exposure: str) -> str:
    kind = _hop_kind(label)
    if kind in {"entry", "ingress", "gateway", "policy"}:
        return "zone:edge-ingress"
    if str(exposure).lower() in {"internal", "private", "isolated"}:
        return "zone:private-internal"
    return "zone:edge-ingress"


def _hop_kind(label: str) -> str:
    lowered = label.lower()
    if "gateway" in lowered or "apigateway" in lowered or "api_gateway" in lowered:
        return "gateway"
    if "load balancer" in lowered or "_lb" in lowered or "listener" in lowered or "ingress" in lowered:
        return "ingress"
    if "security_group" in lowered or "firewall" in lowered or "network_policy" in lowered or "network policy" in lowered or "nsg" in lowered:
        return "policy"
    if "internal network" in lowered or "restricted ingress" in lowered or "public ingress" in lowered or "unresolved path" in lowered:
        return "boundary"
    if "target_group" in lowered or "service" in lowered:
        return "service"
    return "hop"


def _stable_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _fallback_network_path(asset: dict[str, Any]) -> dict[str, Any]:
    exposure = _strongest_exposure(asset.get("exposures") or [])
    return {
        "id": "",
        "assetId": asset["id"],
        "entryId": f"entry:{_entry_kind(exposure)}",
        "entryLabel": _entry_label(exposure),
        "entrySubtitle": _entry_subtitle(exposure),
        "exposure": exposure,
        "pathType": "unresolved",
        "provider": None,
        "confidence": "low",
        "blockers": [],
        "tier": asset.get("tier") or "informational",
        "score": safe_float(asset.get("score")),
        "label": _fallback_path_label(exposure),
        "summary": _fallback_path_summary(exposure),
        "steps": [],
        "evidence": "",
        "owner": asset.get("owner"),
    }


def _strongest_exposure(exposures: list[str]) -> str:
    strongest = "unknown"
    for exposure in exposures:
        value = str(exposure or "unknown").lower()
        if EXPOSURE_RANK.get(value, 0) > EXPOSURE_RANK.get(strongest, 0):
            strongest = value
    return strongest


def _entry_kind(exposure: str) -> str:
    exposure = str(exposure or "unknown").lower()
    if exposure == "public":
        return "internet"
    if exposure == "external":
        return "external"
    if exposure == "internal":
        return "internal"
    if exposure in {"private", "isolated"}:
        return "isolated"
    return "unknown"


def _entry_label(exposure: str) -> str:
    return _entry_label_for_kind(_entry_kind(exposure))


def _entry_label_for_kind(kind: str) -> str:
    if kind == "internet":
        return "Internet / attacker"
    if kind == "public_pivot":
        return "Internet / attacker"
    if kind == "external":
        return "External source"
    if kind == "lateral":
        return "Internal pivot"
    if kind == "internal":
        return "Internal network"
    if kind == "isolated":
        return "No external entry"
    return "Unknown entry"


def _entry_subtitle(exposure: str) -> str:
    return _entry_subtitle_for_kind(_entry_kind(exposure))


def _entry_subtitle_for_kind(kind: str) -> str:
    if kind == "internet":
        return "direct public route"
    if kind == "public_pivot":
        return "public ingress then internal hop"
    if kind == "external":
        return "restricted public CIDR or external source"
    if kind == "lateral":
        return "requires a reachable internal foothold"
    if kind == "internal":
        return "private network ingress only"
    if kind == "isolated":
        return "no linked network route observed"
    return "insufficient IaC evidence"


def _fallback_path_label(exposure: str) -> str:
    if exposure == "public":
        return "Public ingress"
    if exposure == "external":
        return "External ingress"
    if exposure == "internal":
        return "Internal network path"
    if exposure in {"private", "isolated"}:
        return "Isolated/private network"
    return "Unresolved network path"


def _fallback_path_summary(exposure: str) -> str:
    if exposure == "public":
        return "Public exposure is reported, but no linked Terraform path evidence was emitted."
    if exposure == "external":
        return "External exposure is reported, but the exact ingress path is not linked."
    if exposure == "internal":
        return "Reachable only through an internal network path inferred from the supplied context."
    if exposure in {"private", "isolated"}:
        return "No direct or lateral ingress path was observed in the supplied context."
    return "The supplied context does not prove a network entry path."


def _code_exposure_label(source: dict[str, Any] | str) -> str:
    if isinstance(source, dict):
        if source.get("label"):
            return str(source["label"])
        state = source.get("state") or "unknown"
    else:
        state = source
    return reachability_label(str(state or "unknown"))


def _code_exposure_detail(state: str) -> str:
    state = str(state or "unknown").lower()
    if state == "attacker_controlled":
        return "Source evidence links request/input handling to vulnerable package usage."
    if state == "function_reachable":
        return "Vulnerable package usage was observed, but no attacker-controlled entry path was proven."
    if state == "imported":
        return "The package is imported, but no vulnerable sink pattern was observed."
    if state == "dependency_reachable":
        return "The package is reached through the SBOM dependency graph from an imported parent dependency."
    if state == "unknown_due_to_no_rule":
        return "No package-specific source rule exists and generic import evidence was not observed."
    if state == "package_present":
        return "The package is present in the SBOM, but source usage was not observed."
    if state == "absent":
        return "The analyzer has explicit evidence that the package is absent from the scanned source scope."
    return "Source reachability is unknown."


def _append_unique(items: list[Any], value: Any) -> None:
    if value not in (None, "", [], {}) and value not in items:
        items.append(value)


def _stats(findings: list[dict[str, Any]]) -> dict[str, Any]:
    artifacts = {finding.get("artifact", {}).get("name") for finding in findings}
    components = {
        (
            finding.get("artifact", {}).get("name"),
            finding.get("component", {}).get("name"),
            finding.get("component", {}).get("version"),
        )
        for finding in findings
    }
    tiers = dict.fromkeys(TIER_RANK, 0)
    exposures: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for finding in findings:
        tiers[str(finding.get("tier") or "informational")] = tiers.get(str(finding.get("tier") or "informational"), 0) + 1
        exposure = str(finding.get("context", {}).get("exposure") or "unknown")
        exposures[exposure] = exposures.get(exposure, 0) + 1
        finding_type = canonical_finding_type(str(finding.get("finding_type") or "dependency_vulnerability"))
        by_type[finding_type] = by_type.get(finding_type, 0) + 1
    return {
        "finding_count": len(findings),
        "artifact_count": len({item for item in artifacts if item}),
        "component_count": len({item for item in components if item[1]}),
        "tiers": tiers,
        "exposures": exposures,
        "finding_types": by_type,
    }
