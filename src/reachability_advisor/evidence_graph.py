"""Structured evidence graph generation.

The graph is the machine-readable contract behind the HTML report. It keeps
asset, source, network, IAM, and vulnerability links separate from human
rationale strings so downstream tools do not have to scrape prose.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .effective_graph import build_effective_exposure_graph, effective_path_id
from .iam_capabilities import dedupe_iam_capabilities
from .models import Finding, reachability_label
from .numeric import safe_float
from .visual_layout import EXPOSURE_RANK, TIER_RANK

NETWORK_PATH_RE = re.compile(r"^(?:terraform|context|kubernetes) network path: (?P<exposure>[a-z_]+) via (?P<path>.+)$")
EXPOSURE_INFERENCE_RE = re.compile(r"^(?:terraform|context|kubernetes) exposure inference: (?P<exposure>[a-z_]+) via (?P<target>.+)$")


def build_evidence_graph(findings: list[Finding], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    assets: dict[str, dict[str, Any]] = {}
    components: dict[str, dict[str, Any]] = {}
    vulnerabilities: dict[str, dict[str, Any]] = {}
    finding_nodes: list[dict[str, Any]] = []
    code_edges: list[dict[str, Any]] = []
    network_paths: dict[str, dict[str, Any]] = {}
    network_nodes: dict[str, dict[str, Any]] = {}
    network_edges: dict[str, dict[str, Any]] = {}
    iam_edges: dict[str, dict[str, Any]] = {}
    finding_edges: list[dict[str, Any]] = []

    for finding in findings:
        asset_id = _asset_id(finding.artifact.name)
        component_id = _component_id(finding.artifact.name, finding.component.name, finding.component.version)
        vulnerability_id = _vulnerability_id(finding.vulnerability.id)
        finding_id = _finding_id(finding.key)

        asset = assets.setdefault(
            asset_id,
            {
                "id": asset_id,
                "name": finding.artifact.name,
                "reference": finding.artifact.reference,
                "version": finding.artifact.version,
                "owner": finding.context.owner,
                "environment": finding.context.environment,
                "exposure": finding.context.exposure,
                "privilege": finding.context.privilege,
                "criticality": finding.context.criticality,
                "iam_impacts": [],
                "confidence": finding.context.confidence.value,
                "max_score": 0.0,
                "max_tier": "informational",
                "finding_keys": [],
            },
        )
        _raise_asset(asset, finding)

        components.setdefault(
            component_id,
            {
                "id": component_id,
                "asset_id": asset_id,
                "name": finding.component.name,
                "display_name": finding.component.display_name,
                "version": finding.component.version,
                "purl": finding.component.purl,
                "scope": finding.component.scope,
            },
        )
        vulnerabilities.setdefault(
            vulnerability_id,
            {
                "id": vulnerability_id,
                "advisory_id": finding.vulnerability.id,
                "aliases": finding.vulnerability.aliases,
                "severity": finding.vulnerability.severity,
                "cvss": finding.vulnerability.cvss,
                "epss": finding.vulnerability.epss,
                "known_exploited": finding.vulnerability.known_exploited,
                "summary": finding.vulnerability.summary,
            },
        )
        finding_nodes.append(
            {
                "id": finding_id,
                "key": finding.key,
                "asset_id": asset_id,
                "component_id": component_id,
                "vulnerability_id": vulnerability_id,
                "tier": finding.tier.value,
                "score": round(finding.score, 2),
                "confidence": finding.confidence.value,
                "policy_status": finding.policy_status,
                "effective_path_id": effective_path_id(finding),
            }
        )
        finding_edges.extend(
            [
                {"id": f"{asset_id}->{finding_id}", "source": asset_id, "target": finding_id, "kind": "asset_finding", "finding_key": finding.key},
                {"id": f"{finding_id}->{component_id}", "source": finding_id, "target": component_id, "kind": "finding_component", "finding_key": finding.key},
                {"id": f"{component_id}->{vulnerability_id}", "source": component_id, "target": vulnerability_id, "kind": "component_vulnerability", "finding_key": finding.key},
            ]
        )
        code_edges.append(_code_edge(finding, asset_id, component_id, finding_id))
        for path in _network_paths_for_finding(finding, asset_id):
            _merge_node(network_paths, path)
        for edge in _iam_edges_for_finding(finding, asset_id):
            _merge_node(iam_edges, edge)

    for path in network_paths.values():
        _add_typed_network_path(path, network_nodes, network_edges)

    effective_exposure_graph = build_effective_exposure_graph(findings)
    ordered_assets = sorted(assets.values(), key=lambda item: (-TIER_RANK.get(item["max_tier"], 0), -safe_float(item["max_score"]), item["name"]))
    return {
        "schema_version": "1.0",
        "metadata": {
            "tool": "reachability-advisor",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **(metadata or {}),
        },
        "assets": ordered_assets,
        "components": sorted(components.values(), key=lambda item: (item["asset_id"], item["name"], item.get("version") or "")),
        "vulnerabilities": sorted(vulnerabilities.values(), key=lambda item: item["advisory_id"]),
        "findings": sorted(finding_nodes, key=lambda item: (-TIER_RANK.get(item["tier"], 0), -safe_float(item["score"]), item["key"])),
        "network_paths": sorted(network_paths.values(), key=lambda item: (item["asset_id"], -EXPOSURE_RANK.get(item["exposure"], 0), item["id"])),
        "network_nodes": sorted(network_nodes.values(), key=lambda item: (item["kind"], item["label"], item["id"])),
        "network_edges": sorted(network_edges.values(), key=lambda item: (item["path_id"], item["sequence"])),
        "iam_edges": sorted(iam_edges.values(), key=lambda item: (item["asset_id"], item["id"])),
        "code_edges": sorted(code_edges, key=lambda item: item["finding_key"]),
        "effective_exposure_graph": effective_exposure_graph,
        "edges": finding_edges,
    }


def _raise_asset(asset: dict[str, Any], finding: Finding) -> None:
    if finding.key not in asset["finding_keys"]:
        asset["finding_keys"].append(finding.key)
    asset["max_score"] = max(safe_float(asset["max_score"]), finding.score)
    if TIER_RANK.get(finding.tier.value, 0) > TIER_RANK.get(asset["max_tier"], 0):
        asset["max_tier"] = finding.tier.value
    if not asset.get("owner") and finding.context.owner:
        asset["owner"] = finding.context.owner
    asset["environment"] = _stronger_value(asset.get("environment"), finding.context.environment, {"unknown": 0, "dev": 1, "development": 1, "staging": 2, "prod": 3, "production": 3})
    asset["exposure"] = _stronger_value(asset.get("exposure"), finding.context.exposure, EXPOSURE_RANK)
    asset["privilege"] = _stronger_value(asset.get("privilege"), finding.context.privilege, {"unknown": 0, "none": 1, "limited": 2, "sensitive": 3, "admin": 4})
    asset["criticality"] = _stronger_value(asset.get("criticality"), finding.context.criticality, {"unknown": 0, "low": 1, "medium": 2, "high": 3})
    for impact in finding.context.iam_impacts:
        if impact not in asset["iam_impacts"]:
            asset["iam_impacts"].append(impact)


def _merge_node(target: dict[str, dict[str, Any]], node: dict[str, Any]) -> None:
    existing = target.get(node["id"])
    if existing is None:
        target[node["id"]] = node
        return
    for key in ("finding_keys",):
        values = existing.setdefault(key, [])
        for value in node.get(key, []):
            if value not in values:
                values.append(value)


def _stronger_value(left: Any, right: Any, rank: dict[str, int]) -> str:
    left_s = str(left or "unknown").lower()
    right_s = str(right or "unknown").lower()
    return right_s if rank.get(right_s, 0) > rank.get(left_s, 0) else left_s


def _code_edge(finding: Finding, asset_id: str, component_id: str, finding_id: str) -> dict[str, Any]:
    return {
        "id": f"code:{finding.key}",
        "kind": "code_reachability",
        "source": asset_id,
        "target": component_id,
        "finding_id": finding_id,
        "finding_key": finding.key,
        "state": finding.source.reachability.value,
        "label": reachability_label(finding.source.reachability),
        "confidence": finding.source.confidence.value,
        "language": finding.source.language,
        "provider": finding.source.evidence_source,
        "reason": finding.source.reason,
        "locations": [location.to_json() for location in finding.source.locations],
        "matched_symbols": finding.source.matched_symbols,
        "dependency_path": finding.source.dependency_path,
        "diagnostics": finding.source.diagnostics,
    }


def _add_typed_network_path(path: dict[str, Any], nodes: dict[str, dict[str, Any]], edges: dict[str, dict[str, Any]]) -> None:
    path_id = str(path.get("id") or "")
    asset_id = str(path.get("asset_id") or "")
    if not path_id or not asset_id:
        return
    entry_label = str(path.get("entry_label") or _entry_label(str(path.get("exposure") or "unknown")))
    entry_id = f"network-node:{_stable_token(path_id + ':entry')}"
    nodes.setdefault(entry_id, {"id": entry_id, "kind": str(path.get("entry_kind") or "unknown"), "label": entry_label, "source": path.get("source")})
    previous_id = entry_id
    raw_steps = path.get("steps")
    steps: list[Any] = raw_steps if isinstance(raw_steps, list) else []
    for index, step in enumerate(steps):
        step_label = str(step)
        step_id = f"network-node:{_stable_token(step_label)}"
        nodes.setdefault(step_id, {"id": step_id, "kind": _network_node_kind(step_label), "label": step_label, "source": path.get("source")})
        edge_id = f"network-edge:{_stable_token(path_id + ':' + str(index) + ':' + previous_id + ':' + step_id)}"
        edges[edge_id] = {
            "id": edge_id,
            "path_id": path_id,
            "source": previous_id,
            "target": step_id,
            "kind": "network_path_step",
            "sequence": index,
            "exposure": path.get("exposure"),
            "finding_keys": path.get("finding_keys", []),
        }
        previous_id = step_id
    final_sequence = len(steps)
    final_edge_id = f"network-edge:{_stable_token(path_id + ':asset:' + previous_id + ':' + asset_id)}"
    edges[final_edge_id] = {
        "id": final_edge_id,
        "path_id": path_id,
        "source": previous_id,
        "target": asset_id,
        "kind": "network_path_asset",
        "sequence": final_sequence,
        "exposure": path.get("exposure"),
        "finding_keys": path.get("finding_keys", []),
    }


def _network_node_kind(label: str) -> str:
    text = label.lower()
    if any(token in text for token in ("cloudfront", "frontdoor", "cdn", "api_gateway", "apigateway", "function url")):
        return "public_gateway"
    if any(token in text for token in ("aws_lb", "aws_alb", "load balancer", "application_gateway", "forwarding_rule", "backend_service")):
        return "load_balancer"
    if any(token in text for token in ("security_group", "network_security_group", "firewall")):
        return "security_boundary"
    if any(token in text for token in ("ingress", "kubernetes_service", "nodeport", "clusterip")):
        return "kubernetes_network"
    if any(token in text for token in ("vpc", "vnet", "subnet", "vpn", "transit", "peering", "private network", "express_route", "interconnect")):
        return "private_network"
    if any(token in text for token in ("ecs_service", "aws_instance", "lambda", "cloud_run", "container_app", "virtual_machine", "kubernetes_deployment", "deployment.")):
        return "workload"
    return "resource"


def _network_paths_for_finding(finding: Finding, asset_id: str) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for index, raw_path in enumerate(finding.context.network_paths):
        parsed_record = _network_path_from_record(finding, asset_id, raw_path, index)
        if parsed_record:
            paths.append(parsed_record)
    if paths:
        return paths
    for index, evidence in enumerate(finding.context.evidence):
        parsed = _network_path_from_evidence(finding, asset_id, evidence, index)
        if parsed:
            paths.append(parsed)
    if not paths:
        # Keep uncertainty explicit in the graph. A missing path means "not
        # proven from supplied evidence", not "safe" or "not reachable".
        exposure = str(finding.context.exposure or "unknown").lower()
        paths.append(
            {
                "id": f"network:{asset_id}:fallback",
                "asset_id": asset_id,
                "source": finding.context.source,
                "exposure": exposure,
                "entry_kind": _entry_kind(exposure),
                "entry_label": _entry_label(exposure),
                "entry_subtitle": _entry_subtitle(exposure),
                "label": _fallback_path_label(exposure),
                "summary": _fallback_path_summary(exposure),
                "steps": [],
                "evidence": "",
                "confidence": finding.context.confidence.value,
                "finding_keys": [finding.key],
            }
        )
    return paths


def _network_path_from_record(finding: Finding, asset_id: str, record: dict[str, Any], index: int) -> dict[str, Any] | None:
    exposure = str(record.get("exposure") or finding.context.exposure or "unknown").lower()
    raw_steps = record.get("steps")
    steps = [str(step) for step in raw_steps if str(step)] if isinstance(raw_steps, list) else []
    entry_kind = str(record.get("entry") or record.get("entry_kind") or "")
    if entry_kind in {"internet", "public_pivot"}:
        entry_kind = "internet" if exposure == "public" else "public_pivot"
    elif not entry_kind or entry_kind in {"internal_network", "private_network", "isolated_network"}:
        entry_kind = _entry_kind_for_path(exposure, steps)
    path_type = str(record.get("path_type") or _network_path_type_from_steps(exposure, steps))
    evidence = str(record.get("evidence") or "typed network path evidence")
    return {
        "id": f"network:{asset_id}:typed:{index}:{_stable_token(jsonish(record))}",
        "asset_id": asset_id,
        "source": record.get("source") or finding.context.source,
        "provider": record.get("provider"),
        "exposure": exposure,
        "path_type": path_type,
        "entry_kind": entry_kind,
        "entry_label": _entry_label_for_kind(entry_kind),
        "entry_subtitle": _entry_subtitle_for_kind(entry_kind),
        "label": str(record.get("label") or (steps[0] if steps else _fallback_path_label(exposure))),
        "summary": str(record.get("summary") or _path_summary(steps, exposure)),
        "steps": steps,
        "evidence": evidence,
        "confidence": str(record.get("confidence") or finding.context.confidence.value),
        "blockers": record.get("blockers", []) if isinstance(record.get("blockers"), list) else [],
        "finding_keys": [finding.key],
    }


def _network_path_from_evidence(finding: Finding, asset_id: str, evidence: str, index: int) -> dict[str, Any] | None:
    match = NETWORK_PATH_RE.match(evidence)
    if match:
        exposure = match.group("exposure")
        steps = [step.strip() for step in match.group("path").split(" -> ") if step.strip()]
        entry_kind = _entry_kind_for_path(exposure, steps)
        return {
            "id": f"network:{asset_id}:{index}:{_stable_token(evidence)}",
            "asset_id": asset_id,
            "source": finding.context.source,
            "exposure": exposure,
            "entry_kind": entry_kind,
            "entry_label": _entry_label_for_kind(entry_kind),
            "entry_subtitle": _entry_subtitle_for_kind(entry_kind),
            "label": steps[0] if steps else _fallback_path_label(exposure),
            "summary": _path_summary(steps, exposure),
            "steps": steps,
            "evidence": evidence,
            "confidence": finding.context.confidence.value,
            "finding_keys": [finding.key],
        }
    inference = EXPOSURE_INFERENCE_RE.match(evidence)
    if inference:
        exposure = inference.group("exposure")
        target = inference.group("target").strip()
        entry_kind = _entry_kind_for_path(exposure, [target])
        return {
            "id": f"network:{asset_id}:{index}:{_stable_token(evidence)}",
            "asset_id": asset_id,
            "source": finding.context.source,
            "exposure": exposure,
            "entry_kind": entry_kind,
            "entry_label": _entry_label_for_kind(entry_kind),
            "entry_subtitle": _entry_subtitle_for_kind(entry_kind),
            "label": f"{exposure} exposure",
            "summary": f"Exposure inferred through {target}",
            "steps": [target],
            "evidence": evidence,
            "confidence": finding.context.confidence.value,
            "finding_keys": [finding.key],
        }
    return None


def _iam_edges_for_finding(finding: Finding, asset_id: str) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for index, access in enumerate(finding.context.effective_access or []):
        edge_suffix = _stable_token(jsonish(access))
        edges.append(
            {
                "id": f"iam:{asset_id}:effective:{index}:{edge_suffix}",
                "asset_id": asset_id,
                "kind": "effective_access",
                "privilege": finding.context.privilege,
                "identity": access.get("identity"),
                "resource": access.get("resource"),
                "action": access.get("action"),
                "impact": access.get("impact"),
                "effect": access.get("effect", "allow"),
                "access": access.get("access"),
                "decision": access.get("decision", "allowed"),
                "confidence": access.get("confidence", finding.context.confidence.value),
                "blockers": access.get("blockers", []) if isinstance(access.get("blockers"), list) else [],
                "resource_refs": access.get("resource_refs", []),
                "target_resources": access.get("target_resources", []),
                "resource_scope": access.get("resource_scope", "unknown"),
                "condition_keys": access.get("condition_keys", []),
                "provider": access.get("provider", "unknown"),
                "source": access.get("source") or finding.context.source,
                "evidence": access.get("evidence") or "",
                "finding_keys": [finding.key],
            }
        )
    capabilities = dedupe_iam_capabilities(finding.context.iam_capabilities or [])
    for index, capability in enumerate(capabilities):
        edge_suffix = _stable_token(f"{capability.get('impact') or ''}:{capability.get('action') or ''}:{capability.get('resource_refs') or ''}")
        edges.append(
            {
                "id": f"iam:{asset_id}:{index}:{edge_suffix}",
                "asset_id": asset_id,
                "kind": "iam_capability",
                "privilege": finding.context.privilege,
                "impact": capability.get("impact"),
                "action": capability.get("action"),
                "effect": capability.get("effect", "allow"),
                "access": capability.get("access"),
                "resource_refs": capability.get("resource_refs", []),
                "resource_scope": capability.get("resource_scope", "unknown"),
                "condition_keys": capability.get("condition_keys", []),
                "provider": capability.get("provider", "unknown"),
                "catalog": capability.get("catalog", ""),
                "source": capability.get("source") or finding.context.source,
                "evidence": capability.get("evidence") or "",
                "finding_keys": [finding.key],
            }
        )
    if not edges and (finding.context.privilege != "unknown" or finding.context.iam_impacts):
        edges.append(
            {
                "id": f"iam:{asset_id}:summary",
                "asset_id": asset_id,
                "kind": "iam_summary",
                "privilege": finding.context.privilege,
                "impacts": finding.context.iam_impacts,
                "criticality": finding.context.criticality,
                "source": finding.context.source,
                "evidence": "; ".join(item for item in finding.context.evidence if "identity" in item.lower() or "iam" in item.lower())[:1000],
                "finding_keys": [finding.key],
            }
        )
    return edges


def _entry_kind(exposure: str) -> str:
    if exposure == "public":
        return "internet"
    if exposure == "external":
        return "external"
    if exposure == "internal":
        return "internal"
    if exposure in {"private", "isolated"}:
        return "isolated"
    return "unknown"


def _entry_kind_for_path(exposure: str, steps: list[str]) -> str:
    kind = _entry_kind(exposure)
    if kind != "internal":
        return kind
    text = " ".join(steps).lower()
    if "loadbalancer" in text or "nodeport" in text or "public ingress" in text:
        return "public_pivot"
    if "allows traffic from" in text or "security_group_rule" in text or "provider private network reaches" in text:
        return "lateral"
    return "internal"


def _entry_label(exposure: str) -> str:
    return _entry_label_for_kind(_entry_kind(exposure))


def _entry_label_for_kind(kind: str) -> str:
    return {
        "internet": "Internet / attacker",
        "public_pivot": "Internet / attacker",
        "external": "External source",
        "lateral": "Internal pivot",
        "internal": "Internal network",
        "isolated": "No external entry",
    }.get(kind, "Unknown entry")


def _entry_subtitle(exposure: str) -> str:
    return _entry_subtitle_for_kind(_entry_kind(exposure))


def _entry_subtitle_for_kind(kind: str) -> str:
    return {
        "internet": "direct public route",
        "public_pivot": "public ingress then internal hop",
        "external": "restricted public CIDR or external source",
        "lateral": "requires a reachable internal foothold",
        "internal": "private network ingress only",
        "isolated": "no linked network route observed",
    }.get(kind, "insufficient IaC evidence")


def _path_summary(steps: list[str], exposure: str) -> str:
    if not steps:
        return _fallback_path_summary(exposure)
    short_steps = steps[:4]
    suffix = " -> ..." if len(steps) > len(short_steps) else ""
    return " -> ".join(short_steps) + suffix


def _network_path_type_from_steps(exposure: str, steps: list[str]) -> str:
    text = " ".join(steps).lower()
    if "load balancer" in text or "aws_lb" in text or "aws_alb" in text:
        return "public_load_balancer" if exposure == "public" else "internal_load_balancer"
    if "application_gateway" in text or "cloudfront" in text or "frontdoor" in text:
        return "public_gateway"
    if "allows traffic from" in text or "network bridge" in text:
        return "lateral_internal_path"
    if exposure == "public":
        return "direct_public"
    if exposure == "internal":
        return "internal_ingress"
    if exposure in {"private", "isolated"}:
        return "no_observed_ingress"
    return "unresolved"


def _fallback_path_label(exposure: str) -> str:
    return {
        "public": "Public ingress",
        "external": "External ingress",
        "internal": "Internal network path",
        "private": "Isolated/private network",
        "isolated": "Isolated/private network",
    }.get(exposure, "Unresolved network path")


def _fallback_path_summary(exposure: str) -> str:
    return {
        "public": "Public exposure is reported, but no linked network path evidence was emitted.",
        "external": "External exposure is reported, but the exact ingress path is not linked.",
        "internal": "Reachable only through an internal network path inferred from the supplied context.",
        "private": "No direct or lateral ingress path was observed in the supplied context.",
        "isolated": "No direct or lateral ingress path was observed in the supplied context.",
    }.get(exposure, "The supplied context does not prove a network entry path.")


def _asset_id(name: str) -> str:
    return f"asset:{name}"


def _component_id(asset: str, component: str, version: str | None) -> str:
    return f"component:{asset}:{component}:{version or 'unknown'}"


def _vulnerability_id(vulnerability: str) -> str:
    return f"vulnerability:{vulnerability}"


def _finding_id(key: str) -> str:
    return f"finding:{key}"


def _stable_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def jsonish(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


__all__ = ["build_evidence_graph"]
