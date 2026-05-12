"""Unified effective exposure graph.

This module builds the canonical per-finding path used by scoring explanations
and machine-readable reports:

asset -> network path -> identity -> reachable code/package -> vulnerability -> score

The evidence graph still exposes separate compatibility views for network,
IAM, and code edges. The effective graph is the normalized path contract that
ties those signals together and records provenance on every edge.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .effective_exposure import evaluate_effective_exposure
from .iam_capabilities import capability_risk_multiplier, dedupe_iam_capabilities
from .models import Finding, Reachability, reachability_label
from .numeric import safe_float

PATH_ORDER = ("asset", "network_path", "identity", "reachable_code_package", "vulnerability", "score")
NETWORK_PATH_RE = re.compile(r"^(?:terraform|context|kubernetes) network path: (?P<exposure>[a-z_]+) via (?P<path>.+)$")
EXPOSURE_INFERENCE_RE = re.compile(r"^(?:terraform|context|kubernetes) exposure inference: (?P<exposure>[a-z_]+) via (?P<target>.+)$")


def build_effective_exposure_graph(findings: list[Finding]) -> dict[str, Any]:
    """Return the unified graph for a set of findings."""

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    paths: list[dict[str, Any]] = []

    for finding in findings:
        path = effective_exposure_path(finding)
        for node in path["nodes"]:
            nodes.setdefault(str(node["id"]), node)
        for edge in path["edges"]:
            edges.setdefault(str(edge["id"]), edge)
        paths.append(
            {
                "id": path["id"],
                "finding_key": path["finding_key"],
                "order": list(PATH_ORDER),
                "node_ids": path["node_ids"],
                "edge_ids": path["edge_ids"],
                "risk_inputs": path["risk_inputs"],
            }
        )

    return {
        "schema_version": "1.0",
        "path_order": list(PATH_ORDER),
        "paths": sorted(paths, key=lambda item: str(item["finding_key"])),
        "nodes": sorted(nodes.values(), key=lambda item: (str(item.get("kind")), str(item.get("label")), str(item.get("id")))),
        "edges": sorted(edges.values(), key=lambda item: (str(item.get("path_id")), int(item.get("sequence", 0)))),
    }


def effective_path_id(finding: Finding) -> str:
    return f"effective-path:{_stable_token(finding.key)}"


def effective_exposure_path(finding: Finding) -> dict[str, Any]:
    asset = _asset_node(finding)
    network = _network_node(finding)
    identity = _identity_node(finding)
    code = _code_node(finding)
    vulnerability = _vulnerability_node(finding)
    score = _score_node(finding)
    path_id = effective_path_id(finding)
    nodes = [asset, network, identity, code, vulnerability, score]

    edges = [
        _edge(
            path_id=path_id,
            sequence=0,
            source=asset["id"],
            target=network["id"],
            kind="asset_deployed_on_network_path",
            evidence_layer=str(network["evidence_layer"]),
            evidence_source=str(network["evidence_source"]),
            confidence=str(network["confidence"]),
            provider=str(network["provider"]),
            blockers=_objects(network.get("blockers")),
            unknowns=_strings(network.get("unknowns")),
        ),
        _edge(
            path_id=path_id,
            sequence=1,
            source=network["id"],
            target=identity["id"],
            kind="network_path_reaches_identity",
            evidence_layer="iam",
            evidence_source=str(identity["evidence_source"]),
            confidence=str(identity["confidence"]),
            provider=str(identity["provider"]),
            blockers=_objects(identity.get("blockers")),
            unknowns=_strings(identity.get("unknowns")),
            origin_layer=str(identity.get("origin_layer") or "unknown"),
        ),
        _edge(
            path_id=path_id,
            sequence=2,
            source=identity["id"],
            target=code["id"],
            kind="identity_runs_reachable_code_package",
            evidence_layer=str(code["evidence_layer"]),
            evidence_source=str(code["evidence_source"]),
            confidence=str(code["confidence"]),
            provider=str(code["provider"]),
            language=str(code["language"]),
            unknowns=_strings(code.get("unknowns")),
        ),
        _edge(
            path_id=path_id,
            sequence=3,
            source=code["id"],
            target=vulnerability["id"],
            kind="package_has_vulnerability",
            evidence_layer="sbom",
            evidence_source="SBOM component match plus vulnerability intelligence",
            confidence=_package_vulnerability_confidence(finding),
            provider=_ecosystem(finding.component.purl),
            language=str(code["language"]),
            unknowns=_package_vulnerability_unknowns(finding),
        ),
        _edge(
            path_id=path_id,
            sequence=4,
            source=vulnerability["id"],
            target=score["id"],
            kind="vulnerability_prioritized_as_score",
            evidence_layer="scoring",
            evidence_source=f"scoring model {finding.score_details.get('model_version') or 'unknown'}",
            confidence=finding.confidence.value,
            provider=_ecosystem(finding.component.purl),
            language=str(code["language"]),
            unknowns=_score_unknowns(finding),
        ),
    ]

    return {
        "id": path_id,
        "finding_key": finding.key,
        "order": list(PATH_ORDER),
        "nodes": nodes,
        "edges": edges,
        "node_ids": [str(node["id"]) for node in nodes],
        "edge_ids": [str(edge["id"]) for edge in edges],
        "risk_inputs": {
            "artifact": finding.artifact.name,
            "component": finding.component.display_name,
            "vulnerability": finding.vulnerability.id,
            "score": round(finding.score, 2),
            "tier": finding.tier.value,
            "network_exposure": finding.context.exposure,
            "identity_privilege": finding.context.privilege,
            "source_reachability": finding.source.reachability.value,
            "known_exploited": finding.vulnerability.known_exploited,
            "confidence": finding.confidence.value,
        },
    }


def scoring_path_summary(finding: Finding) -> dict[str, Any]:
    """Small scoring-facing view of the effective path."""

    graph = effective_exposure_path(finding)
    return {
        "path_id": graph["id"],
        "order": graph["order"],
        "node_ids": graph["node_ids"],
        "edge_ids": graph["edge_ids"],
        "risk_inputs": graph["risk_inputs"],
    }


def _asset_node(finding: Finding) -> dict[str, Any]:
    return _node(
        id=f"asset:{finding.artifact.name}",
        kind="asset",
        label=finding.artifact.name,
        reference=finding.artifact.reference,
        owner=finding.context.owner,
        environment=finding.context.environment,
    )


def _network_node(finding: Finding) -> dict[str, Any]:
    exposure_record = _primary_effective_exposure_record(finding)
    record = _objects_get(exposure_record, "network") or _primary_network_record(finding)
    exposure = str(record.get("exposure") or finding.context.exposure or "unknown").lower()
    source = str(record.get("source") or finding.context.source or "context")
    evidence_layer = _deployment_layer(source)
    steps = _strings(record.get("steps"))
    unknowns = _strings(record.get("unknowns"))
    if not finding.context.network_paths and not record.get("evidence"):
        unknowns.append("no typed network path evidence")
    if not steps and exposure not in {"private", "isolated", "none"}:
        unknowns.append("no concrete network hop sequence")
    return _node(
        id=f"network-path:{finding.artifact.name}:{_stable_token(jsonish(record))}",
        kind="network_path",
        label=str(record.get("label") or _network_label(exposure)),
        exposure=exposure,
        path_type=str(record.get("path_type") or _network_path_type(exposure, steps)),
        entry_kind=str(record.get("entry_kind") or record.get("entry") or _entry_kind(exposure, steps)),
        steps=steps,
        evidence_source=str(record.get("evidence") or f"{evidence_layer} network context"),
        evidence_layer=evidence_layer,
        provider=str(record.get("provider") or _provider_from_source(source)),
        confidence=_confidence_value(record.get("confidence"), finding.context.confidence.value),
        effective_decision=str(exposure_record.get("decision") or record.get("decision") or "unknown"),
        blockers=_objects(record.get("blockers")),
        unknowns=_dedupe_strings(unknowns),
    )


def _identity_node(finding: Finding) -> dict[str, Any]:
    exposure_record = _primary_effective_exposure_record(finding)
    identity = _objects_get(exposure_record, "identity")
    if identity:
        source = str(identity.get("source") or finding.context.source or "context")
        return _node(
            id=f"identity:{finding.artifact.name}:{_stable_token(jsonish(identity))}",
            kind="identity",
            label=str(identity.get("identity") or identity.get("action") or identity.get("impact") or identity.get("decision") or "effective identity"),
            privilege=finding.context.privilege,
            action=identity.get("action"),
            impact=identity.get("impact"),
            resource=identity.get("resource"),
            access=identity.get("access"),
            decision=identity.get("decision", "unknown"),
            decision_basis=identity.get("decision_basis"),
            policy_layer=identity.get("policy_layer"),
            evidence_source=str(identity.get("source") or identity.get("evidence") or "effective exposure engine"),
            provider=str(identity.get("provider") or _provider_from_source(source)),
            confidence=_confidence_value(identity.get("confidence"), finding.context.confidence.value),
            blockers=_objects(identity.get("blockers")),
            unknowns=_strings(identity.get("unknowns")),
            origin_layer=_deployment_layer(source),
        )

    access = _strongest_effective_access(finding)
    if access:
        source = str(access.get("source") or finding.context.source or "context")
        return _node(
            id=f"identity:{finding.artifact.name}:{_stable_token(jsonish(access))}",
            kind="identity",
            label=str(access.get("identity") or access.get("action") or access.get("impact") or "effective identity"),
            privilege=finding.context.privilege,
            action=access.get("action"),
            impact=access.get("impact"),
            resource=access.get("resource"),
            access=access.get("access"),
            decision=access.get("decision", "allowed"),
            evidence_source=str(access.get("evidence") or access.get("source") or "effective access record"),
            provider=str(access.get("provider") or _provider_from_source(source)),
            confidence=_confidence_value(access.get("confidence"), finding.context.confidence.value),
            blockers=_objects(access.get("blockers")),
            unknowns=_strings(access.get("unknowns")),
            origin_layer=_deployment_layer(source),
        )

    capabilities = dedupe_iam_capabilities(finding.context.iam_capabilities)
    capability = _strongest_capability(capabilities)
    if capability:
        source = str(capability.get("source") or finding.context.source or "context")
        return _node(
            id=f"identity:{finding.artifact.name}:{_stable_token(jsonish(capability))}",
            kind="identity",
            label=str(capability.get("action") or capability.get("impact") or "IAM capability"),
            privilege=finding.context.privilege,
            action=capability.get("action"),
            impact=capability.get("impact"),
            access=capability.get("access"),
            resource_scope=capability.get("resource_scope", "unknown"),
            condition_keys=capability.get("condition_keys", []),
            risk_multiplier=capability_risk_multiplier(capability),
            evidence_source=str(capability.get("evidence") or capability.get("source") or "IAM capability record"),
            provider=str(capability.get("provider") or _provider_from_source(source)),
            confidence=finding.context.confidence.value,
            blockers=[],
            unknowns=_capability_unknowns(capability),
            origin_layer=_deployment_layer(source),
        )

    unknowns: list[str] = []
    if finding.context.privilege == "unknown":
        unknowns.append("no effective identity or IAM capability evidence")
    return _node(
        id=f"identity:{finding.artifact.name}:summary",
        kind="identity",
        label=f"{finding.context.privilege or 'unknown'} identity",
        privilege=finding.context.privilege,
        impacts=finding.context.iam_impacts,
        evidence_source=finding.context.source,
        provider=_provider_from_source(finding.context.source),
        confidence=finding.context.confidence.value,
        blockers=[],
        unknowns=unknowns,
        origin_layer=_deployment_layer(finding.context.source),
    )


def _code_node(finding: Finding) -> dict[str, Any]:
    evidence_source = finding.source.evidence_source or "builtin"
    evidence_layer = "external_analyzer" if evidence_source != "builtin" else "source"
    unknowns: list[str] = []
    if evidence_source == "builtin":
        unknowns.append("built-in source analyzer fallback")
    if finding.source.reachability in {Reachability.PACKAGE_PRESENT, Reachability.UNKNOWN_DUE_TO_NO_RULE, Reachability.ABSENT}:
        unknowns.append(f"weak source state: {finding.source.reachability.value}")
    return _node(
        id=f"code-package:{finding.artifact.name}:{finding.component.name}:{finding.component.version or 'unknown'}",
        kind="reachable_code_package",
        label=f"{finding.component.display_name}@{finding.component.version or 'unknown'}",
        package=finding.component.display_name,
        version=finding.component.version,
        purl=finding.component.purl,
        reachability=finding.source.reachability.value,
        reachability_label=reachability_label(finding.source.reachability),
        evidence_source=evidence_source,
        evidence_layer=evidence_layer,
        provider=_ecosystem(finding.component.purl),
        language=finding.source.language,
        confidence=finding.source.confidence.value,
        matched_symbols=finding.source.matched_symbols,
        dependency_path=finding.source.dependency_path,
        locations=[location.to_json() for location in finding.source.locations],
        unknowns=_dedupe_strings(unknowns),
    )


def _vulnerability_node(finding: Finding) -> dict[str, Any]:
    return _node(
        id=f"vulnerability:{finding.vulnerability.id}",
        kind="vulnerability",
        label=finding.vulnerability.id,
        severity=finding.vulnerability.severity,
        cvss=finding.vulnerability.cvss,
        epss=finding.vulnerability.epss,
        known_exploited=finding.vulnerability.known_exploited,
        package_name=finding.vulnerability.package_name,
        fixed_versions=finding.vulnerability.fixed_versions,
    )


def _score_node(finding: Finding) -> dict[str, Any]:
    return _node(
        id=f"score:{finding.key}",
        kind="score",
        label=f"{finding.tier.value} {finding.score:.1f}",
        score=round(finding.score, 2),
        tier=finding.tier.value,
        confidence=finding.confidence.value,
        gates=finding.score_details.get("gates", []),
        dimensions=finding.score_details.get("dimensions", []),
    )


def _edge(
    *,
    path_id: str,
    sequence: int,
    source: str,
    target: str,
    kind: str,
    evidence_layer: str,
    evidence_source: str,
    confidence: str,
    provider: str = "unknown",
    language: str = "unknown",
    blockers: list[dict[str, Any]] | None = None,
    unknowns: list[str] | None = None,
    origin_layer: str | None = None,
) -> dict[str, Any]:
    normalized_blockers = blockers or []
    normalized_unknowns = _dedupe_strings(unknowns or [])
    return {
        "id": f"effective-edge:{_stable_token(path_id + ':' + str(sequence) + ':' + source + ':' + target)}",
        "path_id": path_id,
        "source": source,
        "target": target,
        "kind": kind,
        "sequence": sequence,
        "evidence_layer": evidence_layer,
        "origin_layer": origin_layer or evidence_layer,
        "evidence_source": evidence_source,
        "confidence": _confidence_value(confidence),
        "provider": provider or "unknown",
        "language": language or "unknown",
        "blockers": normalized_blockers,
        "unknowns": normalized_unknowns,
        "blocker_state": "blocked" if normalized_blockers else ("unknown" if normalized_unknowns else "none"),
    }


def _primary_network_record(finding: Finding) -> dict[str, Any]:
    for item in finding.context.network_paths:
        if isinstance(item, dict):
            return {str(key): value for key, value in item.items()}
    for evidence in finding.context.evidence:
        parsed = _network_record_from_evidence(finding, evidence)
        if parsed:
            return parsed
    return {
        "source": finding.context.source,
        "exposure": finding.context.exposure,
        "label": _network_label(finding.context.exposure),
        "evidence": "",
        "confidence": finding.context.confidence.value,
        "steps": [],
    }


def _primary_effective_exposure_record(finding: Finding) -> dict[str, Any]:
    records = [dict(item) for item in finding.context.effective_exposure if isinstance(item, dict)]
    if not records:
        records = evaluate_effective_exposure(finding.artifact.name, finding.context)
    if not records:
        return {}
    return max(records, key=lambda item: (_decision_rank(str(item.get("decision") or "")), _confidence_rank(str(item.get("confidence") or ""))))


def _network_record_from_evidence(finding: Finding, evidence: str) -> dict[str, Any] | None:
    match = NETWORK_PATH_RE.match(evidence)
    if match:
        exposure = match.group("exposure")
        steps = [step.strip() for step in match.group("path").split(" -> ") if step.strip()]
        return {
            "source": finding.context.source,
            "exposure": exposure,
            "label": steps[0] if steps else _network_label(exposure),
            "path_type": _network_path_type(exposure, steps),
            "entry_kind": _entry_kind(exposure, steps),
            "evidence": evidence,
            "confidence": finding.context.confidence.value,
            "steps": steps,
        }
    inference = EXPOSURE_INFERENCE_RE.match(evidence)
    if inference:
        exposure = inference.group("exposure")
        target = inference.group("target").strip()
        return {
            "source": finding.context.source,
            "exposure": exposure,
            "label": f"{exposure} exposure",
            "path_type": _network_path_type(exposure, [target]),
            "entry_kind": _entry_kind(exposure, [target]),
            "evidence": evidence,
            "confidence": finding.context.confidence.value,
            "steps": [target],
        }
    return None


def _strongest_effective_access(finding: Finding) -> dict[str, Any] | None:
    records = [{str(key): value for key, value in item.items()} for item in finding.context.effective_access if isinstance(item, dict)]
    if not records:
        return None
    return max(records, key=lambda item: (_impact_rank(str(item.get("impact") or "")), _confidence_rank(str(item.get("confidence") or ""))))


def _strongest_capability(capabilities: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not capabilities:
        return None
    return max(capabilities, key=lambda item: (_impact_rank(str(item.get("impact") or "")), safe_float(item.get("risk_multiplier"))))


def _impact_rank(impact: str) -> int:
    return {
        "admin_control": 6,
        "iam_escalation": 5,
        "network_control": 5,
        "compute_control": 4,
        "data_access": 4,
        "limited_access": 1,
    }.get(impact.lower(), 0)


def _confidence_rank(confidence: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(confidence.lower(), 0)


def _decision_rank(decision: str) -> int:
    return {"blocked": 0, "isolated": 1, "unknown": 2, "reachable_without_effective_identity": 3, "constrained": 4, "reachable": 5}.get(decision.lower(), 2)


def _confidence_value(value: Any, default: str = "low") -> str:
    candidate = str(value or default).lower()
    return candidate if candidate in {"high", "medium", "low"} else default


def _deployment_layer(source: str) -> str:
    value = source.lower()
    if "terraform" in value or value.startswith("tf"):
        return "terraform"
    if "kubernetes" in value or "k8s" in value or "manifest" in value:
        return "kubernetes"
    if value in {"context", "context_json"}:
        return "context"
    if value in {"none", "", "unknown"}:
        return "context"
    return value.replace(" ", "_")


def _provider_from_source(source: str) -> str:
    value = source.lower()
    for provider in ("aws", "azure", "gcp", "kubernetes"):
        if provider in value:
            return provider
    if "terraform" in value:
        return "multicloud"
    return "unknown"


def _entry_kind(exposure: str, steps: list[str]) -> str:
    text = " ".join(steps).lower()
    if exposure == "public":
        return "internet"
    if exposure == "external":
        return "external"
    if exposure == "internal" and any(token in text for token in ("public", "loadbalancer", "nodeport", "internet-facing")):
        return "public_pivot"
    if exposure == "internal":
        return "internal"
    if exposure in {"private", "isolated", "none"}:
        return "isolated"
    return "unknown"


def _network_label(exposure: str) -> str:
    return {
        "public": "Public ingress",
        "external": "External ingress",
        "internal": "Internal network path",
        "private": "Isolated/private network",
        "isolated": "Isolated/private network",
        "none": "No observed ingress",
    }.get(str(exposure or "unknown").lower(), "Unresolved network path")


def _network_path_type(exposure: str, steps: list[str]) -> str:
    text = " ".join(steps).lower()
    if "load balancer" in text or "aws_lb" in text or "alb" in text:
        return "public_load_balancer" if exposure == "public" else "internal_load_balancer"
    if "application_gateway" in text or "api gateway" in text or "cloudfront" in text or "frontdoor" in text:
        return "public_gateway"
    if "allows traffic from" in text or "security_group_rule" in text:
        return "lateral_internal_path"
    if exposure == "public":
        return "direct_public"
    if exposure == "internal":
        return "internal_ingress"
    if exposure in {"private", "isolated", "none"}:
        return "no_observed_ingress"
    return "unresolved"


def _ecosystem(purl: str | None) -> str:
    if not purl or not purl.startswith("pkg:"):
        return "unknown"
    rest = purl[4:]
    return rest.split("/", 1)[0].split("@", 1)[0].lower() or "unknown"


def _package_vulnerability_confidence(finding: Finding) -> str:
    if finding.component.purl and finding.vulnerability.package_purl:
        return "high" if finding.component.purl == finding.vulnerability.package_purl else "medium"
    if finding.component.name.lower() == finding.vulnerability.package_name.lower():
        return "medium"
    return "low"


def _package_vulnerability_unknowns(finding: Finding) -> list[str]:
    unknowns: list[str] = []
    if not finding.vulnerability.affected_versions:
        unknowns.append("vulnerability record has no explicit affected version range")
    if not finding.component.purl:
        unknowns.append("component has no package URL")
    return unknowns


def _score_unknowns(finding: Finding) -> list[str]:
    unknowns: list[str] = []
    gates = finding.score_details.get("gates", [])
    if isinstance(gates, list):
        for gate in gates:
            if isinstance(gate, dict) and gate.get("status") == "capped":
                unknowns.append(f"score cap: {gate.get('name') or 'priority_cap'}")
    return unknowns


def _capability_unknowns(capability: dict[str, Any]) -> list[str]:
    unknowns: list[str] = []
    if str(capability.get("resource_scope") or "unknown") == "unknown":
        unknowns.append("IAM resource scope unknown")
    if not capability.get("condition_keys"):
        unknowns.append("IAM conditions not observed")
    return unknowns


def _objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [{str(key): item_value for key, item_value in item.items()} for item in value if isinstance(item, dict)]


def _objects_get(value: dict[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key)
    return {str(item_key): item_value for item_key, item_value in item.items()} if isinstance(item, dict) else {}


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _dedupe_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    for value in values:
        if value and value not in deduped:
            deduped.append(value)
    return deduped


def _node(id: str, kind: str, label: str, **extra: Any) -> dict[str, Any]:
    node: dict[str, Any] = {"id": id, "kind": kind, "label": label}
    node.update(extra)
    return node


def _stable_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def jsonish(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


__all__ = [
    "PATH_ORDER",
    "build_effective_exposure_graph",
    "effective_exposure_path",
    "effective_path_id",
    "scoring_path_summary",
]
