"""Attack-path view model for the self-contained HTML report."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .finding_types import (
    CLOUD_POSTURE_FINDING,
    DEPENDENCY_VULNERABILITY,
    DYNAMIC_RUNTIME_OBSERVATION,
    STATIC_CODE_WEAKNESS,
    canonical_finding_type,
)
from .models import Finding, Reachability, RuntimeEvidenceState, reachability_label
from .numeric import safe_float
from .visual_layout import EXPOSURE_RANK, TIER_RANK


def build_attack_paths(
    findings: list[Finding],
    network_paths: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
    remediations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build one deterministic attack-path story per finding."""

    paths_by_asset = _network_paths_by_asset(network_paths)
    vulnerability_by_key = {str(item.get("findingKey") or ""): item for item in vulnerabilities}
    remediation_by_key = _remediation_by_finding_key(remediations)
    attack_paths: list[dict[str, Any]] = []
    for finding in findings:
        asset_id = f"asset:{finding.artifact.name}"
        network_path = _primary_network_path(paths_by_asset.get(asset_id, []))
        vulnerability = vulnerability_by_key.get(finding.key, {})
        nodes, edges = _path_nodes_and_edges(finding, network_path, vulnerability)
        layers = _layers_for_path(nodes, edges)
        path_id = f"attack:path:{_stable_token(finding.key)}"
        title = _title_for_finding(finding)
        attack_paths.append(
            {
                "id": path_id,
                "findingKey": finding.key,
                "tier": finding.tier.value,
                "score": round(finding.score, 2),
                "confidence": finding.confidence.value,
                "findingType": canonical_finding_type(finding.finding_type),
                "findingTypeLabel": _finding_type_label(finding.finding_type),
                "title": title,
                "shortReason": _short_reason(finding, network_path),
                "artifact": {
                    "name": finding.artifact.name,
                    "reference": finding.artifact.reference,
                    "version": finding.artifact.version,
                },
                "owner": finding.context.owner,
                "exposure": finding.context.exposure or "unknown",
                "provider": _provider_for_path(network_path),
                "component": {
                    "name": finding.component.display_name,
                    "version": finding.component.version,
                    "purl": finding.component.purl,
                    "scope": finding.component.scope,
                },
                "advisory": {
                    "id": finding.vulnerability.id,
                    "aliases": finding.vulnerability.aliases,
                    "severity": finding.vulnerability.severity,
                    "cvss": finding.vulnerability.cvss,
                    "epss": finding.vulnerability.epss,
                    "known_exploited": finding.vulnerability.known_exploited,
                    "summary": finding.vulnerability.summary,
                },
                "nodes": nodes,
                "edges": edges,
                "evidenceLayers": layers,
                "evidenceSummary": _evidence_summary(finding, network_path),
                "unknowns": _dedupe([*finding.unknowns, *_source_unknowns(finding), *_network_unknowns(network_path)]),
                "blockers": _blockers(finding, network_path),
                "remediation": remediation_by_key.get(finding.key) or finding.fix_commands,
                "remediationGroup": remediation_by_key.get(finding.key, [""])[0] if remediation_by_key.get(finding.key) else "",
                "why": _why_prioritized(finding, network_path),
                "rawEvidence": {
                    "finding": finding.to_json(),
                    "network_path": network_path or {},
                    "visual_vulnerability": vulnerability,
                },
            }
        )
    return sorted(
        attack_paths,
        key=lambda item: (
            -TIER_RANK.get(str(item.get("tier") or "informational"), 0),
            -safe_float(item.get("score")),
            str(item.get("title") or ""),
        ),
    )


def _path_nodes_and_edges(
    finding: Finding,
    network_path: dict[str, Any] | None,
    vulnerability: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    finding_type = canonical_finding_type(finding.finding_type)
    prefix = _stable_token(finding.key)

    def add_node(
        node_type: str,
        label: str,
        *,
        subtitle: str = "",
        confidence: str | None = None,
        evidence_layer: str = "Context",
        raw_ref: str = "",
        state: str = "normal",
    ) -> str:
        node_id = f"attack:{prefix}:{node_type}:{len(nodes)}"
        nodes.append(
            {
                "id": node_id,
                "type": node_type,
                "label": label,
                "subtitle": subtitle,
                "confidence": confidence or finding.confidence.value,
                "evidenceLayer": evidence_layer,
                "rawRef": raw_ref,
                "state": state,
            }
        )
        return node_id

    def add_edge(
        source: str,
        target: str,
        *,
        edge_type: str,
        label: str,
        confidence: str | None = None,
        evidence_layer: str = "Context",
        blocker: bool = False,
        unknown: bool = False,
    ) -> None:
        edges.append(
            {
                "id": f"attack-edge:{prefix}:{len(edges)}",
                "from": source,
                "to": target,
                "type": edge_type,
                "label": label,
                "confidence": confidence or finding.confidence.value,
                "evidenceLayer": evidence_layer,
                "blocker": blocker,
                "unknown": unknown,
            }
        )

    previous = _entry_node(finding, network_path, add_node)
    ingress = _ingress_node(finding, network_path, add_node)
    add_edge(previous, ingress, edge_type="entry_ingress", label=_edge_label(network_path, "entry"), evidence_layer=_network_layer(network_path), confidence=_path_confidence(network_path))
    previous = ingress

    workload = add_node(
        "workload",
        _workload_label(finding, network_path),
        subtitle=finding.context.environment or "unknown environment",
        confidence=finding.context.confidence.value,
        evidence_layer=_network_layer(network_path),
        raw_ref=finding.artifact.name,
    )
    add_edge(previous, workload, edge_type="ingress_workload", label="routes to workload", confidence=_path_confidence(network_path), evidence_layer=_network_layer(network_path))
    previous = workload

    artifact = add_node(
        "artifact",
        finding.artifact.name,
        subtitle=finding.artifact.reference or "SBOM artifact",
        confidence="high",
        evidence_layer="SBOM",
        raw_ref=finding.artifact.bom_ref or finding.artifact.name,
    )
    add_edge(previous, artifact, edge_type="workload_artifact", label="mapped artifact", evidence_layer="SBOM")
    previous = artifact

    if finding_type == DYNAMIC_RUNTIME_OBSERVATION:
        evidence_node = _runtime_node(finding, add_node)
        add_edge(previous, evidence_node, edge_type="artifact_runtime", label="runtime observation", confidence=finding.runtime_evidence.confidence.value, evidence_layer="DAST")
        previous = evidence_node
        if _source_is_unknown(finding):
            unknown = add_node("unknown", "Source mapping unknown", subtitle="DAST does not prove source reachability", confidence="low", evidence_layer="Source", state="unknown")
            add_edge(previous, unknown, edge_type="runtime_source_unknown", label="source not mapped", confidence="low", evidence_layer="Source", unknown=True)
            previous = unknown
    elif finding_type == CLOUD_POSTURE_FINDING:
        evidence_node = _posture_node(finding, add_node)
        add_edge(previous, evidence_node, edge_type="artifact_posture", label="posture control", confidence=finding.posture_evidence.confidence.value, evidence_layer="CSPM")
        previous = evidence_node
    else:
        evidence_node = _source_node(finding, add_node)
        layer = "SAST" if finding_type == STATIC_CODE_WEAKNESS else "Source"
        add_edge(previous, evidence_node, edge_type="artifact_source", label=reachability_label(finding.source.reachability), confidence=finding.source.confidence.value, evidence_layer=layer)
        previous = evidence_node

    risk_type = "vulnerability" if finding_type == DEPENDENCY_VULNERABILITY else "posture" if finding_type == CLOUD_POSTURE_FINDING else "weakness"
    risk = add_node(
        risk_type,
        finding.vulnerability.id,
        subtitle=_risk_subtitle(finding, vulnerability),
        confidence=finding.confidence.value,
        evidence_layer=_risk_layer(finding_type),
        raw_ref=finding.key,
    )
    add_edge(previous, risk, edge_type="evidence_finding", label=_finding_type_label(finding_type), evidence_layer=_risk_layer(finding_type))
    previous = risk

    identity = _identity_node(finding, add_node)
    if identity:
        add_edge(previous, identity, edge_type="finding_identity", label="effective access / privilege", evidence_layer="IAM", confidence=finding.context.confidence.value)
        previous = identity
    data = _data_node(finding, add_node)
    if data:
        add_edge(previous, data, edge_type="identity_data", label="blast-radius context", evidence_layer="IAM", confidence=finding.context.confidence.value)
        previous = data

    for blocker in _blockers(finding, network_path)[:2]:
        node = add_node("blocker", _blocker_label(blocker), subtitle=_blocker_detail(blocker), confidence="medium", evidence_layer=_network_layer(network_path), state="blocked")
        add_edge(ingress, node, edge_type="path_blocker", label="path constraint", confidence="medium", evidence_layer=_network_layer(network_path), blocker=True)
    for unknown in _dedupe([*_source_unknowns(finding), *_network_unknowns(network_path)])[:2]:
        node = add_node("unknown", unknown, subtitle="visibility gap", confidence="low", evidence_layer="Context", state="unknown")
        add_edge(previous, node, edge_type="visibility_gap", label="unknown", confidence="low", evidence_layer="Context", unknown=True)

    return nodes, edges


def _entry_node(finding: Finding, network_path: dict[str, Any] | None, add_node: Any) -> str:
    finding_type = canonical_finding_type(finding.finding_type)
    if finding_type == DYNAMIC_RUNTIME_OBSERVATION:
        runtime = finding.runtime_evidence
        label = runtime.tool if runtime.tool and runtime.tool != "none" else "DAST probe"
        subtitle = " ".join(part for part in [runtime.method, runtime.url] if part) or runtime.state.value
        return str(add_node("entry", label, subtitle=subtitle, confidence=runtime.confidence.value, evidence_layer="DAST", raw_ref=runtime.url or ""))
    if finding_type == STATIC_CODE_WEAKNESS:
        return str(add_node("entry", "Source entrypoint", subtitle=finding.source.language or finding.source.evidence_source, confidence=finding.source.confidence.value, evidence_layer="SAST"))
    label = str((network_path or {}).get("entryLabel") or _entry_label(finding.context.exposure))
    return str(add_node("entry", label, subtitle=str((network_path or {}).get("entrySubtitle") or finding.context.exposure or "unknown"), confidence=_path_confidence(network_path), evidence_layer=_network_layer(network_path)))


def _ingress_node(finding: Finding, network_path: dict[str, Any] | None, add_node: Any) -> str:
    if network_path:
        label = str(network_path.get("label") or network_path.get("pathType") or "Network path")
        subtitle = str(network_path.get("pathType") or network_path.get("exposure") or "")
        return str(add_node("ingress", label, subtitle=subtitle, confidence=_path_confidence(network_path), evidence_layer=_network_layer(network_path), raw_ref=str(network_path.get("id") or "")))
    label = "Unresolved ingress" if finding.context.exposure == "unknown" else f"{finding.context.exposure or 'unknown'} ingress"
    return str(add_node("unknown", label, subtitle="No linked network path", confidence="low", evidence_layer="Context", state="unknown"))


def _source_node(finding: Finding, add_node: Any) -> str:
    location = finding.source.locations[0].to_json() if finding.source.locations else {}
    label = reachability_label(finding.source.reachability)
    if location:
        label = str(location.get("path") or label)
    subtitle_parts = [finding.source.reason]
    if location:
        subtitle_parts.append(f"line {location.get('line')}")
    return str(add_node(
        "source",
        label,
        subtitle=" | ".join(part for part in subtitle_parts if part),
        confidence=finding.source.confidence.value,
        evidence_layer="SAST" if canonical_finding_type(finding.finding_type) == STATIC_CODE_WEAKNESS else "Source",
        raw_ref=json.dumps(location, sort_keys=True) if location else finding.source.evidence_source,
        state="unknown" if _source_is_unknown(finding) else "normal",
    ))


def _posture_node(finding: Finding, add_node: Any) -> str:
    posture = finding.posture_evidence
    label = posture.resource_id or finding.component.name or "Cloud resource"
    subtitle = " | ".join(part for part in [posture.provider, posture.resource_type, posture.service] if part)
    return str(add_node(
        "posture",
        label,
        subtitle=subtitle or posture.control or "posture evidence",
        confidence=posture.confidence.value,
        evidence_layer="CSPM",
        raw_ref=posture.rule_id,
        state="unknown" if finding.artifact.name.startswith("unmapped:") else "normal",
    ))


def _runtime_node(finding: Finding, add_node: Any) -> str:
    runtime = finding.runtime_evidence
    label = " ".join(part for part in [runtime.method, runtime.url] if part) or runtime.state.value
    subtitle = " | ".join(part for part in [runtime.parameter, runtime.authentication_context, runtime.tool] if part)
    return str(add_node(
        "runtime",
        label,
        subtitle=subtitle,
        confidence=runtime.confidence.value,
        evidence_layer="DAST",
        raw_ref=runtime.url or finding.vulnerability.id,
    ))


def _identity_node(finding: Finding, add_node: Any) -> str | None:
    if finding.context.effective_access:
        access = finding.context.effective_access[0]
        label = str(access.get("identity") or access.get("principal") or "Effective identity")
        subtitle = " ".join(str(access.get(key) or "") for key in ("action", "decision", "resource")).strip()
        return str(add_node("identity", label, subtitle=subtitle, confidence=str(access.get("confidence") or finding.context.confidence.value), evidence_layer="IAM", raw_ref=json.dumps(access, sort_keys=True)))
    if finding.context.privilege and finding.context.privilege != "unknown":
        return str(add_node("identity", f"{finding.context.privilege} privilege", subtitle=", ".join(finding.context.iam_impacts[:3]), confidence=finding.context.confidence.value, evidence_layer="IAM"))
    return None


def _data_node(finding: Finding, add_node: Any) -> str | None:
    impacts = [impact for impact in finding.context.iam_impacts if impact]
    criticality = finding.context.criticality if finding.context.criticality != "unknown" else ""
    if not impacts and not criticality:
        return None
    label = impacts[0] if impacts else f"{criticality} criticality"
    subtitle = ", ".join([*impacts[1:4], criticality]).strip(", ")
    return str(add_node("data", label, subtitle=subtitle, confidence=finding.context.confidence.value, evidence_layer="IAM"))


def _network_paths_by_asset(network_paths: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for path in network_paths:
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


def _remediation_by_finding_key(remediations: list[dict[str, Any]]) -> dict[str, list[str]]:
    by_key: dict[str, list[str]] = {}
    for group in remediations:
        if not isinstance(group, dict):
            continue
        commands = [str(command) for command in group.get("fix_commands") or group.get("commands") or [] if command]
        suggested = group.get("suggested_fix")
        if suggested:
            commands.insert(0, str(suggested))
        for finding in group.get("findings") or []:
            key = finding.get("key") if isinstance(finding, dict) else None
            if key and commands:
                by_key[str(key)] = _dedupe(commands)
    return by_key


def _layers_for_path(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[str]:
    return _dedupe([str(item.get("evidenceLayer") or "") for item in [*nodes, *edges] if item.get("evidenceLayer")])


def _evidence_summary(finding: Finding, network_path: dict[str, Any] | None) -> list[str]:
    values = [*finding.evidence_summary]
    if finding.source.reason:
        values.append(finding.source.reason)
    if network_path and network_path.get("evidence"):
        values.append(str(network_path.get("evidence")))
    for item in finding.context.evidence[:4]:
        values.append(str(item))
    return _dedupe(values)


def _why_prioritized(finding: Finding, network_path: dict[str, Any] | None) -> list[str]:
    why = list(finding.rationale[:6])
    scoring = finding.score_details.get("graph_decision") if isinstance(finding.score_details, dict) else None
    if isinstance(scoring, dict):
        why.extend(str(driver) for driver in scoring.get("drivers") or [])
    if network_path:
        why.append(str(network_path.get("summary") or network_path.get("label") or "network path evidence"))
    return _dedupe([value for value in why if value])


def _blockers(finding: Finding, network_path: dict[str, Any] | None) -> list[Any]:
    blockers: list[Any] = []
    if network_path and isinstance(network_path.get("blockers"), list):
        blockers.extend(network_path.get("blockers") or [])
    scoring = finding.score_details.get("graph_decision") if isinstance(finding.score_details, dict) else None
    if isinstance(scoring, dict):
        blockers.extend(scoring.get("blockers") or [])
    return blockers


def _source_unknowns(finding: Finding) -> list[str]:
    if canonical_finding_type(finding.finding_type) == DYNAMIC_RUNTIME_OBSERVATION and _source_is_unknown(finding):
        return ["source mapping unavailable"]
    if canonical_finding_type(finding.finding_type) == CLOUD_POSTURE_FINDING and finding.artifact.name.startswith("unmapped:"):
        return ["posture resource is not mapped to a workload artifact"]
    if finding.source.reachability in {Reachability.UNKNOWN_DUE_TO_NO_RULE, Reachability.PACKAGE_PRESENT}:
        return [reachability_label(finding.source.reachability)]
    return []


def _network_unknowns(network_path: dict[str, Any] | None) -> list[str]:
    if not network_path:
        return ["network path unavailable"]
    if str(network_path.get("exposure") or "") == "unknown" or str(network_path.get("confidence") or "") == "low":
        return ["network path confidence is low or unresolved"]
    return []


def _source_is_unknown(finding: Finding) -> bool:
    return not finding.source.locations and finding.source.reachability in {
        Reachability.PACKAGE_PRESENT,
        Reachability.UNKNOWN_DUE_TO_NO_RULE,
        Reachability.ABSENT,
    }


def _short_reason(finding: Finding, network_path: dict[str, Any] | None) -> str:
    if finding.rationale:
        return finding.rationale[0]
    if finding.runtime_evidence.state != RuntimeEvidenceState.NOT_OBSERVED:
        return f"{finding.runtime_evidence.state.value} by {finding.runtime_evidence.tool}"
    if network_path:
        return str(network_path.get("summary") or network_path.get("label") or "linked deployment context")
    return finding.source.reason or finding.vulnerability.summary


def _title_for_finding(finding: Finding) -> str:
    finding_type = canonical_finding_type(finding.finding_type)
    if finding_type == DEPENDENCY_VULNERABILITY:
        return f"{finding.vulnerability.id} in {finding.component.display_name}"
    weakness = finding.weakness.get("weakness") or finding.vulnerability.summary or finding.vulnerability.id
    return f"{finding.vulnerability.id} {weakness}".strip()


def _workload_label(finding: Finding, network_path: dict[str, Any] | None) -> str:
    steps = network_path.get("steps") if network_path else None
    if isinstance(steps, list) and steps:
        return str(steps[-1])
    return finding.artifact.name


def _risk_subtitle(finding: Finding, vulnerability: dict[str, Any]) -> str:
    if canonical_finding_type(finding.finding_type) == DEPENDENCY_VULNERABILITY:
        return f"{finding.component.display_name}@{finding.component.version or 'unknown'}"
    weakness = finding.weakness
    parts = [str(weakness.get("cwe") or ""), str(weakness.get("tool") or ""), str(vulnerability.get("severity") or finding.vulnerability.severity or "")]
    return " | ".join(part for part in parts if part)


def _finding_type_label(finding_type: str) -> str:
    canonical = canonical_finding_type(finding_type)
    if canonical == DEPENDENCY_VULNERABILITY:
        return "dependency vulnerability"
    if canonical == STATIC_CODE_WEAKNESS:
        return "static code weakness"
    if canonical == DYNAMIC_RUNTIME_OBSERVATION:
        return "dynamic runtime observation"
    if canonical == CLOUD_POSTURE_FINDING:
        return "cloud posture finding"
    return canonical.replace("_", " ")


def _risk_layer(finding_type: str) -> str:
    canonical = canonical_finding_type(finding_type)
    if canonical == DEPENDENCY_VULNERABILITY:
        return "SCA"
    if canonical == STATIC_CODE_WEAKNESS:
        return "SAST"
    if canonical == DYNAMIC_RUNTIME_OBSERVATION:
        return "DAST"
    if canonical == CLOUD_POSTURE_FINDING:
        return "CSPM"
    return "Context"


def _network_layer(network_path: dict[str, Any] | None) -> str:
    if not network_path:
        return "Context"
    provider = str(network_path.get("provider") or "").lower()
    evidence = str(network_path.get("evidence") or "").lower()
    if "kubernetes" in provider or "kubernetes" in evidence:
        return "Kubernetes"
    if evidence.startswith("terraform") or provider in {"aws", "azure", "gcp"}:
        return "Terraform"
    return "Context"


def _path_confidence(network_path: dict[str, Any] | None) -> str:
    return str((network_path or {}).get("confidence") or "low")


def _provider_for_path(network_path: dict[str, Any] | None) -> str:
    if not network_path:
        return "Context"
    provider = network_path.get("provider")
    if provider:
        return str(provider)
    text = " ".join([str(network_path.get("label") or ""), str(network_path.get("evidence") or ""), " ".join(str(step) for step in network_path.get("steps") or [])]).lower()
    if "aws_" in text or "amazon" in text:
        return "AWS"
    if "azurerm_" in text or "azure" in text:
        return "Azure"
    if "google_" in text or "gcp" in text:
        return "GCP"
    if "kubernetes" in text:
        return "Kubernetes"
    return "Context"


def _entry_label(exposure: str) -> str:
    if exposure == "public":
        return "Internet"
    if exposure == "external":
        return "External source"
    if exposure == "internal":
        return "Internal pivot"
    if exposure in {"private", "isolated"}:
        return "Private network"
    return "Unknown entry"


def _edge_label(network_path: dict[str, Any] | None, fallback: str) -> str:
    if not network_path:
        return fallback
    return str(network_path.get("pathType") or network_path.get("exposure") or fallback)


def _blocker_label(blocker: Any) -> str:
    if isinstance(blocker, dict):
        return str(blocker.get("kind") or blocker.get("type") or "blocker")
    return str(blocker)


def _blocker_detail(blocker: Any) -> str:
    if isinstance(blocker, dict):
        return str(blocker.get("evidence") or blocker.get("reason") or blocker.get("detail") or "")
    return ""


def _dedupe(values: list[Any]) -> list[Any]:
    seen: set[str] = set()
    result: list[Any] = []
    for value in values:
        if value in (None, ""):
            continue
        key = json.dumps(value, sort_keys=True, default=str) if isinstance(value, (dict, list)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _stable_token(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]
