"""Self-contained visual HTML report renderer."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .evidence_graph import build_evidence_graph
from .models import Finding, reachability_label
from .numeric import safe_float
from .remediation import build_remediation_groups
from .visual_graph import visual_graph_model
from .visual_layout import EXPOSURE_RANK, TIER_RANK

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
    return {
        "metadata": {
            "tool": "reachability-advisor",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **(metadata or {}),
        },
        "stats": _stats(finding_rows),
        "remediations": build_remediation_groups(findings),
        "evidenceGraph": graph,
        "findings": finding_rows,
        "assets": ordered_assets,
        "networkPaths": network_paths,
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
    network_paths: list[dict[str, Any]] = []
    for asset in assets:
        paths = asset.get("networkPaths") or []
        if not paths:
            paths = [_fallback_network_path(asset)]
            asset["networkPaths"] = paths
        paths.sort(key=lambda item: (-EXPOSURE_RANK.get(item.get("exposure", "unknown"), 0), -TIER_RANK.get(item.get("tier", "informational"), 0), item.get("label", "")))
        for index, path in enumerate(paths):
            path["id"] = f"network:{asset['id']}:{index}"
            path["tier"] = asset["tier"] if TIER_RANK.get(asset["tier"], 0) > TIER_RANK.get(path.get("tier", "informational"), 0) else path.get("tier", "informational")
            path["score"] = max(safe_float(path.get("score")), safe_float(asset.get("score")))
            network_paths.append(path)
    return network_paths


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
    for finding in findings:
        tiers[str(finding.get("tier") or "informational")] = tiers.get(str(finding.get("tier") or "informational"), 0) + 1
        exposure = str(finding.get("context", {}).get("exposure") or "unknown")
        exposures[exposure] = exposures.get(exposure, 0) + 1
    return {
        "finding_count": len(findings),
        "artifact_count": len({item for item in artifacts if item}),
        "component_count": len({item for item in components if item[1]}),
        "tiers": tiers,
        "exposures": exposures,
    }


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reachability Advisor Visual Report</title>
<style>
:root {
  --bg: #f6f8fb;
  --panel: #ffffff;
  --ink: #101828;
  --muted: #667085;
  --line: #d8dee8;
  --soft: #eef2f7;
  --urgent: #8a1f11;
  --high: #c2410c;
  --medium: #b7791f;
  --low: #2563eb;
  --info: #64748b;
  --asset: #0f766e;
  --entry: #334155;
  --path: #475569;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: var(--ink);
  background: var(--bg);
}
header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 16px 20px;
  background: #111827;
  color: white;
}
h1 {
  margin: 0;
  font-size: 18px;
  letter-spacing: 0;
  font-weight: 650;
}
.subtitle {
  margin-top: 3px;
  color: #cbd5e1;
  font-size: 12px;
}
.stats {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
}
.stat {
  padding: 7px 9px;
  background: rgba(255,255,255,.09);
  border: 1px solid rgba(255,255,255,.15);
  border-radius: 6px;
  font-size: 12px;
}
.toolbar {
  display: grid;
  grid-template-columns: minmax(250px, 1fr) 140px 150px 130px auto auto auto auto;
  gap: 8px;
  padding: 12px;
  border-bottom: 1px solid var(--line);
  background: var(--panel);
}
input, select, button {
  height: 34px;
  border: 1px solid #c8d0dc;
  background: white;
  color: var(--ink);
  border-radius: 6px;
  padding: 0 10px;
  font: inherit;
  font-size: 13px;
}
button {
  cursor: pointer;
  background: #17202a;
  color: white;
  border-color: #17202a;
  min-width: 74px;
}
button.secondary {
  background: white;
  color: var(--ink);
}
label.check {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  white-space: nowrap;
  color: var(--muted);
}
label.check input {
  width: 16px;
  height: 16px;
}
.layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 390px;
  min-height: calc(100vh - 111px);
}
.graph-shell {
  position: relative;
  min-width: 0;
  overflow: hidden;
  background:
    linear-gradient(#e9eef5 1px, transparent 1px),
    linear-gradient(90deg, #e9eef5 1px, transparent 1px);
  background-size: 32px 32px;
}
#graph {
  width: 100%;
  height: calc(100vh - 111px);
  min-height: 560px;
  position: relative;
  overflow: hidden;
  cursor: grab;
}
#graph.dragging { cursor: grabbing; }
#surface {
  position: absolute;
  left: 0;
  top: 0;
  transform-origin: 0 0;
}
#edges {
  position: absolute;
  left: 0;
  top: 0;
  overflow: visible;
  pointer-events: none;
}
#cards {
  position: absolute;
  left: 0;
  top: 0;
}
.card {
  position: absolute;
  background: white;
  border: 1px solid var(--line);
  border-left: 8px solid var(--info);
  border-radius: 8px;
  box-shadow: 0 8px 18px rgba(16, 24, 40, .10);
  overflow: hidden;
  cursor: pointer;
}
.card.selected {
  outline: 3px solid #111827;
  outline-offset: 2px;
}
.card .top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
  padding: 12px 12px 8px;
}
.asset-card .top {
  background: #f8fafc;
  border-bottom: 1px solid #e4e9f1;
}
.entry-card {
  border-left-color: var(--entry);
}
.entry-card .top {
  background: #111827;
  color: white;
}
.entry-card .sub {
  color: #cbd5e1;
}
.entry-card .body {
  padding-top: 10px;
}
.path-card {
  border-left-color: var(--path);
}
.path-card .top {
  background: #f1f5f9;
  border-bottom: 1px solid #dbe3ee;
}
.title {
  min-width: 0;
  font-weight: 700;
  font-size: 15px;
  line-height: 1.25;
}
.sub {
  margin-top: 3px;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.35;
  overflow-wrap: anywhere;
}
.body {
  padding: 0 12px 12px;
}
.row {
  display: grid;
  grid-template-columns: 84px minmax(0, 1fr);
  gap: 6px;
  margin-top: 7px;
  font-size: 12px;
  line-height: 1.35;
}
.row .label {
  color: var(--muted);
}
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}
.chip {
  display: inline-flex;
  align-items: center;
  min-height: 20px;
  border-radius: 999px;
  padding: 2px 7px;
  font-size: 11px;
  background: var(--soft);
  color: #344054;
  white-space: nowrap;
}
.chip.urgent, .chip.high { background: #fee2e2; color: #991b1b; }
.chip.medium { background: #fef3c7; color: #92400e; }
.chip.low { background: #dbeafe; color: #1e40af; }
.chip.informational { background: #e2e8f0; color: #334155; }
.chip.request-controlled-path { background: #dcfce7; color: #166534; }
.chip.reachable-vulnerable-api, .chip.import-observed, .chip.reachable-through-dependency-graph { background: #fef3c7; color: #92400e; }
.chip.sbom-only, .chip.no-source-rule, .chip.absent-from-scanned-source { background: #e2e8f0; color: #334155; }
.chip.score, .chip.count, .chip.paths { background: #eef2f7; color: #344054; }
.card.urgent { border-left-color: var(--urgent); }
.card.high { border-left-color: var(--high); }
.card.medium { border-left-color: var(--medium); }
.card.low { border-left-color: var(--low); }
.card.informational { border-left-color: var(--info); }
.vuln-card .title {
  font-size: 14px;
}
.vuln-card .body {
  padding-top: 0;
}
.path-card .body .sub,
.vuln-card .body .sub {
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.edge {
  fill: none;
  stroke: #94a3b8;
  stroke-width: 2;
  opacity: .85;
  stroke-linecap: round;
  stroke-linejoin: round;
}
.edge.network {
  stroke: #475569;
  stroke-width: 2.4;
}
.edge.vulnerability {
  opacity: .76;
}
.edge.entry {
  stroke-dasharray: 7 5;
}
.edge.urgent { stroke: var(--urgent); stroke-width: 3; }
.edge.high { stroke: var(--high); stroke-width: 2.6; }
.edge.medium { stroke: var(--medium); }
.edge.low { stroke: var(--low); }
aside {
  border-left: 1px solid var(--line);
  background: var(--panel);
  min-width: 0;
  overflow: hidden;
  display: grid;
  grid-template-rows: auto minmax(180px, 42vh) 1fr;
}
.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 12px;
  border-bottom: 1px solid var(--line);
}
.legend span {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 12px;
  color: var(--muted);
}
.swatch {
  width: 10px;
  height: 10px;
  border-radius: 2px;
}
.details, .finding-list {
  padding: 12px;
  overflow: auto;
}
.details {
  border-bottom: 1px solid var(--line);
}
.details h2, .finding-list h2 {
  margin: 0 0 10px;
  font-size: 14px;
}
.empty {
  color: var(--muted);
  font-size: 13px;
}
.kv {
  display: grid;
  grid-template-columns: 105px minmax(0, 1fr);
  gap: 5px 8px;
  font-size: 12px;
  margin: 8px 0;
}
.kv div:nth-child(odd) {
  color: var(--muted);
}
.kv div:nth-child(even) {
  overflow-wrap: anywhere;
}
.item {
  padding: 10px;
  border: 1px solid var(--line);
  border-radius: 7px;
  margin-bottom: 8px;
  background: #fbfcfe;
  cursor: pointer;
}
.item:hover {
  border-color: #9aa8bb;
}
.item-title {
  font-size: 13px;
  font-weight: 650;
  display: flex;
  justify-content: space-between;
  gap: 8px;
}
.item-meta {
  margin-top: 5px;
  font-size: 12px;
  color: var(--muted);
}
ul {
  margin: 6px 0 0 17px;
  padding: 0;
}
li {
  margin: 4px 0;
  font-size: 12px;
}
@media (max-width: 980px) {
  .toolbar { grid-template-columns: 1fr 1fr; }
  .layout { grid-template-columns: 1fr; }
  aside { border-left: 0; border-top: 1px solid var(--line); }
  #graph { height: 58vh; min-height: 430px; }
}
</style>
</head>
<body>
<header>
  <div>
    <h1>Reachability Advisor Visual Report</h1>
    <div class="subtitle" id="generated"></div>
  </div>
  <div class="stats" id="stats"></div>
</header>
<section class="toolbar">
  <input id="search" type="search" placeholder="Search asset, component, CVE, IAM, network, owner">
  <select id="tier">
    <option value="informational">All tiers</option>
    <option value="low">Low and above</option>
    <option value="medium">Medium and above</option>
    <option value="high">High and above</option>
    <option value="urgent">Urgent only</option>
  </select>
  <select id="exposure">
    <option value="">All exposures</option>
  </select>
  <select id="topLimit">
    <option value="50">Top 50</option>
    <option value="100">Top 100</option>
    <option value="">All findings</option>
  </select>
  <label class="check"><input id="highestPerAsset" type="checkbox" checked> top per asset</label>
  <label class="check"><input id="activeOnly" type="checkbox" checked> active only</label>
  <button id="fit" title="Fit graph to viewport">Fit</button>
  <button id="reset" class="secondary" title="Reset zoom and pan">Reset</button>
</section>
<main class="layout">
  <section class="graph-shell">
    <div id="graph" role="img" aria-label="Network entry, asset, and vulnerability graph">
      <div id="surface">
        <svg id="edges"></svg>
        <div id="cards"></div>
      </div>
    </div>
  </section>
  <aside>
    <div class="legend">
      <span><i class="swatch" style="background:var(--urgent)"></i>urgent</span>
      <span><i class="swatch" style="background:var(--high)"></i>high</span>
      <span><i class="swatch" style="background:var(--medium)"></i>medium</span>
      <span><i class="swatch" style="background:var(--low)"></i>low</span>
      <span><i class="swatch" style="background:var(--info)"></i>informational</span>
    </div>
    <section class="details" id="details"></section>
    <section class="finding-list">
      <h2>Visible Findings</h2>
      <div id="findingList"></div>
    </section>
  </aside>
</main>
<script id="report-data" type="application/json">__REPORT_DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById("report-data").textContent);
const tierRank = {informational: 0, low: 1, medium: 2, high: 3, urgent: 4};
const exposureRank = {unknown: 0, isolated: 1, private: 1, internal: 2, external: 3, public: 4};
const assetById = new Map((DATA.assets || []).map(asset => [asset.id, asset]));
const vulnerabilityByFindingKey = new Map((DATA.vulnerabilities || []).map(vuln => [vuln.findingKey, vuln]));
const vulnerabilitiesByAssetId = new Map();
for (const vuln of DATA.vulnerabilities || []) {
  if (!vulnerabilitiesByAssetId.has(vuln.assetId)) vulnerabilitiesByAssetId.set(vuln.assetId, []);
  vulnerabilitiesByAssetId.get(vuln.assetId).push(vuln);
}
const networkPathsByAssetId = new Map();
for (const path of DATA.networkPaths || []) {
  if (!networkPathsByAssetId.has(path.assetId)) networkPathsByAssetId.set(path.assetId, []);
  networkPathsByAssetId.get(path.assetId).push(path);
}
for (const paths of networkPathsByAssetId.values()) {
  paths.sort((a, b) => ((exposureRank[b.exposure] ?? 0) - (exposureRank[a.exposure] ?? 0)) || ((tierRank[b.tier] ?? 0) - (tierRank[a.tier] ?? 0)) || ((b.score || 0) - (a.score || 0)));
}
const entryWidth = 180;
const entryHeight = 88;
const pathWidth = 248;
const pathHeight = 140;
const assetWidth = 360;
const assetHeight = 260;
const vulnWidth = 430;
const vulnHeight = 94;
const rowGap = 54;
const vulnGap = 14;
const entryX = 42;
const pathX = 262;
const assetX = 552;
const vulnX = 970;
const graph = document.getElementById("graph");
const surface = document.getElementById("surface");
const edgesSvg = document.getElementById("edges");
const cards = document.getElementById("cards");
const details = document.getElementById("details");
const search = document.getElementById("search");
const tier = document.getElementById("tier");
const exposure = document.getElementById("exposure");
const topLimit = document.getElementById("topLimit");
const highestPerAsset = document.getElementById("highestPerAsset");
const activeOnly = document.getElementById("activeOnly");
let selected = null;
let transform = {x: 30, y: 30, scale: 1};
let drag = null;
let surfaceBounds = {width: 1000, height: 700};

function init() {
  document.getElementById("generated").textContent = `${DATA.metadata.tool} ${DATA.metadata.version} generated ${DATA.metadata.generated_at}`;
  renderStats();
  for (const item of Object.keys(DATA.stats.exposures || {}).sort()) {
    const option = document.createElement("option");
    option.value = item;
    option.textContent = item;
    exposure.appendChild(option);
  }
  for (const control of [search, tier, exposure, topLimit, highestPerAsset, activeOnly]) {
    control.addEventListener("input", render);
    control.addEventListener("change", render);
  }
  document.getElementById("fit").addEventListener("click", fitGraph);
  document.getElementById("reset").addEventListener("click", () => {
    transform = {x: 30, y: 30, scale: 1};
    applyTransform();
  });
  graph.addEventListener("wheel", onWheel, {passive: false});
  graph.addEventListener("mousedown", onMouseDown);
  window.addEventListener("mousemove", onMouseMove);
  window.addEventListener("mouseup", onMouseUp);
  render();
  window.setTimeout(fitGraph, 0);
}

function renderStats() {
  const stats = document.getElementById("stats");
  const s = DATA.stats;
  const parts = [
    `${s.finding_count} findings`,
    `${s.artifact_count} assets`,
    `${s.component_count} components`,
    `${s.tiers.urgent || 0} urgent`,
    `${s.tiers.high || 0} high`
  ];
  stats.replaceChildren(...parts.map(value => {
    const el = document.createElement("div");
    el.className = "stat";
    el.textContent = value;
    return el;
  }));
}

function findingText(finding) {
  return JSON.stringify(finding).toLowerCase();
}

function assetText(asset) {
  return JSON.stringify(asset).toLowerCase();
}

function visibleFindings() {
  const query = search.value.trim().toLowerCase();
  const minTier = tierRank[tier.value] ?? 0;
  const exposureFilter = exposure.value;
  const limit = topLimit.value ? Number(topLimit.value) : 0;
  let rows = DATA.findings
    .filter(f => (tierRank[f.tier] ?? 0) >= minTier)
    .filter(f => !activeOnly.checked || f.policy_status !== "excepted")
    .filter(f => !exposureFilter || ((f.context || {}).exposure || "unknown") === exposureFilter)
    .filter(f => !query || findingText(f).includes(query) || assetText(assetForFinding(f)).includes(query))
    .sort((a, b) => (tierRank[b.tier] - tierRank[a.tier]) || (b.score - a.score));
  if (highestPerAsset.checked) {
    const seenAssets = new Set();
    rows = rows.filter(finding => {
      const assetName = (finding.artifact || {}).name || "unknown";
      if (seenAssets.has(assetName)) return false;
      seenAssets.add(assetName);
      return true;
    });
  }
  return limit ? rows.slice(0, limit) : rows;
}

function assetForFinding(finding) {
  const assetId = `asset:${finding.artifact.name}`;
  return assetById.get(assetId) || {};
}

function render() {
  const findings = visibleFindings();
  const visibleKeys = new Set(findings.map(finding => finding.key));
  const visibleVulns = findings.map(finding => vulnerabilityByFindingKey.get(finding.key)).filter(Boolean);
  const visibleAssetIds = new Set(visibleVulns.map(vuln => vuln.assetId));
  const visibleAssets = DATA.assets.filter(asset => visibleAssetIds.has(asset.id));
  const visibleNetworkPaths = visibleAssets.map(asset => primaryNetworkPath(asset)).filter(Boolean);
  const visibleNetworkIds = new Set(visibleNetworkPaths.flatMap(path => [path.id, `${path.id}:entry`]));
  const layout = layoutCards(visibleAssets, visibleVulns);

  edgesSvg.replaceChildren(...renderEdges(visibleAssets, visibleVulns, visibleNetworkPaths, layout));
  cards.replaceChildren(
    ...visibleNetworkPaths.map(path => renderEntryCard(path, layout.entries.get(path.id))),
    ...visibleNetworkPaths.map(path => renderNetworkPathCard(path, layout.networkPaths.get(path.id))),
    ...visibleAssets.map(asset => renderAssetCard(asset, layout.assets.get(asset.id))),
    ...visibleVulns.map(vuln => renderVulnerabilityCard(vuln, layout.vulnerabilities.get(vuln.id)))
  );
  edgesSvg.setAttribute("width", surfaceBounds.width);
  edgesSvg.setAttribute("height", surfaceBounds.height);
  surface.style.width = `${surfaceBounds.width}px`;
  surface.style.height = `${surfaceBounds.height}px`;

  renderFindingList(findings);
  if (selected && !visibleAssetIds.has(selected.id) && !visibleKeys.has(selected.findingKey) && !visibleNetworkIds.has(selected.id) && !visibleAssetIds.has(selected.assetId)) {
    selected = null;
  }
  renderDetails(selected);
  applyTransform();
}

function layoutCards(assets, vulnerabilities) {
  const entryPositions = new Map();
  const networkPathPositions = new Map();
  const assetPositions = new Map();
  const vulnerabilityPositions = new Map();
  const visibleVulnerabilitiesByAssetId = new Map();
  for (const vuln of vulnerabilities) {
    if (!visibleVulnerabilitiesByAssetId.has(vuln.assetId)) visibleVulnerabilitiesByAssetId.set(vuln.assetId, []);
    visibleVulnerabilitiesByAssetId.get(vuln.assetId).push(vuln);
  }
  let y = 42;
  let maxVulnCount = 0;
  for (const asset of assets) {
    const networkPath = primaryNetworkPath(asset);
    const assetVulns = (visibleVulnerabilitiesByAssetId.get(asset.id) || [])
      .sort((a, b) => (tierRank[b.tier] - tierRank[a.tier]) || (b.score - a.score) || a.label.localeCompare(b.label));
    maxVulnCount = Math.max(maxVulnCount, assetVulns.length);
    const rowHeight = Math.max(assetHeight, pathHeight, assetVulns.length * (vulnHeight + vulnGap) - vulnGap);
    if (networkPath) {
      entryPositions.set(networkPath.id, {x: entryX, y: y + Math.max(0, (rowHeight - entryHeight) / 2), width: entryWidth, height: entryHeight});
      networkPathPositions.set(networkPath.id, {x: pathX, y: y + Math.max(0, (rowHeight - pathHeight) / 2), width: pathWidth, height: pathHeight});
    }
    const assetY = y + Math.max(0, (rowHeight - assetHeight) / 2);
    assetPositions.set(asset.id, {x: assetX, y: assetY, width: assetWidth, height: assetHeight});
    assetVulns.forEach((vuln, index) => {
      vulnerabilityPositions.set(vuln.id, {x: vulnX, y: y + index * (vulnHeight + vulnGap), width: vulnWidth, height: vulnHeight});
    });
    y += rowHeight + rowGap;
  }
  surfaceBounds = {
    width: Math.max(980, vulnX + vulnWidth + 80),
    height: Math.max(620, y + 40),
    maxVulnCount,
  };
  return {entries: entryPositions, networkPaths: networkPathPositions, assets: assetPositions, vulnerabilities: vulnerabilityPositions};
}

function renderEdges(assets, vulnerabilities, networkPaths, layout) {
  const paths = [];
  for (const pathNode of networkPaths) {
    const entry = layout.entries.get(pathNode.id);
    const path = layout.networkPaths.get(pathNode.id);
    const asset = layout.assets.get(pathNode.assetId);
    if (!entry || !path || !asset) continue;
    paths.push(edgePath(entry.x + entry.width, entry.y + entry.height / 2, path.x, path.y + path.height / 2, `edge network entry ${pathNode.exposure}`, `${pathNode.id}:entry`, pathNode.id));
    paths.push(edgePath(path.x + path.width, path.y + path.height / 2, asset.x, asset.y + asset.height / 2, `edge network ${pathNode.tier}`, pathNode.id, pathNode.assetId));
  }
  for (const vuln of vulnerabilities) {
    const asset = layout.assets.get(vuln.assetId);
    const target = layout.vulnerabilities.get(vuln.id);
    if (!asset || !target) continue;
    const x1 = asset.x + asset.width;
    const y1 = asset.y + asset.height / 2;
    const x2 = target.x;
    const y2 = target.y + target.height / 2;
    const busX = x1 + 44;
    paths.push(fanEdgePath(x1, y1, busX, x2, y2, `edge vulnerability ${vuln.tier}`, vuln.assetId, vuln.id));
  }
  return paths;
}

function edgePath(x1, y1, x2, y2, className, sourceId, targetId) {
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("class", className);
  path.dataset.edgeSource = sourceId;
  path.dataset.edgeTarget = targetId;
  path.setAttribute("d", `M ${x1} ${y1} C ${x1 + 42} ${y1}, ${x2 - 42} ${y2}, ${x2} ${y2}`);
  return path;
}

function fanEdgePath(x1, y1, busX, x2, y2, className, sourceId, targetId) {
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("class", className);
  path.dataset.edgeSource = sourceId;
  path.dataset.edgeTarget = targetId;
  path.setAttribute("d", `M ${x1} ${y1} L ${busX} ${y1} L ${busX} ${y2} L ${x2} ${y2}`);
  return path;
}

function primaryNetworkPath(asset) {
  const paths = networkPathsForAsset(asset.id);
  return paths.length ? paths[0] : null;
}

function networkPathsForAsset(assetId) {
  return networkPathsByAssetId.get(assetId) || [];
}

function renderEntryCard(path, position) {
  const datum = {...path, id: `${path.id}:entry`, networkKind: "entry"};
  const card = createCard("entry-card", path.exposure || "unknown", position, datum);
  card.append(
    cardTop(path.entryLabel || "Unknown entry", [exposureChip(path.exposure || "unknown")], path.entrySubtitle || ""),
    smallBody(path.exposure === "public" ? "Attacker-controlled traffic can start here." : path.entrySubtitle || "Network entry state is inferred from context evidence.")
  );
  return card;
}

function renderNetworkPathCard(path, position) {
  const pathsForAsset = networkPathsForAsset(path.assetId);
  const datum = {...path, networkKind: "path"};
  const card = createCard("path-card", path.tier || "informational", position, datum);
  card.append(
    cardTop("Ingress path", [exposureChip(path.exposure || "unknown"), tag(path.pathType || "unresolved", "count"), pathCountChip(pathsForAsset.length)], path.label || "unknown path"),
    smallBody(path.summary || "No linked path evidence.")
  );
  return card;
}

function renderAssetCard(asset, position) {
  const card = createCard("asset-card", asset.tier, position, asset);
  card.append(
    cardTop(asset.name, [priorityChip(asset.tier), scoreChip(asset.score, "max"), countChip(asset.findingKeys.length, "findings")], asset.owner || "unknown owner"),
    assetBody(asset)
  );
  return card;
}

function smallBody(value) {
  const body = document.createElement("div");
  body.className = "body";
  const summary = document.createElement("div");
  summary.className = "sub";
  summary.textContent = value;
  body.append(summary);
  return body;
}

function assetBody(asset) {
  const body = document.createElement("div");
  body.className = "body";
  const paths = networkPathsForAsset(asset.id);
  body.append(
    contextRow("Network", asset.exposures),
    contextRow("Ingress", paths.map(path => path.label).slice(0, 3)),
    contextRow("IAM", [...asset.privileges, ...asset.iamImpacts]),
    contextRow("Criticality", asset.criticalities),
    contextRow("Code", asset.codeExposures),
    contextRow("Source", asset.sourceStates),
    contextRow("Environment", asset.environments)
  );
  if (asset.evidence && asset.evidence.length) {
    body.append(contextRow("Evidence", asset.evidence.slice(0, 2)));
  }
  return body;
}

function renderVulnerabilityCard(vuln, position) {
  const card = createCard("vuln-card", vuln.tier, position, vuln);
  const subtitle = `${vuln.component}@${vuln.componentVersion} | code ${vuln.codeExposure} | network ${vuln.exposure} | IAM ${vuln.privilege}`;
  card.append(
    cardTop(vuln.label, [priorityChip(vuln.tier), scoreChip(vuln.score), vuln.knownExploited ? tag("known exploited", "urgent") : null], subtitle),
    vulnBody(vuln)
  );
  return card;
}

function vulnBody(vuln) {
  const body = document.createElement("div");
  body.className = "body";
  const summary = document.createElement("div");
  summary.className = "sub";
  summary.textContent = vuln.summary || first(vuln.rationale) || "No summary available.";
  body.append(summary);
  return body;
}

function createCard(kind, tierValue, position, datum) {
  position = position || {x: 0, y: 0, width: 220, height: 90};
  const card = document.createElement("div");
  card.className = `card ${kind} ${tierValue}${selected && selected.id === datum.id ? " selected" : ""}`;
  card.dataset.role = kind;
  card.dataset.nodeId = datum.id;
  card.style.left = `${position.x}px`;
  card.style.top = `${position.y}px`;
  card.style.width = `${position.width}px`;
  card.style.height = `${position.height}px`;
  card.addEventListener("mousedown", event => event.stopPropagation());
  card.addEventListener("click", event => {
    event.stopPropagation();
    selected = datum;
    render();
  });
  return card;
}

function cardTop(titleText, chipsValue, subtitle) {
  const top = document.createElement("div");
  top.className = "top";
  const titleWrap = document.createElement("div");
  titleWrap.className = "title";
  titleWrap.textContent = titleText;
  if (subtitle) {
    const sub = document.createElement("div");
    sub.className = "sub";
    sub.textContent = subtitle;
    titleWrap.append(sub);
  }
  top.append(titleWrap, chips(chipsValue));
  return top;
}

function contextRow(label, values) {
  const row = document.createElement("div");
  row.className = "row";
  const labelEl = document.createElement("div");
  labelEl.className = "label";
  labelEl.textContent = label;
  row.append(labelEl, chips(values && values.length ? values : ["unknown"]));
  return row;
}

function chips(values) {
  const wrap = document.createElement("div");
  wrap.className = "chips";
  for (const value of (values || []).filter(Boolean).slice(0, 8)) {
    const data = chipValue(value);
    if (!data.text) continue;
    const chip = document.createElement("span");
    chip.className = `chip ${data.className}`;
    chip.textContent = data.text;
    wrap.appendChild(chip);
  }
  return wrap;
}

function chipValue(value) {
  if (value && typeof value === "object") {
    const text = String(value.text || "");
    return {text, className: chipClass(value.className || text)};
  }
  const text = String(value || "");
  return {text, className: chipClass(text)};
}

function tag(text, className) {
  return {text, className};
}

function priorityChip(value) {
  return tag(`priority ${value || "unknown"}`, value || "unknown");
}

function scoreChip(value, suffix = "score") {
  return tag(`${Number(value || 0).toFixed(1)} ${suffix}`, "score");
}

function countChip(value, label) {
  return tag(`${value} ${label}`, "count");
}

function pathCountChip(value) {
  return tag(`${value} path${value === 1 ? "" : "s"}`, "paths");
}

function exposureChip(value) {
  return tag(`network ${value || "unknown"}`, value || "unknown");
}

function chipClass(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "unknown";
}

function renderFindingList(findings) {
  const list = document.getElementById("findingList");
  if (!findings.length) {
    list.innerHTML = '<div class="empty">No findings match the current filters.</div>';
    return;
  }
  list.replaceChildren(...findings.map(finding => {
    const item = document.createElement("div");
    item.className = "item";
    item.addEventListener("click", () => {
      selected = vulnerabilityByFindingKey.get(finding.key);
      render();
    });
    const title = document.createElement("div");
    title.className = "item-title";
    title.append(text(`${finding.vulnerability.id} in ${finding.component.name}`));
    const chip = document.createElement("span");
    chip.className = `chip ${finding.tier}`;
    chip.textContent = `priority ${finding.tier} ${Number(finding.score).toFixed(1)}`;
    title.append(chip);
    const meta = document.createElement("div");
    meta.className = "item-meta";
    meta.textContent = `${finding.artifact.name} | code ${codeExposureFromState(finding.source_reachability || {})} | source ${(finding.source_reachability || {}).state} | exposure ${(finding.context || {}).exposure || "unknown"} | privilege ${(finding.context || {}).privilege || "unknown"}`;
    item.append(title, meta);
    return item;
  }));
}

function renderDetails(datum) {
  if (!datum) {
    details.innerHTML = '<h2>Details</h2><div class="empty">Select an asset or vulnerability. Use mouse wheel to zoom and drag the graph background to pan.</div>';
    return;
  }
  const section = document.createElement("section");
  if (datum.networkKind) {
    const asset = assetById.get(datum.assetId) || {};
    section.append(heading(datum.networkKind === "entry" ? datum.entryLabel : `${datum.label} -> ${asset.name || "asset"}`));
    section.append(chips([exposureChip(datum.exposure), scoreChip(datum.score || 0, "max")]));
    section.append(kv({
      asset: asset.name,
      entry: datum.entryLabel,
      "network exposure": datum.exposure,
      "path type": datum.pathType,
      confidence: datum.confidence,
      provider: datum.provider,
      path: datum.summary,
      owner: datum.owner || asset.owner,
    }));
    appendList(section, "Path steps", datum.steps || []);
    appendList(section, "Blockers and constraints", (datum.blockers || []).map(blocker => `${blocker.kind}: ${blocker.evidence}`));
    appendList(section, "Network evidence", networkPathsForAsset(datum.assetId).map(path => path.evidence || path.summary).filter(Boolean));
  } else if (datum.findingKey) {
    section.append(heading(`${datum.label} in ${datum.component}`));
    section.append(chips([priorityChip(datum.tier), scoreChip(datum.score)]));
    section.append(kv({
      component: `${datum.component}@${datum.componentVersion}`,
      "code exposure": datum.codeExposure,
      "code detail": datum.codeExposureDetail,
      "source state": datum.reachability,
      "network exposure": datum.exposure,
      "IAM privilege": datum.privilege,
      "asset criticality": datum.criticality,
      "IAM impact": datum.iamImpacts,
      policy: datum.policyStatus,
    }));
    appendList(section, "Rationale", datum.rationale || []);
    appendList(section, "Effective exposure path", effectivePathLabels(datum.effectivePath));
    appendList(section, "Fix commands", datum.fixCommands || []);
    appendList(section, "Effective access", (datum.effectiveAccess || []).map(access => `${access.identity || "identity"} ${access.action || "action"} ${access.decision || "allowed"} (${access.confidence || "unknown"})`));
    appendList(section, "Context evidence", datum.contextEvidence || []);
    appendList(section, "Source evidence", datum.sourceReason ? [datum.sourceReason] : []);
    appendList(section, "Source locations", (datum.sourceLocations || []).map(location => `${location.path}:${location.line}`));
  } else {
    section.append(heading(`Asset: ${datum.name}`));
    section.append(chips([priorityChip(datum.tier), scoreChip(datum.score, "max"), countChip(datum.findingKeys.length, "findings")]));
    section.append(kv({
      owner: datum.owner,
      reference: datum.reference,
      network: datum.exposures,
      IAM: [...datum.privileges, ...datum.iamImpacts],
      "effective access": (datum.effectiveAccess || []).map(access => access.action || access.impact || "access").slice(0, 5),
      criticality: datum.criticalities,
      "code exposure": datum.codeExposures,
      source: datum.sourceStates,
      environment: datum.environments,
    }));
    appendList(section, "Network paths", networkPathsForAsset(datum.id).map(path => path.evidence || path.summary).filter(Boolean));
    appendList(section, "Evidence", datum.evidence || []);
    appendList(section, "Linked vulnerabilities", (vulnerabilitiesByAssetId.get(datum.id) || []).map(vuln => `${vuln.tier} ${Number(vuln.score).toFixed(1)} ${vuln.label} in ${vuln.component}`));
  }
  details.replaceChildren(section);
}

function codeExposureFromState(source) {
  const state = typeof source === "object" ? source.state : source;
  if (source && typeof source === "object" && source.label) return source.label;
  if (state === "attacker_controlled") return "request-controlled path";
  if (state === "function_reachable") return "reachable vulnerable API";
  if (state === "dependency_reachable") return "dependency evidence";
  if (state === "imported") return "import observed";
  if (state === "unknown_due_to_no_rule") return "no source rule";
  if (state === "package_present") return "SBOM only";
  if (state === "absent") return "absent from scanned source";
  return "unknown source reachability";
}

function effectivePathLabels(path) {
  if (!path || !Array.isArray(path.order)) return [];
  const nodeIds = Array.isArray(path.node_ids) ? path.node_ids : [];
  return path.order.map((step, index) => `${index + 1}. ${step}: ${nodeIds[index] || "unknown"}`);
}

function heading(value) {
  const h = document.createElement("h2");
  h.textContent = value;
  return h;
}

function kv(data) {
  const wrap = document.createElement("div");
  wrap.className = "kv";
  for (const [key, value] of Object.entries(data || {})) {
    if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) continue;
    const k = document.createElement("div");
    k.textContent = key;
    const v = document.createElement("div");
    v.textContent = Array.isArray(value) ? value.join(", ") : String(value);
    wrap.append(k, v);
  }
  return wrap;
}

function appendList(parent, title, values) {
  if (!values || !values.length) return;
  const h = document.createElement("h2");
  h.textContent = title;
  const list = document.createElement("ul");
  for (const value of values.slice(0, 20)) {
    const item = document.createElement("li");
    item.textContent = value;
    list.appendChild(item);
  }
  parent.append(h, list);
}

function text(value) {
  return document.createTextNode(value);
}

function first(values) {
  return values && values.length ? values[0] : "";
}

function applyTransform() {
  surface.style.transform = `translate(${transform.x}px, ${transform.y}px) scale(${transform.scale})`;
}

function fitGraph() {
  const width = graph.clientWidth || 900;
  const height = graph.clientHeight || 600;
  const scale = Math.min(1.25, Math.max(0.18, Math.min((width - 70) / surfaceBounds.width, (height - 70) / surfaceBounds.height)));
  transform = {scale, x: 35, y: 35};
  applyTransform();
}

function onWheel(event) {
  event.preventDefault();
  const factor = event.deltaY > 0 ? 0.9 : 1.1;
  const nextScale = Math.min(3.5, Math.max(0.15, transform.scale * factor));
  const rect = graph.getBoundingClientRect();
  const px = event.clientX - rect.left;
  const py = event.clientY - rect.top;
  const graphX = (px - transform.x) / transform.scale;
  const graphY = (py - transform.y) / transform.scale;
  transform.x = px - graphX * nextScale;
  transform.y = py - graphY * nextScale;
  transform.scale = nextScale;
  applyTransform();
}

function onMouseDown(event) {
  if (event.button !== 0) return;
  drag = {x: event.clientX, y: event.clientY, tx: transform.x, ty: transform.y};
  graph.classList.add("dragging");
}

function onMouseMove(event) {
  if (!drag) return;
  transform.x = drag.tx + event.clientX - drag.x;
  transform.y = drag.ty + event.clientY - drag.y;
  applyTransform();
}

function onMouseUp() {
  drag = null;
  graph.classList.remove("dragging");
}

init();
</script>
</body>
</html>
"""
