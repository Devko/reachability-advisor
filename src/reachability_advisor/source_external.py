"""External source reachability evidence adapters."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import (
    Component,
    Confidence,
    Reachability,
    SourceEvidence,
    SourceLocation,
    VulnerabilityRecord,
)

VULNERABILITY_ID_RE = re.compile(r"^(CVE-\d{4}-\d+|GHSA-[a-z0-9-]+|GO-\d{4}-\d+|OSV-\d+|PYSEC-\d{4}-\d+)", re.IGNORECASE)

REACHABILITY_STRENGTH = {
    Reachability.ABSENT: 0,
    Reachability.UNKNOWN_DUE_TO_NO_RULE: 1,
    Reachability.PACKAGE_PRESENT: 2,
    Reachability.DEPENDENCY_REACHABLE: 3,
    Reachability.IMPORTED: 4,
    Reachability.FUNCTION_REACHABLE: 5,
    Reachability.ATTACKER_CONTROLLED: 6,
}
PROVIDER_TRUST = {
    "codeql": 5,
    "semgrep": 4,
    "govulncheck": 4,
    "reachability-advisor": 3,
    "builtin": 1,
}


class ExternalSourceEvidenceError(ValueError):
    """Raised when external source evidence cannot be parsed."""


@dataclass(frozen=True)
class ExternalSourceEvidenceRecord:
    evidence: SourceEvidence
    artifact: str | None = None
    component: str | None = None
    vulnerability: str | None = None
    package_purl: str | None = None
    provider: str = ""

    @property
    def has_matching_selector(self) -> bool:
        return bool(self.component or self.vulnerability or self.package_purl)


@dataclass
class ExternalSourceEvidenceStore:
    records: list[ExternalSourceEvidenceRecord] = field(default_factory=list)

    def best_for(self, artifact: str, component: Component, vulnerability: VulnerabilityRecord) -> SourceEvidence | None:
        candidates: list[ExternalSourceEvidenceRecord] = []
        component_names = {component.name.lower(), component.display_name.lower()}
        if component.purl:
            component_names.add(component.purl.lower())
        vuln_ids = {vulnerability.id.lower(), *(alias.lower() for alias in vulnerability.aliases)}
        for record in self.records:
            if record.artifact and record.artifact != artifact:
                continue
            if record.vulnerability and record.vulnerability.lower() not in vuln_ids:
                continue
            if record.package_purl:
                if not component.purl:
                    continue
                if record.package_purl.lower() != component.purl.lower():
                    continue
            if record.component and record.component.lower() not in component_names:
                continue
            if not record.component and not record.package_purl and not record.vulnerability:
                # Artifact names only narrow the service. They do not prove
                # which SBOM dependency the external analyzer result applies to.
                continue
            candidates.append(record)
        if not candidates:
            return None
        return max(candidates, key=_record_rank).evidence

    def provider_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self.records:
            provider = _provider_name(record)
            counts[provider] = counts.get(provider, 0) + 1
        return dict(sorted(counts.items()))

    def selector_diagnostics(self) -> dict[str, int]:
        diagnostics = {"records": len(self.records), "matchable_records": 0, "artifact_only_records": 0, "unscoped_records": 0}
        for record in self.records:
            if record.has_matching_selector:
                diagnostics["matchable_records"] += 1
            elif record.artifact:
                diagnostics["artifact_only_records"] += 1
            else:
                diagnostics["unscoped_records"] += 1
        return diagnostics


def merge_source_evidence(base: SourceEvidence, external: SourceEvidence | None) -> SourceEvidence:
    if external is None:
        return base
    base_key = (REACHABILITY_STRENGTH[base.reachability], _confidence_strength(base.confidence))
    external_key = (REACHABILITY_STRENGTH[external.reachability], _confidence_strength(external.confidence))
    if external_key < base_key:
        return base
    locations = [*external.locations, *base.locations][:8]
    symbols = list(dict.fromkeys([*external.matched_symbols, *base.matched_symbols]))
    dependency_path = external.dependency_path or base.dependency_path
    reason = external.reason
    diagnostics = [
        *external.diagnostics,
        {
            "code": "external_source_selected",
            "severity": "info",
            "message": "External source evidence was selected over or equal to the built-in source analyzer result.",
            "detail": {"provider": external.evidence_source, "built_in_state": base.reachability.value, "external_state": external.reachability.value},
        },
        *base.diagnostics,
    ]
    if base.reason and base.reachability != external.reachability:
        reason = f"{external.reason}; built-in analyzer reported {base.reachability.value}: {base.reason}"
    return SourceEvidence(
        reachability=external.reachability,
        confidence=external.confidence,
        language=external.language if external.language != "unknown" else base.language,
        reason=reason,
        locations=locations,
        matched_symbols=symbols,
        dependency_path=dependency_path,
        evidence_source=external.evidence_source,
        diagnostics=diagnostics,
    )


def load_external_source_evidence(paths: Iterable[str | Path]) -> ExternalSourceEvidenceStore:
    store = ExternalSourceEvidenceStore()
    for path in paths:
        evidence_path = Path(path)
        text = evidence_path.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
            store.records.extend(_external_records_from_data(data, evidence_path))
        except json.JSONDecodeError as document_error:
            parsed_line = False
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    line_data = json.loads(line)
                except json.JSONDecodeError as line_error:
                    raise ExternalSourceEvidenceError(f"{evidence_path}: invalid JSON evidence on line {line_number}: {line_error}") from line_error
                parsed_line = True
                store.records.extend(_external_records_from_data(line_data, evidence_path))
            if not parsed_line:
                raise ExternalSourceEvidenceError(f"{evidence_path}: invalid JSON evidence: {document_error}") from document_error
    return store


def _external_records_from_data(data: Any, path: Path) -> list[ExternalSourceEvidenceRecord]:
    if isinstance(data, dict) and isinstance(data.get("evidence"), list):
        return [_record_from_plain(item, path) for item in data["evidence"] if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [_record_from_finding(item, path) for item in data["findings"] if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        if data.get("version") == "2.1.0" or data.get("$schema"):
            return _records_from_sarif(data, path)
        return [_record_from_semgrep(item, path) for item in data["results"] if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("runs"), list):
        return _records_from_sarif(data, path)
    if isinstance(data, list):
        return [_record_from_plain(item, path) for item in data if isinstance(item, dict)]
    if isinstance(data, dict) and ("finding" in data or "osv" in data):
        record = _record_from_govulncheck(data, path)
        return [record] if record else []
    return []


def _confidence_strength(confidence: Confidence) -> int:
    return {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}[confidence]


def _record_rank(record: ExternalSourceEvidenceRecord) -> tuple[int, int, int, int]:
    evidence = record.evidence
    return (
        REACHABILITY_STRENGTH[evidence.reachability],
        _confidence_strength(evidence.confidence),
        _selector_strength(record),
        _provider_trust(record),
    )


def _selector_strength(record: ExternalSourceEvidenceRecord) -> int:
    strength = 0
    if record.component:
        strength = max(strength, 2)
    if record.package_purl:
        strength = max(strength, 3)
    if record.vulnerability:
        strength = max(strength, 3)
    if record.artifact:
        strength += 1
    return strength


def _provider_trust(record: ExternalSourceEvidenceRecord) -> int:
    provider = _provider_name(record)
    return PROVIDER_TRUST.get(provider.lower(), 2)


def _provider_name(record: ExternalSourceEvidenceRecord) -> str:
    return str(record.provider or record.evidence.evidence_source or "unknown")


def _state(value: Any, default: Reachability = Reachability.FUNCTION_REACHABLE) -> Reachability:
    try:
        return Reachability(str(value or default.value))
    except ValueError:
        return default


def _confidence(value: Any, default: Confidence = Confidence.MEDIUM) -> Confidence:
    try:
        return Confidence(str(value or default.value))
    except ValueError:
        return default


def _locations(items: Any) -> list[SourceLocation]:
    locations: list[SourceLocation] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        raw_path = item.get("path") or item.get("uri") or item.get("file")
        if not raw_path:
            continue
        locations.append(
            SourceLocation(
                path=Path(str(raw_path)),
                line=int(item.get("line") or item.get("startLine") or 1),
                column=int(item.get("column") or item.get("startColumn") or 1),
                snippet=str(item.get("snippet") or ""),
            )
        )
    return locations


def _first_selector(sources: Iterable[Mapping[str, Any]], *keys: str) -> Any:
    for source in sources:
        for key in keys:
            value = source.get(key)
            if value not in (None, ""):
                return value
    return None


def _vulnerability_selector(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value)
    return text if VULNERABILITY_ID_RE.match(text) else None


def _language_from_locations(locations: list[dict[str, Any]]) -> str:
    for location in locations:
        raw_path = location.get("path") or location.get("uri") or location.get("file")
        if raw_path:
            language = _language_for(Path(str(raw_path)))
            if language != "unknown":
                return language
    return "unknown"


def _language_for(path: Path) -> str:
    if path.suffix == ".java":
        return "java"
    if path.suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return "javascript"
    if path.suffix == ".py":
        return "python"
    if path.suffix == ".go":
        return "go"
    return "unknown"


def _dedupe_location_dicts(locations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, int, int]] = set()
    deduped: list[dict[str, Any]] = []
    for location in locations:
        raw_path = location.get("path") or location.get("uri") or location.get("file")
        if not raw_path:
            continue
        key = (str(raw_path), int(location.get("line") or location.get("startLine") or 1), int(location.get("column") or location.get("startColumn") or 1))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(location)
    return deduped


def _record_from_plain(item: dict[str, Any], path: Path) -> ExternalSourceEvidenceRecord:
    source = str(item.get("tool") or item.get("source") or path.name)
    artifact = str(item.get("artifact")) if item.get("artifact") else None
    component = str(item.get("component") or item.get("package")) if item.get("component") or item.get("package") else None
    vulnerability = str(item.get("vulnerability") or item.get("vulnerability_id")) if item.get("vulnerability") or item.get("vulnerability_id") else None
    package_purl = str(item.get("purl") or item.get("package_purl")) if item.get("purl") or item.get("package_purl") else None
    diagnostics = [dict(diagnostic) for diagnostic in item.get("diagnostics", []) if isinstance(diagnostic, dict)] if isinstance(item.get("diagnostics"), list) else []
    diagnostics.extend(_selector_diagnostics(artifact=artifact, component=component, vulnerability=vulnerability, package_purl=package_purl, source=source))
    evidence = SourceEvidence(
        reachability=_state(item.get("state") or item.get("reachability")),
        confidence=_confidence(item.get("confidence")),
        language=str(item.get("language") or "unknown"),
        reason=str(item.get("reason") or f"external source evidence from {source}"),
        locations=_locations(item.get("locations")),
        matched_symbols=[str(symbol) for symbol in item.get("matched_symbols", []) or []],
        dependency_path=[str(part) for part in item.get("dependency_path", []) or []],
        evidence_source=source,
        diagnostics=diagnostics,
    )
    return ExternalSourceEvidenceRecord(
        evidence=evidence,
        artifact=artifact,
        component=component,
        vulnerability=vulnerability,
        package_purl=package_purl,
        provider=source,
    )


def _selector_diagnostics(*, artifact: str | None, component: str | None, vulnerability: str | None, package_purl: str | None, source: str) -> list[dict[str, Any]]:
    if component or vulnerability or package_purl:
        return []
    code = "external_selector_artifact_only" if artifact else "external_selector_missing"
    message = (
        "External source evidence only names an artifact; artifact narrows matches but cannot select a dependency vulnerability."
        if artifact
        else "External source evidence has no component, package URL, or vulnerability selector and cannot upgrade a finding."
    )
    return [{"code": code, "severity": "warning", "message": message, "detail": {"provider": source, "artifact": artifact}}]


def _record_from_finding(item: dict[str, Any], path: Path) -> ExternalSourceEvidenceRecord:
    source = _as_object(item.get("source_reachability"))
    artifact = _as_object(item.get("artifact"))
    component = _as_object(item.get("component"))
    vulnerability = _as_object(item.get("vulnerability"))
    plain = {
        "artifact": artifact.get("name"),
        "component": component.get("name"),
        "purl": component.get("purl"),
        "vulnerability": vulnerability.get("id"),
        "state": source.get("state"),
        "confidence": source.get("confidence"),
        "language": source.get("language"),
        "reason": source.get("reason"),
        "locations": source.get("locations"),
        "matched_symbols": source.get("matched_symbols"),
        "dependency_path": source.get("dependency_path"),
        "diagnostics": source.get("diagnostics"),
        "tool": source.get("evidence_source") or "reachability-advisor",
    }
    return _record_from_plain(plain, path)


def _semgrep_reason(extra: Mapping[str, Any], has_taint_trace: bool, check_id: Any) -> str:
    message = str(extra.get("message") or f"Semgrep rule {check_id}")
    return f"Semgrep dataflow trace: {message}" if has_taint_trace else message


def _semgrep_rule_package(check_id: str) -> str | None:
    parts = check_id.split(".")
    if len(parts) >= 3 and parts[0] == "reachability":
        return parts[2]
    return None


def _semgrep_has_taint_trace(trace: Any) -> bool:
    trace_object = _as_object(trace)
    return bool(trace_object.get("taint_source") and trace_object.get("taint_sink"))


def _semgrep_trace_locations(trace: Any) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []

    def visit(value: Any, label: str = "") -> None:
        if isinstance(value, dict):
            location = _as_object(value.get("location"))
            if location:
                parsed = _semgrep_location(location, str(value.get("content") or value.get("message") or label))
                if parsed:
                    locations.append(parsed)
            elif value.get("path") and value.get("start"):
                parsed = _semgrep_location(value, str(value.get("content") or value.get("message") or label))
                if parsed:
                    locations.append(parsed)
            for key, child in value.items():
                visit(child, str(key))
        elif isinstance(value, list):
            for child in value:
                visit(child, label)

    visit(trace)
    return _dedupe_location_dicts(locations)


def _semgrep_location(location: Mapping[str, Any], snippet: str = "") -> dict[str, Any] | None:
    raw_path = location.get("path") or location.get("file")
    start = _as_object(location.get("start"))
    if not raw_path:
        return None
    return {
        "path": raw_path,
        "line": start.get("line") or location.get("line") or 1,
        "column": start.get("col") or start.get("column") or location.get("col") or location.get("column") or 1,
        "snippet": snippet,
    }


def _semgrep_matched_symbols(item: Mapping[str, Any], extra: Mapping[str, Any]) -> list[str]:
    symbols = [str(item.get("check_id") or "semgrep")]
    metavars = _as_object(extra.get("metavars"))
    for name, value in sorted(metavars.items()):
        value_object = _as_object(value)
        content = value_object.get("abstract_content") or value_object.get("unique_id") or value_object.get("name")
        if content:
            symbols.append(f"{name}:{content}")
    return list(dict.fromkeys(symbols))


def _record_from_semgrep(item: dict[str, Any], path: Path) -> ExternalSourceEvidenceRecord:
    extra = _as_object(item.get("extra"))
    metadata = _as_object(extra.get("metadata"))
    ra = _as_object(metadata.get("reachability_advisor"))
    start = _as_object(item.get("start"))
    trace_locations = _semgrep_trace_locations(extra.get("dataflow_trace"))
    primary_location = {"path": item.get("path"), "line": start.get("line", 1), "column": start.get("col", 1)}
    locations = _dedupe_location_dicts([*trace_locations, primary_location])
    has_taint_trace = _semgrep_has_taint_trace(extra.get("dataflow_trace"))
    rule_package = _semgrep_rule_package(str(item.get("check_id") or ""))
    metadata_sources: tuple[Mapping[str, Any], ...] = (ra, metadata)
    state = _first_selector(metadata_sources, "state", "reachability", "source_state")
    confidence = _first_selector(metadata_sources, "confidence")
    plain = {
        "artifact": _first_selector(metadata_sources, "artifact", "artifact_name", "service"),
        "component": _first_selector(metadata_sources, "component", "package", "package_name", "dependency", "module") or rule_package,
        "purl": _first_selector(metadata_sources, "purl", "package_purl", "package-url"),
        "vulnerability": _first_selector(metadata_sources, "vulnerability", "vulnerability_id", "cve", "cve_id", "osv", "osv_id", "ghsa"),
        "state": state or (Reachability.ATTACKER_CONTROLLED.value if has_taint_trace else Reachability.FUNCTION_REACHABLE.value),
        "confidence": confidence or (Confidence.HIGH.value if has_taint_trace else Confidence.MEDIUM.value),
        "language": _first_selector(metadata_sources, "language") or _language_from_locations(locations) or _language_for(Path(str(item.get("path") or ""))),
        "reason": _semgrep_reason(extra, has_taint_trace, item.get("check_id")),
        "locations": locations,
        "matched_symbols": _semgrep_matched_symbols(item, extra),
        "tool": "semgrep",
        "diagnostics": [
            {
                "code": "semgrep_dataflow_trace" if has_taint_trace else "semgrep_result",
                "severity": "info",
                "message": "Semgrep native dataflow evidence was imported." if has_taint_trace else "Semgrep result evidence was imported.",
                "detail": {"check_id": item.get("check_id"), "trace_locations": len(trace_locations)},
            }
        ],
    }
    return _record_from_plain(plain, path)


def _sarif_rules_by_id(driver: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for rule in _as_list(driver.get("rules")):
        if not isinstance(rule, dict):
            continue
        rule_id = str(rule.get("id") or "")
        if rule_id:
            rules[rule_id] = rule
    return rules


def _sarif_location(location: Mapping[str, Any], message: str = "") -> dict[str, Any] | None:
    physical = _as_object(location.get("physicalLocation"))
    artifact = _as_object(physical.get("artifactLocation"))
    region = _as_object(physical.get("region"))
    raw_path = artifact.get("uri")
    if not raw_path:
        return None
    return {
        "path": raw_path,
        "line": region.get("startLine") or 1,
        "column": region.get("startColumn") or 1,
        "snippet": message,
    }


def _sarif_result_locations(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for location in _as_list(result.get("locations")):
        if not isinstance(location, dict):
            continue
        message = _as_object(location.get("message"))
        parsed = _sarif_location(location, str(message.get("text") or ""))
        if parsed:
            locations.append(parsed)
    return locations


def _sarif_related_locations(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for location in _as_list(result.get("relatedLocations")):
        if not isinstance(location, dict):
            continue
        message = _as_object(location.get("message"))
        parsed = _sarif_location(location, str(message.get("text") or ""))
        if parsed:
            locations.append(parsed)
    return locations


def _sarif_code_flow_locations(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for code_flow in _as_list(result.get("codeFlows")):
        if not isinstance(code_flow, dict):
            continue
        for thread_flow in _as_list(code_flow.get("threadFlows")):
            if not isinstance(thread_flow, dict):
                continue
            for thread_location in _as_list(thread_flow.get("locations")):
                if not isinstance(thread_location, dict):
                    continue
                location = _as_object(thread_location.get("location"))
                message = _as_object(location.get("message"))
                parsed = _sarif_location(location, str(message.get("text") or ""))
                if parsed:
                    locations.append(parsed)
    return locations


def _sarif_reason(tool_name: str, message: Any, rule_id: str, has_flow: bool) -> str:
    text = str(message or f"SARIF result {rule_id}")
    return f"{tool_name} data-flow path: {text}" if has_flow else text


def _sarif_matched_symbols(rule_id: str, result: Mapping[str, Any], rule: Mapping[str, Any]) -> list[str]:
    symbols = [rule_id or "sarif"]
    props = _as_object(result.get("properties"))
    rule_props = _as_object(rule.get("properties"))
    for source in (props, rule_props):
        for key in ("sink", "source", "sink_symbol", "source_symbol", "queryName"):
            value = source.get(key)
            if value:
                symbols.append(f"{key}:{value}")
    return list(dict.fromkeys(symbols))


def _records_from_sarif(data: dict[str, Any], path: Path) -> list[ExternalSourceEvidenceRecord]:
    records: list[ExternalSourceEvidenceRecord] = []
    for run in data.get("runs", []) or []:
        if not isinstance(run, dict):
            continue
        tool = _as_object(run.get("tool"))
        driver = _as_object(tool.get("driver"))
        tool_name = driver.get("name", "sarif")
        rules = _sarif_rules_by_id(driver)
        for result in _as_list(run.get("results")):
            if not isinstance(result, dict):
                continue
            rule = rules.get(str(result.get("ruleId") or ""), {})
            props = _as_object(result.get("properties"))
            rule_props = _as_object(rule.get("properties"))
            ra = _as_object(props.get("reachability_advisor"))
            rule_ra = _as_object(rule_props.get("reachability_advisor"))
            metadata_sources: tuple[Mapping[str, Any], ...] = (ra, props, rule_ra, rule_props)
            top_locations = _sarif_result_locations(result)
            flow_locations = _sarif_code_flow_locations(result)
            locations = _dedupe_location_dicts([*top_locations, *flow_locations, *_sarif_related_locations(result)])
            message = _as_object(result.get("message"))
            rule_id = str(result.get("ruleId") or "")
            state = _first_selector(metadata_sources, "state", "reachability", "source_state")
            confidence = _first_selector(metadata_sources, "confidence")
            vuln = _first_selector(metadata_sources, "vulnerability", "vulnerability_id", "cve", "cve_id", "osv", "osv_id", "ghsa")
            has_flow = bool(flow_locations)
            flow_code = "codeql_code_flow" if str(tool_name).lower() == "codeql" and has_flow else "sarif_code_flow" if has_flow else "sarif_result"
            plain = {
                "artifact": _first_selector(metadata_sources, "artifact", "artifact_name", "service"),
                "component": _first_selector(metadata_sources, "component", "package", "package_name", "dependency", "module", "library"),
                "purl": _first_selector(metadata_sources, "purl", "package_purl", "package-url"),
                "vulnerability": vuln or _vulnerability_selector(rule_id),
                "state": state or (Reachability.ATTACKER_CONTROLLED.value if has_flow else Reachability.FUNCTION_REACHABLE.value),
                "confidence": confidence or (Confidence.HIGH.value if has_flow else Confidence.MEDIUM.value),
                "language": _first_selector(metadata_sources, "language") or _language_from_locations(locations),
                "reason": _sarif_reason(str(tool_name), message.get("text"), rule_id, has_flow),
                "locations": locations,
                "matched_symbols": _sarif_matched_symbols(rule_id, result, rule),
                "tool": str(tool_name),
                "diagnostics": [
                    {
                        "code": flow_code,
                        "severity": "info",
                        "message": "SARIF data-flow evidence was imported." if has_flow else "SARIF result evidence was imported.",
                        "detail": {"tool": str(tool_name), "rule_id": rule_id, "flow_locations": len(flow_locations)},
                    }
                ],
            }
            records.append(_record_from_plain(plain, path))
    return records


def _record_from_govulncheck(item: dict[str, Any], path: Path) -> ExternalSourceEvidenceRecord | None:
    finding = _as_object(item.get("finding")) or item
    vuln = finding.get("osv") or finding.get("osv_id") or finding.get("id")
    trace = _as_list(finding.get("trace"))
    if not vuln:
        return None
    package = None
    locations = []
    for frame in trace:
        if not isinstance(frame, dict):
            continue
        package = frame.get("module") or frame.get("package") or package
        position = _as_object(frame.get("position"))
        if position.get("filename"):
            locations.append({"path": position.get("filename"), "line": position.get("line", 1), "column": position.get("column", 1)})
    return _record_from_plain(
        {
            "component": package,
            "vulnerability": vuln,
            "state": Reachability.FUNCTION_REACHABLE.value,
            "confidence": Confidence.HIGH.value,
            "reason": "govulncheck reported a call stack to a vulnerable function",
            "locations": locations,
            "tool": "govulncheck",
            "language": "go",
        },
        path,
    )


def _as_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


__all__ = [
    "ExternalSourceEvidenceRecord",
    "ExternalSourceEvidenceStore",
    "load_external_source_evidence",
    "merge_source_evidence",
]
