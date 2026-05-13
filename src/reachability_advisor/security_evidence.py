"""SAST/DAST code-weakness evidence adapters.

Security scanners report first-party weaknesses such as XSS, SQL injection, or
SSRF. These are not dependency CVEs, but they can use the same exposure graph
once they are normalized to asset, source, network, and scoring evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .artifacts import artifact_match_evidence
from .effective_exposure import evaluate_effective_exposure
from .effective_graph import scoring_path_summary
from .models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    Finding,
    Reachability,
    SbomDocument,
    SourceEvidence,
    SourceLocation,
    VulnerabilityRecord,
)
from .scoring import ScorePolicy, score_finding
from .security_profiles import profiles_for_security_record, security_evidence_profile_report


@dataclass(frozen=True)
class SecurityEvidenceRecord:
    scanner_type: str
    tool: str
    rule_id: str
    weakness: str
    severity: str = "unknown"
    cvss: float | None = None
    confidence: Confidence = Confidence.MEDIUM
    artifact: str | None = None
    component: str | None = None
    cwe: str | None = None
    message: str = ""
    url: str | None = None
    method: str | None = None
    route: str | None = None
    source: SourceLocation | None = None
    sink: str | None = None
    dataflow: str | None = None
    exposure: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class SecurityEvidenceError(ValueError):
    """Raised when SAST/DAST evidence cannot be parsed."""


def load_security_evidence(paths: Sequence[str | Path]) -> list[SecurityEvidenceRecord]:
    records: list[SecurityEvidenceRecord] = []
    for path in paths:
        evidence_path = Path(path)
        try:
            data = json.loads(evidence_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SecurityEvidenceError(f"{evidence_path}: invalid JSON security evidence: {exc}") from exc
        records.extend(_records_from_data(data, evidence_path))
    return records


def generate_security_findings(
    records: list[SecurityEvidenceRecord],
    sboms: list[SbomDocument],
    contexts: dict[str, ContextEvidence],
    policy: ScorePolicy,
) -> tuple[list[Finding], dict[str, Any]]:
    artifacts = [sbom.artifact for sbom in sboms]
    findings: list[Finding] = []
    unmapped: list[dict[str, Any]] = []
    for record in records:
        artifact, match = _match_record_artifact(record, artifacts)
        if artifact is None:
            unmapped.append(
                {
                    "rule_id": record.rule_id,
                    "tool": record.tool,
                    "type": record.scanner_type,
                    "artifact": record.artifact,
                    "url": record.url,
                    "reason": "no SBOM artifact matched this scanner finding",
                    "match": match.to_json() if match else None,
                }
            )
            continue
        context = _context_for_record(contexts.get(artifact.name, ContextEvidence()), record, artifact.name)
        finding = score_finding(
            SbomDocument(path=Path("security-evidence"), artifact=artifact, components=[]),
            _component_for_record(record),
            _vulnerability_for_record(record),
            _source_for_record(record),
            context,
            policy,
        )
        finding.key = _finding_key(artifact, record)
        finding.finding_type = "code_weakness"
        finding.weakness = _weakness_json(record)
        finding.fix_commands = [record.remediation] if record.remediation else []
        finding.score_details["finding_type"] = "code_weakness"
        finding.score_details["security_evidence"] = _weakness_json(record)
        finding.score_details["effective_exposure_path"] = scoring_path_summary(finding)
        findings.append(finding)
    profile_report = security_evidence_profile_report(records, unmapped)
    report = {
        "schema_version": "1.0",
        "records": len(records),
        "mapped": len(findings),
        "unmapped": len(unmapped),
        "by_type": _count_by(records, lambda item: item.scanner_type),
        "by_tool": _count_by(records, lambda item: item.tool),
        "unmapped_records": unmapped,
        "summary": {
            **profile_report["summary"],
            "mapped": len(findings),
            "unmapped": len(unmapped),
            "by_type": _count_by(records, lambda item: item.scanner_type),
            "by_tool": _count_by(records, lambda item: item.tool),
        },
        "profiles": profile_report["profiles"],
        "profile_records": profile_report["records"],
    }
    return sorted(findings, key=lambda finding: finding.score, reverse=True), report


def _records_from_data(data: Any, path: Path) -> list[SecurityEvidenceRecord]:
    if isinstance(data, dict) and isinstance(data.get("security_evidence"), list):
        return [_record_from_plain(item, path) for item in data["security_evidence"] if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [_record_from_plain(item, path) for item in data["findings"] if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        if data.get("version") == "2.1.0" or data.get("$schema"):
            return _records_from_sarif(data, path)
        return [_record_from_semgrep(item, path) for item in data["results"] if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("runs"), list):
        return _records_from_sarif(data, path)
    if isinstance(data, list):
        return [_record_from_plain(item, path) for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [_record_from_plain(data, path)]
    return []


def _record_from_plain(item: dict[str, Any], path: Path) -> SecurityEvidenceRecord:
    scanner_type = _scanner_type(item)
    rule_id = _first_string(item, ("rule_id", "ruleId", "id", "check_id", "name")) or f"scanner-{_stable_token(json.dumps(item, sort_keys=True, default=str))}"
    weakness = _weakness(item, rule_id)
    evidence = _as_object(item.get("evidence"))
    source = _as_object(item.get("source")) or _as_object(item.get("location"))
    sink = _as_object(item.get("sink"))
    return SecurityEvidenceRecord(
        scanner_type=scanner_type,
        tool=_first_string(item, ("tool", "scanner", "provider")) or path.stem,
        rule_id=rule_id,
        weakness=weakness,
        cwe=_cwe(item),
        severity=_severity(item),
        cvss=_optional_float(item.get("cvss") or item.get("score")),
        confidence=_confidence(item.get("confidence") or item.get("confidence_level")),
        artifact=_first_string(item, ("artifact", "service", "application", "asset")),
        component=_first_string(item, ("component", "route", "handler")),
        message=_first_string(item, ("message", "title", "description")) or weakness,
        url=_first_string(item, ("url", "uri", "endpoint", "target")),
        method=_first_string(item, ("method", "http_method")),
        route=_first_string(item, ("route", "path", "endpoint_path")) or _first_string(evidence, ("entrypoint", "route")),
        source=_source_location(source),
        sink=_first_string(sink, ("function", "symbol", "name")) or _first_string(item, ("sink", "sink_function")),
        dataflow=_first_string(evidence, ("dataflow", "trace")) or _first_string(item, ("dataflow", "trace")),
        exposure=_first_string(item, ("exposure", "network_exposure")),
        remediation=_first_string(item, ("remediation", "fix", "recommendation")),
        references=_string_list(item.get("references")),
        raw=item,
    )


def _record_from_semgrep(item: dict[str, Any], path: Path) -> SecurityEvidenceRecord:
    extra = _as_object(item.get("extra"))
    metadata = _as_object(extra.get("metadata"))
    start = _as_object(item.get("start"))
    source = SourceLocation(
        path=Path(str(item.get("path") or path)),
        line=max(1, int(start.get("line") or 1)),
        column=max(1, int(start.get("col") or start.get("column") or 1)),
        snippet=str(extra.get("lines") or ""),
    )
    rule_id = str(item.get("check_id") or "semgrep-finding")
    dataflow = extra.get("dataflow_trace")
    return SecurityEvidenceRecord(
        scanner_type="sast",
        tool="semgrep",
        rule_id=rule_id,
        weakness=_weakness(metadata, rule_id),
        cwe=_cwe(metadata),
        severity=_severity(extra) if extra.get("severity") else _severity(metadata),
        cvss=_optional_float(metadata.get("cvss") or metadata.get("security-severity")),
        confidence=_confidence(metadata.get("confidence") or "medium"),
        artifact=_first_string(metadata, ("artifact", "service", "application")),
        component=_first_string(metadata, ("component", "route", "handler")),
        message=str(extra.get("message") or rule_id),
        route=_first_string(metadata, ("route", "endpoint")),
        source=source,
        sink=_first_string(metadata, ("sink", "sink_function")),
        dataflow=json.dumps(dataflow, sort_keys=True, default=str) if isinstance(dataflow, dict) else None,
        remediation=_first_string(metadata, ("remediation", "fix")),
        references=_string_list(metadata.get("references")),
        raw=item,
    )


def _records_from_sarif(data: dict[str, Any], path: Path) -> list[SecurityEvidenceRecord]:
    records: list[SecurityEvidenceRecord] = []
    for run in data.get("runs", []):
        if not isinstance(run, dict):
            continue
        driver = _as_object(_as_object(run.get("tool")).get("driver"))
        tool = str(driver.get("name") or "sarif")
        rule_metadata = _sarif_rule_metadata(run)
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            rule_ref = _as_object(result.get("rule"))
            rule_id = str(result.get("ruleId") or rule_ref.get("id") or "sarif-finding")
            metadata = {**rule_metadata.get(rule_id, {}), **_as_object(result.get("properties"))}
            location = _sarif_location(result, path)
            records.append(
                SecurityEvidenceRecord(
                    scanner_type=_scanner_type(metadata, default="sast"),
                    tool=tool,
                    rule_id=rule_id,
                    weakness=_weakness(metadata, rule_id),
                    cwe=_cwe(metadata),
                    severity=_severity(result) if result.get("level") else _severity(metadata),
                    cvss=_optional_float(metadata.get("security-severity") or metadata.get("cvss")),
                    confidence=_confidence(metadata.get("confidence") or "medium"),
                    artifact=_first_string(metadata, ("artifact", "service", "application")),
                    component=_first_string(metadata, ("component", "route", "handler")),
                    message=str(_as_object(result.get("message")).get("text") or rule_id),
                    url=_first_string(metadata, ("url", "uri", "endpoint")),
                    method=_first_string(metadata, ("method", "http_method")),
                    route=_first_string(metadata, ("route", "endpoint_path")),
                    source=location,
                    sink=_first_string(metadata, ("sink", "sink_function")),
                    dataflow="SARIF codeFlows present" if result.get("codeFlows") else None,
                    exposure=_first_string(metadata, ("exposure", "network_exposure")),
                    remediation=_first_string(metadata, ("remediation", "fix")),
                    references=_string_list(metadata.get("references")),
                    raw=result,
                )
            )
    return records


def _match_record_artifact(record: SecurityEvidenceRecord, artifacts: list[Artifact]) -> tuple[Artifact | None, Any]:
    if record.artifact:
        for artifact in artifacts:
            if artifact.name == record.artifact:
                return artifact, artifact_match_evidence(artifact, record.artifact)
    target = record.url or record.artifact
    if target:
        best_artifact = None
        best_match = None
        for artifact in artifacts:
            match = artifact_match_evidence(artifact, target)
            if best_match is None or match.score > best_match.score:
                best_artifact = artifact
                best_match = match
            if record.url and _url_mentions_artifact(record.url, artifact.name):
                return artifact, match
        if best_match and best_match.matched:
            return best_artifact, best_match
        return None, best_match
    return (artifacts[0], None) if len(artifacts) == 1 else (None, None)


def _context_for_record(base: ContextEvidence, record: SecurityEvidenceRecord, artifact_name: str) -> ContextEvidence:
    context = replace(base)
    evidence = list(context.evidence)
    evidence.append(f"{record.scanner_type.upper()} evidence from {record.tool}: {record.rule_id}")
    context.evidence = evidence
    if record.scanner_type == "dast":
        inferred_exposure = record.exposure or ("public" if record.url and urlparse(record.url).scheme in {"http", "https"} else "unknown")
        if _exposure_rank(inferred_exposure) > _exposure_rank(context.exposure):
            context.exposure = inferred_exposure
        context.confidence = _stronger_confidence(context.confidence, record.confidence)
        context.network_paths = [
            *context.network_paths,
            {
                "source": "security-evidence",
                "provider": record.tool,
                "exposure": context.exposure,
                "path_type": "dynamic_test",
                "entry_kind": "dast_probe",
                "label": f"DAST {record.method or 'HTTP'} {record.url or record.route or record.rule_id}",
                "steps": [value for value in (record.method, record.url or record.route) if value],
                "evidence": record.message or record.rule_id,
                "confidence": record.confidence.value,
                "blockers": [],
            },
        ]
        context.effective_exposure = evaluate_effective_exposure(artifact_name, context)
    elif not context.effective_exposure:
        context.effective_exposure = evaluate_effective_exposure(artifact_name, context)
    return context


def _component_for_record(record: SecurityEvidenceRecord) -> Component:
    source_path = str(record.source.path) if record.source else None
    name = record.component or record.route or source_path or record.url or record.weakness
    return Component(
        name=str(name),
        scope="runtime",
        properties={
            "finding_type": "code_weakness",
            "scanner:type": record.scanner_type,
            "scanner:tool": record.tool,
            "scanner:rule_id": record.rule_id,
            "source:path": source_path or "",
            "route": record.route or "",
            "url": record.url or "",
        },
    )


def _vulnerability_for_record(record: SecurityEvidenceRecord) -> VulnerabilityRecord:
    return VulnerabilityRecord(
        id=record.rule_id,
        package_name="first-party-code",
        aliases=[record.cwe] if record.cwe else [],
        severity=record.severity,
        cvss=record.cvss,
        summary=record.message or record.weakness,
        references=record.references,
        intelligence={
            "finding_type": "code_weakness",
            "scanner_type": record.scanner_type,
            "tool": record.tool,
            "weakness": record.weakness,
            "cwe": record.cwe,
            "url": record.url,
            "method": record.method,
            "route": record.route,
        },
    )


def _source_for_record(record: SecurityEvidenceRecord) -> SourceEvidence:
    reachability = Reachability.ATTACKER_CONTROLLED if record.scanner_type == "dast" or record.dataflow or record.url else Reachability.FUNCTION_REACHABLE
    locations = [record.source] if record.source else []
    matched = [value for value in (record.weakness, record.cwe, record.rule_id, record.route, record.sink) if value]
    return SourceEvidence(
        reachability=reachability,
        confidence=record.confidence,
        language=_language(record.source.path if record.source else None),
        reason=f"{record.scanner_type.upper()} evidence from {record.tool}: {record.message or record.rule_id}",
        locations=locations,
        matched_symbols=matched,
        evidence_source=record.tool,
        diagnostics=[
            {
                "code": "security_evidence_imported",
                "severity": "info",
                "message": "First-party scanner evidence was imported as a code weakness.",
                "detail": {"type": record.scanner_type, "tool": record.tool, "rule_id": record.rule_id},
            }
        ],
    )


def _weakness_json(record: SecurityEvidenceRecord) -> dict[str, Any]:
    profile_ids = profiles_for_security_record(record.scanner_type, record.cwe, record.weakness)
    return {
        "scanner_type": record.scanner_type,
        "tool": record.tool,
        "rule_id": record.rule_id,
        "weakness": record.weakness,
        "cwe": record.cwe,
        "severity": record.severity,
        "confidence": record.confidence.value,
        "url": record.url,
        "method": record.method,
        "route": record.route,
        "sink": record.sink,
        "dataflow": record.dataflow,
        "remediation": record.remediation,
        "profiles": list(profile_ids),
    }


def _finding_key(artifact: Artifact, record: SecurityEvidenceRecord) -> str:
    location = f"{record.source.path}:{record.source.line}" if record.source else record.url or record.route or ""
    return "|".join(["code", artifact.name, record.rule_id, _stable_token(location)])


def _scanner_type(item: dict[str, Any], default: str = "sast") -> str:
    value = _first_string(item, ("scanner_type", "type", "kind", "category")) or default
    value = value.lower()
    if "dast" in value or "dynamic" in value or _first_string(item, ("url", "endpoint", "target")):
        return "dast"
    return "sast"


def _weakness(item: dict[str, Any], fallback: str) -> str:
    value = (
        _first_string(item, ("weakness", "cwe_name", "vulnerability_class", "class"))
        or _first_list_string(item, ("vulnerability_class", "cwe_name", "category"))
        or _first_string(item, ("category",))
    )
    if value:
        return _normalize_label(value)
    cwe = _cwe(item)
    return cwe or _normalize_label(fallback)


def _cwe(item: dict[str, Any]) -> str | None:
    value = _first_string(item, ("cwe", "CWE"))
    if not value and isinstance(item.get("cwe"), list):
        value = _string_list(item.get("cwe"))[0] if _string_list(item.get("cwe")) else None
    if not value:
        return None
    match = re.search(r"\bCWE[-_ ]?(\d+)\b", value, flags=re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    value = value.upper().replace("_", "-")
    return value if value.startswith("CWE-") else f"CWE-{value}" if value.isdigit() else value


def _severity(item: dict[str, Any]) -> str:
    value = _first_string(item, ("severity", "level", "impact")) or "unknown"
    value = value.lower()
    return {"error": "high", "warning": "medium", "note": "low", "none": "informational"}.get(value, value)


def _confidence(value: Any) -> Confidence:
    try:
        return Confidence(str(value or "medium").lower())
    except ValueError:
        return Confidence.MEDIUM


def _source_location(value: dict[str, Any]) -> SourceLocation | None:
    path = _first_string(value, ("path", "file", "uri", "artifactLocation"))
    if not path:
        return None
    return SourceLocation(
        path=Path(path),
        line=max(1, int(_optional_float(value.get("line") or value.get("startLine")) or 1)),
        column=max(1, int(_optional_float(value.get("column") or value.get("col") or value.get("startColumn")) or 1)),
        snippet=str(value.get("snippet") or value.get("content") or ""),
    )


def _sarif_rule_metadata(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = _as_object(_as_object(run.get("tool")).get("driver"))
    rules_value = driver.get("rules", [])
    rules = rules_value if isinstance(rules_value, list) else []
    metadata: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if not isinstance(rule, dict) or not rule.get("id"):
            continue
        metadata[str(rule["id"])] = _as_object(rule.get("properties"))
    return metadata


def _sarif_location(result: dict[str, Any], path: Path) -> SourceLocation | None:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return None
    first = locations[0]
    if not isinstance(first, dict):
        return None
    physical = _as_object(first.get("physicalLocation"))
    artifact = _as_object(physical.get("artifactLocation"))
    region = _as_object(physical.get("region"))
    uri = artifact.get("uri") or str(path)
    return SourceLocation(
        path=Path(str(uri)),
        line=max(1, int(region.get("startLine") or 1)),
        column=max(1, int(region.get("startColumn") or 1)),
    )


def _first_string(data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _first_list_string(data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    return item.strip()
    return None


def _as_object(value: Any) -> dict[str, Any]:
    return {str(key): item for key, item in value.items()} if isinstance(value, dict) else {}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _optional_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _language(path: Path | None) -> str:
    if path is None:
        return "unknown"
    return {
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".py": "python",
        ".java": "java",
        ".go": "go",
    }.get(path.suffix.lower(), "unknown")


def _url_mentions_artifact(url: str, artifact: str) -> bool:
    parsed = urlparse(url)
    haystack = f"{parsed.netloc} {parsed.path}".lower()
    return _normalize_label(artifact) in _normalize_label(haystack)


def _exposure_rank(value: str | None) -> int:
    return {"none": 0, "private": 1, "internal": 2, "unknown": 3, "external": 4, "public": 5}.get(str(value or "unknown").lower(), 3)


def _stronger_confidence(left: Confidence, right: Confidence) -> Confidence:
    order = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
    return right if order[right] > order[left] else left


def _normalize_label(value: str) -> str:
    return "_".join(part for part in "".join(char.lower() if char.isalnum() else " " for char in value).split() if part)


def _stable_token(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _count_by(records: list[SecurityEvidenceRecord], selector: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        key = str(selector(record) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


__all__ = [
    "SecurityEvidenceError",
    "SecurityEvidenceRecord",
    "generate_security_findings",
    "load_security_evidence",
]
