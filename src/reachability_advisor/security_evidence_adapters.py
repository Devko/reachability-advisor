"""Scanner evidence adapters for normalized SAST/DAST records."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .models import Confidence, SourceLocation
from .security_evidence_model import SecurityEvidenceError, SecurityEvidenceRecord


def load_security_evidence(paths: Sequence[str | Path], *, default_scanner_type: str | None = None) -> list[SecurityEvidenceRecord]:
    records: list[SecurityEvidenceRecord] = []
    for path in paths:
        evidence_path = Path(path)
        if evidence_path.suffix.lower() in {".jsonl", ".ndjson"}:
            records.extend(_records_from_jsonl(evidence_path, default_scanner_type=default_scanner_type))
            continue
        try:
            data = json.loads(evidence_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SecurityEvidenceError(f"{evidence_path}: invalid JSON security evidence: {exc}") from exc
        records.extend(_records_from_data(data, evidence_path, default_scanner_type=default_scanner_type))
    return records


def _records_from_jsonl(path: Path, *, default_scanner_type: str | None = None) -> list[SecurityEvidenceRecord]:
    records: list[SecurityEvidenceRecord] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SecurityEvidenceError(f"{path}:{line_number}: invalid JSONL security evidence: {exc}") from exc
        if not isinstance(item, dict):
            continue
        if _is_nuclei_record(item):
            records.append(_record_from_nuclei(item, path, default_scanner_type=default_scanner_type))
        else:
            records.append(_record_from_plain(item, path, default_scanner_type=default_scanner_type))
    return records


def _records_from_data(data: Any, path: Path, *, default_scanner_type: str | None = None) -> list[SecurityEvidenceRecord]:
    if isinstance(data, dict) and isinstance(data.get("security_evidence"), list):
        return [_record_from_plain(item, path, default_scanner_type=default_scanner_type) for item in data["security_evidence"] if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [_record_from_plain(item, path, default_scanner_type=default_scanner_type) for item in data["findings"] if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("site"), list):
        return _records_from_zap(data, path, default_scanner_type=default_scanner_type)
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        if data.get("version") == "2.1.0" or data.get("$schema"):
            return _records_from_sarif(data, path, default_scanner_type=default_scanner_type)
        return [_record_from_semgrep(item, path) for item in data["results"] if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("runs"), list):
        return _records_from_sarif(data, path, default_scanner_type=default_scanner_type)
    if isinstance(data, list):
        return [_record_from_plain(item, path, default_scanner_type=default_scanner_type) for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [_record_from_plain(data, path, default_scanner_type=default_scanner_type)]
    return []


def _record_from_plain(item: dict[str, Any], path: Path, *, default_scanner_type: str | None = None) -> SecurityEvidenceRecord:
    scanner_type = _scanner_type(item, default=default_scanner_type or "sast")
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
        parameter=_first_string(item, ("parameter", "param", "evidence_parameter")),
        request_evidence=_first_string(evidence, ("request", "request_evidence", "payload")) or _first_string(item, ("request_evidence", "payload")),
        response_evidence=_first_string(evidence, ("response", "response_evidence", "evidence")) or _first_string(item, ("response_evidence",)),
        authentication_context=_first_string(item, ("authentication_context", "auth", "authenticated")),
        route=_first_string(item, ("route", "path", "endpoint_path")) or _first_string(evidence, ("entrypoint", "route")),
        source=_source_location(source),
        sink=_first_string(sink, ("function", "symbol", "name")) or _first_string(item, ("sink", "sink_function")),
        dataflow=_first_string(evidence, ("dataflow", "trace")) or _first_string(item, ("dataflow", "trace")),
        exposure=_first_string(item, ("exposure", "network_exposure")),
        remediation=_first_string(item, ("remediation", "fix", "recommendation")),
        references=_string_list(item.get("references")),
        raw=item,
        input_path=str(path),
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
        input_path=str(path),
    )


def _records_from_zap(data: dict[str, Any], path: Path, *, default_scanner_type: str | None = None) -> list[SecurityEvidenceRecord]:
    records: list[SecurityEvidenceRecord] = []
    for site in data.get("site", []):
        if not isinstance(site, dict):
            continue
        site_host = _first_string(site, ("@host", "host", "name")) or ""
        site_base = _first_string(site, ("@name", "name")) or (f"https://{site_host}" if site_host else "")
        for alert in site.get("alerts", []) or []:
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances") if isinstance(alert.get("instances"), list) else [{}]
            for instance in instances or [{}]:
                instance_obj = _as_object(instance)
                url = _first_string(instance_obj, ("uri", "url")) or site_base
                records.append(
                    SecurityEvidenceRecord(
                        scanner_type=_scanner_type(alert, default=default_scanner_type or "dast"),
                        tool="zap",
                        rule_id=_first_string(alert, ("pluginid", "alertRef", "id")) or f"zap-{_stable_token(json.dumps(alert, sort_keys=True, default=str))}",
                        weakness=_first_string(alert, ("alert", "name")) or "zap finding",
                        cwe=_cwe({"cwe": _first_string(alert, ("cweid", "cwe")) or ""}),
                        severity=_severity({"severity": _first_string(alert, ("riskdesc", "riskcode", "risk")) or "unknown"}),
                        confidence=_confidence(_first_string(alert, ("confidence",)) or "medium"),
                        message=_first_string(alert, ("desc", "description", "alert")) or "",
                        url=url,
                        method=_first_string(instance_obj, ("method",)),
                        parameter=_first_string(instance_obj, ("param", "parameter")),
                        request_evidence=_first_string(instance_obj, ("attack", "evidence")),
                        response_evidence=_first_string(instance_obj, ("evidence",)),
                        remediation=_first_string(alert, ("solution", "remediation")),
                        references=_string_list(alert.get("reference")),
                        raw={"alert": alert, "instance": instance_obj},
                        input_path=str(path),
                    )
                )
    return records


def _record_from_nuclei(item: dict[str, Any], path: Path, *, default_scanner_type: str | None = None) -> SecurityEvidenceRecord:
    info = _as_object(item.get("info"))
    classification = _as_object(info.get("classification"))
    matcher_name = _first_string(item, ("matcher-name", "matcher_name"))
    return SecurityEvidenceRecord(
        scanner_type=_scanner_type(item, default=default_scanner_type or "dast"),
        tool="nuclei",
        rule_id=_first_string(item, ("template-id", "template_id", "id")) or f"nuclei-{_stable_token(json.dumps(item, sort_keys=True, default=str))}",
        weakness=_first_string(info, ("name", "description")) or matcher_name or "nuclei finding",
        cwe=_cwe(classification),
        severity=_severity(info),
        confidence=_confidence(_first_string(info, ("confidence",)) or "medium"),
        message=_first_string(info, ("description", "name")) or "",
        url=_first_string(item, ("matched-at", "matched_at", "host", "url")),
        method=_first_string(item, ("method",)),
        parameter=_first_string(item, ("extracted-results", "parameter")),
        request_evidence=_first_string(item, ("request", "curl-command")),
        response_evidence=_first_string(item, ("response", "matcher-status")),
        remediation=_first_string(info, ("remediation",)),
        references=_string_list(info.get("reference")),
        raw=item,
        input_path=str(path),
    )


def _records_from_sarif(data: dict[str, Any], path: Path, *, default_scanner_type: str | None = None) -> list[SecurityEvidenceRecord]:
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
                    scanner_type=_scanner_type(metadata, default=default_scanner_type or "sast"),
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
                    input_path=str(path),
                )
            )
    return records


def _is_nuclei_record(item: dict[str, Any]) -> bool:
    return any(key in item for key in ("template-id", "template_id", "matched-at", "matched_at")) and isinstance(item.get("info"), dict)


def _scanner_type(item: dict[str, Any], default: str = "sast") -> str:
    value = _first_string(item, ("scanner_type", "type", "kind", "category")) or default
    value = value.lower()
    if "dast" in value or "dynamic" in value or _first_string(item, ("url", "endpoint", "target")):
        return "dast"
    if default == "dast" and "sast" not in value and "static" not in value:
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
    value = _first_string(item, ("cwe", "CWE", "cweid", "cwe-id", "cwe_id"))
    if not value and isinstance(item.get("cwe"), list):
        values = _string_list(item.get("cwe"))
        value = values[0] if values else None
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
    for token in ("critical", "high", "medium", "low", "informational"):
        if token in value:
            return token
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
    if isinstance(value, str):
        return [item.strip() for item in re.split(r"[\n,]+", value) if item.strip()]
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


def _normalize_label(value: str) -> str:
    return "_".join(part for part in "".join(char.lower() if char.isalnum() else " " for char in value).split() if part)


def _stable_token(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


__all__ = ["load_security_evidence"]
