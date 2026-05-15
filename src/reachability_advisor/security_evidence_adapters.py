"""Scanner evidence adapters for normalized SAST/DAST records."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .input_limits import InputSizeError, iter_text_lines_limited, read_text_limited
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
            data = json.loads(read_text_limited(evidence_path, "security evidence"))
        except InputSizeError as exc:
            raise SecurityEvidenceError(str(exc)) from exc
        except json.JSONDecodeError as exc:
            raise SecurityEvidenceError(f"{evidence_path}: invalid JSON security evidence: {exc}") from exc
        records.extend(_records_from_data(data, evidence_path, default_scanner_type=default_scanner_type))
    return records


def _records_from_jsonl(path: Path, *, default_scanner_type: str | None = None) -> list[SecurityEvidenceRecord]:
    records: list[SecurityEvidenceRecord] = []
    try:
        lines = iter_text_lines_limited(path, "security evidence JSONL")
        for line_number, line in enumerate(lines, start=1):
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
    except InputSizeError as exc:
        raise SecurityEvidenceError(str(exc)) from exc
    return records


def _require_list(data: dict[str, Any], key: str, path: Path) -> list[Any] | None:
    if key not in data:
        return None
    value = data.get(key)
    if not isinstance(value, list):
        raise SecurityEvidenceError(f"{path}: {key} must be a list")
    return value


def _records_from_data(data: Any, path: Path, *, default_scanner_type: str | None = None) -> list[SecurityEvidenceRecord]:
    if isinstance(data, dict):
        normalized = _require_list(data, "security_evidence", path)
        if normalized is not None:
            return [_record_from_plain(item, path, default_scanner_type=default_scanner_type) for item in normalized if isinstance(item, dict)]
        findings = _require_list(data, "findings", path)
        if findings is not None:
            return [_record_from_plain(item, path, default_scanner_type=default_scanner_type) for item in findings if isinstance(item, dict)]
        if _is_checkov_report(data):
            return _records_from_checkov(data, path, default_scanner_type=default_scanner_type)
        if _is_trivy_config_report(data):
            return _records_from_trivy_config(data, path, default_scanner_type=default_scanner_type)
        if _is_kics_report(data):
            return _records_from_kics(data, path, default_scanner_type=default_scanner_type)
        if _is_tfsec_report(data):
            return _records_from_tfsec(data, path, default_scanner_type=default_scanner_type)
        if isinstance(data.get("site"), list):
            return _records_from_zap(data, path, default_scanner_type=default_scanner_type)
        results = _require_list(data, "results", path)
        if results is not None:
            if data.get("version") == "2.1.0" or data.get("$schema"):
                return _records_from_sarif(data, path, default_scanner_type=default_scanner_type)
            return [_record_from_semgrep(item, path) for item in results if isinstance(item, dict)]
        runs = _require_list(data, "runs", path)
        if runs is not None:
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
        provider=_first_string(item, ("provider", "cloud_provider", "platform")),
        resource_id=_first_string(item, ("resource_id", "resource", "resourceId", "resource_name", "resourceName")),
        resource_type=_first_string(item, ("resource_type", "resourceType", "type_name")),
        service=_first_string(item, ("service", "cloud_service")),
        control=_first_string(item, ("control", "category", "policy", "policy_name")),
        expected=_first_string(item, ("expected", "expected_state", "expectedState")),
        actual=_first_string(item, ("actual", "actual_state", "actualState")),
        evidence_source=_first_string(item, ("evidence_source", "source_type")) or ("scanner" if scanner_type == "cspm" else None),
        blockers=_string_list(item.get("blockers")),
        unknowns=_string_list(item.get("unknowns")),
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
        line=_positive_int(start.get("line"), default=1),
        column=_positive_int(start.get("col") or start.get("column"), default=1),
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
        dataflow=json.dumps(dataflow, sort_keys=True, default=str) if isinstance(dataflow, dict | list) else None,
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
                if not isinstance(instance, dict):
                    continue
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


def _records_from_checkov(data: dict[str, Any], path: Path, *, default_scanner_type: str | None = None) -> list[SecurityEvidenceRecord]:
    results = _as_object(data.get("results"))
    failed = results.get("failed_checks")
    checks = failed if isinstance(failed, list) else []
    records: list[SecurityEvidenceRecord] = []
    for item in checks:
        if not isinstance(item, dict):
            continue
        source = {
            "path": _first_string(item, ("file_path", "repo_file_path", "file_abs_path")) or str(path),
            "line": _first_line(item.get("file_line_range")),
        }
        records.append(
            SecurityEvidenceRecord(
                scanner_type=_scanner_type(item, default=default_scanner_type or "cspm"),
                tool="checkov",
                rule_id=_first_string(item, ("check_id", "id")) or f"checkov-{_stable_token(json.dumps(item, sort_keys=True, default=str))}",
                weakness=_first_string(item, ("check_name", "bc_check_name")) or "checkov posture finding",
                severity=_severity(item),
                confidence=_confidence(item.get("confidence") or "medium"),
                artifact=_first_string(item, ("artifact", "service", "application")),
                component=_first_string(item, ("resource", "resource_name")),
                message=_first_string(item, ("check_name", "guideline")) or "",
                source=_source_location(source),
                provider=_first_string(item, ("provider", "cloud_provider")),
                resource_id=_first_string(item, ("resource", "resource_name")),
                resource_type=_first_string(item, ("resource_type", "entity_type")),
                service=_first_string(item, ("service",)),
                control=_first_string(item, ("check_class", "category", "check_name")),
                expected=_first_string(item, ("expected",)),
                actual=_first_string(item, ("actual",)),
                evidence_source="checkov",
                remediation=_first_string(item, ("guideline", "remediation")),
                references=_string_list(item.get("guideline")),
                raw=item,
                input_path=str(path),
            )
        )
    return records


def _records_from_trivy_config(data: dict[str, Any], path: Path, *, default_scanner_type: str | None = None) -> list[SecurityEvidenceRecord]:
    records: list[SecurityEvidenceRecord] = []
    for result in data.get("Results", []) or []:
        if not isinstance(result, dict):
            continue
        target = _first_string(result, ("Target", "Class", "Type")) or str(path)
        for item in result.get("Misconfigurations", []) or []:
            if not isinstance(item, dict):
                continue
            records.append(
                SecurityEvidenceRecord(
                    scanner_type=_scanner_type(item, default=default_scanner_type or "cspm"),
                    tool="trivy-config",
                    rule_id=_first_string(item, ("ID", "AVDID", "id")) or f"trivy-{_stable_token(json.dumps(item, sort_keys=True, default=str))}",
                    weakness=_first_string(item, ("Title", "Description")) or "trivy config finding",
                    severity=_severity({"severity": _first_string(item, ("Severity",)) or "unknown"}),
                    confidence=_confidence(item.get("confidence") or "medium"),
                    artifact=_first_string(item, ("artifact", "service", "application")),
                    component=_first_string(item, ("CauseMetadata", "Resource")) or target,
                    message=_first_string(item, ("Description", "Message", "Title")) or "",
                    source=_source_location(_trivy_source(item, target)),
                    provider=_first_string(item, ("Provider", "provider")),
                    resource_id=_first_string(item, ("Resource", "resource")) or target,
                    resource_type=_first_string(item, ("Type", "resource_type")),
                    service=_first_string(item, ("Service", "service")),
                    control=_first_string(item, ("Type", "Category", "Title")),
                    expected=_first_string(item, ("Expected",)),
                    actual=_first_string(item, ("Actual",)),
                    evidence_source="trivy-config",
                    remediation=_first_string(item, ("Resolution", "remediation")),
                    references=_string_list(item.get("References")),
                    raw=item,
                    input_path=str(path),
                )
            )
    return records


def _records_from_kics(data: dict[str, Any], path: Path, *, default_scanner_type: str | None = None) -> list[SecurityEvidenceRecord]:
    records: list[SecurityEvidenceRecord] = []
    for query in data.get("queries", []) or []:
        if not isinstance(query, dict):
            continue
        query_files = query.get("files")
        files = query_files if isinstance(query_files, list) else [{}]
        for file_record in files:
            item = _as_object(file_record)
            records.append(
                SecurityEvidenceRecord(
                    scanner_type=_scanner_type(query, default=default_scanner_type or "cspm"),
                    tool="kics",
                    rule_id=_first_string(query, ("query_id", "id")) or f"kics-{_stable_token(json.dumps(query, sort_keys=True, default=str))}",
                    weakness=_first_string(query, ("query_name", "description")) or "kics posture finding",
                    severity=_severity({"severity": _first_string(query, ("severity",)) or "unknown"}),
                    confidence=_confidence(query.get("confidence") or "medium"),
                    component=_first_string(item, ("resource_name", "resource_id")),
                    message=_first_string(query, ("description", "query_name")) or "",
                    source=_source_location({"path": _first_string(item, ("file_name", "file_path")) or str(path), "line": _first_string(item, ("line",)) or 1}),
                    provider=_first_string(query, ("platform", "provider")),
                    resource_id=_first_string(item, ("resource_id", "resource_name")),
                    resource_type=_first_string(item, ("resource_type",)),
                    service=_first_string(query, ("service",)),
                    control=_first_string(query, ("category", "query_name")),
                    expected=_first_string(query, ("expected",)),
                    actual=_first_string(item, ("actual_value", "search_value")),
                    evidence_source="kics",
                    remediation=_first_string(query, ("remediation",)),
                    references=_string_list(query.get("references")),
                    raw={"query": query, "file": item},
                    input_path=str(path),
                )
            )
    return records


def _records_from_tfsec(data: dict[str, Any], path: Path, *, default_scanner_type: str | None = None) -> list[SecurityEvidenceRecord]:
    records: list[SecurityEvidenceRecord] = []
    for item in data.get("results", []) or []:
        if not isinstance(item, dict):
            continue
        location = _as_object(item.get("location"))
        records.append(
            SecurityEvidenceRecord(
                scanner_type=_scanner_type(item, default=default_scanner_type or "cspm"),
                tool="tfsec",
                rule_id=_first_string(item, ("rule_id", "long_id", "id")) or f"tfsec-{_stable_token(json.dumps(item, sort_keys=True, default=str))}",
                weakness=_first_string(item, ("description", "rule_description")) or "tfsec posture finding",
                severity=_severity(item),
                confidence=_confidence(item.get("confidence") or "medium"),
                component=_first_string(item, ("resource", "resource_name")),
                message=_first_string(item, ("description", "impact")) or "",
                source=_source_location({"path": _first_string(location, ("filename", "path")) or str(path), "line": _first_string(location, ("start_line", "line")) or 1}),
                provider=_first_string(item, ("provider",)),
                resource_id=_first_string(item, ("resource", "resource_name")),
                resource_type=_first_string(item, ("resource_type",)),
                service=_first_string(item, ("service",)),
                control=_first_string(item, ("rule_description", "impact")),
                expected=_first_string(item, ("expected",)),
                actual=_first_string(item, ("impact", "actual")),
                evidence_source="tfsec",
                remediation=_first_string(item, ("resolution", "remediation")),
                references=_string_list(item.get("links")),
                raw=item,
                input_path=str(path),
            )
        )
    return records


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
                    message=_sarif_message(result.get("message")) or rule_id,
                    url=_first_string(metadata, ("url", "uri", "endpoint")),
                    method=_first_string(metadata, ("method", "http_method")),
                    route=_first_string(metadata, ("route", "endpoint_path")),
                    source=location,
                    sink=_first_string(metadata, ("sink", "sink_function")),
                    dataflow="SARIF codeFlows present" if result.get("codeFlows") else None,
                    exposure=_first_string(metadata, ("exposure", "network_exposure")),
                    provider=_first_string(metadata, ("provider", "cloud_provider", "platform")),
                    resource_id=_first_string(metadata, ("resource_id", "resource", "resourceId")),
                    resource_type=_first_string(metadata, ("resource_type", "resourceType")),
                    service=_first_string(metadata, ("service", "cloud_service")),
                    control=_first_string(metadata, ("control", "category", "policy")),
                    expected=_first_string(metadata, ("expected", "expected_state")),
                    actual=_first_string(metadata, ("actual", "actual_state")),
                    evidence_source=_first_string(metadata, ("evidence_source", "source_type")),
                    blockers=_string_list(metadata.get("blockers")),
                    unknowns=_string_list(metadata.get("unknowns")),
                    remediation=_first_string(metadata, ("remediation", "fix")),
                    references=_string_list(metadata.get("references")),
                    raw=result,
                    input_path=str(path),
                )
            )
    return records


def _is_checkov_report(data: dict[str, Any]) -> bool:
    results = data.get("results")
    return isinstance(results, dict) and isinstance(results.get("failed_checks"), list)


def _is_trivy_config_report(data: dict[str, Any]) -> bool:
    return isinstance(data.get("Results"), list) and any(isinstance(item, dict) and isinstance(item.get("Misconfigurations"), list) for item in data.get("Results", []))


def _is_kics_report(data: dict[str, Any]) -> bool:
    return isinstance(data.get("queries"), list)


def _is_tfsec_report(data: dict[str, Any]) -> bool:
    return isinstance(data.get("results"), list) and any(isinstance(item, dict) and ("rule_id" in item or "long_id" in item) for item in data.get("results", []))


def _is_nuclei_record(item: dict[str, Any]) -> bool:
    return any(key in item for key in ("template-id", "template_id", "matched-at", "matched_at")) and isinstance(item.get("info"), dict)


def _scanner_type(item: dict[str, Any], default: str = "sast") -> str:
    value = _first_string(item, ("scanner_type", "type", "kind", "category")) or default
    value = value.lower()
    if default == "cspm" or any(token in value for token in ("cspm", "posture", "misconfig", "configuration", "iac", "checkov", "trivy", "kics", "tfsec")):
        return "cspm"
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


def _first_line(value: Any) -> int:
    if isinstance(value, list) and value:
        first = value[0]
        if isinstance(first, int):
            return max(1, first)
        if isinstance(first, str) and first.isdigit():
            return max(1, int(first))
    return 1


def _trivy_source(item: dict[str, Any], target: str) -> dict[str, Any]:
    cause = _as_object(item.get("CauseMetadata"))
    start = _as_object(cause.get("StartLine"))
    return {
        "path": _first_string(cause, ("Filename", "Resource")) or target,
        "line": start.get("Line") or cause.get("StartLine") or 1,
    }


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
        line=_positive_int(value.get("line") or value.get("startLine"), default=1),
        column=_positive_int(value.get("column") or value.get("col") or value.get("startColumn"), default=1),
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
        line=_positive_int(region.get("startLine"), default=1),
        column=_positive_int(region.get("startColumn"), default=1),
    )


def _first_string(data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = _scalar_string(data.get(key))
        if value:
            return value
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
    values: list[str] = []
    for item in value:
        if isinstance(item, dict):
            candidate = _first_string(item, ("url", "href", "uri", "reference"))
        else:
            candidate = _scalar_string(item)
        if candidate:
            values.append(candidate)
    return values


def _optional_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_label(value: str) -> str:
    return "_".join(part for part in "".join(char.lower() if char.isalnum() else " " for char in value).split() if part)


def _scalar_string(value: Any) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, list):
        for item in value:
            candidate = _scalar_string(item)
            if candidate:
                return candidate
    return None


def _positive_int(value: Any, *, default: int) -> int:
    number = _optional_float(value)
    if number is None:
        return default
    return max(1, int(number))


def _sarif_message(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    message = _as_object(value)
    return _first_string(message, ("text", "markdown"))


def _stable_token(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


__all__ = ["load_security_evidence"]
