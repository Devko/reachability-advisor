"""Source, runtime, and context evidence construction for scanner records."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .effective_exposure import evaluate_effective_exposure
from .models import (
    Confidence,
    ContextEvidence,
    PostureEvidence,
    Reachability,
    RuntimeEvidence,
    RuntimeEvidenceState,
    SourceEvidence,
)
from .security_evidence_model import SecurityEvidenceRecord


def context_for_security_record(base: ContextEvidence, record: SecurityEvidenceRecord, artifact_name: str) -> ContextEvidence:
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
    elif record.scanner_type == "cspm":
        if record.exposure and _exposure_rank(record.exposure) > _exposure_rank(context.exposure):
            context.exposure = record.exposure
        if _posture_is_sensitive(record) and context.criticality == "unknown":
            context.criticality = "high"
        if _posture_is_privileged(record) and context.privilege == "unknown":
            context.privilege = "sensitive"
        if _posture_impact(record):
            impact = _posture_impact(record)
            context.iam_impacts = list(dict.fromkeys([*context.iam_impacts, impact]))
            context.effective_access = [
                *context.effective_access,
                {
                    "source": record.evidence_source or record.tool,
                    "provider": record.provider,
                    "identity": record.resource_id or record.component or "posture resource",
                    "resource": record.resource_id,
                    "action": record.control or record.rule_id,
                    "effect": "allow",
                    "decision": "allowed",
                    "impact": impact,
                    "confidence": record.confidence.value,
                    "evidence": record.message or record.weakness,
                },
            ]
        if not context.effective_exposure:
            context.effective_exposure = evaluate_effective_exposure(artifact_name, context)
    elif not context.effective_exposure:
        context.effective_exposure = evaluate_effective_exposure(artifact_name, context)
    return context


def source_for_security_record(record: SecurityEvidenceRecord) -> SourceEvidence:
    if record.scanner_type == "dast":
        reachability = Reachability.FUNCTION_REACHABLE if record.source else Reachability.PACKAGE_PRESENT
    elif record.scanner_type == "cspm":
        reachability = Reachability.PACKAGE_PRESENT
    else:
        reachability = Reachability.ATTACKER_CONTROLLED if record.dataflow else Reachability.FUNCTION_REACHABLE
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
                "message": "First-party scanner evidence was imported.",
                "detail": {"type": record.scanner_type, "tool": record.tool, "rule_id": record.rule_id},
            },
            *_posture_diagnostics(record),
            *_source_mapping_diagnostics(record),
        ],
    )


def runtime_for_security_record(record: SecurityEvidenceRecord) -> RuntimeEvidence:
    if record.scanner_type != "dast":
        return RuntimeEvidence()
    auth = (record.authentication_context or "").lower()
    if "unauth" in auth or "anonymous" in auth:
        state = RuntimeEvidenceState.UNAUTHENTICATED_OBSERVED
    elif "auth" in auth:
        state = RuntimeEvidenceState.AUTHENTICATED_OBSERVED
    elif record.rule_id or record.weakness:
        state = RuntimeEvidenceState.VULNERABILITY_OBSERVED
    else:
        state = RuntimeEvidenceState.ENDPOINT_OBSERVED
    diagnostics: list[dict[str, Any]] = []
    if not record.source:
        diagnostics.append({
            "code": "source_mapping_unavailable",
            "severity": "warning",
            "message": "Runtime observation is not source reachability without source mapping.",
        })
    return RuntimeEvidence(
        state=state,
        confidence=record.confidence,
        tool=record.tool,
        url=record.url,
        method=record.method,
        parameter=record.parameter,
        request_evidence=record.request_evidence,
        response_evidence=record.response_evidence,
        authentication_context=record.authentication_context,
        evidence_source=record.input_path or record.tool,
        diagnostics=diagnostics,
    )


def posture_for_security_record(record: SecurityEvidenceRecord) -> PostureEvidence:
    if record.scanner_type != "cspm":
        return PostureEvidence()
    diagnostics: list[dict[str, Any]] = []
    if not record.resource_id:
        diagnostics.append({
            "code": "posture_resource_unavailable",
            "severity": "warning",
            "message": "CSPM finding did not include a concrete resource identifier.",
        })
    return PostureEvidence(
        scanner=record.scanner_type,
        tool=record.tool,
        rule_id=record.rule_id,
        provider=record.provider,
        resource_id=record.resource_id,
        resource_type=record.resource_type,
        service=record.service,
        control=record.control,
        category=record.weakness,
        expected=record.expected,
        actual=record.actual,
        remediation=record.remediation,
        confidence=record.confidence,
        evidence_source=record.evidence_source or record.input_path or record.tool,
        input_path=record.input_path,
        location=record.source,
        blockers=record.blockers,
        unknowns=record.unknowns,
        diagnostics=diagnostics,
    )


def _source_mapping_diagnostics(record: SecurityEvidenceRecord) -> list[dict[str, Any]]:
    if record.scanner_type != "dast" or record.source:
        return []
    return [{
        "code": "source_mapping_unavailable",
        "severity": "warning",
        "message": "DAST runtime evidence did not include a source location or source dataflow.",
        "detail": {"url": record.url, "method": record.method, "tool": record.tool},
    }]


def _posture_diagnostics(record: SecurityEvidenceRecord) -> list[dict[str, Any]]:
    if record.scanner_type != "cspm":
        return []
    return [{
        "code": "posture_evidence_imported",
        "severity": "info",
        "message": "CSPM evidence is configuration context, not source or runtime proof.",
        "detail": {"provider": record.provider, "resource_id": record.resource_id, "resource_type": record.resource_type},
    }]


def _posture_is_sensitive(record: SecurityEvidenceRecord) -> bool:
    text = _posture_text(record)
    return any(token in text for token in ("secret", "key", "kms", "database", "bucket", "storage", "data", "public"))


def _posture_is_privileged(record: SecurityEvidenceRecord) -> bool:
    text = _posture_text(record)
    return any(token in text for token in ("admin", "wildcard", "privileged", "hostpath", "hostnetwork", "rbac", "iam", "owner", "contributor"))


def _posture_impact(record: SecurityEvidenceRecord) -> str:
    text = _posture_text(record)
    if any(token in text for token in ("admin", "owner", "contributor", "wildcard", "privileged")):
        return "admin_control"
    if any(token in text for token in ("iam", "rbac", "assume", "role", "serviceaccount")):
        return "iam_escalation"
    if any(token in text for token in ("secret", "database", "bucket", "storage", "data")):
        return "data_access"
    if any(token in text for token in ("ingress", "public", "loadbalancer", "security_group", "firewall")):
        return "network_control"
    return ""


def _posture_text(record: SecurityEvidenceRecord) -> str:
    return " ".join(
        str(value or "")
        for value in (
            record.rule_id,
            record.weakness,
            record.resource_type,
            record.resource_id,
            record.service,
            record.control,
            record.message,
            record.actual,
        )
    ).lower()


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


def _exposure_rank(value: str | None) -> int:
    return {"none": 0, "unknown": 0, "private": 1, "isolated": 1, "internal": 2, "external": 4, "public": 5}.get(str(value or "unknown").lower(), 0)


def _stronger_confidence(left: Confidence, right: Confidence) -> Confidence:
    order = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
    return right if order[right] > order[left] else left


__all__ = [
    "context_for_security_record",
    "runtime_for_security_record",
    "posture_for_security_record",
    "source_for_security_record",
]
