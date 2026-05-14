"""SAST/DAST security evidence normalization.

Security scanners report first-party weaknesses such as XSS, SQL injection, or
SSRF. These are not dependency CVEs, but they can use the same exposure graph
once they are normalized to asset, source, network, and scoring evidence.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .effective_graph import scoring_path_summary
from .finding_types import DYNAMIC_RUNTIME_OBSERVATION, STATIC_CODE_WEAKNESS
from .models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    Finding,
    SbomDocument,
    VulnerabilityRecord,
)
from .scoring import ScorePolicy, score_finding, score_security_finding
from .security_evidence_adapters import load_security_evidence
from .security_evidence_model import SecurityEvidenceError, SecurityEvidenceRecord
from .security_mapping import (
    SecurityEvidenceMappingDecision,
    map_security_evidence_record,
    unmapped_runtime_artifact,
)
from .security_profiles import profiles_for_security_record, security_evidence_profile_report
from .security_runtime import (
    context_for_security_record,
    runtime_for_security_record,
    source_for_security_record,
)


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
        mapping = map_security_evidence_record(record, artifacts, contexts)
        artifact = mapping.artifact
        if artifact is None:
            if record.scanner_type == "dast":
                artifact = unmapped_runtime_artifact(record)
            else:
                unmapped.append(
                    {
                        "rule_id": record.rule_id,
                        "tool": record.tool,
                        "type": record.scanner_type,
                        "artifact": record.artifact,
                        "url": record.url,
                        "reason": "no SBOM artifact matched this scanner finding",
                        "match": mapping.match_json(),
                        "mapping_confidence": mapping.confidence.value,
                    }
                )
                continue
        if artifact.name.startswith("unmapped:"):
            unmapped.append(
                {
                    "rule_id": record.rule_id,
                    "tool": record.tool,
                    "type": record.scanner_type,
                    "artifact": record.artifact,
                    "url": record.url,
                    "reason": "DAST URL did not map to a supplied SBOM artifact or deployment workload",
                    "match": mapping.match_json(),
                    "mapping_confidence": mapping.confidence.value,
                }
            )
        context = context_for_security_record(contexts.get(artifact.name, ContextEvidence()), record, artifact.name)
        finding = score_finding(
            SbomDocument(path=Path("security-evidence"), artifact=artifact, components=[]),
            _component_for_record(record),
            _vulnerability_for_record(record),
            source_for_security_record(record),
            context,
            policy,
        )
        finding.key = _finding_key(artifact, record)
        finding.finding_type = _finding_type_for_record(record)
        finding.weakness = _weakness_json(record)
        finding.fix_commands = [record.remediation] if record.remediation else []
        finding.runtime_evidence = runtime_for_security_record(record)
        finding.input_sources = [_input_source(record)]
        finding.unknowns = _unknowns_for_record(record, mapping)
        finding.evidence_summary = _evidence_summary(record, finding)
        finding.score_details["finding_type"] = finding.finding_type
        finding.score_details["security_evidence"] = _weakness_json(record)
        score_security_finding(finding, record)
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


def _component_for_record(record: SecurityEvidenceRecord) -> Component:
    source_path = str(record.source.path) if record.source else None
    name = record.component or record.route or source_path or record.url or record.weakness
    finding_type = _finding_type_for_record(record)
    return Component(
        name=str(name),
        scope="runtime",
        properties={
            "finding_type": finding_type,
            "scanner:type": record.scanner_type,
            "scanner:tool": record.tool,
            "scanner:rule_id": record.rule_id,
            "source:path": source_path or "",
            "route": record.route or "",
            "url": record.url or "",
        },
    )


def _vulnerability_for_record(record: SecurityEvidenceRecord) -> VulnerabilityRecord:
    finding_type = _finding_type_for_record(record)
    return VulnerabilityRecord(
        id=record.rule_id,
        package_name="first-party-code",
        aliases=[record.cwe] if record.cwe else [],
        severity=record.severity,
        cvss=record.cvss,
        summary=record.message or record.weakness,
        references=record.references,
        intelligence={
            "finding_type": finding_type,
            "scanner_type": record.scanner_type,
            "tool": record.tool,
            "weakness": record.weakness,
            "cwe": record.cwe,
            "url": record.url,
            "method": record.method,
            "route": record.route,
        },
    )


def _finding_type_for_record(record: SecurityEvidenceRecord) -> str:
    return DYNAMIC_RUNTIME_OBSERVATION if record.scanner_type == "dast" else STATIC_CODE_WEAKNESS


def _input_source(record: SecurityEvidenceRecord) -> dict[str, Any]:
    return {
        "kind": "security_evidence",
        "scanner_type": record.scanner_type,
        "tool": record.tool,
        "path": record.input_path,
        "rule_id": record.rule_id,
    }


def _unknowns_for_record(record: SecurityEvidenceRecord, mapping: SecurityEvidenceMappingDecision) -> list[str]:
    unknowns: list[str] = []
    if record.scanner_type == "dast" and not record.source:
        unknowns.append("source mapping unavailable")
    if record.scanner_type == "dast" and mapping.confidence == Confidence.LOW and not record.artifact:
        unknowns.append("artifact mapping unavailable or weak one-SBOM fallback")
    if record.scanner_type == "dast" and not record.authentication_context:
        unknowns.append("authentication context unavailable")
    return unknowns


def _evidence_summary(record: SecurityEvidenceRecord, finding: Finding) -> list[str]:
    summary = [f"{record.scanner_type.upper()} {record.tool} reported {record.rule_id}"]
    if record.scanner_type == "dast" and record.url:
        summary.append(f"Runtime URL observed: {record.method or 'HTTP'} {record.url}")
    if finding.source.locations:
        summary.append(f"Source location: {finding.source.locations[0].path}:{finding.source.locations[0].line}")
    return summary


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
        "parameter": record.parameter,
        "route": record.route,
        "sink": record.sink,
        "dataflow": record.dataflow,
        "remediation": record.remediation,
        "profiles": list(profile_ids),
    }


def _finding_key(artifact: Artifact, record: SecurityEvidenceRecord) -> str:
    location = f"{record.source.path}:{record.source.line}" if record.source else record.url or record.route or ""
    return "|".join(["code", artifact.name, record.rule_id, _stable_token(location)])


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
