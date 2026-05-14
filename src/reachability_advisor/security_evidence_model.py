"""Shared model for imported SAST/DAST scanner evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Confidence, SourceLocation


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
    parameter: str | None = None
    request_evidence: str | None = None
    response_evidence: str | None = None
    authentication_context: str | None = None
    route: str | None = None
    source: SourceLocation | None = None
    sink: str | None = None
    dataflow: str | None = None
    exposure: str | None = None
    provider: str | None = None
    resource_id: str | None = None
    resource_type: str | None = None
    service: str | None = None
    control: str | None = None
    expected: str | None = None
    actual: str | None = None
    evidence_source: str | None = None
    blockers: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    input_path: str | None = None


class SecurityEvidenceError(ValueError):
    """Raised when SAST/DAST evidence cannot be parsed."""


__all__ = ["SecurityEvidenceError", "SecurityEvidenceRecord"]
