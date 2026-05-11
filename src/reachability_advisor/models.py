"""Typed data model for Reachability Advisor.

The project intentionally keeps the model small.  The tool is meant to be
embeddable in CI pipelines and editor integrations, so the primary objects are
SBOM components, vulnerability records, source evidence, deployment context,
and findings.
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Reachability(str, Enum):
    """Conservative source reachability states.

    These states do not prove exploitability. They represent increasing levels
    of static source evidence that the dependency is used by the application.
    """

    ABSENT = "absent"
    UNKNOWN_DUE_TO_NO_RULE = "unknown_due_to_no_rule"
    PACKAGE_PRESENT = "package_present"
    DEPENDENCY_REACHABLE = "dependency_reachable"
    IMPORTED = "imported"
    FUNCTION_REACHABLE = "function_reachable"
    ATTACKER_CONTROLLED = "attacker_controlled"


REACHABILITY_LABELS: dict[Reachability, str] = {
    Reachability.ABSENT: "absent from scanned source",
    Reachability.UNKNOWN_DUE_TO_NO_RULE: "no source rule",
    Reachability.PACKAGE_PRESENT: "SBOM only",
    Reachability.DEPENDENCY_REACHABLE: "dependency evidence",
    Reachability.IMPORTED: "import observed",
    Reachability.FUNCTION_REACHABLE: "reachable vulnerable API",
    Reachability.ATTACKER_CONTROLLED: "request-controlled path",
}


def reachability_label(reachability: Reachability | str) -> str:
    try:
        state = reachability if isinstance(reachability, Reachability) else Reachability(str(reachability))
    except ValueError:
        return "unknown source reachability"
    return REACHABILITY_LABELS[state]


class Tier(str, Enum):
    URGENT = "urgent"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class PackageUrl:
    """Small package-url representation.

    It is intentionally partial. We only normalize fields required for matching
    components against vulnerability intelligence and source-analysis rules.
    """

    raw: str
    ptype: str | None = None
    namespace: str | None = None
    name: str | None = None
    version: str | None = None

    @property
    def ecosystem(self) -> str:
        mapping = {"maven": "maven", "npm": "npm", "pypi": "pypi", "golang": "go", "gem": "ruby"}
        return mapping.get((self.ptype or "").lower(), (self.ptype or "unknown").lower())


@dataclass
class Component:
    name: str
    version: str | None = None
    purl: str | None = None
    scope: str = "runtime"
    group: str | None = None
    bom_ref: str | None = None
    properties: dict[str, str] = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        return f"{self.group + '/' if self.group else ''}{self.name}"


@dataclass
class Artifact:
    name: str
    reference: str | None = None
    version: str | None = None
    bom_ref: str | None = None
    properties: dict[str, str] = field(default_factory=dict)


@dataclass
class SbomDocument:
    path: Path
    artifact: Artifact
    components: list[Component]
    dependencies: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class VulnerabilityRecord:
    id: str
    package_name: str
    artifact_name: str | None = None
    package_purl: str | None = None
    affected_versions: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    severity: str = "unknown"
    cvss: float | None = None
    epss: float | None = None
    known_exploited: bool = False
    fixed_versions: list[str] = field(default_factory=list)
    summary: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class SourceLocation:
    path: Path
    line: int
    column: int = 1
    snippet: str = ""

    def to_json(self, root: Path | None = None) -> dict[str, Any]:
        path = self.path
        if root:
            with suppress(ValueError):
                path = path.relative_to(root)
        return {"path": str(path), "line": self.line, "column": self.column, "snippet": self.snippet}


@dataclass
class SourceEvidence:
    reachability: Reachability = Reachability.PACKAGE_PRESENT
    confidence: Confidence = Confidence.LOW
    language: str = "unknown"
    reason: str = "component appears in SBOM"
    locations: list[SourceLocation] = field(default_factory=list)
    matched_symbols: list[str] = field(default_factory=list)
    dependency_path: list[str] = field(default_factory=list)
    evidence_source: str = "builtin"
    diagnostics: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ContextEvidence:
    environment: str = "unknown"
    exposure: str = "unknown"
    privilege: str = "unknown"
    criticality: str = "unknown"
    iam_impacts: list[str] = field(default_factory=list)
    iam_capabilities: list[dict[str, Any]] = field(default_factory=list)
    owner: str | None = None
    source: str = "none"
    confidence: Confidence = Confidence.LOW
    evidence: list[str] = field(default_factory=list)


@dataclass
class Finding:
    key: str
    artifact: Artifact
    component: Component
    vulnerability: VulnerabilityRecord
    source: SourceEvidence
    context: ContextEvidence
    score: float
    tier: Tier
    confidence: Confidence
    rationale: list[str]
    fix_commands: list[str] = field(default_factory=list)
    policy_status: str = "active"
    score_details: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "artifact": {
                "name": self.artifact.name,
                "reference": self.artifact.reference,
                "version": self.artifact.version,
                "bom_ref": self.artifact.bom_ref,
                "properties": self.artifact.properties,
            },
            "component": {
                "name": self.component.name,
                "display_name": self.component.display_name,
                "version": self.component.version,
                "purl": self.component.purl,
                "scope": self.component.scope,
                "group": self.component.group,
                "properties": self.component.properties,
            },
            "vulnerability": {
                "id": self.vulnerability.id,
                "aliases": self.vulnerability.aliases,
                "severity": self.vulnerability.severity,
                "cvss": self.vulnerability.cvss,
                "epss": self.vulnerability.epss,
                "known_exploited": self.vulnerability.known_exploited,
                "fixed_versions": self.vulnerability.fixed_versions,
                "summary": self.vulnerability.summary,
                "references": self.vulnerability.references,
            },
            "source_reachability": {
                "state": self.source.reachability.value,
                "label": reachability_label(self.source.reachability),
                "confidence": self.source.confidence.value,
                "language": self.source.language,
                "reason": self.source.reason,
                "matched_symbols": self.source.matched_symbols,
                "dependency_path": self.source.dependency_path,
                "evidence_source": self.source.evidence_source,
                "diagnostics": self.source.diagnostics,
                "locations": [location.to_json() for location in self.source.locations],
            },
            "context": {
                "environment": self.context.environment,
                "exposure": self.context.exposure,
                "privilege": self.context.privilege,
                "criticality": self.context.criticality,
                "iam_impacts": self.context.iam_impacts,
                "iam_capabilities": self.context.iam_capabilities,
                "owner": self.context.owner,
                "source": self.context.source,
                "confidence": self.context.confidence.value,
                "evidence": self.context.evidence,
            },
            "scoring": self.score_details,
            "score": round(self.score, 2),
            "tier": self.tier.value,
            "confidence": self.confidence.value,
            "rationale": self.rationale,
            "fix_commands": self.fix_commands,
            "policy_status": self.policy_status,
        }


def finding_key(artifact: Artifact, component: Component, vulnerability: VulnerabilityRecord) -> str:
    return "|".join([artifact.name, component.name, component.version or "", vulnerability.id])
