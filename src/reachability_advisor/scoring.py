"""Explainable scoring engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import (
    Component,
    Confidence,
    ContextEvidence,
    Finding,
    Reachability,
    SbomDocument,
    SourceEvidence,
    Tier,
    VulnerabilityRecord,
    finding_key,
)
from .source import ReachabilityRule, analyze_component_source
from .vulnerability import matching_vulnerabilities


@dataclass(frozen=True)
class ScorePolicy:
    tier_thresholds: dict[Tier, float] = field(
        default_factory=lambda: {
            Tier.URGENT: 85.0,
            Tier.HIGH: 65.0,
            Tier.MEDIUM: 40.0,
            Tier.LOW: 20.0,
            Tier.INFORMATIONAL: 0.0,
        }
    )
    severity_points: dict[str, float] = field(
        default_factory=lambda: {"critical": 40.0, "high": 30.0, "medium": 18.0, "low": 8.0, "unknown": 10.0}
    )
    reachability_points: dict[Reachability, float] = field(
        default_factory=lambda: {
            Reachability.ABSENT: -10.0,
            Reachability.PACKAGE_PRESENT: 4.0,
            Reachability.IMPORTED: 14.0,
            Reachability.FUNCTION_REACHABLE: 24.0,
            Reachability.ATTACKER_CONTROLLED: 34.0,
        }
    )
    scope_adjustments: dict[str, float] = field(
        default_factory=lambda: {"runtime": 0.0, "test": -18.0, "dev": -18.0, "development": -18.0, "provided": -8.0, "optional": -8.0}
    )
    exposure_points: dict[str, float] = field(
        default_factory=lambda: {"public": 16.0, "external": 12.0, "internal": 5.0, "private": 3.0, "none": 0.0, "unknown": 0.0}
    )
    environment_points: dict[str, float] = field(
        default_factory=lambda: {"prod": 12.0, "production": 12.0, "staging": 5.0, "dev": 1.0, "development": 1.0, "unknown": 0.0}
    )
    privilege_points: dict[str, float] = field(
        default_factory=lambda: {"admin": 18.0, "sensitive": 12.0, "limited": 4.0, "none": 0.0, "unknown": 0.0}
    )
    criticality_points: dict[str, float] = field(
        default_factory=lambda: {"high": 10.0, "medium": 5.0, "low": 1.0, "unknown": 0.0}
    )


DEFAULT_POLICY = ScorePolicy()


def _severity_score(vulnerability: VulnerabilityRecord, policy: ScorePolicy) -> tuple[float, str]:
    if vulnerability.cvss is not None:
        return min(40.0, max(0.0, vulnerability.cvss * 4.0)), f"CVSS {vulnerability.cvss}"
    severity = vulnerability.severity.lower()
    return policy.severity_points.get(severity, policy.severity_points["unknown"]), f"severity {severity}"


def _epss_points(epss: float | None) -> float:
    if epss is None:
        return 0.0
    if epss >= 0.8:
        return 12.0
    if epss >= 0.5:
        return 8.0
    if epss >= 0.2:
        return 4.0
    return 0.0


def tier_for_score(score: float, policy: ScorePolicy = DEFAULT_POLICY) -> Tier:
    if score >= policy.tier_thresholds[Tier.URGENT]:
        return Tier.URGENT
    if score >= policy.tier_thresholds[Tier.HIGH]:
        return Tier.HIGH
    if score >= policy.tier_thresholds[Tier.MEDIUM]:
        return Tier.MEDIUM
    if score >= policy.tier_thresholds[Tier.LOW]:
        return Tier.LOW
    return Tier.INFORMATIONAL


def _confidence(source: SourceEvidence, context: ContextEvidence) -> Confidence:
    if source.confidence == Confidence.HIGH and context.confidence in {Confidence.MEDIUM, Confidence.HIGH}:
        return Confidence.HIGH
    if source.confidence == Confidence.HIGH:
        return Confidence.MEDIUM
    if context.confidence == Confidence.HIGH and source.confidence == Confidence.MEDIUM:
        return Confidence.HIGH
    if context.confidence == Confidence.HIGH:
        return Confidence.MEDIUM
    if source.confidence == Confidence.MEDIUM and context.confidence in {Confidence.MEDIUM, Confidence.HIGH}:
        return Confidence.HIGH if context.confidence == Confidence.HIGH else Confidence.MEDIUM
    if source.confidence == Confidence.MEDIUM:
        return Confidence.MEDIUM
    if context.confidence == Confidence.MEDIUM:
        return Confidence.MEDIUM
    return Confidence.LOW


def _private_no_ingress_cap_applies(vulnerability: VulnerabilityRecord, source: SourceEvidence, context: ContextEvidence) -> bool:
    exposure = (context.exposure or "unknown").lower()
    privilege = (context.privilege or "unknown").lower()
    criticality = (context.criticality or "unknown").lower()
    return (
        exposure in {"private", "none"}
        and source.reachability != Reachability.ATTACKER_CONTROLLED
        and not vulnerability.known_exploited
        and privilege not in {"admin", "sensitive"}
        and criticality != "high"
        and not context.iam_impacts
    )


def fix_commands(component: Component, vulnerability: VulnerabilityRecord) -> list[str]:
    if not vulnerability.fixed_versions:
        return []
    fixed = vulnerability.fixed_versions[0]
    purl = component.purl or ""
    if purl.startswith("pkg:npm/"):
        return [f"npm install {component.name}@{fixed}"]
    if purl.startswith("pkg:pypi/"):
        return [f"python -m pip install --upgrade {component.name}=={fixed}"]
    if purl.startswith("pkg:maven/"):
        display = component.display_name.replace("/", ":")
        return [f"Set Maven dependency {display} to version {fixed}"]
    return [f"Upgrade {component.name} to {fixed}"]


def score_finding(
    sbom: SbomDocument,
    component: Component,
    vulnerability: VulnerabilityRecord,
    source: SourceEvidence,
    context: ContextEvidence,
    policy: ScorePolicy = DEFAULT_POLICY,
) -> Finding:
    score, severity_reason = _severity_score(vulnerability, policy)
    rationale = [f"{severity_reason} contributes {score:.1f} points"]
    if vulnerability.known_exploited:
        score += 22.0
        rationale.append("known exploited vulnerability contributes 22.0 points")
    epss_points = _epss_points(vulnerability.epss)
    if epss_points:
        score += epss_points
        rationale.append(f"EPSS {vulnerability.epss} contributes {epss_points:.1f} points")
    reach_points = policy.reachability_points[source.reachability]
    score += reach_points
    rationale.append(f"source reachability {source.reachability.value} contributes {reach_points:.1f} points")
    scope_adjust = policy.scope_adjustments.get(component.scope, 0.0)
    if scope_adjust:
        # Do not heavily demote a test/dev component if we observed attacker-controlled source usage.
        if source.reachability == Reachability.ATTACKER_CONTROLLED:
            scope_adjust = min(0.0, scope_adjust / 3.0)
        score += scope_adjust
        rationale.append(f"dependency scope {component.scope} adjusts score by {scope_adjust:.1f} points")
    for label, table, value in (
        ("exposure", policy.exposure_points, context.exposure),
        ("environment", policy.environment_points, context.environment),
        ("privilege", policy.privilege_points, context.privilege),
        ("criticality", policy.criticality_points, context.criticality),
    ):
        points = table.get((value or "unknown").lower(), 0.0)
        if points:
            score += points
            rationale.append(f"{label} {value} contributes {points:.1f} points")
    if source.reachability == Reachability.PACKAGE_PRESENT and component.scope in {"test", "dev", "development"}:
        score = min(score, 39.0)
        rationale.append("dev/test dependency without source usage is capped below high priority")
    if _private_no_ingress_cap_applies(vulnerability, source, context):
        score = min(score, policy.tier_thresholds[Tier.HIGH] - 1.0)
        rationale.append("private/no-ingress finding without attacker-controlled source, known exploitation, privilege, IAM impact, or high criticality is capped below high priority")
    if source.reachability == Reachability.PACKAGE_PRESENT and context.exposure == "unknown":
        score -= 6.0
        rationale.append("weak evidence penalty subtracts 6.0 points")
    score = max(0.0, min(100.0, score))
    return Finding(
        key=finding_key(sbom.artifact, component, vulnerability),
        artifact=sbom.artifact,
        component=component,
        vulnerability=vulnerability,
        source=source,
        context=context,
        score=score,
        tier=tier_for_score(score, policy),
        confidence=_confidence(source, context),
        rationale=rationale,
        fix_commands=fix_commands(component, vulnerability),
    )


def generate_findings(
    sboms: list[SbomDocument],
    vulnerabilities: list[VulnerabilityRecord],
    source_roots: dict[str, object],
    contexts: dict[str, ContextEvidence],
    policy: ScorePolicy = DEFAULT_POLICY,
    reachability_rules: tuple[ReachabilityRule, ...] = (),
) -> list[Finding]:
    findings: list[Finding] = []
    for sbom in sboms:
        root = source_roots.get(sbom.artifact.name)
        context = contexts.get(sbom.artifact.name, ContextEvidence())
        for component in sbom.components:
            matches = matching_vulnerabilities(component, vulnerabilities)
            if not matches:
                continue
            for vulnerability in matches:
                source = analyze_component_source(component, root, vulnerability=vulnerability, custom_rules=reachability_rules)  # type: ignore[arg-type]
                findings.append(score_finding(sbom, component, vulnerability, source, context, policy))
    return sorted(findings, key=lambda finding: finding.score, reverse=True)
