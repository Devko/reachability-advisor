"""Explainable scoring engine."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .effective_exposure import best_effective_exposure, evaluate_effective_exposure
from .effective_graph import scoring_path_summary
from .iam_capabilities import (
    CRITICAL_CAPABILITY_IMPACTS,
    capability_risk_multiplier,
    dedupe_iam_capabilities,
)
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
    reachability_label,
)
from .source import (
    ExternalSourceEvidenceStore,
    ReachabilityRule,
    analyze_component_source,
    build_source_index,
    merge_source_evidence,
    source_coverage_report,
)
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
            Reachability.UNKNOWN_DUE_TO_NO_RULE: 0.0,
            Reachability.PACKAGE_PRESENT: 1.0,
            Reachability.DEPENDENCY_REACHABLE: 4.0,
            Reachability.IMPORTED: 8.0,
            Reachability.FUNCTION_REACHABLE: 16.0,
            Reachability.ATTACKER_CONTROLLED: 26.0,
        }
    )
    scope_adjustments: dict[str, float] = field(
        default_factory=lambda: {"runtime": 0.0, "test": -18.0, "dev": -18.0, "development": -18.0, "provided": -8.0, "optional": -8.0}
    )
    exposure_points: dict[str, float] = field(
        default_factory=lambda: {"public": 14.0, "external": 10.0, "internal": 5.0, "private": 0.0, "none": 0.0, "unknown": 0.0}
    )
    environment_points: dict[str, float] = field(
        default_factory=lambda: {"prod": 4.0, "production": 4.0, "staging": 2.0, "dev": 0.0, "development": 0.0, "unknown": 0.0}
    )
    privilege_points: dict[str, float] = field(
        default_factory=lambda: {"admin": 16.0, "sensitive": 10.0, "limited": 3.0, "none": 0.0, "unknown": 0.0}
    )
    criticality_points: dict[str, float] = field(
        default_factory=lambda: {"high": 13.0, "medium": 6.0, "low": 1.0, "unknown": 0.0}
    )
    iam_impact_points: dict[str, float] = field(
        default_factory=lambda: {
            "admin_control": 22.0,
            "iam_escalation": 20.0,
            "network_control": 18.0,
            "compute_control": 16.0,
            "data_access": 12.0,
            "limited_access": 3.0,
        }
    )


DEFAULT_POLICY = ScorePolicy()
SCORING_MODEL_VERSION = "2026-05-11"


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
    if source.confidence == Confidence.HIGH:
        return Confidence.HIGH if context.confidence in {Confidence.MEDIUM, Confidence.HIGH} else Confidence.MEDIUM
    if context.confidence == Confidence.HIGH and source.confidence == Confidence.MEDIUM:
        return Confidence.HIGH
    if context.confidence == Confidence.HIGH:
        return Confidence.MEDIUM
    if source.confidence == Confidence.MEDIUM or context.confidence == Confidence.MEDIUM:
        return Confidence.MEDIUM
    return Confidence.LOW


WEAK_SOURCE_STATES = {Reachability.ABSENT, Reachability.UNKNOWN_DUE_TO_NO_RULE, Reachability.PACKAGE_PRESENT}


def _normalized(value: str | None, default: str = "unknown") -> str:
    return (value or default).lower()


def _high_exploit_signal(vulnerability: VulnerabilityRecord) -> bool:
    return vulnerability.known_exploited or (vulnerability.epss is not None and vulnerability.epss >= 0.5)


def _context_impact(context: ContextEvidence, policy: ScorePolicy) -> tuple[float, str]:
    candidates: list[tuple[float, str]] = []
    privilege = _normalized(context.privilege)
    privilege_points = policy.privilege_points.get(privilege, 0.0)
    if privilege_points:
        candidates.append((privilege_points, f"privilege {privilege}"))
    criticality = _normalized(context.criticality)
    criticality_points = policy.criticality_points.get(criticality, 0.0)
    if criticality_points:
        candidates.append((criticality_points, f"criticality {criticality}"))
    normalized_capabilities = dedupe_iam_capabilities(context.iam_capabilities)
    capability_impacts = {
        _normalized(str(capability.get("impact") or ""), "")
        for capability in normalized_capabilities
        if str(capability.get("effect") or "allow").lower() == "allow"
    }
    for impact in context.iam_impacts:
        impact_name = _normalized(impact, "")
        if impact_name in capability_impacts:
            # Aggregate iam_impacts still drive concise report labels. When a
            # concrete capability exists, score that capability once instead
            # of double-counting the same blast-radius signal.
            continue
        impact_points = policy.iam_impact_points.get(impact_name, 0.0)
        if impact_points:
            candidates.append((impact_points, f"IAM impact {impact_name}"))
    for capability in normalized_capabilities:
        if str(capability.get("effect") or "allow").lower() != "allow":
            continue
        impact_name = _normalized(str(capability.get("impact") or ""), "")
        impact_points = policy.iam_impact_points.get(impact_name, 0.0)
        if impact_points:
            # A scoped secret read and an unbounded secret read share the same
            # impact class, but they should not receive the same score. The
            # capability multiplier carries that scope/condition distinction.
            adjusted_points = impact_points * capability_risk_multiplier(capability)
            action = str(capability.get("action") or "unknown")
            effective_risk = str(capability.get("effective_risk") or "unknown")
            candidates.append((adjusted_points, f"IAM capability {impact_name}:{action} ({effective_risk})"))
    if not candidates:
        return 0.0, ""
    return max(candidates, key=lambda item: item[0])


def _has_critical_context(context: ContextEvidence) -> bool:
    privilege = _normalized(context.privilege)
    criticality = _normalized(context.criticality)
    iam_impacts = {_normalized(impact, "") for impact in context.iam_impacts}
    capability_impacts = {
        _normalized(str(capability.get("impact") or ""), "")
        for capability in dedupe_iam_capabilities(context.iam_capabilities)
        if str(capability.get("effect") or "allow").lower() == "allow"
    }
    return (
        privilege in {"admin", "sensitive"}
        or criticality == "high"
        or bool(iam_impacts & {"admin_control", "iam_escalation", "network_control", "compute_control", "data_access"})
        or bool(capability_impacts & CRITICAL_CAPABILITY_IMPACTS)
    )


def _urgent_gate_satisfied(vulnerability: VulnerabilityRecord, source: SourceEvidence, context: ContextEvidence) -> bool:
    exposure = _normalized(context.exposure)
    if _high_exploit_signal(vulnerability):
        return True
    if source.reachability == Reachability.ATTACKER_CONTROLLED and exposure in {"public", "external"}:
        return True
    if source.reachability == Reachability.ATTACKER_CONTROLLED and _has_critical_context(context):
        return True
    return source.reachability == Reachability.FUNCTION_REACHABLE and exposure in {"public", "external"} and _has_critical_context(context)


def _private_no_ingress_cap_applies(vulnerability: VulnerabilityRecord, source: SourceEvidence, context: ContextEvidence) -> bool:
    return (
        _normalized(context.exposure) in {"private", "none"}
        and source.reachability != Reachability.ATTACKER_CONTROLLED
        and not _high_exploit_signal(vulnerability)
        and not _has_critical_context(context)
    )


def _network_blocker_effects(context: ContextEvidence) -> set[str]:
    effects: set[str] = set()
    for record in _effective_exposure_records(context):
        network = record.get("network") if isinstance(record, dict) else None
        network_record = network if isinstance(network, dict) else record
        decision = _normalized(str(network_record.get("decision") or ""), "")
        if decision == "blocked":
            effects.add("blocks")
        elif decision == "constrained":
            effects.add("constrains")
        elif decision == "unknown":
            effects.add("unknown")
        for blocker in network_record.get("blockers", []) if isinstance(network_record.get("blockers"), list) else []:
            if isinstance(blocker, dict):
                effect = _normalized(str(blocker.get("effect") or ""), "")
                effects.add(effect if effect in {"blocks", "constrains"} else "unknown")
    for path in context.network_paths:
        blockers = path.get("blockers")
        if not isinstance(blockers, list):
            continue
        for blocker in blockers:
            if not isinstance(blocker, dict):
                continue
            effect = _normalized(str(blocker.get("effect") or ""), "")
            effects.add(effect if effect in {"blocks", "constrains"} else "unknown")
    return effects


def _effective_exposure_records(context: ContextEvidence) -> list[dict[str, Any]]:
    if context.effective_exposure:
        return [dict(item) for item in context.effective_exposure if isinstance(item, dict)]
    return evaluate_effective_exposure("unknown", context)


def _low_confidence_network_paths(context: ContextEvidence) -> bool:
    best = best_effective_exposure(context)
    network = best.get("network") if isinstance(best, dict) else None
    if isinstance(network, dict) and str(network.get("confidence") or "").lower() == "low":
        return True
    return bool(context.network_paths) and all(_normalized(str(path.get("confidence") or ""), "") == "low" for path in context.network_paths)


def _low_confidence_effective_access(context: ContextEvidence) -> bool:
    records = [record for record in context.effective_access if str(record.get("effect") or "allow").lower() == "allow"]
    return bool(records) and all(_normalized(str(record.get("confidence") or ""), "") == "low" for record in records)


def _score_caps(vulnerability: VulnerabilityRecord, source: SourceEvidence, context: ContextEvidence, policy: ScorePolicy) -> list[tuple[float, str]]:
    caps: list[tuple[float, str]] = []
    below_high = policy.tier_thresholds[Tier.HIGH] - 1.0
    below_urgent = policy.tier_thresholds[Tier.URGENT] - 1.0
    exposure = _normalized(context.exposure)
    exploit_signal = _high_exploit_signal(vulnerability)
    network_effects = _network_blocker_effects(context)

    if source.reachability in WEAK_SOURCE_STATES:
        if exploit_signal:
            caps.append((below_urgent, "weak source evidence keeps the finding below urgent until source usage is proven"))
        else:
            caps.append((below_high, "weak source evidence keeps the finding below high until source usage, known exploitation, or high EPSS is observed"))
    elif source.reachability == Reachability.DEPENDENCY_REACHABLE and not exploit_signal:
        if exposure not in {"public", "external"} or not _has_critical_context(context):
            caps.append((below_high, "dependency-graph source evidence without public/external critical context is capped below high"))
        else:
            caps.append((below_urgent, "dependency-graph source evidence is capped below urgent until direct vulnerable API usage is observed"))
    elif source.reachability == Reachability.IMPORTED and not exploit_signal:
        if exposure not in {"public", "external"} or not _has_critical_context(context):
            caps.append((below_high, "import-only source evidence without public/external critical context is capped below high"))
        else:
            caps.append((below_urgent, "import-only source evidence is capped below urgent until vulnerable API usage is observed"))

    if _private_no_ingress_cap_applies(vulnerability, source, context):
        caps.append((below_high, "private/no-ingress finding without exploit signal or critical context is capped below high"))
    if "blocks" in network_effects and not exploit_signal:
        caps.append((below_high, "confirmed network blocker keeps the finding below high until the ingress path is proven reachable"))
    elif network_effects & {"constrains", "unknown"} and not exploit_signal:
        caps.append((below_urgent, "network blocker uncertainty keeps the finding below urgent until the effective path is proven reachable"))
    if _low_confidence_network_paths(context) and not exploit_signal:
        caps.append((below_urgent, "low-confidence network path keeps the finding below urgent until deployment evidence is stronger"))
    if _low_confidence_effective_access(context) and not exploit_signal:
        caps.append((below_urgent, "low-confidence IAM effective access keeps the finding below urgent until permission evidence is stronger"))
    if not _urgent_gate_satisfied(vulnerability, source, context):
        caps.append((below_urgent, "urgent requires known exploitation, high EPSS, request-controlled public/external code, or critical reachable context"))
    return caps


def _score_dimension(name: str, value: Any, points: float, reason: str) -> dict[str, Any]:
    return {
        "name": name,
        "value": str(value),
        "points": round(points, 2),
        "reason": reason,
    }


def _score_gate(name: str, status: str, reason: str, cap: float | None = None) -> dict[str, Any]:
    gate: dict[str, Any] = {"name": name, "status": status, "reason": reason}
    if cap is not None:
        gate["cap"] = round(cap, 2)
    return gate


def _gate_name(reason: str) -> str:
    if "dev/test dependency" in reason:
        return "dev_test_without_usage"
    if "weak source evidence" in reason:
        return "weak_source_evidence"
    if "dependency-graph source evidence" in reason:
        return "dependency_graph_evidence"
    if "import-only source evidence" in reason:
        return "import_only_evidence"
    if "private/no-ingress" in reason:
        return "private_no_ingress"
    if "network blocker" in reason:
        return "network_blocker"
    if "low-confidence network" in reason:
        return "low_confidence_network"
    if "low-confidence IAM" in reason:
        return "low_confidence_iam"
    if "urgent requires" in reason:
        return "urgent_gate"
    return "priority_cap"


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
    dimensions = [_score_dimension("severity", vulnerability.cvss if vulnerability.cvss is not None else vulnerability.severity, score, severity_reason)]
    gates: list[dict[str, Any]] = []
    rationale = [f"{severity_reason} contributes {score:.1f} points"]
    if vulnerability.known_exploited:
        score += 22.0
        dimensions.append(_score_dimension("known_exploited", True, 22.0, "known exploited vulnerability"))
        rationale.append("known exploited vulnerability contributes 22.0 points")
    epss_points = _epss_points(vulnerability.epss)
    if epss_points:
        score += epss_points
        dimensions.append(_score_dimension("epss", vulnerability.epss, epss_points, "exploit probability signal"))
        rationale.append(f"EPSS {vulnerability.epss} contributes {epss_points:.1f} points")
    reach_points = policy.reachability_points[source.reachability]
    score += reach_points
    dimensions.append(_score_dimension("source_reachability", source.reachability.value, reach_points, reachability_label(source.reachability)))
    rationale.append(f"source reachability {source.reachability.value} contributes {reach_points:.1f} points")
    scope_adjust = policy.scope_adjustments.get(component.scope, 0.0)
    if scope_adjust:
        # Do not heavily demote a test/dev component if we observed attacker-controlled source usage.
        if source.reachability == Reachability.ATTACKER_CONTROLLED:
            scope_adjust = min(0.0, scope_adjust / 3.0)
        score += scope_adjust
        dimensions.append(_score_dimension("dependency_scope", component.scope, scope_adjust, "dependency scope adjustment"))
        rationale.append(f"dependency scope {component.scope} adjusts score by {scope_adjust:.1f} points")
    exposure_value = context.exposure or "unknown"
    exposure_points = policy.exposure_points.get(exposure_value.lower(), 0.0)
    network_effects = _network_blocker_effects(context)
    if exposure_points:
        if "blocks" in network_effects:
            dimensions.append(_score_dimension("exposure", exposure_value, 0.0, "exposure path blocked by network evidence"))
            rationale.append(f"exposure {exposure_value} contributes 0.0 points because a network blocker is present")
        else:
            adjusted_exposure_points = exposure_points
            exposure_reason = "exposure context"
            if "constrains" in network_effects:
                adjusted_exposure_points = exposure_points * 0.7
                exposure_reason = "exposure context constrained by auth/WAF/firewall evidence"
            elif "unknown" in network_effects:
                adjusted_exposure_points = exposure_points * 0.85
                exposure_reason = "exposure context has unresolved network blocker semantics"
            score += adjusted_exposure_points
            dimensions.append(_score_dimension("exposure", exposure_value, adjusted_exposure_points, exposure_reason))
            rationale.append(f"exposure {exposure_value} contributes {adjusted_exposure_points:.1f} points")
    environment_points = policy.environment_points.get((context.environment or "unknown").lower(), 0.0)
    if environment_points:
        score += environment_points
        dimensions.append(_score_dimension("environment", context.environment, environment_points, "environment context"))
        rationale.append(f"environment {context.environment} contributes {environment_points:.1f} points")
    context_points, context_reason = _context_impact(context, policy)
    if context_points:
        score += context_points
        dimensions.append(_score_dimension("context_impact", context_reason, context_points, "strongest privilege/IAM/criticality signal"))
        rationale.append(f"highest context impact ({context_reason}) contributes {context_points:.1f} points")
    if source.reachability in {Reachability.PACKAGE_PRESENT, Reachability.UNKNOWN_DUE_TO_NO_RULE} and component.scope in {"test", "dev", "development"}:
        uncapped_score = score
        score = min(score, 39.0)
        gates.append(_score_gate("dev_test_without_usage", "capped" if uncapped_score > score else "passed", "dev/test dependency without source usage is capped below medium priority", 39.0))
        rationale.append("dev/test dependency without source usage is capped below medium priority")
    for cap, reason in _score_caps(vulnerability, source, context, policy):
        if score > cap:
            score = cap
            gates.append(_score_gate(_gate_name(reason), "capped", reason, cap))
            rationale.append(f"{reason}; score capped at {cap:.1f}")
        else:
            gates.append(_score_gate(_gate_name(reason), "passed", reason, cap))
            if reason.startswith("urgent requires"):
                continue
            rationale.append(f"{reason}; score remains below cap")
    score = max(0.0, min(100.0, score))
    tier = tier_for_score(score, policy)
    finding = Finding(
        key=finding_key(sbom.artifact, component, vulnerability),
        artifact=sbom.artifact,
        component=component,
        vulnerability=vulnerability,
        source=source,
        context=context,
        score=score,
        tier=tier,
        confidence=_confidence(source, context),
        rationale=rationale,
        fix_commands=fix_commands(component, vulnerability),
        score_details={
            "model_version": SCORING_MODEL_VERSION,
            "dimensions": dimensions,
            "gates": gates,
            "final_score": round(score, 2),
            "tier": tier.value,
        },
    )
    finding.score_details["effective_exposure_path"] = scoring_path_summary(finding)
    return finding


def generate_findings(
    sboms: list[SbomDocument],
    vulnerabilities: list[VulnerabilityRecord],
    source_roots: Mapping[str, Path],
    contexts: dict[str, ContextEvidence],
    policy: ScorePolicy = DEFAULT_POLICY,
    reachability_rules: tuple[ReachabilityRule, ...] = (),
    external_source_evidence: ExternalSourceEvidenceStore | None = None,
) -> list[Finding]:
    findings, _ = generate_findings_with_source_report(
        sboms,
        vulnerabilities,
        source_roots,
        contexts,
        policy=policy,
        reachability_rules=reachability_rules,
        external_source_evidence=external_source_evidence,
    )
    return findings


def generate_findings_with_source_report(
    sboms: list[SbomDocument],
    vulnerabilities: list[VulnerabilityRecord],
    source_roots: Mapping[str, Path],
    contexts: dict[str, ContextEvidence],
    policy: ScorePolicy = DEFAULT_POLICY,
    reachability_rules: tuple[ReachabilityRule, ...] = (),
    external_source_evidence: ExternalSourceEvidenceStore | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    source_indexes = {artifact: build_source_index(root) for artifact, root in source_roots.items()}
    for sbom in sboms:
        root = source_roots.get(sbom.artifact.name)
        source_index = source_indexes.get(sbom.artifact.name)
        context = contexts.get(sbom.artifact.name, ContextEvidence())
        for component in sbom.components:
            matches = matching_vulnerabilities(component, vulnerabilities, sbom.artifact.name)
            if not matches:
                continue
            for vulnerability in matches:
                source = analyze_component_source(component, root, vulnerability=vulnerability, custom_rules=reachability_rules, source_index=source_index, sbom=sbom)
                if external_source_evidence:
                    source = merge_source_evidence(source, external_source_evidence.best_for(sbom.artifact.name, component, vulnerability))
                findings.append(score_finding(sbom, component, vulnerability, source, context, policy))
    sorted_findings = sorted(findings, key=lambda finding: finding.score, reverse=True)
    report = source_coverage_report(sboms, source_roots, source_indexes, sorted_findings, external_source_evidence)
    return sorted_findings, report
