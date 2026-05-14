"""Graph-first risk decisions for findings.

The evaluator treats exposure as a typed path problem. It decides the tier from
the strongest credible path and only then projects that tier into the 0-100
score range used by CI gates and sorting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .finding_types import (
    CLOUD_POSTURE_FINDING,
    DYNAMIC_RUNTIME_OBSERVATION,
    STATIC_CODE_WEAKNESS,
    canonical_finding_type,
    is_dependency_finding,
)
from .models import Finding, Reachability, RuntimeEvidenceState, Tier

TIER_RANK: dict[Tier, int] = {
    Tier.INFORMATIONAL: 0,
    Tier.LOW: 1,
    Tier.MEDIUM: 2,
    Tier.HIGH: 3,
    Tier.URGENT: 4,
}

TIER_SCORE_BANDS: dict[Tier, tuple[float, float, float]] = {
    Tier.URGENT: (85.0, 100.0, 91.0),
    Tier.HIGH: (65.0, 84.0, 74.0),
    Tier.MEDIUM: (40.0, 64.0, 56.0),
    Tier.LOW: (20.0, 39.0, 28.0),
    Tier.INFORMATIONAL: (0.0, 19.0, 10.0),
}


@dataclass(frozen=True)
class GraphRiskDecision:
    tier: Tier
    potential_tier: Tier
    confidence: str
    matched_rule: str
    score: float
    drivers: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    visibility_gaps: list[str] = field(default_factory=list)
    band_adjustments: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "scoring_model": "graph_path_v1",
            "tier": self.tier.value,
            "potential_tier": self.potential_tier.value,
            "confidence": self.confidence,
            "matched_rule": self.matched_rule,
            "score_band": self.tier.value,
            "score": round(self.score, 2),
            "drivers": self.drivers,
            "blockers": self.blockers,
            "unknowns": self.unknowns,
            "visibility_gaps": self.visibility_gaps,
            "band_adjustments": self.band_adjustments,
        }


def evaluate_graph_risk(finding: Finding) -> GraphRiskDecision:
    context = finding.context
    source = finding.source
    vulnerability = finding.vulnerability
    finding_type = canonical_finding_type(finding.finding_type)
    exposure = _normalized(context.exposure)
    network_decision = _network_decision(finding)
    network_blockers = _network_blockers(finding)
    network_unknowns = _network_unknowns(finding)
    source_strength = _source_strength(source.reachability)
    impact = _impact_level(finding)
    critical_context = _critical_context(finding)
    exploit_signal = _exploit_signal(finding)
    runtime_observed = _runtime_observed(finding)
    strong_correlation = _has_correlation(finding, "high")
    medium_correlation = _has_correlation(finding, "medium")
    weak_correlation = _has_correlation(finding, "low")
    drivers: list[str] = []
    blockers = list(network_blockers)
    unknowns = _dedupe([*network_unknowns, *finding.unknowns])
    visibility_gaps = _visibility_gaps(finding, unknowns)

    if vulnerability.known_exploited:
        drivers.append("known exploited vulnerability")
    if vulnerability.epss is not None and vulnerability.epss >= 0.5:
        drivers.append(f"high EPSS {vulnerability.epss}")
    if impact in {"critical", "high"}:
        drivers.append(f"{impact} technical impact")
    if exposure in {"public", "external"}:
        drivers.append(f"{exposure} network path")
    elif exposure == "unknown":
        unknowns.append("network exposure unknown")
    if source_strength in {"attacker_controlled", "function_reachable"}:
        drivers.append(source_strength.replace("_", " "))
    if critical_context:
        drivers.append("sensitive identity or data context")
    if runtime_observed:
        drivers.append(f"runtime evidence {finding.runtime_evidence.state.value}")
    if strong_correlation:
        drivers.append("strong scanner correlation")

    if finding_type == DYNAMIC_RUNTIME_OBSERVATION:
        tier, rule = _runtime_tier(finding, exposure, impact, runtime_observed, strong_correlation, network_decision, blockers)
    elif finding_type == STATIC_CODE_WEAKNESS:
        tier, rule = _static_tier(finding, exposure, impact, source_strength, strong_correlation, medium_correlation, network_decision, blockers)
    elif finding_type == CLOUD_POSTURE_FINDING:
        tier, rule = _posture_tier(finding, exposure, impact, critical_context, network_decision, blockers, strong_correlation, medium_correlation)
    elif is_dependency_finding(finding_type):
        tier, rule = _dependency_tier(finding, exposure, impact, source_strength, critical_context, exploit_signal, network_decision, blockers)
    else:
        tier, rule = (Tier.MEDIUM if impact in {"critical", "high"} else Tier.LOW, "generic security finding")

    tier, cap_rule = _apply_path_constraints(tier, finding, exposure, source_strength, network_decision, blockers, exploit_signal, runtime_observed, strong_correlation)
    if cap_rule:
        rule = f"{rule}; {cap_rule}"

    potential_tier = _potential_tier(tier, finding, exposure, source_strength, impact, critical_context, exploit_signal, unknowns, runtime_observed)
    confidence = _decision_confidence(finding, tier, potential_tier, unknowns, blockers)
    score, adjustments = _project_score(finding, tier, confidence, impact, exploit_signal, strong_correlation, medium_correlation, weak_correlation, bool(blockers), bool(unknowns))
    return GraphRiskDecision(
        tier=tier,
        potential_tier=potential_tier,
        confidence=confidence,
        matched_rule=rule,
        score=score,
        drivers=_dedupe(drivers),
        blockers=_dedupe(blockers),
        unknowns=_dedupe(unknowns),
        visibility_gaps=_dedupe(visibility_gaps),
        band_adjustments=adjustments,
    )


def graph_dimensions(finding: Finding, decision: GraphRiskDecision) -> list[dict[str, Any]]:
    return [
        _dimension("vulnerability_impact", _impact_level(finding), "Technical impact from CVSS/severity, KEV, EPSS, and scanner severity."),
        _dimension("source_reachability", finding.source.reachability.value, "Static source evidence on whether vulnerable code/package is used."),
        _dimension("runtime_evidence", finding.runtime_evidence.state.value, "Runtime scanner observation, separate from source reachability."),
        _dimension("posture_evidence", finding.posture_evidence.rule_id or "none", "CSPM posture evidence from scanner imports or native local IaC checks."),
        _dimension("deployment_exposure", finding.context.exposure, "Network path state from context, Terraform, Kubernetes, or DAST mapping."),
        _dimension("identity_blast_radius", _identity_value(finding), "Effective access, IAM capability, privilege, and data impact context."),
        _dimension("corroboration", _correlation_value(finding), "Non-destructive relation to other scanner findings."),
        _dimension("confidence_penalty", decision.confidence, "Confidence and unknowns constrain confirmed priority."),
        _dimension("uncertainty_premium", ",".join(decision.visibility_gaps[:3]) or "none", "Unknown evidence is reported as potential risk, not as confirmed exposure."),
    ]


def _dependency_tier(
    finding: Finding,
    exposure: str,
    impact: str,
    source_strength: str,
    critical_context: bool,
    exploit_signal: bool,
    network_decision: str,
    blockers: list[str],
) -> tuple[Tier, str]:
    public_like = exposure in {"public", "external"}
    unknown_like = exposure == "unknown"
    direct_source = source_strength in {"attacker_controlled", "function_reachable"}
    weak_source = source_strength in {"absent", "unknown", "package_present"}
    if exploit_signal and direct_source and public_like and not blockers and network_decision != "blocked":
        return Tier.URGENT, "exploit intelligence plus confirmed public reachable source path"
    if direct_source and public_like and critical_context and impact in {"critical", "high"} and not blockers and not _low_confidence_effective_access(finding):
        return Tier.URGENT, "confirmed public reachable path with critical impact and blast radius"
    if direct_source and public_like and critical_context and impact == "medium":
        return Tier.HIGH, "confirmed public reachable path with medium impact and critical blast radius"
    if direct_source and (public_like or unknown_like or critical_context or exploit_signal) and impact in {"critical", "high"}:
        return Tier.HIGH, "strong source path with high impact and credible exposure"
    if exploit_signal and direct_source:
        return Tier.HIGH, "exploit intelligence with reachable source path"
    if source_strength in {"dependency_reachable", "imported"} and public_like and critical_context and impact in {"critical", "high"}:
        return Tier.HIGH, "dependency or import evidence on public critical deployment"
    if exploit_signal and weak_source and public_like and impact in {"critical", "high"}:
        return Tier.HIGH, "exploit intelligence with public deployment but weak source evidence"
    if weak_source and not exploit_signal:
        return (Tier.MEDIUM if impact in {"critical", "high"} or critical_context else Tier.LOW, "weak source evidence prevents confirmed high priority")
    if source_strength == "imported" and not exploit_signal:
        return (Tier.MEDIUM if impact in {"critical", "high", "medium"} else Tier.LOW, "import_only_evidence without direct vulnerable API usage")
    if exposure in {"internal", "unknown"} and impact in {"critical", "high"}:
        return Tier.MEDIUM, "internal or unresolved path with significant impact"
    if exposure in {"private", "isolated", "none"} and not critical_context and not exploit_signal:
        if direct_source and impact in {"critical", "high", "medium"}:
            return Tier.MEDIUM, "private or isolated path has reachable code but no confirmed ingress"
        return Tier.LOW, "private or isolated path without exploit signal or critical context"
    return (Tier.MEDIUM if impact in {"critical", "high", "medium"} else Tier.LOW, "default dependency graph decision")


def _static_tier(
    finding: Finding,
    exposure: str,
    impact: str,
    source_strength: str,
    strong_correlation: bool,
    medium_correlation: bool,
    network_decision: str,
    blockers: list[str],
) -> tuple[Tier, str]:
    dataflow = source_strength in {"attacker_controlled", "function_reachable"}
    public_like = exposure in {"public", "external"}
    if dataflow and public_like and impact in {"critical", "high"} and (strong_correlation or not blockers) and network_decision != "blocked":
        return Tier.HIGH, "static dataflow evidence reaches exposed deployment"
    if strong_correlation and impact in {"critical", "high"}:
        return Tier.HIGH, "static finding corroborated by matching runtime evidence"
    if dataflow and (public_like or exposure == "unknown" or medium_correlation) and impact in {"critical", "high", "medium"}:
        return Tier.MEDIUM, "static dataflow evidence without fully confirmed exposed runtime path"
    if finding.source.locations:
        return Tier.MEDIUM if impact in {"critical", "high"} else Tier.LOW, "static location-only evidence"
    return Tier.LOW, "static scanner evidence without source location or dataflow"


def _runtime_tier(
    finding: Finding,
    exposure: str,
    impact: str,
    runtime_observed: bool,
    strong_correlation: bool,
    network_decision: str,
    blockers: list[str],
) -> tuple[Tier, str]:
    if finding.vulnerability.severity.lower() in {"info", "informational", "notice"} and not strong_correlation:
        return Tier.LOW, "informational runtime observation without corroboration"
    if runtime_observed and not (finding.runtime_evidence.url or finding.weakness.get("route")):
        return Tier.LOW, "runtime observation without URL or route cannot prove affected attack surface"
    public_like = exposure in {"public", "external"}
    unauthenticated = finding.runtime_evidence.state == RuntimeEvidenceState.UNAUTHENTICATED_OBSERVED
    if runtime_observed and public_like and impact in {"critical", "high"} and (unauthenticated or strong_correlation) and network_decision != "blocked":
        return Tier.HIGH, "runtime-observed vulnerability on exposed route"
    if runtime_observed and impact in {"critical", "high"}:
        return Tier.MEDIUM, "runtime-observed vulnerability without confirmed public unauthenticated path"
    if finding.runtime_evidence.state == RuntimeEvidenceState.ENDPOINT_OBSERVED:
        return Tier.LOW, "endpoint observed without confirmed vulnerability"
    return Tier.LOW, "runtime evidence not observed"


def _posture_tier(
    finding: Finding,
    exposure: str,
    impact: str,
    critical_context: bool,
    network_decision: str,
    blockers: list[str],
    strong_correlation: bool,
    medium_correlation: bool,
) -> tuple[Tier, str]:
    """Tier CSPM as risky configuration context, not exploit proof."""

    public_like = exposure in {"public", "external"}
    high_impact = impact in {"critical", "high"}
    if high_impact and public_like and critical_context and not blockers and network_decision != "blocked":
        return Tier.HIGH, "risky cloud posture on exposed sensitive or privileged resource"
    if high_impact and (public_like or critical_context or strong_correlation):
        return Tier.MEDIUM, "high-risk cloud posture with exposure, blast radius, or strong correlated context"
    if impact == "medium" and (public_like or critical_context or medium_correlation):
        return Tier.MEDIUM, "medium-risk posture with deployment or identity context"
    if finding.posture_evidence.confidence.value == "low" or finding.context.exposure == "unknown":
        return Tier.LOW, "posture finding lacks enough mapping or exposure evidence for higher priority"
    return (Tier.MEDIUM if impact in {"critical", "high", "medium"} else Tier.LOW, "posture finding without exploit proof")


def _apply_path_constraints(
    tier: Tier,
    finding: Finding,
    exposure: str,
    source_strength: str,
    network_decision: str,
    blockers: list[str],
    exploit_signal: bool,
    runtime_observed: bool,
    strong_correlation: bool,
) -> tuple[Tier, str]:
    if network_decision == "blocked" and not (exploit_signal or runtime_observed):
        return _min_tier(tier, Tier.MEDIUM), "blocked network path caps confirmed priority"
    if _low_confidence_effective_access(finding) and tier == Tier.URGENT and not exploit_signal:
        return Tier.HIGH, "low-confidence effective access caps confirmed urgent priority"
    if blockers and not (exploit_signal or runtime_observed or strong_correlation):
        return _min_tier(tier, Tier.HIGH), "provider blocker constrains confirmed graph path"
    if finding.component.scope in {"test", "dev", "development"} and source_strength in {"package_present", "unknown", "absent"}:
        return _min_tier(tier, Tier.LOW), "dev/test dependency without source usage caps confirmed priority"
    if canonical_finding_type(finding.finding_type) == CLOUD_POSTURE_FINDING and tier == Tier.URGENT:
        return Tier.HIGH, "CSPM posture evidence alone cannot be urgent"
    if exposure in {"private", "isolated", "none"} and source_strength != "attacker_controlled" and not exploit_signal and not _critical_context(finding):
        return _min_tier(tier, Tier.MEDIUM), "private/no-ingress path caps confirmed priority"
    return tier, ""


def _potential_tier(
    tier: Tier,
    finding: Finding,
    exposure: str,
    source_strength: str,
    impact: str,
    critical_context: bool,
    exploit_signal: bool,
    unknowns: list[str],
    runtime_observed: bool,
) -> Tier:
    potential = tier
    if unknowns and impact in {"critical", "high"} and (source_strength in {"attacker_controlled", "function_reachable"} or runtime_observed or exploit_signal):
        potential = _max_tier(potential, Tier.HIGH)
    if unknowns and exploit_signal and source_strength in {"attacker_controlled", "function_reachable"} and exposure in {"public", "external", "unknown"}:
        potential = _max_tier(potential, Tier.URGENT)
    if unknowns and critical_context and impact == "critical" and exposure in {"public", "external", "unknown"}:
        potential = _max_tier(potential, Tier.URGENT)
    return potential


def _project_score(
    finding: Finding,
    tier: Tier,
    confidence: str,
    impact: str,
    exploit_signal: bool,
    strong_correlation: bool,
    medium_correlation: bool,
    weak_correlation: bool,
    has_blocker: bool,
    has_unknowns: bool,
) -> tuple[float, list[dict[str, Any]]]:
    low, high, score = TIER_SCORE_BANDS[tier]
    adjustments: list[dict[str, Any]] = []
    for name, amount, reason in _band_adjustments(finding, confidence, impact, exploit_signal, strong_correlation, medium_correlation, weak_correlation, has_blocker, has_unknowns):
        score += amount
        adjustments.append({"name": name, "adjustment": round(amount, 2), "reason": reason})
    return round(max(low, min(high, score)), 2), adjustments


def _band_adjustments(
    finding: Finding,
    confidence: str,
    impact: str,
    exploit_signal: bool,
    strong_correlation: bool,
    medium_correlation: bool,
    weak_correlation: bool,
    has_blocker: bool,
    has_unknowns: bool,
) -> list[tuple[str, float, str]]:
    adjustments: list[tuple[str, float, str]] = []
    if impact == "critical":
        adjustments.append(("impact", 4.0, "critical impact places the finding higher inside its tier band"))
    elif impact == "high":
        adjustments.append(("impact", 2.0, "high impact places the finding higher inside its tier band"))
    if exploit_signal:
        adjustments.append(("exploit_likelihood", 4.0, "KEV or high EPSS increases ordering inside the tier band"))
    if _critical_context(finding):
        adjustments.append(("blast_radius", 2.0, "critical identity or data context places the finding higher inside its tier band"))
    if finding.context.criticality == "high" or finding.context.iam_impacts:
        adjustments.append(("data_sensitivity", 1.5, "explicit data criticality or IAM impact refines ordering inside the tier band"))
    if confidence == "high":
        adjustments.append(("confidence", 2.0, "high-confidence graph path"))
    elif confidence == "low":
        adjustments.append(("confidence", -3.0, "low-confidence graph path"))
    if strong_correlation:
        adjustments.append(("corroboration", 3.0, "high-confidence correlation"))
    elif medium_correlation:
        adjustments.append(("corroboration", 1.5, "medium-confidence correlation"))
    elif weak_correlation:
        adjustments.append(("corroboration", 0.5, "weak correlation only"))
    if finding.vulnerability.fixed_versions:
        adjustments.append(("fix_available", -1.0, "fix availability slightly lowers ordering within the tier band"))
    if has_blocker:
        adjustments.append(("blocker", -1.0, "blocker constrains the graph path"))
    if has_unknowns:
        adjustments.append(("uncertainty", -2.0, "unknown evidence lowers confirmed ordering but remains visible as potential risk"))
    return adjustments


def _decision_confidence(finding: Finding, tier: Tier, potential_tier: Tier, unknowns: list[str], blockers: list[str]) -> str:
    if finding.confidence.value == "high" and not unknowns and not blockers and tier == potential_tier:
        return "high"
    if finding.confidence.value == "low" or TIER_RANK[potential_tier] > TIER_RANK[tier] or unknowns:
        return "low" if finding.confidence.value == "low" else "medium"
    return "medium"


def _impact_level(finding: Finding) -> str:
    if finding.vulnerability.cvss is not None:
        if finding.vulnerability.cvss >= 9.0:
            return "critical"
        if finding.vulnerability.cvss >= 7.0:
            return "high"
        if finding.vulnerability.cvss >= 4.0:
            return "medium"
        return "low"
    severity = finding.vulnerability.severity.lower()
    if severity in {"critical", "error"}:
        return "critical"
    if severity in {"high", "warning"}:
        return "high"
    if severity in {"medium", "moderate"}:
        return "medium"
    if severity in {"info", "informational", "notice"}:
        return "informational"
    return "unknown"


def _source_strength(reachability: Reachability) -> str:
    return {
        Reachability.ABSENT: "absent",
        Reachability.UNKNOWN_DUE_TO_NO_RULE: "unknown",
        Reachability.PACKAGE_PRESENT: "package_present",
        Reachability.DEPENDENCY_REACHABLE: "dependency_reachable",
        Reachability.IMPORTED: "imported",
        Reachability.FUNCTION_REACHABLE: "function_reachable",
        Reachability.ATTACKER_CONTROLLED: "attacker_controlled",
    }[reachability]


def _network_decision(finding: Finding) -> str:
    for record in finding.context.effective_exposure:
        if isinstance(record, dict) and record.get("decision"):
            return str(record["decision"]).lower()
    effects = _network_blocker_effects(finding)
    if "blocks" in effects:
        return "blocked"
    if "constrains" in effects:
        return "constrained"
    if finding.context.exposure in {"private", "isolated", "none"}:
        return "isolated"
    if finding.context.exposure == "unknown":
        return "unknown"
    return "reachable"


def _network_blockers(finding: Finding) -> list[str]:
    blockers: list[str] = []
    for record in [*finding.context.effective_exposure, *finding.context.network_paths]:
        if not isinstance(record, dict):
            continue
        network = record.get("network") if isinstance(record.get("network"), dict) else record
        if not isinstance(network, dict):
            continue
        for blocker in network.get("blockers", []) if isinstance(network.get("blockers"), list) else []:
            if isinstance(blocker, dict):
                blockers.append(str(blocker.get("kind") or blocker.get("effect") or blocker.get("evidence") or "network blocker"))
    return blockers


def _network_blocker_effects(finding: Finding) -> set[str]:
    effects: set[str] = set()
    for record in [*finding.context.effective_exposure, *finding.context.network_paths]:
        if not isinstance(record, dict):
            continue
        network = record.get("network") if isinstance(record.get("network"), dict) else record
        if not isinstance(network, dict):
            continue
        decision = str(network.get("decision") or "").lower()
        if decision == "blocked":
            effects.add("blocks")
        elif decision == "constrained":
            effects.add("constrains")
        for blocker in network.get("blockers", []) if isinstance(network.get("blockers"), list) else []:
            if isinstance(blocker, dict):
                effect = str(blocker.get("effect") or "").lower()
                if effect in {"blocks", "constrains"}:
                    effects.add(effect)
    return effects


def _network_unknowns(finding: Finding) -> list[str]:
    unknowns: list[str] = []
    for record in finding.context.effective_exposure:
        if not isinstance(record, dict):
            continue
        network = record.get("network") if isinstance(record.get("network"), dict) else record
        if not isinstance(network, dict):
            continue
        for value in network.get("unknowns", []) if isinstance(network.get("unknowns"), list) else []:
            unknowns.append(str(value))
    if finding.context.exposure == "unknown":
        unknowns.append("network exposure unresolved")
    if finding.context.privilege == "unknown" and not finding.context.effective_access and not finding.context.iam_capabilities:
        unknowns.append("identity/effective access unresolved")
    return unknowns


def _critical_context(finding: Finding) -> bool:
    privilege = _normalized(finding.context.privilege)
    criticality = _normalized(finding.context.criticality)
    impacts = {_normalized(item) for item in finding.context.iam_impacts}
    capability_impacts = {
        _normalized(str(capability.get("impact") or ""))
        for capability in finding.context.iam_capabilities
        if str(capability.get("effect") or "allow").lower() == "allow"
    }
    critical_impacts = {"admin_control", "iam_escalation", "network_control", "compute_control", "data_access"}
    return privilege in {"admin", "sensitive"} or criticality == "high" or bool((impacts | capability_impacts) & critical_impacts)


def _low_confidence_effective_access(finding: Finding) -> bool:
    records = [record for record in finding.context.effective_access if isinstance(record, dict) and str(record.get("effect") or "allow").lower() == "allow"]
    return bool(records) and all(str(record.get("confidence") or "").lower() == "low" for record in records)


def _exploit_signal(finding: Finding) -> bool:
    return finding.vulnerability.known_exploited or (finding.vulnerability.epss is not None and finding.vulnerability.epss >= 0.5)


def _runtime_observed(finding: Finding) -> bool:
    return finding.runtime_evidence.state in {
        RuntimeEvidenceState.VULNERABILITY_OBSERVED,
        RuntimeEvidenceState.AUTHENTICATED_OBSERVED,
        RuntimeEvidenceState.UNAUTHENTICATED_OBSERVED,
    }


def _has_correlation(finding: Finding, confidence: str) -> bool:
    return any(item.confidence.value == confidence for item in finding.correlated_evidence)


def _identity_value(finding: Finding) -> str:
    if finding.context.iam_impacts:
        return ",".join(finding.context.iam_impacts)
    if finding.context.iam_capabilities:
        return ",".join(str(item.get("impact") or item.get("action") or "capability") for item in finding.context.iam_capabilities[:3])
    return finding.context.privilege


def _correlation_value(finding: Finding) -> str:
    if not finding.correlated_evidence:
        return "none"
    return ",".join(item.correlation_type for item in finding.correlated_evidence[:3])


def _visibility_gaps(finding: Finding, unknowns: list[str]) -> list[str]:
    gaps = list(unknowns)
    if finding.source.reachability in {Reachability.PACKAGE_PRESENT, Reachability.UNKNOWN_DUE_TO_NO_RULE}:
        gaps.append("source usage not proven")
    if finding.context.exposure == "unknown":
        gaps.append("deployment exposure not proven")
    if finding.context.privilege == "unknown":
        gaps.append("effective identity blast radius not proven")
    if canonical_finding_type(finding.finding_type) == DYNAMIC_RUNTIME_OBSERVATION and not finding.source.locations:
        gaps.append("runtime finding has no source mapping")
    if canonical_finding_type(finding.finding_type) == CLOUD_POSTURE_FINDING and finding.artifact.name.startswith("unmapped:"):
        gaps.append("posture finding is not mapped to a workload artifact")
    return gaps


def _min_tier(left: Tier, right: Tier) -> Tier:
    return left if TIER_RANK[left] <= TIER_RANK[right] else right


def _max_tier(left: Tier, right: Tier) -> Tier:
    return left if TIER_RANK[left] >= TIER_RANK[right] else right


def _dimension(name: str, value: Any, reason: str) -> dict[str, Any]:
    return {"name": name, "value": str(value), "points": 0.0, "reason": reason}


def _normalized(value: str | None, default: str = "unknown") -> str:
    return (value or default).lower()


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


__all__ = ["GraphRiskDecision", "evaluate_graph_risk", "graph_dimensions"]
