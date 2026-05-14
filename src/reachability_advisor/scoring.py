"""Explainable scoring engine."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .effective_graph import scoring_path_summary
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
from .risk_graph_scoring import GraphRiskDecision, evaluate_graph_risk, graph_dimensions
from .security_evidence_model import SecurityEvidenceRecord
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
    """Compatibility policy for projecting graph decisions into tier bands."""

    tier_thresholds: dict[Tier, float] = field(
        default_factory=lambda: {
            Tier.URGENT: 85.0,
            Tier.HIGH: 65.0,
            Tier.MEDIUM: 40.0,
            Tier.LOW: 20.0,
            Tier.INFORMATIONAL: 0.0,
        }
    )


DEFAULT_POLICY = ScorePolicy()
SCORING_MODEL_VERSION = "2026-05-graph-v1"


def tier_for_score(score: float, policy: ScorePolicy = DEFAULT_POLICY) -> Tier:
    """Project a compatibility score into the configured tier thresholds."""

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


def _score_gate(name: str, status: str, reason: str, cap: float | None = None) -> dict[str, Any]:
    gate: dict[str, Any] = {"name": name, "status": status, "reason": reason}
    if cap is not None:
        gate["cap"] = round(cap, 2)
    return gate


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
    finding = Finding(
        key=finding_key(sbom.artifact, component, vulnerability),
        artifact=sbom.artifact,
        component=component,
        vulnerability=vulnerability,
        source=source,
        context=context,
        score=0.0,
        tier=Tier.INFORMATIONAL,
        confidence=_confidence(source, context),
        rationale=[],
        fix_commands=fix_commands(component, vulnerability),
        score_details={
            "model_version": SCORING_MODEL_VERSION,
            "dimensions": [],
            "gates": [],
            "final_score": 0.0,
            "tier": Tier.INFORMATIONAL.value,
        },
    )
    apply_graph_score(finding, policy)
    finding.score_details["effective_exposure_path"] = scoring_path_summary(finding)
    return finding


def apply_graph_score(finding: Finding, policy: ScorePolicy = DEFAULT_POLICY) -> Finding:
    """Make the typed exposure graph decision authoritative for score/tier."""

    details = finding.score_details
    decision = evaluate_graph_risk(finding)
    existing_gates = details.get("gates", [])
    existing_gate_list = existing_gates if isinstance(existing_gates, list) else []
    finding.score = decision.score
    finding.tier = decision.tier
    details["model_version"] = SCORING_MODEL_VERSION
    details["dimensions"] = graph_dimensions(finding, decision)
    details["graph_decision"] = decision.to_json()
    details["gates"] = _merge_gates(existing_gate_list, _graph_gates(decision, finding))
    details["final_score"] = round(finding.score, 2)
    details["tier"] = finding.tier.value
    details["effective_exposure_path"] = scoring_path_summary(finding)
    rationale = [f"graph decision {decision.matched_rule}; confirmed {finding.tier.value} {finding.score:.1f}; potential {decision.potential_tier.value}"]
    if decision.drivers:
        rationale.append(f"graph drivers: {', '.join(decision.drivers)}")
    if decision.blockers:
        rationale.append(f"graph blockers: {', '.join(decision.blockers)}")
    if decision.visibility_gaps:
        rationale.append(f"visibility gaps: {', '.join(decision.visibility_gaps)}")
    gates = [str(gate.get("name")) for gate in details.get("gates", []) if isinstance(gate, dict) and gate.get("name")]
    if gates:
        rationale.append(f"graph gates: {', '.join(dict.fromkeys(gates))}")
    finding.rationale = rationale
    return finding


def _graph_gates(decision: GraphRiskDecision, finding: Finding) -> list[dict[str, Any]]:
    gates: list[dict[str, Any]] = []
    matched_rule = decision.matched_rule.lower()
    exploit_signal = finding.vulnerability.known_exploited or (finding.vulnerability.epss is not None and finding.vulnerability.epss >= 0.5)
    if decision.blockers:
        gates.append(_score_gate("network_blocker", "capped", "; ".join(decision.blockers)))
    if "weak source evidence" in matched_rule or "source usage not proven" in decision.visibility_gaps:
        gates.append(_score_gate("weak_source_evidence", "passed" if exploit_signal else "capped", "source usage is not proven strongly enough for confirmed high priority"))
    if finding.source.reachability == Reachability.DEPENDENCY_REACHABLE:
        gates.append(_score_gate("dependency_graph_evidence", "passed", "dependency graph evidence is weaker than direct vulnerable API usage"))
    if "import_only_evidence" in matched_rule:
        gates.append(_score_gate("import_only_evidence", "capped", "import-only evidence does not prove direct vulnerable API usage"))
    if "private/no-ingress" in matched_rule:
        gates.append(_score_gate("private_no_ingress", "passed", "private or no-ingress path constrains confirmed priority"))
    if "low-confidence effective access" in matched_rule:
        gates.append(_score_gate("low_confidence_iam", "passed", "low-confidence IAM effective access constrains confirmed priority"))
    if "blocked network path" in matched_rule:
        gates.append(_score_gate("network_blocker", "capped", "blocked network path constrains confirmed priority"))
    if "dev/test dependency" in matched_rule:
        gates.append(_score_gate("dev_test_without_usage", "capped", "dev/test dependency without source usage constrains confirmed priority"))
    if _has_low_confidence_iam(finding):
        gates.append(_score_gate("low_confidence_iam", "passed", "low-confidence IAM effective access constrains confirmed priority"))
    if decision.tier != Tier.URGENT:
        gates.append(_score_gate("urgent_gate", "passed", "urgent requires confirmed viable exposure plus critical impact or strong exploit/runtime evidence"))
    if decision.unknowns:
        gates.append(_score_gate("visibility_gap", "reported", "; ".join(decision.unknowns)))
    if decision.potential_tier != decision.tier:
        gates.append(_score_gate("potential_tier", "reported", f"potential tier remains {decision.potential_tier.value} because evidence is incomplete"))
    return gates


def _has_low_confidence_iam(finding: Finding) -> bool:
    records = [record for record in finding.context.effective_access if isinstance(record, dict) and str(record.get("effect") or "allow").lower() == "allow"]
    return bool(records) and all(str(record.get("confidence") or "").lower() == "low" for record in records)


def _merge_gates(existing: list[Any], generated: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for gate in [*existing, *generated]:
        if not isinstance(gate, dict):
            continue
        name = str(gate.get("name") or "")
        reason = str(gate.get("reason") or "")
        key = (name, reason)
        if not name or key in seen:
            continue
        seen.add(key)
        merged.append(gate)
    return merged


def score_security_finding(finding: Finding, record: SecurityEvidenceRecord) -> Finding:
    """Attach scanner-specific graph gates and re-evaluate the finding."""

    gates = finding.score_details.setdefault("gates", [])
    if record.scanner_type == "dast":
        if record.severity in {"info", "informational", "notice"} and not finding.correlated_evidence:
            gates.append(_score_gate("dast_informational", "applied", "DAST informational finding stays low unless corroborated"))
        if not record.url:
            gates.append(_score_gate("dast_missing_url", "applied", "DAST evidence without a URL or route stays below medium"))
    else:
        dataflow = bool(record.dataflow)
        location = bool(record.source)
        if location and not dataflow and finding.context.exposure in {"unknown", "internal", "private", "isolated"}:
            gates.append(_score_gate("sast_location_only", "applied", "SAST location-only finding without deployment or dataflow context stays below high"))
    apply_graph_score(finding)
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
