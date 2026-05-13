"""Executable scoring benchmark fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    Finding,
    Reachability,
    SbomDocument,
    SourceEvidence,
    VulnerabilityRecord,
)
from .scoring import ScorePolicy, score_finding


def run_scoring_benchmark(path: str | Path, policy: ScorePolicy | None = None) -> dict[str, Any]:
    benchmark_path = Path(path)
    data = json.loads(benchmark_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{benchmark_path}: expected a JSON object")
    cases = data.get("cases")
    if not isinstance(cases, list):
        raise ValueError(f"{benchmark_path}: cases must be a list")

    require_expected_decisions = bool(data.get("require_expected_decisions"))
    results = [_run_case(case, policy or ScorePolicy(), require_expected_decisions) for case in cases if isinstance(case, dict)]
    failed = [result for result in results if result["status"] != "passed"]
    return {
        "schema_version": "1.0",
        "status": "failed" if failed else "passed",
        "case_count": len(results),
        "failed_count": len(failed),
        "results": results,
    }


def _run_case(case: dict[str, Any], policy: ScorePolicy, require_expected_decisions: bool) -> dict[str, Any]:
    sbom = SbomDocument(path=Path(str(case.get("id") or "benchmark")), artifact=Artifact(name=str(case.get("artifact") or "app")), components=[])
    component_raw = _as_dict(case.get("component"))
    vulnerability_raw = _as_dict(case.get("vulnerability"))
    source_raw = _as_dict(case.get("source"))
    context_raw = _as_dict(case.get("context"))
    finding = score_finding(
        sbom,
        Component(
            name=str(component_raw.get("name") or "component"),
            version=str(component_raw.get("version")) if component_raw.get("version") else None,
            purl=str(component_raw.get("purl")) if component_raw.get("purl") else None,
            scope=str(component_raw.get("scope") or "runtime"),
        ),
        VulnerabilityRecord(
            id=str(vulnerability_raw.get("id") or "BENCHMARK"),
            package_name=str(vulnerability_raw.get("package_name") or component_raw.get("name") or "component"),
            severity=str(vulnerability_raw.get("severity") or "unknown"),
            cvss=_optional_float(vulnerability_raw.get("cvss")),
            epss=_optional_float(vulnerability_raw.get("epss")),
            known_exploited=bool(vulnerability_raw.get("known_exploited")),
        ),
        SourceEvidence(
            reachability=_reachability(source_raw.get("reachability")),
            confidence=_confidence(source_raw.get("confidence")),
            language=str(source_raw.get("language") or "unknown"),
            reason=str(source_raw.get("reason") or "benchmark source evidence"),
        ),
        ContextEvidence(
            environment=str(context_raw.get("environment") or "unknown"),
            exposure=str(context_raw.get("exposure") or "unknown"),
            privilege=str(context_raw.get("privilege") or "unknown"),
            criticality=str(context_raw.get("criticality") or "unknown"),
            iam_impacts=[str(item) for item in context_raw.get("iam_impacts", [])] if isinstance(context_raw.get("iam_impacts"), list) else [],
            iam_capabilities=[dict(item) for item in context_raw.get("iam_capabilities", []) if isinstance(item, dict)] if isinstance(context_raw.get("iam_capabilities"), list) else [],
            effective_access=[dict(item) for item in context_raw.get("effective_access", []) if isinstance(item, dict)] if isinstance(context_raw.get("effective_access"), list) else [],
            effective_exposure=[dict(item) for item in context_raw.get("effective_exposure", []) if isinstance(item, dict)] if isinstance(context_raw.get("effective_exposure"), list) else [],
            network_paths=[dict(item) for item in context_raw.get("network_paths", []) if isinstance(item, dict)] if isinstance(context_raw.get("network_paths"), list) else [],
            confidence=_confidence(context_raw.get("confidence")),
        ),
        policy,
    )
    expected_tier = str(case.get("expected_tier") or "")
    min_score = _optional_float(case.get("min_score"))
    max_score = _optional_float(case.get("max_score"))
    problems: list[str] = []
    if expected_tier and finding.tier.value != expected_tier:
        problems.append(f"expected tier {expected_tier}, got {finding.tier.value}")
    if min_score is not None and finding.score < min_score:
        problems.append(f"expected score >= {min_score}, got {finding.score:.2f}")
    if max_score is not None and finding.score > max_score:
        problems.append(f"expected score <= {max_score}, got {finding.score:.2f}")
    expected_decision = _as_dict(case.get("expected_decision"))
    expected_why = str(expected_decision.get("why") or "").strip()
    required_reason_labels = _string_list(expected_decision.get("required_reason_labels"))
    decision_labels = _decision_reason_labels(finding)
    if require_expected_decisions and not expected_decision:
        problems.append("missing expected_decision rationale")
    elif require_expected_decisions and not expected_why:
        problems.append("missing expected_decision.why")
    missing_reason_labels = [label for label in required_reason_labels if label not in decision_labels]
    if missing_reason_labels:
        problems.append("missing expected decision reason labels: " + ", ".join(sorted(missing_reason_labels)))
    return {
        "id": str(case.get("id") or "unnamed"),
        "status": "failed" if problems else "passed",
        "score": round(finding.score, 2),
        "tier": finding.tier.value,
        "expected_tier": expected_tier,
        "problems": problems,
        "expected_decision": {
            "why": expected_why,
            "required_reason_labels": required_reason_labels,
            "matched_reason_labels": [label for label in required_reason_labels if label in decision_labels],
        },
        "decision_reason_labels": decision_labels,
        "gates": finding.score_details.get("gates", []),
        "dimensions": finding.score_details.get("dimensions", []),
    }


def _reachability(value: Any) -> Reachability:
    try:
        return Reachability(str(value or Reachability.PACKAGE_PRESENT.value))
    except ValueError:
        return Reachability.PACKAGE_PRESENT


def _confidence(value: Any) -> Confidence:
    try:
        return Confidence(str(value or Confidence.LOW.value))
    except ValueError:
        return Confidence.LOW


def _optional_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _decision_reason_labels(finding: Finding) -> list[str]:
    """Return stable labels that explain why the benchmark case landed in its tier."""

    labels: list[str] = [f"tier:{finding.tier.value}"]
    vulnerability = finding.vulnerability
    source = finding.source
    context = finding.context

    if vulnerability.cvss is not None:
        labels.append(f"severity:{_cvss_band(vulnerability.cvss)}")
    else:
        labels.append(f"severity:{str(vulnerability.severity or 'unknown').lower()}")
    if vulnerability.known_exploited:
        labels.append("exploit:known_exploited")
    if vulnerability.epss is not None:
        labels.append("exploit:epss_high" if vulnerability.epss >= 0.5 else "exploit:epss_signal" if vulnerability.epss >= 0.2 else "exploit:epss_low")

    source_state = source.reachability.value
    labels.append(f"source:{source_state}")
    if source.reachability in {Reachability.ABSENT, Reachability.UNKNOWN_DUE_TO_NO_RULE, Reachability.PACKAGE_PRESENT}:
        labels.append("source:weak")
    elif source.reachability in {Reachability.FUNCTION_REACHABLE, Reachability.ATTACKER_CONTROLLED}:
        labels.append("source:direct_usage")
    elif source.reachability == Reachability.DEPENDENCY_REACHABLE:
        labels.append("source:dependency_graph")
    elif source.reachability == Reachability.IMPORTED:
        labels.append("source:import_only")
    labels.append(f"source_confidence:{source.confidence.value}")

    exposure = str(context.exposure or "unknown").lower()
    labels.append(f"network:{exposure}")
    labels.extend(_network_reason_labels(context))

    environment = str(context.environment or "unknown").lower()
    labels.append(f"environment:{environment}")
    privilege = str(context.privilege or "unknown").lower()
    labels.append(f"iam:{privilege}")
    for impact in context.iam_impacts:
        labels.append(f"iam_impact:{str(impact).lower()}")
    labels.extend(_iam_reason_labels(context))
    criticality = str(context.criticality or "unknown").lower()
    labels.append(f"asset_criticality:{criticality}")
    labels.append(f"context_confidence:{context.confidence.value}")

    for gate in finding.score_details.get("gates", []):
        if not isinstance(gate, dict):
            continue
        name = str(gate.get("name") or "unknown").strip().lower()
        status = str(gate.get("status") or "unknown").strip().lower()
        labels.append(f"gate:{name}")
        labels.append(f"gate:{name}:{status}")

    return sorted(dict.fromkeys(labels))


def _cvss_band(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _network_reason_labels(context: ContextEvidence) -> list[str]:
    labels: list[str] = []
    for record in list(context.network_paths) + list(context.effective_exposure):
        if not isinstance(record, dict):
            continue
        network_candidate = record.get("network")
        network: dict[str, Any] = network_candidate if isinstance(network_candidate, dict) else record
        decision = str(network.get("decision") or "").strip().lower()
        if decision:
            labels.append(f"network_decision:{decision}")
        confidence = str(network.get("confidence") or "").strip().lower()
        if confidence:
            labels.append(f"network_confidence:{confidence}")
        blockers = network.get("blockers")
        if not isinstance(blockers, list):
            continue
        for blocker in blockers:
            if not isinstance(blocker, dict):
                continue
            effect = str(blocker.get("effect") or "unknown").strip().lower()
            kind = str(blocker.get("kind") or "unknown").strip().lower()
            labels.append(f"network_blocker:{effect}")
            labels.append(f"network_blocker:{kind}")
    return labels


def _iam_reason_labels(context: ContextEvidence) -> list[str]:
    labels: list[str] = []
    for capability in context.iam_capabilities:
        if not isinstance(capability, dict):
            continue
        impact = str(capability.get("impact") or "").strip().lower()
        if impact:
            labels.append(f"iam_capability:{impact}")
        effect = str(capability.get("effect") or "").strip().lower()
        if effect:
            labels.append(f"iam_capability_effect:{effect}")
    for record in context.effective_access:
        if not isinstance(record, dict):
            continue
        decision = str(record.get("decision") or record.get("effect") or "").strip().lower()
        if decision:
            labels.append(f"iam_decision:{decision}")
        confidence = str(record.get("confidence") or "").strip().lower()
        if confidence:
            labels.append(f"iam_confidence:{confidence}")
    return labels


__all__ = ["run_scoring_benchmark"]
