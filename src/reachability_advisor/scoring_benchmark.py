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

    results = [_run_case(case, policy or ScorePolicy()) for case in cases if isinstance(case, dict)]
    failed = [result for result in results if result["status"] != "passed"]
    return {
        "schema_version": "1.0",
        "status": "failed" if failed else "passed",
        "case_count": len(results),
        "failed_count": len(failed),
        "results": results,
    }


def _run_case(case: dict[str, Any], policy: ScorePolicy) -> dict[str, Any]:
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
    return {
        "id": str(case.get("id") or "unnamed"),
        "status": "failed" if problems else "passed",
        "score": round(finding.score, 2),
        "tier": finding.tier.value,
        "expected_tier": expected_tier,
        "problems": problems,
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


__all__ = ["run_scoring_benchmark"]
