"""Regression checks for real-application benchmark tier distributions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

TIER_KEYS = ("urgent", "high", "medium", "low", "informational")


class BenchmarkSnapshotError(ValueError):
    """Raised when a benchmark snapshot input is malformed."""


def validate_benchmark_snapshots(benchmark: str | Path | dict[str, Any], expectations: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Validate a complex benchmark against checked-in tier expectations."""

    benchmark_doc = _load_doc(benchmark, "benchmark")
    expectations_doc = _load_doc(expectations, "expectations")
    snapshots = expectations_doc.get("snapshots")
    if not isinstance(snapshots, list):
        raise BenchmarkSnapshotError("benchmark snapshot expectations must contain a snapshots list")
    results = [_validate_snapshot(benchmark_doc, snapshot) for snapshot in snapshots if isinstance(snapshot, dict)]
    failed = [result for result in results if result["status"] != "passed"]
    return {
        "schema_version": "1.0",
        "status": "failed" if failed else "passed",
        "benchmark": {
            "generated_at": benchmark_doc.get("generated_at"),
            "corpus": benchmark_doc.get("corpus"),
        },
        "snapshot_count": len(results),
        "failed_count": len(failed),
        "results": results,
    }


def _validate_snapshot(benchmark: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    target = _select_target(benchmark, snapshot)
    tier_counts = _tier_counts(target.get("tier_counts"))
    total_findings = _int(target.get("finding_count")) or sum(tier_counts.values())
    expected = _tier_counts(snapshot.get("expected_tier_counts"))
    limits_raw = snapshot.get("regression_limits")
    limits: dict[str, Any] = limits_raw if isinstance(limits_raw, dict) else {}
    problems: list[str] = []

    allowed_delta_raw = limits.get("allowed_count_delta_by_tier")
    allowed_delta: dict[str, Any] = allowed_delta_raw if isinstance(allowed_delta_raw, dict) else {}
    for tier in TIER_KEYS:
        expected_count = expected.get(tier, 0)
        actual_count = tier_counts.get(tier, 0)
        tolerance = _int(allowed_delta.get(tier))
        if abs(actual_count - expected_count) > tolerance:
            problems.append(f"{tier} count expected {expected_count} +/- {tolerance}, got {actual_count}")

    max_count_raw = limits.get("max_count_by_tier")
    max_count: dict[str, Any] = max_count_raw if isinstance(max_count_raw, dict) else {}
    for tier, limit in max_count.items():
        if tier == "high_or_urgent":
            actual = tier_counts.get("high", 0) + tier_counts.get("urgent", 0)
        else:
            actual = tier_counts.get(str(tier), 0)
        if actual > _int(limit):
            problems.append(f"{tier} count limit {_int(limit)} exceeded by {actual}")

    max_ratio_raw = limits.get("max_ratio_by_tier")
    max_ratio: dict[str, Any] = max_ratio_raw if isinstance(max_ratio_raw, dict) else {}
    for tier, limit in max_ratio.items():
        actual_count = tier_counts.get("high", 0) + tier_counts.get("urgent", 0) if tier == "high_or_urgent" else tier_counts.get(str(tier), 0)
        ratio = _ratio(actual_count, total_findings)
        if ratio > _float(limit):
            problems.append(f"{tier} ratio limit {_float(limit):.4f} exceeded by {ratio:.4f}")

    min_total = limits.get("min_total_findings")
    if min_total is not None and total_findings < _int(min_total):
        problems.append(f"total findings expected at least {_int(min_total)}, got {total_findings}")

    max_total_delta_ratio = limits.get("max_total_findings_delta_ratio")
    expected_total = sum(expected.values())
    if max_total_delta_ratio is not None and expected_total:
        delta_ratio = abs(total_findings - expected_total) / expected_total
        if delta_ratio > _float(max_total_delta_ratio):
            problems.append(f"total finding drift limit {_float(max_total_delta_ratio):.4f} exceeded by {delta_ratio:.4f}")

    if snapshot.get("required_status") and str(target.get("status")) != str(snapshot["required_status"]):
        problems.append(f"status expected {snapshot['required_status']}, got {target.get('status')}")

    return {
        "id": str(snapshot.get("id") or snapshot.get("case_id") or "aggregate"),
        "status": "failed" if problems else "passed",
        "scope": "case" if snapshot.get("case_id") else "aggregate",
        "case_id": snapshot.get("case_id"),
        "total_findings": total_findings,
        "expected_tier_counts": expected,
        "actual_tier_counts": tier_counts,
        "regression_limits": limits,
        "problems": problems,
    }


def _select_target(benchmark: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    case_id = snapshot.get("case_id")
    if not case_id:
        target = benchmark.get("aggregate")
        if not isinstance(target, dict):
            raise BenchmarkSnapshotError("benchmark is missing aggregate metrics")
        return target
    for row in benchmark.get("cases") or []:
        if isinstance(row, dict) and row.get("id") == case_id:
            return row
    raise BenchmarkSnapshotError(f"benchmark case not found: {case_id}")


def _load_doc(value: str | Path | dict[str, Any], label: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    path = Path(value)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BenchmarkSnapshotError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BenchmarkSnapshotError(f"{path}: expected a JSON object for {label}")
    return data


def _tier_counts(value: Any) -> dict[str, int]:
    raw = value if isinstance(value, dict) else {}
    return {tier: _int(raw.get(tier)) for tier in TIER_KEYS}


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _ratio(count: int, total: int) -> float:
    return 0.0 if total <= 0 else count / total


__all__ = ["BenchmarkSnapshotError", "validate_benchmark_snapshots"]
