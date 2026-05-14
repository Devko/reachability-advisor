"""Canonical finding type helpers."""

from __future__ import annotations

from collections.abc import Iterable

DEPENDENCY_VULNERABILITY = "dependency_vulnerability"
STATIC_CODE_WEAKNESS = "static_code_weakness"
DYNAMIC_RUNTIME_OBSERVATION = "dynamic_runtime_observation"
CORRELATED_SECURITY_FINDING = "correlated_security_finding"

CANONICAL_FINDING_TYPES = {
    DEPENDENCY_VULNERABILITY,
    STATIC_CODE_WEAKNESS,
    DYNAMIC_RUNTIME_OBSERVATION,
    CORRELATED_SECURITY_FINDING,
}

SECURITY_FINDING_TYPES = {
    STATIC_CODE_WEAKNESS,
    DYNAMIC_RUNTIME_OBSERVATION,
    CORRELATED_SECURITY_FINDING,
}


def canonical_finding_type(value: str | None) -> str:
    """Return the canonical finding type while preserving unknown future values."""

    return str(value or DEPENDENCY_VULNERABILITY)


def is_dependency_finding(value: str | None) -> bool:
    return canonical_finding_type(value) == DEPENDENCY_VULNERABILITY


def is_static_finding(value: str | None) -> bool:
    return canonical_finding_type(value) == STATIC_CODE_WEAKNESS


def is_dynamic_finding(value: str | None) -> bool:
    return canonical_finding_type(value) == DYNAMIC_RUNTIME_OBSERVATION


def is_security_finding(value: str | None) -> bool:
    return canonical_finding_type(value) in SECURITY_FINDING_TYPES


def finding_kind(value: str | None) -> str:
    finding_type = canonical_finding_type(value)
    return {
        DEPENDENCY_VULNERABILITY: "vulnerability",
        STATIC_CODE_WEAKNESS: STATIC_CODE_WEAKNESS,
        DYNAMIC_RUNTIME_OBSERVATION: DYNAMIC_RUNTIME_OBSERVATION,
        CORRELATED_SECURITY_FINDING: CORRELATED_SECURITY_FINDING,
    }.get(finding_type, "security_finding")


def count_canonical_types(values: Iterable[str | None]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        finding_type = canonical_finding_type(value)
        counts[finding_type] = counts.get(finding_type, 0) + 1
    return dict(sorted(counts.items()))


__all__ = [
    "CANONICAL_FINDING_TYPES",
    "CORRELATED_SECURITY_FINDING",
    "DEPENDENCY_VULNERABILITY",
    "DYNAMIC_RUNTIME_OBSERVATION",
    "SECURITY_FINDING_TYPES",
    "STATIC_CODE_WEAKNESS",
    "canonical_finding_type",
    "count_canonical_types",
    "finding_kind",
    "is_dependency_finding",
    "is_dynamic_finding",
    "is_security_finding",
    "is_static_finding",
]
