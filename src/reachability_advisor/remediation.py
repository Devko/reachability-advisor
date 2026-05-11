"""Remediation grouping for developer-facing fix queues."""

from __future__ import annotations

import re
from typing import Any

from .models import Component, Finding, Reachability, Tier, reachability_label

TIER_ORDER = {Tier.INFORMATIONAL: 0, Tier.LOW: 1, Tier.MEDIUM: 2, Tier.HIGH: 3, Tier.URGENT: 4}
REACHABILITY_ORDER = {
    Reachability.ABSENT: 0,
    Reachability.UNKNOWN_DUE_TO_NO_RULE: 1,
    Reachability.PACKAGE_PRESENT: 2,
    Reachability.DEPENDENCY_REACHABLE: 3,
    Reachability.IMPORTED: 4,
    Reachability.FUNCTION_REACHABLE: 5,
    Reachability.ATTACKER_CONTROLLED: 6,
}


def build_remediation_groups(findings: list[Finding]) -> list[dict[str, Any]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        key = "|".join(
            [
                finding.artifact.name,
                finding.component.name,
                finding.component.version or "",
                finding.component.purl or "",
            ]
        )
        grouped.setdefault(key, []).append(finding)

    groups = [_group_to_json(key, items) for key, items in grouped.items()]
    return sorted(
        groups,
        key=lambda item: (
            float(item["max_score"]),
            int(item["vulnerability_count"]),
            TIER_ORDER[Tier(str(item["tier"]))],
            str(item["artifact"]["name"]),
            str(item["component"]["name"]),
        ),
        reverse=True,
    )


def _group_to_json(key: str, findings: list[Finding]) -> dict[str, Any]:
    top = max(findings, key=lambda finding: (finding.score, TIER_ORDER[finding.tier]))
    highest_reachability = max((finding.source.reachability for finding in findings), key=lambda item: REACHABILITY_ORDER[item])
    fixed_versions = _sorted_versions_desc(
        {
            version
            for finding in findings
            for version in finding.vulnerability.fixed_versions
            if version
        }
    )
    suggested_version = fixed_versions[0] if fixed_versions else None
    return {
        "key": key,
        "artifact": {
            "name": top.artifact.name,
            "reference": top.artifact.reference,
            "version": top.artifact.version,
        },
        "component": {
            "name": top.component.name,
            "display_name": top.component.display_name,
            "version": top.component.version,
            "purl": top.component.purl,
            "scope": top.component.scope,
            "group": top.component.group,
        },
        "vulnerability_count": len(findings),
        "max_score": round(top.score, 2),
        "tier": top.tier.value,
        "confidence": top.confidence.value,
        "reachability": highest_reachability.value,
        "reachability_label": reachability_label(highest_reachability),
        "context": {
            "exposure": top.context.exposure,
            "environment": top.context.environment,
            "privilege": top.context.privilege,
            "criticality": top.context.criticality,
            "iam_impacts": top.context.iam_impacts,
            "owner": top.context.owner,
        },
        "fix_available": bool(suggested_version),
        "suggested_version": suggested_version,
        "suggested_fix": _fix_command_for_version(top.component, suggested_version) if suggested_version else None,
        "candidate_fixed_versions": fixed_versions,
        "candidate_fix_commands": _dedupe(
            [
                command
                for finding in sorted(findings, key=lambda item: item.score, reverse=True)
                for command in finding.fix_commands
            ]
        ),
        "top_vulnerabilities": [
            {
                "id": finding.vulnerability.id,
                "aliases": finding.vulnerability.aliases,
                "severity": finding.vulnerability.severity,
                "cvss": finding.vulnerability.cvss,
                "epss": finding.vulnerability.epss,
                "known_exploited": finding.vulnerability.known_exploited,
                "fixed_versions": finding.vulnerability.fixed_versions,
                "score": round(finding.score, 2),
                "tier": finding.tier.value,
            }
            for finding in sorted(findings, key=lambda item: item.score, reverse=True)
        ],
    }


def _fix_command_for_version(component: Component, version: str | None) -> str | None:
    if not version:
        return None
    purl = component.purl or ""
    if purl.startswith("pkg:npm/"):
        return f"npm install {component.name}@{version}"
    if purl.startswith("pkg:pypi/"):
        return f"python -m pip install --upgrade {component.name}=={version}"
    if purl.startswith("pkg:maven/"):
        return f"Set Maven dependency {component.display_name.replace('/', ':')} to version {version}"
    return f"Upgrade {component.name} to {version}"


def _sorted_versions_desc(versions: set[str]) -> list[str]:
    return sorted(versions, key=_version_key, reverse=True)


def _version_key(version: str) -> tuple[tuple[int, int | str], ...]:
    parts = [part for part in re.split(r"[.\-+_]", version) if part]
    key: list[tuple[int, int | str]] = []
    for part in parts:
        if part.isdigit():
            key.append((1, int(part)))
        else:
            key.append((0, part.lower()))
    return tuple(key)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped
