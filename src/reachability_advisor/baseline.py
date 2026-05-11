"""Stable baseline artifacts for pull-request delta gates."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Finding
from .numeric import safe_float

BASELINE_SCHEMA_VERSION = "1.0"
BASELINE_KIND = "reachability-advisor-baseline"
TIER_ORDER = ("urgent", "high", "medium", "low", "informational")


def create_baseline_from_findings(findings: list[Finding], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    return create_baseline({"metadata": metadata or {}, "findings": [finding.to_json() for finding in findings]})


def create_baseline(data: dict[str, Any]) -> dict[str, Any]:
    findings = [_baseline_finding(item) for item in data.get("findings", []) if isinstance(item, dict) and item.get("key")]
    findings.sort(key=lambda item: item["key"])
    metadata = _baseline_metadata(findings, data.get("metadata"))
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "kind": BASELINE_KIND,
        "metadata": metadata,
        "findings": findings,
    }


def write_baseline(baseline: dict[str, Any], path: str | Path) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def load_baseline(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("baseline artifact must be a JSON object")
    if data.get("kind") != BASELINE_KIND:
        raise ValueError(f"baseline artifact kind must be {BASELINE_KIND!r}")
    if data.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise ValueError(f"unsupported baseline schema_version: {data.get('schema_version')!r}")
    if not isinstance(data.get("findings"), list):
        raise ValueError("baseline artifact must contain a findings array")
    return data


def baseline_as_findings_json(baseline: dict[str, Any]) -> dict[str, Any]:
    return {"metadata": baseline.get("metadata", {}), "findings": baseline.get("findings", [])}


def _baseline_finding(finding: dict[str, Any]) -> dict[str, Any]:
    source = finding.get("source_reachability", {}) if isinstance(finding.get("source_reachability"), dict) else {}
    context = finding.get("context", {}) if isinstance(finding.get("context"), dict) else {}
    return {
        "key": str(finding.get("key")),
        "artifact": _compact_object(finding.get("artifact"), ("name", "reference", "version")),
        "component": _compact_object(finding.get("component"), ("name", "display_name", "version", "purl", "scope", "group")),
        "vulnerability": _compact_object(finding.get("vulnerability"), ("id", "aliases", "severity", "known_exploited")),
        "score": round(safe_float(finding.get("score")), 2),
        "tier": str(finding.get("tier") or "informational"),
        "confidence": str(finding.get("confidence") or "low"),
        "policy_status": str(finding.get("policy_status") or "active"),
        "source_reachability": _compact_object(source, ("state", "label", "confidence", "evidence_source")),
        "context": _compact_object(context, ("environment", "exposure", "privilege", "criticality", "iam_impacts", "owner", "confidence")),
    }


def _compact_object(value: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    compact: dict[str, Any] = {}
    for key in keys:
        if key not in value:
            continue
        item = value[key]
        if item is None:
            continue
        if isinstance(item, list):
            compact[key] = sorted(str(entry) for entry in item)
        else:
            compact[key] = item
    return compact


def _baseline_metadata(findings: list[dict[str, Any]], source_metadata: Any) -> dict[str, Any]:
    tier_counts: dict[str, int] = dict.fromkeys(TIER_ORDER, 0)
    policy_status_counts: dict[str, int] = {}
    for finding in findings:
        tier = str(finding.get("tier") or "informational")
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
        status = str(finding.get("policy_status") or "active")
        policy_status_counts[status] = policy_status_counts.get(status, 0) + 1
    metadata: dict[str, Any] = {
        "finding_count": len(findings),
        "active_finding_count": sum(1 for finding in findings if finding.get("policy_status") != "excepted"),
        "tier_counts": tier_counts,
        "policy_status_counts": dict(sorted(policy_status_counts.items())),
    }
    if isinstance(source_metadata, dict):
        metadata["source_metadata"] = source_metadata
    return metadata
