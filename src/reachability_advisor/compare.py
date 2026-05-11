"""PR delta comparison for developer workflows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .numeric import safe_float

ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "urgent": 4}


def _finding_map(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item.get("key")): item for item in data.get("findings", []) if isinstance(item, dict) and item.get("key")}


def compare_findings(base: dict[str, Any], head: dict[str, Any], score_delta: float = 5.0) -> dict[str, Any]:
    base_map = _finding_map(base)
    head_map = _finding_map(head)
    new: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    regressed: list[dict[str, Any]] = []
    improved: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []
    for key, finding in head_map.items():
        if key not in base_map:
            new.append(finding)
            continue
        old = base_map[key]
        old_score = safe_float(old.get("score"))
        new_score = safe_float(finding.get("score"))
        if _is_worsened(old, finding, score_delta):
            regressed.append({"before": old, "after": finding})
        elif new_score <= old_score - score_delta or _tier_rank(finding) < _tier_rank(old):
            improved.append({"before": old, "after": finding})
        else:
            unchanged.append(finding)
    for key, finding in base_map.items():
        if key not in head_map:
            resolved.append(finding)
    new.sort(key=_finding_sort_key)
    resolved.sort(key=_finding_sort_key)
    regressed.sort(key=lambda item: _finding_sort_key(item.get("after", {})))
    improved.sort(key=lambda item: _finding_sort_key(item.get("after", {})))
    unchanged.sort(key=_finding_sort_key)
    return {
        "schema_version": "1.0",
        "mode": "full",
        "summary": {
            "new": len(new),
            "resolved": len(resolved),
            "regressed": len(regressed),
            "improved": len(improved),
            "unchanged": len(unchanged),
        },
        "new": new,
        "resolved": resolved,
        "regressed": regressed,
        "improved": improved,
        "unchanged": unchanged,
    }


def pr_delta(delta: dict[str, Any]) -> dict[str, Any]:
    new = list(delta.get("new", []))
    worsened = list(delta.get("regressed", []))
    return {
        "schema_version": "1.0",
        "mode": "new-or-worsened",
        "summary": {
            "new": len(new),
            "worsened": len(worsened),
            "total": len(new) + len(worsened),
        },
        "new": new,
        "worsened": worsened,
    }


def write_delta(delta: dict[str, Any], path: str | Path) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(delta, indent=2), encoding="utf-8")


def write_delta_markdown(delta: dict[str, Any], path: str | Path) -> None:
    lines = ["# Reachability Advisor PR Delta", ""]
    summary = delta.get("summary", {})
    if delta.get("mode") == "new-or-worsened":
        lines.extend([
            f"- New findings: `{summary.get('new', 0)}`",
            f"- Worsened findings: `{summary.get('worsened', 0)}`",
            f"- Total actionable findings: `{summary.get('total', 0)}`",
            "",
        ])
    else:
        lines.extend([
            f"- New findings: `{summary.get('new', 0)}`",
            f"- Regressed findings: `{summary.get('regressed', 0)}`",
            f"- Resolved findings: `{summary.get('resolved', 0)}`",
            f"- Improved findings: `{summary.get('improved', 0)}`",
            "",
        ])
    if delta.get("new"):
        lines.append("## New findings")
        for finding in delta["new"][:10]:
            lines.append(_finding_line(finding))
        lines.append("")
    worsened_items = delta.get("worsened") if delta.get("mode") == "new-or-worsened" else delta.get("regressed")
    if worsened_items:
        lines.append("## Worsened findings" if delta.get("mode") == "new-or-worsened" else "## Regressed findings")
        for item in worsened_items[:10]:
            after = item.get("after", {})
            before = item.get("before", {})
            lines.append(f"- `{after.get('tier')}` `{after.get('vulnerability', {}).get('id')}` in `{after.get('component', {}).get('name')}` score `{before.get('score')}` -> `{after.get('score')}`")
        lines.append("")
    if delta.get("mode") != "new-or-worsened" and delta.get("resolved"):
        lines.append("## Resolved findings")
        for finding in delta["resolved"][:10]:
            lines.append(_finding_line(finding))
        lines.append("")
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _finding_line(finding: dict[str, Any]) -> str:
    return f"- `{finding.get('tier')}` `{finding.get('vulnerability', {}).get('id')}` in `{finding.get('artifact', {}).get('name')}/{finding.get('component', {}).get('name')}` score `{finding.get('score')}`"


def delta_fails(delta: dict[str, Any], tier: str) -> bool:
    threshold = ORDER[tier]
    for finding in delta.get("new", []):
        if _tier_rank(finding) >= threshold:
            return True
    for item in delta.get("regressed", []) + delta.get("worsened", []):
        after = item.get("after", {})
        if isinstance(after, dict) and _tier_rank(after) >= threshold:
            return True
    return False


def _is_worsened(old: dict[str, Any], finding: dict[str, Any], score_delta: float) -> bool:
    old_score = safe_float(old.get("score"))
    new_score = safe_float(finding.get("score"))
    if new_score >= old_score + score_delta:
        return True
    if _tier_rank(finding) > _tier_rank(old):
        return True
    return old.get("policy_status") == "excepted" and finding.get("policy_status") != "excepted"


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, float, str]:
    return (-_tier_rank(finding), -safe_float(finding.get("score")), str(finding.get("key") or ""))


def _tier_rank(finding: dict[str, Any]) -> int:
    return ORDER.get(str(finding.get("tier") or ""), 0)
