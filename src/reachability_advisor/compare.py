"""PR delta comparison for developer workflows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "urgent": 4}


def _finding_map(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item.get("key")): item for item in data.get("findings", []) if isinstance(item, dict) and item.get("key")}


def compare_findings(base: dict[str, Any], head: dict[str, Any], score_delta: float = 5.0) -> dict[str, Any]:
    base_map = _finding_map(base)
    head_map = _finding_map(head)
    new = []
    resolved = []
    regressed = []
    improved = []
    unchanged = []
    for key, finding in head_map.items():
        if key not in base_map:
            new.append(finding)
            continue
        old = base_map[key]
        old_score = float(old.get("score") or 0)
        new_score = float(finding.get("score") or 0)
        if new_score >= old_score + score_delta or ORDER.get(str(finding.get("tier")), 0) > ORDER.get(str(old.get("tier")), 0):
            regressed.append({"before": old, "after": finding})
        elif new_score <= old_score - score_delta or ORDER.get(str(finding.get("tier")), 0) < ORDER.get(str(old.get("tier")), 0):
            improved.append({"before": old, "after": finding})
        else:
            unchanged.append(finding)
    for key, finding in base_map.items():
        if key not in head_map:
            resolved.append(finding)
    return {
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


def write_delta(delta: dict[str, Any], path: str | Path) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(delta, indent=2), encoding="utf-8")


def write_delta_markdown(delta: dict[str, Any], path: str | Path) -> None:
    lines = ["# Reachability Advisor PR Delta", ""]
    summary = delta.get("summary", {})
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
    if delta.get("regressed"):
        lines.append("## Regressed findings")
        for item in delta["regressed"][:10]:
            after = item.get("after", {})
            before = item.get("before", {})
            lines.append(f"- `{after.get('tier')}` `{after.get('vulnerability', {}).get('id')}` in `{after.get('component', {}).get('name')}` score `{before.get('score')}` -> `{after.get('score')}`")
        lines.append("")
    if delta.get("resolved"):
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
        if ORDER.get(str(finding.get("tier")), 0) >= threshold:
            return True
    for item in delta.get("regressed", []):
        after = item.get("after", {})
        if ORDER.get(str(after.get("tier")), 0) >= threshold:
            return True
    return False
