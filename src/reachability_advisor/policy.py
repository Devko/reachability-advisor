"""Policy loading and exception handling."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .models import Finding, Tier
from .scoring import ScorePolicy


@dataclass(frozen=True)
class ExceptionRule:
    vulnerability: str | None = None
    artifact: str | None = None
    component: str | None = None
    expires: date | None = None
    reason: str = ""

    def applies(self, finding: Finding, today: date | None = None) -> bool:
        today = today or date.today()
        if self.expires and self.expires < today:
            return False
        if self.vulnerability and self.vulnerability != finding.vulnerability.id:
            return False
        if self.artifact and self.artifact != finding.artifact.name:
            return False
        if self.component and self.component != finding.component.name:
            return False
        return True


@dataclass
class RuntimePolicy:
    score_policy: ScorePolicy
    fail_on_tier: Tier = Tier.HIGH
    exceptions: list[ExceptionRule] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.exceptions is None:
            self.exceptions = []


def _tier(value: Any, default: Tier) -> Tier:
    raw = str(value or default.value).lower()
    return Tier(raw) if raw in {item.value for item in Tier} else default


def _exceptions(items: Any) -> list[ExceptionRule]:
    rules: list[ExceptionRule] = []
    if not isinstance(items, list):
        return rules
    for item in items:
        if not isinstance(item, dict):
            continue
        expires = None
        if item.get("expires"):
            try:
                expires = date.fromisoformat(str(item["expires"]))
            except ValueError:
                expires = None
        rules.append(
            ExceptionRule(
                vulnerability=str(item.get("vulnerability")) if item.get("vulnerability") else None,
                artifact=str(item.get("artifact")) if item.get("artifact") else None,
                component=str(item.get("component")) if item.get("component") else None,
                expires=expires,
                reason=str(item.get("reason") or ""),
            )
        )
    return rules


def load_runtime_policy(path: str | Path | None) -> RuntimePolicy:
    if not path:
        return RuntimePolicy(score_policy=ScorePolicy())
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return RuntimePolicy(score_policy=ScorePolicy())
    return RuntimePolicy(score_policy=ScorePolicy(), fail_on_tier=_tier(data.get("fail_on_tier"), Tier.HIGH), exceptions=_exceptions(data.get("exceptions")))


def apply_exceptions(findings: list[Finding], runtime_policy: RuntimePolicy) -> list[Finding]:
    for finding in findings:
        for rule in runtime_policy.exceptions:
            if rule.applies(finding):
                finding.policy_status = "excepted"
                finding.rationale.append(f"policy exception applied: {rule.reason or 'no reason provided'}")
                break
    return findings
