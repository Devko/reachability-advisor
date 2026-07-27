"""Policy loading and exception handling."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from .input_limits import read_text_limited
from .models import Finding, Tier
from .scoring import ScorePolicy

POLICY_KEYS = frozenset({"$schema", "schema_version", "fail_on_tier", "exceptions"})
EXCEPTION_KEYS = frozenset({"vulnerability", "artifact", "component", "expires", "reason"})
SELECTOR_KEYS = ("vulnerability", "artifact", "component")


class PolicyError(ValueError):
    """Raised when a runtime policy document is malformed.

    A malformed policy must stop the scan instead of being coerced into a weaker
    policy: every silent coercion in this loader widens a waiver, and a waiver
    that suppresses more than its author intended is indistinguishable from a
    missing scan. Subclassing ``ValueError`` keeps the CLI's top-level handler
    (which already maps ``ValueError`` to ``error: ...`` and exit code 2)
    working without ``policy.py`` importing from ``cli.py``.
    """


@dataclass(frozen=True)
class ExceptionRule:
    vulnerability: str | None = None
    artifact: str | None = None
    component: str | None = None
    expires: date | None = None
    reason: str = ""

    def is_scoped(self) -> bool:
        """True when the rule names at least one finding attribute to match on."""
        return bool(self.vulnerability or self.artifact or self.component)

    def applies(self, finding: Finding, today: date | None = None) -> bool:
        # A rule that names no vulnerability, artifact or component says nothing
        # about which finding it waives. Treating that as "matches everything"
        # turns one bad line of policy into a silent, scan-wide suppression, so
        # an unscoped rule matches nothing instead.
        if not self.is_scoped():
            return False
        today = today or date.today()
        if self.expires and self.expires < today:
            return False
        if self.vulnerability and self.vulnerability != finding.vulnerability.id:
            return False
        if self.artifact and self.artifact != finding.artifact.name:
            return False
        return not (self.component and self.component != finding.component.name)


@dataclass
class RuntimePolicy:
    score_policy: ScorePolicy
    fail_on_tier: Tier = Tier.HIGH
    exceptions: list[ExceptionRule] = field(default_factory=list)


def _tier(value: Any, default: Tier, source: str) -> Tier:
    if value is None:
        return default
    allowed = {item.value for item in Tier}
    raw = str(value).strip().lower()
    if raw not in allowed:
        raise PolicyError(
            f'{source}: "fail_on_tier" must be one of {", ".join(sorted(allowed))}, got {value!r}'
        )
    return Tier(raw)


def _text(item: dict[str, Any], key: str, label: str) -> str | None:
    """Return a present, non-blank string field, or None when the key is absent.

    The value is returned verbatim (not stripped) so that matching semantics are
    unchanged; only blank-or-wrong-typed values are rejected.
    """
    if key not in item:
        return None
    raw = item[key]
    if not isinstance(raw, str) or not raw.strip():
        raise PolicyError(f'{label}: "{key}" must be a non-empty string, got {raw!r}')
    return raw


def _parse_expires(item: dict[str, Any], label: str) -> date | None:
    """Parse an exception expiry, refusing to downgrade a bad value to "never expires".

    Accepts a bare ISO-8601 date (``2026-12-31``) and an ISO-8601 timestamp
    (``2026-12-31T00:00:00Z``); a timestamp is reduced to the calendar date it
    names, as written, without shifting time zones.
    """
    if "expires" not in item:
        return None
    raw = item["expires"]
    if not isinstance(raw, str) or not raw.strip():
        raise PolicyError(
            f'{label}: "expires" must be a non-empty ISO-8601 date string '
            f"(YYYY-MM-DD), got {raw!r}"
        )
    value = raw.strip()
    try:
        return date.fromisoformat(value)
    except ValueError:
        pass
    timestamp = f"{value[:-1]}+00:00" if value.endswith(("Z", "z")) else value
    try:
        return datetime.fromisoformat(timestamp).date()
    except ValueError:
        raise PolicyError(
            f'{label}: "expires" value {raw!r} is not an ISO-8601 date (expected YYYY-MM-DD). '
            "Refusing to treat an unreadable expiry as a waiver that never expires."
        ) from None


def _exceptions(items: Any, source: str) -> list[ExceptionRule]:
    rules: list[ExceptionRule] = []
    if items is None:
        return rules
    if not isinstance(items, list):
        raise PolicyError(f'{source}: "exceptions" must be a list of exception objects')
    for index, item in enumerate(items):
        label = f"{source}: exception[{index}]"
        if not isinstance(item, dict):
            raise PolicyError(f"{label}: must be an object, got {item!r}")
        unknown = sorted(str(key) for key in item if key not in EXCEPTION_KEYS)
        if unknown:
            raise PolicyError(
                f"{label}: unknown key(s) {', '.join(repr(key) for key in unknown)}; "
                f"allowed keys are {', '.join(sorted(EXCEPTION_KEYS))}"
            )
        reason = _text(item, "reason", label)
        if reason is None:
            raise PolicyError(f'{label}: "reason" is required so every waiver is accountable')
        rule = ExceptionRule(
            vulnerability=_text(item, "vulnerability", label),
            artifact=_text(item, "artifact", label),
            component=_text(item, "component", label),
            expires=_parse_expires(item, label),
            reason=reason,
        )
        if not rule.is_scoped():
            raise PolicyError(
                f"{label}: must scope at least one of "
                f"{', '.join(f'{key!r}' for key in SELECTOR_KEYS)}; "
                "an unscoped exception would suppress every finding in the scan"
            )
        rules.append(rule)
    return rules


def load_runtime_policy(path: str | Path | None) -> RuntimePolicy:
    if not path:
        return RuntimePolicy(score_policy=ScorePolicy())
    source = f"runtime policy {path}"
    data = json.loads(read_text_limited(Path(path), "runtime policy"))
    if not isinstance(data, dict):
        raise PolicyError(f"{source}: must be a JSON object")
    unknown = sorted(str(key) for key in data if key not in POLICY_KEYS)
    if unknown:
        raise PolicyError(
            f"{source}: unknown key(s) {', '.join(repr(key) for key in unknown)}; "
            f"allowed keys are {', '.join(sorted(POLICY_KEYS))}"
        )
    return RuntimePolicy(
        score_policy=ScorePolicy(),
        fail_on_tier=_tier(data.get("fail_on_tier"), Tier.HIGH, source),
        exceptions=_exceptions(data.get("exceptions"), source),
    )


def apply_exceptions(findings: list[Finding], runtime_policy: RuntimePolicy) -> list[Finding]:
    for finding in findings:
        for rule in runtime_policy.exceptions:
            if rule.applies(finding):
                finding.policy_status = "excepted"
                finding.rationale.append(
                    f"policy exception applied: {rule.reason or 'no reason provided'}"
                )
                break
    return findings
