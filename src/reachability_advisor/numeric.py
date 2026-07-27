"""Small numeric coercion helpers for external JSON fields."""

from __future__ import annotations

import math
from typing import Any


def finite_float_or_none(value: Any) -> float | None:
    """Parse an untrusted JSON scalar into a *finite* float, or ``None``.

    ``json.loads`` accepts the bare ``NaN``/``Infinity``/``-Infinity`` literals and
    unbounded integer literals. Those must never become a score: a non-finite CVSS
    silently overrides an explicit ``severity`` string during impact classification
    and re-serializes as non-standard JSON that breaks report consumers.

    Unlike :func:`safe_float`, absence stays absent -- there is no default to fall
    back to, so an unusable value cannot be mistaken for a genuine ``0.0``.

    This lives here rather than in a caller because it was previously duplicated in
    ``vulnerability`` and ``vulnerability_intelligence``, and the copies drifted: only
    one of them guarded ``math.isfinite``, which left a live NaN ingest path.
    """

    try:
        if value is None or value == "":
            return None
        number = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def safe_float(value: Any, default: float = 0.0) -> float:
    """Coerce untrusted JSON scalars to a finite float.

    ``json.loads`` accepts the bare ``NaN``/``Infinity``/``-Infinity`` literals and
    arbitrarily large integer literals. Those values sort non-deterministically and
    serialize back as non-standard JSON, so they are treated as absent here.
    """

    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except (OverflowError, ValueError):
            return default
        return number if math.isfinite(number) else default
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            return default
        return number if math.isfinite(number) else default
    return default
