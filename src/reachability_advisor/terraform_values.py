"""Shared Terraform value normalization helpers."""

from __future__ import annotations

import re
from typing import Any


def listify(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def value_reference_candidates(values: Any) -> set[str]:
    candidates: set[str] = set()

    def add(value: Any) -> None:
        if value is None:
            return
        text = str(value).strip().strip('"').strip("'")
        if not text:
            return
        lower = text.lower()
        candidates.add(lower)
        path_parts = [part for part in re.split(r"[/\\]", lower) if part]
        cloud_path_markers = (
            "/backendaddresspools/",
            "/networkinterfaces/",
            "/targetgroup/",
            "/services/",
            "/locations/",
            "/networks/",
            "/regions/",
            "/routetables/",
            "/routes/",
            "/subnets/",
            "/zones/",
        )
        if len(path_parts) > 1 and any(marker in lower for marker in cloud_path_markers):
            candidates.add(path_parts[-1])
        for token in re.findall(r"[A-Za-z0-9_:\-/]+(?:\.[A-Za-z0-9_\-]+)+|sg-[A-Za-z0-9]+|arn:[^\s,\]\}]+", text):
            cleaned = token.strip().strip('"').strip("'").lower()
            if "/" in cleaned and not cleaned.startswith("arn:"):
                continue
            candidates.add(cleaned)

    if isinstance(values, dict):
        for value in values.values():
            candidates.update(value_reference_candidates(value))
    elif isinstance(values, (list, tuple, set)):
        for value in values:
            candidates.update(value_reference_candidates(value))
    else:
        add(values)
    return {candidate for candidate in candidates if candidate}


__all__ = ["listify", "value_reference_candidates"]
