"""Shared visual report ranking, card layout, and de-duplication helpers."""

from __future__ import annotations

import json
from typing import Any

TIER_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "urgent": 4}
EXPOSURE_RANK = {"unknown": 0, "isolated": 1, "private": 1, "internal": 2, "external": 3, "public": 4}
CARD_LAYOUT = {
    "entry_width": 210.0,
    "entry_height": 96.0,
    "path_width": 340.0,
    "path_height": 152.0,
    "asset_width": 410.0,
    "asset_height": 292.0,
    "vulnerability_width": 500.0,
    "vulnerability_height": 112.0,
    "row_gap": 64.0,
    "vulnerability_gap": 16.0,
    "entry_x": 56.0,
    "path_x": 318.0,
    "asset_x": 712.0,
    "vulnerability_x": 1182.0,
}

_EMPTY_VALUES: tuple[Any, ...] = (None, "", [], {})


def _membership_token(value: Any) -> Any:
    """Return a hashable stand-in for ``value`` that de-duplicates the way ``==`` does."""

    try:
        hash(value)
    except TypeError:
        return ("json", json.dumps(value, sort_keys=True, default=str))
    return ("value", value)


class UniqueIndex:
    """Constant-time de-duplication for the append-only lists of the visual payload.

    The report payload is assembled by appending to many small lists that must stay
    JSON arrays and must keep insertion order, so they cannot simply become sets. The
    obvious ``value not in items`` guard is a linear scan, and every one of these
    lists grows with the finding count (a monorepo collapses every finding onto one
    asset, one network path, and one scenario category), which makes report assembly
    quadratic in the number of findings.

    This index keeps a membership set per list instead, keyed by list identity. The
    list object itself is retained so its ``id`` can never be recycled while the index
    is alive. Lists are assumed to be empty when they are first passed in, which is
    how the payload builders create them; pre-existing entries are left untouched
    rather than scanned, since scanning them is exactly the cost being removed.
    """

    __slots__ = ("_lists", "_seen")

    def __init__(self) -> None:
        self._lists: dict[int, list[Any]] = {}
        self._seen: dict[int, set[Any]] = {}

    def append(self, items: list[Any], value: Any) -> None:
        """Append ``value`` to ``items`` unless it is empty or already recorded."""

        if value in _EMPTY_VALUES:
            return
        seen = self._index_for(items)
        token = _membership_token(value)
        if token in seen:
            return
        seen.add(token)
        items.append(value)

    def append_keyed(self, items: list[Any], key: str, item: Any) -> None:
        """Append ``item`` unless ``key`` has already been used for ``items``.

        An empty key carries no identity, so it never de-duplicates: dropping an
        unidentified item would silently hide evidence instead of merging it.
        """

        if not key:
            items.append(item)
            return
        seen = self._index_for(items)
        token = ("key", key)
        if token in seen:
            return
        seen.add(token)
        items.append(item)

    def _index_for(self, items: list[Any]) -> set[Any]:
        marker = id(items)
        seen = self._seen.get(marker)
        if seen is None:
            seen = set()
            self._seen[marker] = seen
            self._lists[marker] = items
        return seen


__all__ = ["CARD_LAYOUT", "EXPOSURE_RANK", "TIER_RANK", "UniqueIndex"]
