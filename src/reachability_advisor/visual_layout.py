"""Shared visual report ranking and card layout constants."""

from __future__ import annotations

TIER_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "urgent": 4}
EXPOSURE_RANK = {"unknown": 0, "isolated": 1, "private": 1, "internal": 2, "external": 3, "public": 4}
CARD_LAYOUT = {
    "entry_width": 210.0,
    "entry_height": 96.0,
    "path_width": 290.0,
    "path_height": 152.0,
    "asset_width": 410.0,
    "asset_height": 292.0,
    "vulnerability_width": 500.0,
    "vulnerability_height": 112.0,
    "row_gap": 64.0,
    "vulnerability_gap": 16.0,
    "entry_x": 56.0,
    "path_x": 318.0,
    "asset_x": 660.0,
    "vulnerability_x": 1130.0,
}

__all__ = ["CARD_LAYOUT", "EXPOSURE_RANK", "TIER_RANK"]
