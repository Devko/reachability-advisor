"""Deterministic graph layout model for visual report regression tests."""

from __future__ import annotations

from typing import Any, cast

from .numeric import safe_float
from .visual_layout import CARD_LAYOUT, EXPOSURE_RANK, TIER_RANK


def visual_graph_model(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the card/edge model used by the browser layout.

    The HTML renderer performs layout in JavaScript. This dependency-free model
    mirrors that logic so tests can verify connectivity and bounds without a
    browser.
    """

    assets = _dict_items(payload.get("assets"))
    vulnerabilities = _dict_items(payload.get("vulnerabilities"))
    network_paths = _dict_items(payload.get("networkPaths"))
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    positions: dict[str, dict[str, float]] = {}
    y = 78.0
    max_vulnerability_count = 0

    for asset in assets:
        asset_id = _string(asset.get("id"))
        if not asset_id:
            continue
        primary_path = _primary_network_path_for_asset(network_paths, asset_id)
        asset_vulnerabilities = _vulnerabilities_for_asset(vulnerabilities, asset_id)
        max_vulnerability_count = max(max_vulnerability_count, len(asset_vulnerabilities))
        vulnerability_block_height = (
            len(asset_vulnerabilities) * (CARD_LAYOUT["vulnerability_height"] + CARD_LAYOUT["vulnerability_gap"])
            - CARD_LAYOUT["vulnerability_gap"]
            if asset_vulnerabilities
            else 0.0
        )
        row_height = max(CARD_LAYOUT["asset_height"], CARD_LAYOUT["path_height"], vulnerability_block_height)

        if primary_path:
            path_id = _string(primary_path.get("id"))
            if path_id:
                entry_id = f"{path_id}:entry"
                entry_position = _position(
                    CARD_LAYOUT["entry_x"],
                    y + max(0.0, (row_height - CARD_LAYOUT["entry_height"]) / 2),
                    CARD_LAYOUT["entry_width"],
                    CARD_LAYOUT["entry_height"],
                )
                path_position = _position(
                    CARD_LAYOUT["path_x"],
                    y + max(0.0, (row_height - CARD_LAYOUT["path_height"]) / 2),
                    CARD_LAYOUT["path_width"],
                    CARD_LAYOUT["path_height"],
                )
                positions[entry_id] = entry_position
                positions[path_id] = path_position
                nodes.append({
                    "id": entry_id,
                    "role": "entry",
                    "assetId": asset_id,
                    "pathId": path_id,
                    "position": entry_position,
                })
                nodes.append({
                    "id": path_id,
                    "role": "network_path",
                    "assetId": asset_id,
                    "position": path_position,
                })
                edges.append({"source": entry_id, "target": path_id, "role": "entry-path"})
                edges.append({"source": path_id, "target": asset_id, "role": "path-asset"})

        asset_position = _position(
            CARD_LAYOUT["asset_x"],
            y + max(0.0, (row_height - CARD_LAYOUT["asset_height"]) / 2),
            CARD_LAYOUT["asset_width"],
            CARD_LAYOUT["asset_height"],
        )
        positions[asset_id] = asset_position
        nodes.append({"id": asset_id, "role": "asset", "position": asset_position})

        for index, vulnerability in enumerate(asset_vulnerabilities):
            vulnerability_id = _string(vulnerability.get("id"))
            if not vulnerability_id:
                continue
            vulnerability_position = _position(
                CARD_LAYOUT["vulnerability_x"],
                y + index * (CARD_LAYOUT["vulnerability_height"] + CARD_LAYOUT["vulnerability_gap"]),
                CARD_LAYOUT["vulnerability_width"],
                CARD_LAYOUT["vulnerability_height"],
            )
            positions[vulnerability_id] = vulnerability_position
            nodes.append({
                "id": vulnerability_id,
                "role": "vulnerability",
                "assetId": asset_id,
                "findingKey": _string(vulnerability.get("findingKey")),
                "position": vulnerability_position,
            })
            edges.append({"source": asset_id, "target": vulnerability_id, "role": "asset-vulnerability"})

        y += row_height + CARD_LAYOUT["row_gap"]

    node_ids = [node["id"] for node in nodes]
    bounds = {
        "width": max(980.0, CARD_LAYOUT["vulnerability_x"] + CARD_LAYOUT["vulnerability_width"] + 80.0),
        "height": max(620.0, y + 40.0),
        "maxVulnerabilityCount": max_vulnerability_count,
    }
    return {
        "nodes": nodes,
        "edges": edges,
        "positions": positions,
        "bounds": bounds,
        "duplicateNodeIds": _duplicates(node_ids),
    }


def _dict_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [cast(dict[str, Any], item) for item in value if isinstance(item, dict)]


def _primary_network_path_for_asset(network_paths: list[dict[str, Any]], asset_id: str) -> dict[str, Any] | None:
    paths = [path for path in network_paths if path.get("assetId") == asset_id]
    if not paths:
        return None
    return sorted(
        paths,
        key=lambda item: (
            -EXPOSURE_RANK.get(_string(item.get("exposure")) or "unknown", 0),
            -TIER_RANK.get(_string(item.get("tier")) or "informational", 0),
            -safe_float(item.get("score")),
            _string(item.get("id")),
        ),
    )[0]


def _vulnerabilities_for_asset(vulnerabilities: list[dict[str, Any]], asset_id: str) -> list[dict[str, Any]]:
    return sorted(
        [item for item in vulnerabilities if item.get("assetId") == asset_id],
        key=lambda item: (
            -TIER_RANK.get(_string(item.get("tier")) or "informational", 0),
            -safe_float(item.get("score")),
            _string(item.get("label")),
        ),
    )


def _position(x: float, y: float, width: float, height: float) -> dict[str, float]:
    return {"x": x, "y": y, "width": width, "height": height}


def _string(value: Any) -> str:
    return str(value) if value not in (None, "") else ""


def _duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicated: list[str] = []
    for value in values:
        if value in seen and value not in duplicated:
            duplicated.append(value)
        seen.add(value)
    return duplicated
