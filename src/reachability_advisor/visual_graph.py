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
    visible_paths: dict[str, dict[str, Any]] = {}
    y = 78.0
    max_vulnerability_count = 0

    for asset in assets:
        asset_id = _string(asset.get("id"))
        if not asset_id:
            continue
        primary_path = _primary_network_path_for_asset(network_paths, asset_id)
        if primary_path:
            path_id = _string(primary_path.get("id"))
            if path_id:
                visible_paths[path_id] = primary_path
        asset_vulnerabilities = _vulnerabilities_for_asset(vulnerabilities, asset_id)
        max_vulnerability_count = max(max_vulnerability_count, len(asset_vulnerabilities))
        vulnerability_block_height = (
            len(asset_vulnerabilities) * (CARD_LAYOUT["vulnerability_height"] + CARD_LAYOUT["vulnerability_gap"])
            - CARD_LAYOUT["vulnerability_gap"]
            if asset_vulnerabilities
            else 0.0
        )
        row_height = max(CARD_LAYOUT["asset_height"], CARD_LAYOUT["path_height"], vulnerability_block_height)

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

    entry_paths: dict[str, list[str]] = {}
    for path in visible_paths.values():
        path_id = _string(path.get("id"))
        connected_assets = [asset_id for asset_id in _asset_ids_for_path(path) if asset_id in positions]
        if not path_id or not connected_assets:
            continue
        path_center = _average([positions[asset_id]["y"] + positions[asset_id]["height"] / 2 for asset_id in connected_assets])
        path_position = _position(
            CARD_LAYOUT["path_x"],
            max(0.0, path_center - CARD_LAYOUT["path_height"] / 2),
            CARD_LAYOUT["path_width"],
            CARD_LAYOUT["path_height"],
        )
        positions[path_id] = path_position
        nodes.append({
            "id": path_id,
            "role": "network_path",
            "assetIds": connected_assets,
            "position": path_position,
        })
        entry_id = _entry_id_for_path(path)
        entry_paths.setdefault(entry_id, []).append(path_id)
        for asset_id in connected_assets:
            edges.append({"source": path_id, "target": asset_id, "role": "path-asset"})

    for entry_id, path_ids in sorted(entry_paths.items()):
        path_centers = [positions[path_id]["y"] + positions[path_id]["height"] / 2 for path_id in path_ids if path_id in positions]
        if not path_centers:
            continue
        entry_center = _average(path_centers)
        entry_position = _position(
            CARD_LAYOUT["entry_x"],
            max(0.0, entry_center - CARD_LAYOUT["entry_height"] / 2),
            CARD_LAYOUT["entry_width"],
            CARD_LAYOUT["entry_height"],
        )
        positions[entry_id] = entry_position
        nodes.append({
            "id": entry_id,
            "role": "entry",
            "pathIds": path_ids,
            "position": entry_position,
        })
        for path_id in path_ids:
            edges.append({"source": entry_id, "target": path_id, "role": "entry-path"})

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
    paths = [path for path in network_paths if asset_id in _asset_ids_for_path(path)]
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


def _asset_ids_for_path(path: dict[str, Any]) -> list[str]:
    asset_ids = path.get("assetIds")
    if isinstance(asset_ids, list):
        return [_string(value) for value in asset_ids if _string(value)]
    asset_id = _string(path.get("assetId"))
    return [asset_id] if asset_id else []


def _entry_id_for_path(path: dict[str, Any]) -> str:
    return _string(path.get("entryNodeId")) or f"{_string(path.get('id'))}:entry"


def _average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


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
