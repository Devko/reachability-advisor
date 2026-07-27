# src/reachability_advisor/config.py
"""Discovery, layering and resolution for .reachability.yml."""

from __future__ import annotations

import importlib.resources
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config_schema import ConfigError, ReachabilityConfig, validate_config
from .yaml_loader import YamlError, load_yaml_mapping

CONFIG_FILENAME = ".reachability.yml"
MAX_EXTENDS_DEPTH = 8
_URL_PREFIXES = ("http://", "https://", "git://", "ssh://", "ftp://")


@dataclass(frozen=True)
class LoadedConfig:
    config: ReachabilityConfig
    path: Path | None = None
    provenance: dict[str, str] = field(default_factory=dict)


def discover_config_path(start: Path) -> Path | None:
    """Find the nearest config, walking up no further than the git root.

    A config outside the repository is not reviewable in that repository's pull requests,
    so the search stops at the repo boundary rather than reaching into the home directory.
    """
    current = start.resolve()
    for directory in (current, *current.parents):
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        if (directory / ".git").exists():
            break
    return None


def _repo_boundary(source: Path) -> Path:
    """The furthest ancestor a path-form `extends` may resolve into from `source`.

    A config file is attacker-influenceable the same way scanner input is -- a pull
    request can add or edit one -- so a relative `extends` must not be able to climb out
    of the repository it was found in (e.g. `extends: ../../../../etc/passwd`). This walks
    the same way ``discover_config_path`` does, up to the nearest git root.

    Without a discoverable git root there is no established repository boundary to bound
    against, so the boundary falls back to `source`'s own directory: fail closed rather
    than allow an unbounded climb. This is recomputed fresh for every layer in the chain
    (relative to that layer's own location), so a layer resolved from an installed package
    -- which legitimately lives outside any repository -- gets its own boundary rooted at
    the package, not at the original repository.
    """
    directory = source.parent.resolve()
    for candidate in (directory, *directory.parents):
        if (candidate / ".git").exists():
            return candidate
    return directory


def _resolve_extends(target: str, source: Path) -> Path:
    if target.startswith(_URL_PREFIXES):
        raise ConfigError(
            f"{source}: extends {target!r} is not local. `extends` must name a relative path "
            "or an installed package; configuration is never fetched over the network."
        )
    if target.startswith((".", "/")) or target.endswith((".yml", ".yaml")):
        candidate = (source.parent / target).resolve()
        boundary = _repo_boundary(source)
        if not candidate.is_relative_to(boundary):
            # Deliberately omit the resolved absolute `candidate` here: the target
            # escapes the repository, so its real location on disk is not this
            # repository's business to know, let alone echo back in an error message.
            raise ConfigError(
                f"{source}: extends target {target!r} resolves outside the repository "
                "root. A path-form `extends` may not leave the project; distribute a "
                "shared baseline as an installed package instead."
            )
        if not candidate.is_file():
            raise ConfigError(f"{source}: extends target {target!r} does not exist at {candidate}")
        return candidate
    try:
        package = importlib.resources.files(target)
    except (ModuleNotFoundError, TypeError):
        raise ConfigError(
            f"{source}: extends target {target!r} is not an installed package and not a path. "
            "Install the package that provides your organization baseline, or use a relative path."
        ) from None
    candidate = Path(str(package)) / CONFIG_FILENAME
    if not candidate.is_file():
        raise ConfigError(f"{source}: package {target!r} does not contain {CONFIG_FILENAME}")
    return candidate


def resolve_layers(path: Path) -> list[tuple[str, dict[str, Any]]]:
    """Return layers lowest-precedence first, following `extends` with cycle detection."""
    layers: list[tuple[str, dict[str, Any]]] = []
    seen: set[Path] = set()
    current: Path | None = path.resolve()
    iterations = 0
    while current is not None:
        iterations += 1
        if iterations > MAX_EXTENDS_DEPTH:
            raise ConfigError(f"{path}: extends chain exceeds {MAX_EXTENDS_DEPTH} levels")
        if current in seen:
            raise ConfigError(f"{path}: extends cycle detected at {current}")
        seen.add(current)
        try:
            raw = load_yaml_mapping(current, "configuration")
        except YamlError as exc:
            raise ConfigError(str(exc)) from None
        layers.append((str(current), raw))
        target = raw.get("extends")
        if target is None:
            current = None
            continue
        if not isinstance(target, str) or not target.strip():
            raise ConfigError(f"{current}: 'extends' must be a non-empty string")
        current = _resolve_extends(target.strip(), current)
    layers.reverse()
    return layers


def merge_layers(layers: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for _, raw in layers:
        _merge_into(merged, raw)
    merged.pop("extends", None)
    return merged


def _merge_into(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _merge_into(target[key], value)
        else:
            # Lists replace: appending would make removing an inherited entry impossible.
            target[key] = value


def _provenance(layers: list[tuple[str, dict[str, Any]]]) -> dict[str, str]:
    trail: dict[str, str] = {}
    for name, raw in layers:
        for dotted in _flatten(raw):
            trail[dotted] = name
    return trail


def _flatten(block: dict[str, Any], prefix: str = "") -> list[str]:
    keys: list[str] = []
    for key, value in block.items():
        if key == "extends":
            continue
        dotted = f"{prefix}{key}"
        if isinstance(value, dict):
            keys.extend(_flatten(value, f"{dotted}."))
        else:
            keys.append(dotted)
    return keys


def load_config(path: str | Path | None, start: Path | None = None) -> LoadedConfig:
    """Load and validate configuration, or return defaults when none exists."""
    if path is None:
        found = discover_config_path(start or Path.cwd())
        if found is None:
            return LoadedConfig(config=validate_config({"version": 1}, "defaults"))
        path = found
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"{config_path}: configuration file does not exist")
    layers = resolve_layers(config_path)
    merged = merge_layers(layers)
    return LoadedConfig(
        config=validate_config(merged, str(config_path)),
        path=config_path,
        provenance=_provenance(layers),
    )
