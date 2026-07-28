# src/reachability_advisor/config.py
"""Discovery, layering and resolution for .reachability.yml."""

from __future__ import annotations

import importlib.util
import os
import stat
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


def _existing_config_problem(candidate: Path) -> str | None:
    """Describe why `candidate` cannot be used as a configuration file.

    Returns `None` in exactly two cases that a caller should treat very differently:
    nothing at all exists at `candidate` (an absent path is not a problem -- a discovery
    walk should keep looking further up the tree), or `candidate` is a readable regular
    file (or a symlink chain that ultimately resolves to one) -- a genuinely usable config.

    Every other outcome describes a real problem: a dangling symlink, a symlink to a
    directory, a symlink to anything else that is not a regular file, a plain directory, a
    FIFO/socket/device, or a regular file this process cannot read. Before this existed,
    `discover_config_path` asked only `candidate.is_file()`, which is `False` for every one
    of those cases -- indistinguishable from "nothing here, keep walking up." A
    `.reachability.yml` replaced by a dangling symlink (a legitimate git blob: mode
    `120000`) therefore made the walk silently continue past it and fall back to built-in
    defaults, `path=None` -- which every consumer (the gate, `config validate`, `doctor`)
    reads as "no config file found," even though one is sitting right there, broken. This
    is used both by `discover_config_path` (which must fail loudly here, not walk past a
    broken entry) and by `load_config`'s explicit-`--config`-path branch (for the same
    reason, with a more accurate message than a bare "does not exist").
    """
    try:
        info = candidate.lstat()
    except OSError:
        return None  # Nothing here at all; not a problem, just absent.
    if stat.S_ISLNK(info.st_mode):
        try:
            target_info = candidate.stat()  # Follows the whole symlink chain.
        except OSError:
            return "a symlink whose target does not exist (a dangling symlink)"
        if stat.S_ISDIR(target_info.st_mode):
            return "a symlink to a directory, not a file"
        if not stat.S_ISREG(target_info.st_mode):
            return "a symlink to something that is not a regular file"
        # Resolves to a real regular file: fall through to the readability check below,
        # exactly as for a plain (non-symlink) regular file.
    elif stat.S_ISDIR(info.st_mode):
        return "a directory, not a file"
    elif not stat.S_ISREG(info.st_mode):
        return "not a regular file (for example a FIFO, socket, or device)"
    if not os.access(candidate, os.R_OK):
        return "not readable (permission denied)"
    return None


def discover_config_path(start: Path) -> Path | None:
    """Find the nearest config, walking up no further than the git root.

    A config outside the repository is not reviewable in that repository's pull requests,
    so the search stops at the repo boundary rather than reaching into the home directory.

    An entry that exists but is not a usable config file (see `_existing_config_problem`)
    stops the walk with a loud `ConfigError` rather than being silently treated as absent:
    walking past it would fall back to built-in defaults with no config file loaded at
    all, which is a silently *weaker* outcome than the broken file the repository actually
    contains -- exactly the "gate that silently stops gating" failure mode this project
    treats as a defect everywhere else.
    """
    current = start.resolve()
    for directory in (current, *current.parents):
        candidate = directory / CONFIG_FILENAME
        problem = _existing_config_problem(candidate)
        if problem is not None:
            raise ConfigError(f"{candidate}: {problem}; not usable as a configuration file")
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
    return _resolve_package_extends(target, source)


def _resolve_package_extends(target: str, source: Path) -> Path:
    """Resolve a package-form `extends` target without executing its code.

    `importlib.resources.files(name)` (and `importlib.import_module(name)`, which it
    calls internally) executes the named module's top-level code before anything about
    its contents is inspected. A config file is attacker-influenceable the same way
    scanner input is -- a pull request can add or edit one -- so an attacker who names a
    module here could get arbitrary code to run merely by having someone scan the
    repository. `importlib.util.find_spec` locates a module without executing it, so it
    is used here instead.

    Dotted names (e.g. `acme.baseline`) are rejected outright: per `find_spec`'s own
    documentation, resolving a submodule name still imports its parent packages first,
    which reopens the exact execution path this function exists to close. A
    single-segment package name is sufficient to distribute an organization baseline.

    The target must be an actual package -- `spec.submodule_search_locations` is
    present and non-empty -- not a single-module `.py` file: a bare module cannot
    contain a `.reachability.yml`, and requiring a package is what keeps a repo-local
    `evil.py` from being treated as a baseline at all.
    """
    if "." in target:
        raise ConfigError(
            f"{source}: extends target {target!r} is a dotted package name, which is not "
            "supported: resolving one imports its parent packages first, and this project "
            "never imports attacker-influenceable names. Use a single-segment package name "
            "for an organization baseline, or a relative path."
        )
    try:
        spec = importlib.util.find_spec(target)
    except (ModuleNotFoundError, ImportError, ValueError, AttributeError, TypeError):
        spec = None
    if spec is None or not spec.submodule_search_locations:
        raise ConfigError(
            f"{source}: extends target {target!r} is not an installed package and not a path. "
            "Install the package that provides your organization baseline, or use a relative path."
        )
    location = next(iter(spec.submodule_search_locations))
    candidate = Path(location) / CONFIG_FILENAME
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


def _check_declared_path_boundaries(config: ReachabilityConfig, config_path: Path) -> None:
    """Reject a relative, path-valued config field that resolves outside the repository.

    `extends` already cannot climb out of the repository it was declared in (see
    `_repo_boundary`/`_resolve_extends`); every other path-valued field -- an artifact's
    `sbom`/`source`/`manifest`, an `evidence.*` entry, an `iac.*` path, `output.dir` -- was
    not checked at all. A relative path with enough `../` segments still names a file
    outside the repository, for example `iac.kubernetes: ../../secrets.yaml`; a parse
    failure on that file used to echo its content into the error message (see
    `yaml_loader`'s safe error formatting), which together let a PR-controlled config
    disclose a file this repository does not own -- for example in a CI log a pull request
    author can read.

    Deliberately scoped to *relative* paths only: an absolute path here has exactly the
    reach an equivalent CLI flag already has and has never been restricted (`--sbom
    /anywhere`, `--kubernetes-manifest /anywhere`, ...) -- these config fields are direct
    stand-ins for those flags, not a new, more powerful primitive the way `extends` is
    (which pulls in and merges a whole second config document, offline, from a location
    the repository does not otherwise reference at all). Boundary-checking relative
    escapes closes the concrete `../` disclosure path without changing what an absolute
    path can already do today, or requiring every legitimate absolute-path config in use
    today to be rewritten.
    """
    boundary = _repo_boundary(config_path)
    base = config_path.parent.resolve()

    def check(value: str, label: str) -> None:
        candidate = Path(value)
        if candidate.is_absolute():
            return
        resolved = (base / candidate).resolve()
        if not resolved.is_relative_to(boundary):
            raise ConfigError(
                f"{config_path}: {label} {value!r} resolves outside the repository root. "
                "A relative config path may not leave the project; use an absolute path, "
                "or move the referenced file into the repository."
            )

    for name, artifact in config.artifacts.items():
        if artifact.sbom:
            check(artifact.sbom, f"artifacts.{name}.sbom")
        if artifact.source:
            check(artifact.source, f"artifacts.{name}.source")
        if artifact.manifest:
            check(artifact.manifest, f"artifacts.{name}.manifest")
    for key, values in config.evidence.items():
        for value in values:
            check(value, f"evidence.{key}")
    for key, value in config.iac.items():
        check(value, f"iac.{key}")
    check(config.output.dir, "output.dir")


def load_config(path: str | Path | None, start: Path | None = None) -> LoadedConfig:
    """Load and validate configuration, or return defaults when none exists."""
    if path is None:
        found = discover_config_path(start or Path.cwd())
        if found is None:
            return LoadedConfig(config=validate_config({"version": 1}, "defaults"))
        path = found
    config_path = Path(path)
    problem = _existing_config_problem(config_path)
    if problem is not None:
        raise ConfigError(f"{config_path}: {problem}; not usable as a configuration file")
    if not config_path.is_file():
        raise ConfigError(f"{config_path}: configuration file does not exist")
    layers = resolve_layers(config_path)
    merged = merge_layers(layers)
    resolved = validate_config(merged, str(config_path))
    _check_declared_path_boundaries(resolved, config_path)
    return LoadedConfig(
        config=resolved,
        path=config_path,
        provenance=_provenance(layers),
    )
