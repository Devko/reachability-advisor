# src/reachability_advisor/config_schema.py
"""Typed schema and strict validation for .reachability.yml."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SUPPORTED_VERSIONS = frozenset({1})
TIERS = ("informational", "low", "medium", "high", "urgent")
PROFILES = ("advisory", "production")

TOP_LEVEL_KEYS = frozenset({"version", "extends", "artifacts", "evidence", "iac", "gate", "output"})
ARTIFACT_KEYS = frozenset({"sbom", "source", "image", "manifest"})
EVIDENCE_KEYS = frozenset({"vulnerabilities", "sast", "dast", "cspm", "posture", "source"})
IAC_KEYS = frozenset({"terraform", "terraform_source", "kubernetes"})
GATE_KEYS = frozenset({"profile", "fail_on", "fail_on_new", "thresholds"})
OUTPUT_KEYS = frozenset({"dir", "formats"})
FORMATS = ("json", "sarif", "markdown", "html", "diagnostics", "annotations", "baseline")


class ConfigError(ValueError):
    """Raised when a configuration document is malformed.

    Subclasses ``ValueError`` so the CLI's existing handler maps it to exit code 2.
    A malformed config must stop the run: every silent coercion here widens a gate.
    """


@dataclass(frozen=True)
class ArtifactConfig:
    sbom: str | None = None
    source: str | None = None
    image: str | None = None
    manifest: str | None = None


@dataclass(frozen=True)
class GateConfig:
    profile: str = "advisory"
    fail_on: str = "high"
    fail_on_new: str | None = None
    thresholds: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class OutputConfig:
    dir: str = "outputs"
    formats: tuple[str, ...] = ("json", "markdown")


@dataclass(frozen=True)
class ReachabilityConfig:
    version: int = 1
    artifacts: dict[str, ArtifactConfig] = field(default_factory=dict)
    evidence: dict[str, tuple[str, ...]] = field(default_factory=dict)
    iac: dict[str, str] = field(default_factory=dict)
    gate: GateConfig = field(default_factory=GateConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


def _reject_unknown(block: dict[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = sorted(str(key) for key in block if key not in allowed)
    if unknown:
        raise ConfigError(
            f"{label}: unknown key(s) {', '.join(repr(key) for key in unknown)}; "
            f"allowed keys are {', '.join(sorted(allowed))}"
        )


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{label}: must be a mapping, got {type(value).__name__}")
    return value


def _string_list(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{label}: must be a string or a list of strings")
    return tuple(value)


def _optional_string(block: dict[str, Any], key: str, label: str) -> str | None:
    if key not in block or block[key] is None:
        return None
    value = block[key]
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label}: {key!r} must be a non-empty string, got {value!r}")
    return value


def _gate(value: Any, label: str) -> GateConfig:
    block = _mapping(value, f"{label}: gate")
    _reject_unknown(block, GATE_KEYS, f"{label}: gate")
    profile = block.get("profile", "advisory")
    if profile not in PROFILES:
        raise ConfigError(
            f"{label}: gate.profile must be one of {', '.join(PROFILES)}, got {profile!r}"
        )
    fail_on = block.get("fail_on", "high")
    if fail_on not in TIERS:
        raise ConfigError(
            f"{label}: gate.fail_on must be one of {', '.join(TIERS)}, got {fail_on!r}"
        )
    fail_on_new = block.get("fail_on_new")
    if fail_on_new is not None and fail_on_new not in TIERS:
        raise ConfigError(
            f"{label}: gate.fail_on_new must be one of {', '.join(TIERS)}, got {fail_on_new!r}"
        )
    raw_thresholds = _mapping(block.get("thresholds"), f"{label}: gate.thresholds")
    thresholds: dict[str, float] = {}
    for key, item in raw_thresholds.items():
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ConfigError(f"{label}: gate.thresholds.{key} must be a number, got {item!r}")
        thresholds[str(key)] = float(item)
    return GateConfig(
        profile=profile, fail_on=fail_on, fail_on_new=fail_on_new, thresholds=thresholds
    )


def _output(value: Any, label: str) -> OutputConfig:
    block = _mapping(value, f"{label}: output")
    _reject_unknown(block, OUTPUT_KEYS, f"{label}: output")
    directory = block.get("dir", "outputs")
    if not isinstance(directory, str) or not directory.strip():
        raise ConfigError(f"{label}: output.dir must be a non-empty string")
    formats = _string_list(block.get("formats", ["json", "markdown"]), f"{label}: output.formats")
    unsupported = [item for item in formats if item not in FORMATS]
    if unsupported:
        raise ConfigError(
            f"{label}: output.formats has unsupported value(s) {', '.join(unsupported)}; "
            f"supported are {', '.join(FORMATS)}"
        )
    return OutputConfig(dir=directory, formats=formats)


def validate_config(raw: dict[str, Any], source: str) -> ReachabilityConfig:
    """Validate a fully merged config mapping into a typed object."""
    _reject_unknown(raw, TOP_LEVEL_KEYS, source)

    if "version" not in raw:
        raise ConfigError(f"{source}: 'version' is required; write `version: 1`")
    version = raw["version"]
    if isinstance(version, bool) or version not in SUPPORTED_VERSIONS:
        raise ConfigError(
            f"{source}: unsupported version {version!r}; "
            f"this build supports {', '.join(str(item) for item in sorted(SUPPORTED_VERSIONS))}"
        )

    artifacts: dict[str, ArtifactConfig] = {}
    for name, block in _mapping(raw.get("artifacts"), f"{source}: artifacts").items():
        label = f"{source}: artifacts.{name}"
        mapping = _mapping(block, label)
        _reject_unknown(mapping, ARTIFACT_KEYS, label)
        artifacts[str(name)] = ArtifactConfig(
            sbom=_optional_string(mapping, "sbom", label),
            source=_optional_string(mapping, "source", label),
            image=_optional_string(mapping, "image", label),
            manifest=_optional_string(mapping, "manifest", label),
        )

    evidence_block = _mapping(raw.get("evidence"), f"{source}: evidence")
    _reject_unknown(evidence_block, EVIDENCE_KEYS, f"{source}: evidence")
    evidence = {
        str(key): _string_list(value, f"{source}: evidence.{key}")
        for key, value in evidence_block.items()
    }

    iac_block = _mapping(raw.get("iac"), f"{source}: iac")
    _reject_unknown(iac_block, IAC_KEYS, f"{source}: iac")
    iac: dict[str, str] = {}
    for key in iac_block:
        value = _optional_string(iac_block, key, f"{source}: iac")
        if value is not None:
            iac[str(key)] = value

    return ReachabilityConfig(
        version=int(version),
        artifacts=artifacts,
        evidence=evidence,
        iac=iac,
        gate=_gate(raw.get("gate"), source),
        output=_output(raw.get("output"), source),
    )
