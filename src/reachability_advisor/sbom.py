"""CycloneDX SBOM loading.

Only CycloneDX JSON is supported by the focused developer edition because it is
common in CI and IDE workflows.  The loader accepts intentionally small SBOMs
and full CycloneDX documents as long as the core metadata/component structure is
present.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .input_limits import InputSizeError, read_text_limited
from .models import Artifact, Component, SbomDocument


class SbomError(ValueError):
    """Raised when an SBOM cannot be parsed as a supported CycloneDX document."""


def _as_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _properties(items: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in _as_list(items):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        value = item.get("value", "")
        result[name] = "" if value is None else str(value)
    return result


def _external_reference_properties(items: Any) -> dict[str, str]:
    """Flatten CycloneDX external references into searchable properties.

    CycloneDX allows external references on the BOM and component objects.  The
    scanner uses them to discover image/distribution/source links while keeping
    the canonical SBOM data unchanged.
    """

    result: dict[str, str] = {}
    for index, item in enumerate(_as_list(items)):
        if not isinstance(item, dict):
            continue
        ref_type = str(item.get("type") or f"ref-{index}").strip().lower()
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        result[f"external:{ref_type}"] = url
        # Common aliases used by artifact matching and source mapping.
        if ref_type in {"distribution", "distribution-intake", "container-image"}:
            result.setdefault("distribution", url)
        if ref_type in {"vcs", "source-distribution", "website"}:
            result.setdefault("source", url)
    return result


def _merge_properties(*groups: dict[str, str]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for group in groups:
        merged.update({key: value for key, value in group.items() if value is not None})
    return merged


def _component_scope(component: dict[str, Any]) -> str:
    scope = str(component.get("scope") or "").lower().strip()
    properties = _properties(component.get("properties"))
    scope = properties.get("dependency.scope", scope) or properties.get("scope", scope)
    if scope in {"test", "provided", "optional", "dev", "development"}:
        return scope
    return "runtime"


def _artifact_from_metadata(path: Path, data: dict[str, Any]) -> Artifact:
    metadata = _as_object(data.get("metadata"))
    component = _as_object(metadata.get("component"))
    props = _merge_properties(
        _properties(data.get("properties")),
        _external_reference_properties(data.get("externalReferences")),
        _properties(metadata.get("properties")),
        _external_reference_properties(metadata.get("externalReferences")),
        _properties(component.get("properties")),
        _external_reference_properties(component.get("externalReferences")),
    )
    name = component.get("name") or props.get("reachability:artifact") or props.get("artifact:name") or path.stem
    version = component.get("version") or props.get("reachability:artifact_version") or props.get("artifact:version")
    reference = (
        component.get("purl")
        or props.get("reachability:artifact_ref")
        or props.get("container:image")
        or props.get("oci:image:ref")
        or props.get("distribution")
    )
    return Artifact(
        name=str(name),
        version=str(version) if version else None,
        reference=str(reference) if reference else None,
        bom_ref=str(component.get("bom-ref")) if component.get("bom-ref") else None,
        properties=props,
    )


def _dependencies(data: dict[str, Any]) -> dict[str, list[str]]:
    graph: dict[str, list[str]] = {}
    for item in _as_list(data.get("dependencies")):
        if not isinstance(item, dict):
            continue
        ref = str(item.get("ref") or "").strip()
        if not ref:
            continue
        depends_on = []
        for dependency in _as_list(item.get("dependsOn")):
            if dependency is None:
                continue
            dependency_ref = str(dependency).strip()
            if dependency_ref:
                depends_on.append(dependency_ref)
        graph[ref] = list(dict.fromkeys(depends_on))
    return graph


def load_sbom(path: str | Path) -> SbomDocument:
    sbom_path = Path(path)
    try:
        data = json.loads(read_text_limited(sbom_path, "SBOM"))
    except InputSizeError as exc:
        raise SbomError(str(exc)) from exc
    except json.JSONDecodeError as exc:
        raise SbomError(f"{sbom_path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SbomError(f"{sbom_path}: expected a JSON object")
    bom_format = str(data.get("bomFormat", "")).lower()
    if bom_format and bom_format != "cyclonedx":
        raise SbomError(f"{sbom_path}: expected CycloneDX bomFormat, got {data.get('bomFormat')!r}")
    artifact = _artifact_from_metadata(sbom_path, data)
    components: list[Component] = []
    for raw_component in _as_list(data.get("components")):
        if not isinstance(raw_component, dict):
            continue
        name = raw_component.get("name")
        if not name:
            continue
        components.append(
            Component(
                name=str(name),
                version=str(raw_component.get("version")) if raw_component.get("version") else None,
                purl=str(raw_component.get("purl")) if raw_component.get("purl") else None,
                group=str(raw_component.get("group")) if raw_component.get("group") else None,
                scope=_component_scope(raw_component),
                bom_ref=str(raw_component.get("bom-ref")) if raw_component.get("bom-ref") else None,
                properties=_merge_properties(
                    _properties(raw_component.get("properties")),
                    _external_reference_properties(raw_component.get("externalReferences")),
                ),
            )
        )
    return SbomDocument(path=sbom_path, artifact=artifact, components=components, dependencies=_dependencies(data))


def load_sboms(paths: list[str]) -> list[SbomDocument]:
    return [load_sbom(path) for path in paths]
