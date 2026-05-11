"""Terraform container image extraction and artifact matching helpers."""

from __future__ import annotations

import json
import re
from typing import Any, Protocol

from .artifacts import artifact_candidates, artifact_match_evidence, clean_image_reference
from .models import Artifact


class TerraformImageResource(Protocol):
    @property
    def name(self) -> str:
        ...

    @property
    def values(self) -> dict[str, Any]:
        ...


def find_image_references(values: Any) -> list[str]:
    """Find likely container image strings across provider-specific shapes."""

    found: list[str] = []

    def add(value: Any) -> None:
        if isinstance(value, str):
            cleaned = clean_image_reference(value)
            if cleaned and _looks_like_image_reference(cleaned):
                found.append(cleaned)

    def walk(value: Any, key_hint: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                key_l = str(key).lower()
                if key_l in {"image", "image_uri", "image_identifier", "container_image", "docker_image", "docker_image_name", "repository_url"} or key_l == "linux_fx_version":
                    add(item)
                    if isinstance(item, (list, dict)):
                        walk(item, key_l)
                elif key_l in {"container_definitions", "task_container_properties"} and isinstance(item, str):
                    try:
                        decoded = json.loads(item)
                    except json.JSONDecodeError:
                        add(item)
                    else:
                        walk(decoded, key_l)
                else:
                    walk(item, key_l)
        elif isinstance(value, list):
            for item in value:
                walk(item, key_hint)
        elif isinstance(value, str) and key_hint in {"image", "image_uri", "image_identifier", "docker_image", "linux_fx_version"}:
            add(value)

    walk(values)
    return list(dict.fromkeys(found))


def image_matches(artifact: Artifact, image: str | None) -> bool:
    return artifact_match_evidence(artifact, image).matched


def candidate_artifact_references(artifact: Artifact) -> set[str]:
    return artifact_candidates(artifact)


def workload_name_matches(artifact: Artifact, resource: TerraformImageResource) -> bool:
    values = resource.values
    names = {
        str(resource.name or ""),
        str(values.get("name") or ""),
        str(values.get("function_name") or ""),
        str(values.get("service_name") or ""),
        str(values.get("app_name") or ""),
        str(values.get("family") or ""),
        str(values.get("container_name") or ""),
    }
    artifact_name = artifact.name.lower()
    return any(name and (artifact_name == name.lower() or artifact_name in name.lower()) for name in names)


def _looks_like_image_reference(value: str) -> bool:
    if "${" in value:
        return True
    if ":" in value or "/" in value or "@sha256:" in value:
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value))


def _strip_image_version(value: str) -> str:
    value = value.split("@sha256:", 1)[0]
    if ":" in value.rsplit("/", 1)[-1]:
        return value.rsplit(":", 1)[0]
    return value


__all__ = [
    "candidate_artifact_references",
    "find_image_references",
    "image_matches",
    "workload_name_matches",
]
