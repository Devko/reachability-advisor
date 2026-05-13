"""CI artifact identity manifest support.

Release pipelines often know the exact image digest and Git revision before an
SBOM writer preserves that metadata. This module imports that CI handoff and
adds it to the SBOM artifact identity proof chain used by Terraform and
Kubernetes matching.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .artifacts import normalize_image_reference


class ArtifactManifestError(ValueError):
    """Raised when a CI artifact manifest cannot be parsed."""


@dataclass(frozen=True)
class ArtifactManifestEntry:
    name: str
    sbom: str | None = None
    image: str | None = None
    digest: str | None = None
    registry_ref: str | None = None
    git_sha: str | None = None
    helm_values_image: str | None = None
    kustomize_image: str | None = None
    terraform_image: str | None = None
    aliases: tuple[str, ...] = ()
    properties: dict[str, str] = field(default_factory=dict)
    manifest_path: Path | None = None
    signed: bool = False

    def identity_values(self) -> dict[str, str]:
        values: dict[str, str] = {}
        if self.image:
            values["ci:image"] = self.image
        if self.digest:
            values["ci:image:digest"] = self.digest
        if self.registry_ref:
            values["ci:registry_ref"] = self.registry_ref
        elif self.image and self.digest:
            normalized = normalize_image_reference(self.image)
            if normalized and normalized.repository:
                values["ci:registry_ref"] = f"{normalized.without_tag}@{self.digest}"
        if self.git_sha:
            values["ci:git_sha"] = self.git_sha
            if self.image and "${" not in self.image:
                values["github:sha:image"] = self.image
        if self.helm_values_image:
            values["helm:values:image"] = self.helm_values_image
        if self.kustomize_image:
            values["kustomize:image"] = self.kustomize_image
        if self.terraform_image:
            values["terraform:module_output:image"] = self.terraform_image
        if self.manifest_path:
            values["ci:artifact_manifest"] = str(self.manifest_path)
        values["ci:artifact_manifest:signed"] = "true" if self.signed else "false"
        values.update(self.properties)
        return {key: value for key, value in values.items() if value}


def create_artifact_manifest_payload(
    artifacts: list[str],
    *,
    image: str | None = None,
    digest: str | None = None,
    registry_ref: str | None = None,
    git_sha: str | None = None,
    sbom: str | None = None,
    signed: bool = False,
) -> dict[str, Any]:
    """Create a CI artifact manifest skeleton with shared metadata."""

    if not artifacts:
        raise ArtifactManifestError("at least one artifact name is required")
    rows = []
    for artifact in artifacts:
        name = str(artifact).strip()
        if not name:
            raise ArtifactManifestError("artifact names must not be empty")
        rows.append(
            {
                "name": name,
                **_optional_field("sbom_path", sbom),
                **_optional_field("image_ref", image),
                **_optional_field("image_digest", digest),
                **_optional_field("registry_ref", registry_ref),
                **_optional_field("git_sha", git_sha),
            }
        )
    return {
        "schema_version": "1.0",
        "kind": "reachability-advisor-artifact-manifest",
        "signed": signed,
        "artifacts": rows,
    }


def write_artifact_manifest(path: str | Path, payload: dict[str, Any]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def validate_artifact_manifest(path: str | Path, *, strict_provenance: bool = False) -> dict[str, Any]:
    """Validate a manifest and return actionable identity coverage details."""

    entries = load_artifact_manifest(path)
    rows: list[dict[str, Any]] = []
    for entry in entries:
        values = entry.identity_values()
        strong = bool(values.get("ci:registry_ref") or values.get("ci:image:digest") or values.get("ci:image"))
        has_digest = _has_digest(values)
        has_git_sha = bool(entry.git_sha)
        valid_git_sha = _valid_git_sha(entry.git_sha)
        blockers = _strict_provenance_blockers(
            entry,
            values,
            strong_identity=strong,
            has_digest=has_digest,
            valid_git_sha=valid_git_sha,
        ) if strict_provenance else []
        rows.append(
            {
                "name": entry.name,
                "strong_identity": strong,
                "has_digest": has_digest,
                "has_sbom_path": bool(entry.sbom),
                "has_git_sha": has_git_sha,
                "valid_git_sha": valid_git_sha,
                "signed": entry.signed,
                "strict_provenance": "ready" if not blockers else "blocked",
                "provenance_blockers": blockers,
                "identity_keys": sorted(values),
            }
        )
    blockers_count = sum(len(row["provenance_blockers"]) for row in rows)
    if strict_provenance:
        status = "ready" if rows and blockers_count == 0 else "blocked"
    else:
        status = "ready" if rows and all(row["strong_identity"] for row in rows) else "warning"
    return {
        "schema_version": "1.0",
        "status": status,
        "strict_provenance": strict_provenance,
        "summary": {
            "artifacts": len(rows),
            "strong_identity": sum(1 for row in rows if row["strong_identity"]),
            "with_digest": sum(1 for row in rows if row["has_digest"]),
            "with_sbom_path": sum(1 for row in rows if row["has_sbom_path"]),
            "with_git_sha": sum(1 for row in rows if row["has_git_sha"]),
            "with_valid_git_sha": sum(1 for row in rows if row["valid_git_sha"]),
            "signed": sum(1 for row in rows if row["signed"]),
            "provenance_blockers": blockers_count,
        },
        "artifacts": rows,
    }


def load_artifact_manifest(path: str | Path) -> list[ArtifactManifestEntry]:
    manifest_path = Path(path)
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ArtifactManifestError(f"{manifest_path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ArtifactManifestError(f"{manifest_path}: expected a JSON object")
    raw_items = data.get("artifacts")
    if not isinstance(raw_items, list):
        raise ArtifactManifestError(f"{manifest_path}: artifacts must be a list")
    signed = bool(data.get("signature") or data.get("signed") or data.get("attestation") or data.get("slsa") or data.get("sigstore_bundle"))
    entries = []
    for index, item in enumerate(raw_items):
        if not isinstance(item, dict):
            raise ArtifactManifestError(f"{manifest_path}: artifacts[{index}] must be an object")
        name = str(item.get("name") or item.get("artifact") or "").strip()
        if not name:
            raise ArtifactManifestError(f"{manifest_path}: artifacts[{index}] is missing name")
        aliases = tuple(str(alias).strip() for alias in item.get("aliases", []) if str(alias).strip()) if isinstance(item.get("aliases"), list) else ()
        properties = {str(key): str(value) for key, value in item.get("properties", {}).items()} if isinstance(item.get("properties"), dict) else {}
        entries.append(
            ArtifactManifestEntry(
                name=name,
                sbom=_optional_string(item.get("sbom") or item.get("sbom_path")),
                image=_optional_string(item.get("image") or item.get("image_ref")),
                digest=_optional_string(item.get("digest") or item.get("image_digest")),
                registry_ref=_optional_string(item.get("registry_ref") or item.get("repository_digest")),
                git_sha=_optional_string(item.get("git_sha") or item.get("commit") or item.get("revision")),
                helm_values_image=_optional_string(item.get("helm_values_image") or item.get("helm_image")),
                kustomize_image=_optional_string(item.get("kustomize_image")),
                terraform_image=_optional_string(item.get("terraform_image") or item.get("terraform_module_output_image")),
                aliases=aliases,
                properties=properties,
                manifest_path=manifest_path,
                signed=signed or bool(item.get("signature") or item.get("signed") or item.get("attestation") or item.get("slsa") or item.get("sigstore_bundle")),
            )
        )
    return entries


def apply_artifact_manifests(sboms: list[Any], paths: list[str]) -> dict[str, Any]:
    entries = [entry for path in paths for entry in load_artifact_manifest(path)]
    unmatched: list[str] = []
    applied = 0
    for entry in entries:
        matched = False
        for sbom in sboms:
            if _entry_matches_sbom(entry, sbom):
                _apply_entry(sbom.artifact, entry)
                matched = True
                applied += 1
        if not matched:
            unmatched.append(entry.name)
    return {
        "schema_version": "1.0",
        "manifests": paths,
        "entries": len(entries),
        "applied": applied,
        "unmatched": unmatched,
    }


def _apply_entry(artifact: Any, entry: ArtifactManifestEntry) -> None:
    artifact.properties.update(entry.identity_values())
    aliases = list(entry.aliases)
    for value in (entry.image, entry.registry_ref, entry.digest, entry.helm_values_image, entry.kustomize_image, entry.terraform_image):
        if value:
            aliases.append(value)
    existing = [item for item in str(artifact.properties.get("reachability:aliases") or "").split(",") if item]
    merged_aliases = list(dict.fromkeys([*existing, *aliases]))
    if merged_aliases:
        artifact.properties["reachability:aliases"] = ",".join(merged_aliases)
    if entry.image:
        artifact.properties.setdefault("reachability:artifact_ref", entry.image)
        artifact.reference = artifact.reference or entry.image
    elif entry.registry_ref:
        artifact.properties.setdefault("reachability:artifact_ref", entry.registry_ref)
        artifact.reference = artifact.reference or entry.registry_ref


def _entry_matches_sbom(entry: ArtifactManifestEntry, sbom: Any) -> bool:
    if entry.name == sbom.artifact.name:
        return True
    if entry.sbom:
        try:
            return Path(entry.sbom).name == Path(sbom.path).name or Path(entry.sbom).resolve() == Path(sbom.path).resolve()
        except OSError:
            return Path(entry.sbom).name == Path(sbom.path).name
    return False


def _optional_string(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _optional_field(key: str, value: str | None) -> dict[str, str]:
    return {key: value} if value else {}


def _has_digest(values: dict[str, str]) -> bool:
    registry_ref = values.get("ci:registry_ref") or ""
    digest = values.get("ci:image:digest") or ""
    return _valid_digest(digest) or "@sha256:" in registry_ref


def _valid_digest(value: str | None) -> bool:
    return bool(value and re.fullmatch(r"sha256:[0-9a-fA-F]{64}", value.strip()))


def _valid_git_sha(value: str | None) -> bool:
    return bool(value and re.fullmatch(r"[0-9a-fA-F]{7,64}", value.strip()))


def _strict_provenance_blockers(
    entry: ArtifactManifestEntry,
    values: dict[str, str],
    *,
    strong_identity: bool,
    has_digest: bool,
    valid_git_sha: bool,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    if not strong_identity:
        blockers.append({"kind": "missing_artifact_identity", "message": "artifact has no image, digest, or registry reference"})
    if not has_digest:
        blockers.append({"kind": "missing_image_digest", "message": "strict provenance requires sha256 image digest or repository digest reference"})
    if not entry.sbom:
        blockers.append({"kind": "missing_sbom_path", "message": "strict provenance requires the SBOM path used for the release artifact"})
    if not entry.git_sha:
        blockers.append({"kind": "missing_git_sha", "message": "strict provenance requires the source Git revision"})
    elif not valid_git_sha:
        blockers.append({"kind": "invalid_git_sha", "message": "git_sha must be a hexadecimal revision prefix or full hash"})
    if not entry.signed:
        blockers.append({"kind": "missing_signature_marker", "message": "strict provenance requires a signed, signature, attestation, or SLSA marker"})
    if values.get("ci:image") and "${" in str(values.get("ci:image")):
        blockers.append({"kind": "unresolved_image_expression", "message": "image reference still contains an unresolved expression"})
    return blockers


__all__ = [
    "ArtifactManifestError",
    "ArtifactManifestEntry",
    "apply_artifact_manifests",
    "create_artifact_manifest_payload",
    "load_artifact_manifest",
    "validate_artifact_manifest",
    "write_artifact_manifest",
]
