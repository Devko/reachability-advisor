"""Artifact identity normalization and matching.

The scanner receives artifact names from SBOM metadata and image references from
Terraform plans.  This module provides a conservative bridge between those two
worlds.  Matching is intentionally evidence-based: exact references and digests
rank highest; loose name-only matches are allowed only as low-confidence hints
and are surfaced in reports.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from .models import Artifact

IMAGE_PROPERTY_KEYS = (
    "container:image",
    "oci:image",
    "oci:image:ref",
    "image",
    "image_uri",
    "image.name",
    "docker:image",
    "artifact:reference",
    "reachability:artifact_ref",
    "distribution",
    "external:distribution",
    "external:container-image",
    "ci:image",
    "ci:container:image",
    "github:image",
    "github:workflow:image",
    "github:container:image",
    "dockerfile:image",
    "helm:image",
    "helm:values:image",
    "kustomize:image",
    "terraform:module_output:image",
    "module:image",
)

IMAGE_DIGEST_RE = re.compile(r"sha256:[a-f0-9]{32,64}", re.IGNORECASE)
TOKEN_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class NormalizedImage:
    """Normalized OCI-ish image reference.

    This is not a full OCI parser.  It covers the forms seen in SBOM metadata,
    Terraform plans, and common CI pipelines: ``repo/app:tag``,
    ``registry/repo/app@sha256:...``, ``DOCKER|repo/app:tag``, and
    ``docker://repo/app:tag``.
    """

    raw: str
    registry: str | None = None
    repository: str | None = None
    tag: str | None = None
    digest: str | None = None

    @property
    def repository_leaf(self) -> str | None:
        if not self.repository:
            return None
        return self.repository.rsplit("/", 1)[-1]

    @property
    def without_tag(self) -> str:
        value = self.repository or self.raw
        if self.registry and value and not value.startswith(self.registry + "/"):
            value = f"{self.registry}/{value}"
        return value.lower()

    @property
    def canonical(self) -> str:
        base = self.without_tag
        if self.digest:
            return f"{base}@{self.digest.lower()}"
        if self.tag:
            return f"{base}:{self.tag.lower()}"
        return base


@dataclass(frozen=True)
class ArtifactMatch:
    matched: bool
    score: int = 0
    confidence: str = "none"
    method: str = "none"
    artifact_candidate: str | None = None
    candidate_source: str | None = None
    candidate_strength: str | None = None
    target: str | None = None
    reasons: tuple[str, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "matched": self.matched,
            "score": self.score,
            "confidence": self.confidence,
            "method": self.method,
            "artifact_candidate": self.artifact_candidate,
            "candidate_source": self.candidate_source,
            "candidate_strength": self.candidate_strength,
            "target": self.target,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class ArtifactIdentityCandidate:
    value: str
    source: str
    strength: str

    def to_json(self) -> dict[str, str]:
        return {"value": self.value, "source": self.source, "strength": self.strength}


def clean_image_reference(value: str | None) -> str | None:
    if value is None:
        return None
    raw = str(value).strip().strip('"').strip("'")
    if not raw:
        return None
    if raw.upper().startswith("DOCKER|"):
        raw = raw.split("|", 1)[1]
    if raw.startswith("docker://"):
        raw = raw[len("docker://") :]
    return raw.strip() or None


def normalize_image_reference(value: str | None) -> NormalizedImage | None:
    raw = clean_image_reference(value)
    if not raw:
        return None
    if "${" in raw:
        return NormalizedImage(raw=raw)

    digest = None
    name_part = raw
    if "@" in name_part:
        name_part, digest_part = name_part.split("@", 1)
        digest_match = IMAGE_DIGEST_RE.search(digest_part)
        digest = digest_match.group(0).lower() if digest_match else digest_part.lower()

    tag = None
    last_segment = name_part.rsplit("/", 1)[-1]
    if ":" in last_segment:
        name_part, tag = name_part.rsplit(":", 1)
        tag = tag or None

    segments = [segment for segment in name_part.split("/") if segment]
    registry = None
    repository = name_part.lower()
    if len(segments) > 1 and ("." in segments[0] or ":" in segments[0] or segments[0].lower() == "localhost"):
        registry = segments[0].lower()
        repository = "/".join(segments[1:]).lower()
    else:
        repository = "/".join(segments).lower()

    return NormalizedImage(raw=raw, registry=registry, repository=repository or None, tag=tag, digest=digest)


def artifact_identity_candidates(artifact: Artifact) -> tuple[ArtifactIdentityCandidate, ...]:
    candidates: dict[str, ArtifactIdentityCandidate] = {}

    def add(value: str | None, source: str, strength: str | None = None) -> None:
        cleaned = str(value or "").strip()
        if not cleaned:
            return
        candidate = ArtifactIdentityCandidate(cleaned, source, strength or _candidate_strength(cleaned))
        current = candidates.get(cleaned)
        if current is None or _candidate_strength_rank(candidate.strength) > _candidate_strength_rank(current.strength):
            candidates[cleaned] = candidate

    # Keep every deployable identity that could explain how the SBOM maps to
    # infrastructure. Reports show this proof chain, so weak aliases remain
    # visible instead of being hidden behind the final match score.
    add(artifact.name, "artifact.name")
    if artifact.reference:
        add(artifact.reference, "artifact.reference")
    if artifact.version:
        add(f"{artifact.name}:{artifact.version}", "artifact.version", strength="versioned_name")
    for key in IMAGE_PROPERTY_KEYS:
        value = artifact.properties.get(key)
        if value:
            for item in _split_candidate_values(value):
                add(item, f"artifact.properties.{key}")
    for key, value in artifact.properties.items():
        key_l = key.lower()
        if any(token in key_l for token in ("image", "artifact", "distribution", "container", "helm", "kustomize", "module_output")) and value:
            for item in _split_candidate_values(value):
                add(item, f"artifact.properties.{key}")
    aliases = artifact.properties.get("reachability:aliases") or artifact.properties.get("aliases")
    if aliases:
        for item in aliases.split(","):
            add(item.strip(), "artifact.alias")
    return tuple(sorted(candidates.values(), key=lambda item: (-_candidate_strength_rank(item.strength), item.source, item.value)))


def artifact_candidates(artifact: Artifact) -> set[str]:
    return {candidate.value for candidate in artifact_identity_candidates(artifact)}


def artifact_identity_proof(artifact: Artifact) -> dict[str, object]:
    candidates = artifact_identity_candidates(artifact)
    strongest = candidates[0].strength if candidates else "none"
    warnings: list[str] = []
    if not candidates:
        warnings.append("artifact has no identity candidates")
    elif _candidate_strength_rank(strongest) < _candidate_strength_rank("image_reference"):
        warnings.append("artifact has no strong image reference or digest; deployment matching may rely on weak name evidence")
    return {
        "artifact": artifact.name,
        "strongest_strength": strongest,
        "candidate_count": len(candidates),
        "candidates": [candidate.to_json() for candidate in candidates],
        "warnings": warnings,
    }


def _split_candidate_values(value: str) -> set[str]:
    raw = str(value or "").strip()
    if not raw:
        return set()
    values = {raw}
    for separator in (",", "\n", "\r"):
        if separator in raw:
            values.update(item.strip() for item in raw.split(separator) if item.strip())
    return values


def artifact_match_evidence(artifact: Artifact, target: str | None, *, allow_name_only: bool = True) -> ArtifactMatch:
    cleaned_target = clean_image_reference(target)
    if not cleaned_target:
        return ArtifactMatch(matched=False, target=target, reasons=("target reference is empty",))
    target_image = normalize_image_reference(cleaned_target)
    target_l = cleaned_target.lower()
    best = ArtifactMatch(matched=False, score=0, target=cleaned_target, reasons=("no candidate matched",))

    for identity_candidate in artifact_identity_candidates(artifact):
        candidate = identity_candidate.value
        candidate_l = candidate.lower()
        candidate_image = normalize_image_reference(candidate)
        score = 0
        method = "none"
        reasons: list[str] = []

        if candidate_l == target_l:
            score = 100
            method = "exact-reference"
            reasons.append("artifact candidate exactly equals target reference")
        elif candidate_image and target_image:
            if candidate_image.digest and target_image.digest and candidate_image.digest == target_image.digest:
                score = 96
                method = "digest"
                reasons.append("image digest matched")
            elif candidate_image.repository and target_image.repository and _repository_equal(candidate_image, target_image) and candidate_image.tag and target_image.tag and candidate_image.tag.lower() == target_image.tag.lower():
                score = 90
                method = "repository-tag"
                reasons.append("image repository and tag matched")
            elif candidate_image.repository and target_image.repository and _repository_equal(candidate_image, target_image):
                score = 72
                method = "repository"
                reasons.append("image repository matched; tag/digest differed or was absent")
            elif allow_name_only and candidate_image.repository_leaf and target_image.repository_leaf and _token_equal(candidate_image.repository_leaf, target_image.repository_leaf):
                score = 58
                method = "repository-leaf"
                reasons.append("repository leaf matched artifact/image leaf")
        elif allow_name_only and _token_equal(candidate_l, target_l):
            score = 52
            method = "name"
            reasons.append("artifact name matched target token")

        if allow_name_only and score == 0 and _token_equal(artifact.name, target_l):
            score = 45
            method = "artifact-name"
            reasons.append("artifact name matched target token")

        # Exact deployment references should win over weak name evidence, but
        # the candidate source/strength is still carried into coverage reports
        # so reviewers can judge whether the match is release-gate quality.
        if score > best.score:
            confidence = "high" if score >= 90 else "medium" if score >= 60 else "low"
            best = ArtifactMatch(
                matched=score >= 45,
                score=score,
                confidence=confidence,
                method=method,
                artifact_candidate=candidate,
                candidate_source=identity_candidate.source,
                candidate_strength=identity_candidate.strength,
                target=cleaned_target,
                reasons=tuple(reasons),
            )
    return best


def best_artifact_match(artifacts: Iterable[Artifact], target: str | None, *, allow_name_only: bool = True) -> tuple[Artifact | None, ArtifactMatch]:
    best_artifact = None
    best_match = ArtifactMatch(matched=False, target=target, reasons=("no artifacts supplied",))
    for artifact in artifacts:
        match = artifact_match_evidence(artifact, target, allow_name_only=allow_name_only)
        if match.score > best_match.score:
            best_artifact = artifact
            best_match = match
    if best_artifact is None:
        return None, best_match
    return best_artifact, best_match


def _repository_equal(left: NormalizedImage, right: NormalizedImage) -> bool:
    if not left.repository or not right.repository:
        return False
    if left.repository.lower() == right.repository.lower():
        return True
    # Registry-qualified vs registry-less comparison.
    return left.without_tag.endswith("/" + right.repository.lower()) or right.without_tag.endswith("/" + left.repository.lower())


def _token_equal(left: str, right: str) -> bool:
    return _tokenize(left) == _tokenize(right)


def _tokenize(value: str) -> tuple[str, ...]:
    # Remove tag/digest from image-like values before comparing names.
    cleaned = clean_image_reference(value) or value
    image = normalize_image_reference(cleaned)
    if image and image.repository_leaf:
        cleaned = image.repository_leaf
    cleaned = cleaned.lower().split("@sha256:", 1)[0]
    if ":" in cleaned.rsplit("/", 1)[-1]:
        cleaned = cleaned.rsplit(":", 1)[0]
    return tuple(token for token in TOKEN_RE.split(cleaned) if token)


def _candidate_strength(value: str) -> str:
    if "${" in value:
        return "unresolved"
    image = normalize_image_reference(value)
    if image and image.digest:
        return "digest"
    if image and image.repository and (image.registry or image.tag):
        return "image_reference"
    if image and image.repository and "/" in image.repository:
        return "repository"
    if ":" in value or "/" in value:
        return "reference"
    return "name"


def _candidate_strength_rank(value: str) -> int:
    return {
        "none": 0,
        "name": 1,
        "versioned_name": 2,
        "unresolved": 2,
        "reference": 3,
        "repository": 4,
        "image_reference": 5,
        "digest": 6,
    }.get(value, 0)


__all__ = [
    "ArtifactMatch",
    "ArtifactIdentityCandidate",
    "NormalizedImage",
    "artifact_candidates",
    "artifact_identity_candidates",
    "artifact_identity_proof",
    "artifact_match_evidence",
    "best_artifact_match",
    "clean_image_reference",
    "normalize_image_reference",
]
