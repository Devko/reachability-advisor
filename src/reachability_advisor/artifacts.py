"""Artifact identity normalization and matching.

The scanner receives artifact names from SBOM metadata and image references from
Terraform plans.  This module provides a conservative bridge between those two
worlds.  Matching is intentionally evidence-based: exact references and digests
rank highest; loose name-only matches are allowed only as low-confidence hints
and are surfaced in reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

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
    target: str | None = None
    reasons: tuple[str, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "matched": self.matched,
            "score": self.score,
            "confidence": self.confidence,
            "method": self.method,
            "artifact_candidate": self.artifact_candidate,
            "target": self.target,
            "reasons": list(self.reasons),
        }


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


def artifact_candidates(artifact: Artifact) -> set[str]:
    candidates: set[str] = {artifact.name}
    if artifact.reference:
        candidates.add(artifact.reference)
    if artifact.version:
        candidates.add(f"{artifact.name}:{artifact.version}")
    for key in IMAGE_PROPERTY_KEYS:
        value = artifact.properties.get(key)
        if value:
            candidates.add(value)
    for key, value in artifact.properties.items():
        key_l = key.lower()
        if any(token in key_l for token in ("image", "artifact", "distribution", "container")) and value:
            candidates.add(value)
    aliases = artifact.properties.get("reachability:aliases") or artifact.properties.get("aliases")
    if aliases:
        candidates.update(item.strip() for item in aliases.split(",") if item.strip())
    return {candidate for candidate in candidates if candidate}


def artifact_match_evidence(artifact: Artifact, target: str | None, *, allow_name_only: bool = True) -> ArtifactMatch:
    cleaned_target = clean_image_reference(target)
    if not cleaned_target:
        return ArtifactMatch(matched=False, target=target, reasons=("target reference is empty",))
    target_image = normalize_image_reference(cleaned_target)
    target_l = cleaned_target.lower()
    best = ArtifactMatch(matched=False, score=0, target=cleaned_target, reasons=("no candidate matched",))

    for candidate in artifact_candidates(artifact):
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

        if score > best.score:
            confidence = "high" if score >= 90 else "medium" if score >= 60 else "low"
            best = ArtifactMatch(
                matched=score >= 45,
                score=score,
                confidence=confidence,
                method=method,
                artifact_candidate=candidate,
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


__all__ = [
    "ArtifactMatch",
    "NormalizedImage",
    "artifact_candidates",
    "artifact_match_evidence",
    "best_artifact_match",
    "clean_image_reference",
    "normalize_image_reference",
]
