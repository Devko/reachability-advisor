"""Artifact and workload mapping for imported scanner evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .artifacts import ArtifactMatch, artifact_match_evidence
from .models import Artifact, Confidence, ContextEvidence
from .security_evidence_model import SecurityEvidenceRecord


@dataclass(frozen=True)
class SecurityEvidenceMappingDecision:
    artifact: Artifact | None
    match: ArtifactMatch | None = None
    confidence: Confidence = Confidence.LOW
    reason: str = "no mapping attempted"

    def match_json(self) -> dict[str, Any] | None:
        return self.match.to_json() if self.match else None


def map_security_evidence_record(
    record: SecurityEvidenceRecord,
    artifacts: list[Artifact],
    contexts: dict[str, ContextEvidence],
) -> SecurityEvidenceMappingDecision:
    if record.artifact:
        for artifact in artifacts:
            if artifact.name == record.artifact:
                return SecurityEvidenceMappingDecision(
                    artifact=artifact,
                    match=artifact_match_evidence(artifact, record.artifact),
                    confidence=Confidence.HIGH,
                    reason="explicit artifact matched SBOM artifact",
                )
    target = record.url or record.artifact
    if target:
        best_artifact = None
        best_match = None
        for artifact in artifacts:
            match = artifact_match_evidence(artifact, target)
            if best_match is None or match.score > best_match.score:
                best_artifact = artifact
                best_match = match
            if record.url and _url_mentions_artifact(record.url, artifact.name):
                return SecurityEvidenceMappingDecision(artifact=artifact, match=match, confidence=Confidence.MEDIUM, reason="DAST URL mentions artifact name")
            if record.url and _url_matches_context(record.url, contexts.get(artifact.name, ContextEvidence())):
                return SecurityEvidenceMappingDecision(
                    artifact=artifact,
                    match=artifact_match_evidence(artifact, artifact.name),
                    confidence=Confidence.HIGH,
                    reason="DAST URL matched deployment context host or path",
                )
        if best_match and best_match.matched:
            return SecurityEvidenceMappingDecision(artifact=best_artifact, match=best_match, confidence=Confidence.MEDIUM, reason="artifact alias matched scanner target")
        if len(artifacts) == 1:
            return SecurityEvidenceMappingDecision(artifact=artifacts[0], match=None, confidence=Confidence.LOW, reason="weak one-SBOM fallback")
        return SecurityEvidenceMappingDecision(artifact=None, match=best_match, confidence=Confidence.LOW, reason="scanner target did not match any artifact")
    if len(artifacts) == 1:
        return SecurityEvidenceMappingDecision(artifact=artifacts[0], match=None, confidence=Confidence.LOW, reason="weak one-SBOM fallback")
    return SecurityEvidenceMappingDecision(artifact=None, match=None, confidence=Confidence.LOW, reason="scanner evidence has no artifact or URL target")


def unmapped_runtime_artifact(record: SecurityEvidenceRecord) -> Artifact:
    parsed = urlparse(record.url or "")
    host = parsed.netloc or parsed.path or "runtime"
    return Artifact(name=f"unmapped:{_normalize_label(host)}", reference=record.url, properties={"mapping:confidence": "unknown"})


def _url_mentions_artifact(url: str, artifact: str) -> bool:
    parsed = urlparse(url)
    haystack = f"{parsed.netloc} {parsed.path}".lower()
    return _normalize_label(artifact) in _normalize_label(haystack)


def _url_matches_context(url: str, context: ContextEvidence) -> bool:
    parsed = urlparse(url)
    host = parsed.netloc.lower().split("@")[-1].split(":")[0]
    path = parsed.path.lower()
    if not host:
        return False
    candidates: list[str] = [str(evidence) for evidence in context.evidence]
    for network_path in context.network_paths:
        candidates.append(json.dumps(network_path, sort_keys=True, default=str))
    text = "\n".join(candidates).lower()
    if host and host in text:
        return True
    return bool(path and path != "/" and path in text and any(token in text for token in ("ingress", "api", "gateway", "listener")))


def _normalize_label(value: str) -> str:
    return "_".join(part for part in "".join(char.lower() if char.isalnum() else " " for char in value).split() if part)


__all__ = [
    "SecurityEvidenceMappingDecision",
    "map_security_evidence_record",
    "unmapped_runtime_artifact",
]
