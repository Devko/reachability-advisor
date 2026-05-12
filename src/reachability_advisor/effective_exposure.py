"""Provider-specific effective exposure evaluation.

Terraform and Kubernetes analyzers emit raw network paths, IAM capability
records, effective-access records, and broad context labels. The provider
evaluator layer turns those signals into one normalized asset decision used by
scoring and graph output.
"""

from __future__ import annotations

from typing import Any

from .models import ContextEvidence
from .provider_evaluators import (
    PROVIDER_POLICIES,
    ProviderExposurePolicy,
    confidence_rank,
    decision_rank,
    evaluate_provider_exposure,
)
from .terraform_exposure import exposure_rank


def enrich_context_with_effective_exposure(artifact_name: str, context: ContextEvidence) -> ContextEvidence:
    """Return a copy of ``context`` with provider-specific exposure records."""

    enriched = ContextEvidence(
        environment=context.environment,
        exposure=context.exposure,
        privilege=context.privilege,
        criticality=context.criticality,
        iam_impacts=list(context.iam_impacts),
        iam_capabilities=list(context.iam_capabilities),
        effective_access=list(context.effective_access),
        network_paths=list(context.network_paths),
        owner=context.owner,
        source=context.source,
        confidence=context.confidence,
        evidence=list(context.evidence),
    )
    enriched.effective_exposure = evaluate_effective_exposure(artifact_name, enriched)
    return enriched


def enrich_context_map_with_effective_exposure(contexts: dict[str, ContextEvidence]) -> dict[str, ContextEvidence]:
    return {artifact_name: enrich_context_with_effective_exposure(artifact_name, context) for artifact_name, context in contexts.items()}


def evaluate_effective_exposure(artifact_name: str, context: ContextEvidence) -> list[dict[str, Any]]:
    """Build provider-specific effective exposure decisions for one asset."""

    if context.effective_exposure:
        return [dict(item) for item in context.effective_exposure if isinstance(item, dict)]
    return [evaluate_provider_exposure(artifact_name, context)]


def best_effective_exposure(context: ContextEvidence) -> dict[str, Any] | None:
    records = [dict(item) for item in context.effective_exposure if isinstance(item, dict)]
    if not records:
        return None
    return max(
        records,
        key=lambda item: (
            decision_rank(str(item.get("decision") or "")),
            exposure_rank(str(item.get("exposure") or "unknown")),
            confidence_rank(str(item.get("confidence") or "")),
        ),
    )


__all__ = [
    "PROVIDER_POLICIES",
    "ProviderExposurePolicy",
    "best_effective_exposure",
    "enrich_context_map_with_effective_exposure",
    "enrich_context_with_effective_exposure",
    "evaluate_effective_exposure",
]
