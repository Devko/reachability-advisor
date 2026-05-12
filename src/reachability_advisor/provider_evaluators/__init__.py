"""Provider-specific evaluators for effective exposure."""

from __future__ import annotations

from typing import Any

from reachability_advisor.models import ContextEvidence

from .aws import AwsExposureEvaluator
from .azure import AzureExposureEvaluator
from .base import (
    ProviderEvaluator,
    ProviderExposurePolicy,
    confidence_rank,
    decision_rank,
    provider_from_source,
    select_network_path,
)
from .gcp import GcpExposureEvaluator
from .kubernetes import KubernetesExposureEvaluator
from .unknown import UnknownExposureEvaluator

EVALUATORS: dict[str, ProviderEvaluator] = {
    "aws": AwsExposureEvaluator(),
    "azure": AzureExposureEvaluator(),
    "gcp": GcpExposureEvaluator(),
    "kubernetes": KubernetesExposureEvaluator(),
    "unknown": UnknownExposureEvaluator(),
}

PROVIDER_POLICIES: dict[str, ProviderExposurePolicy] = {
    provider: evaluator.policy for provider, evaluator in EVALUATORS.items()
}


def evaluate_provider_exposure(artifact_name: str, context: ContextEvidence) -> dict[str, Any]:
    network = select_network_path(context)
    evaluator = evaluator_for_context(context, network)
    return evaluator.evaluate(artifact_name, context, selected_network=network)


def evaluator_for_context(context: ContextEvidence, network: dict[str, Any] | None = None) -> ProviderEvaluator:
    provider = provider_for_context(context, network or select_network_path(context))
    return EVALUATORS.get(provider, EVALUATORS["unknown"])


def provider_for_context(context: ContextEvidence, network: dict[str, Any]) -> str:
    provider = str(network.get("provider") or "").lower()
    if provider in EVALUATORS and provider != "unknown":
        return provider
    for item in context.effective_access:
        item_provider = str(item.get("provider") or "").lower()
        if item_provider in EVALUATORS and item_provider != "unknown":
            return item_provider
    for item in context.iam_capabilities:
        item_provider = str(item.get("provider") or "").lower()
        if item_provider in EVALUATORS and item_provider != "unknown":
            return item_provider
    return provider_from_source(context.source)


__all__ = [
    "EVALUATORS",
    "PROVIDER_POLICIES",
    "ProviderEvaluator",
    "ProviderExposurePolicy",
    "confidence_rank",
    "decision_rank",
    "evaluate_provider_exposure",
    "evaluator_for_context",
    "provider_for_context",
]
