"""Fallback effective exposure evaluator."""

from __future__ import annotations

from typing import ClassVar

from .base import ProviderEvaluator, ProviderExposurePolicy


class UnknownExposureEvaluator(ProviderEvaluator):
    policy: ClassVar[ProviderExposurePolicy] = ProviderExposurePolicy(
        provider="unknown",
        blocking_network_kinds=frozenset({"public_network_disabled", "internal_only_endpoint", "internal_ingress_only"}),
        constraining_network_kinds=frozenset({"auth_required", "api_key_required", "api_authorizer", "waf_or_firewall_policy"}),
        blocking_identity_kinds=frozenset({"explicit_deny", "explicit_deny_precedence"}),
        constraining_identity_kinds=frozenset({"condition", "scoped_resource", "unknown_resource_scope"}),
        unknown_network_notes=("Provider-specific precedence could not be selected.",),
    )
