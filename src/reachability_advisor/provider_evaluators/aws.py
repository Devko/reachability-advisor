"""AWS effective exposure evaluator."""

from __future__ import annotations

from typing import Any, ClassVar

from .base import ProviderEvaluator, ProviderExposurePolicy, dedupe_objects, jsonish


class AwsExposureEvaluator(ProviderEvaluator):
    policy: ClassVar[ProviderExposurePolicy] = ProviderExposurePolicy(
        provider="aws",
        blocking_network_kinds=frozenset(
            {
                "egress_only_gateway",
                "internal_ingress_only",
                "internal_only_endpoint",
                "lambda_function_url_disabled",
                "private_endpoint",
                "private_link_only",
                "public_network_disabled",
                "vpc_endpoint_only",
            }
        ),
        constraining_network_kinds=frozenset(
            {
                "api_authorizer",
                "api_key_required",
                "auth_required",
                "cloudfront_function_auth",
                "lambda_function_url_aws_iam",
                "source_cidr_restriction",
                "source_security_group_restriction",
                "source_vpce_condition",
                "waf_or_firewall_policy",
            }
        ),
        blocking_identity_kinds=frozenset(
            {
                "explicit_deny",
                "explicit_deny_precedence",
                "permission_boundary",
                "resource_policy_deny",
                "scp_deny",
                "trust_policy_deny",
            }
        ),
        constraining_identity_kinds=frozenset(
            {
                "condition",
                "permission_boundary_scope",
                "resource_policy_condition",
                "scp_scope",
                "scoped_resource",
                "session_policy",
                "trust_policy_condition",
                "unknown_resource_scope",
            }
        ),
        unknown_network_notes=("AWS NACL priority and every route-table conflict are not fully simulated.",),
    )

    def augment_network_blockers(
        self,
        network: dict[str, Any],
        blockers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        text = jsonish(network).lower()
        augmented = list(blockers)
        if "authorization_type" in text and "aws_iam" in text:
            augmented.append(
                {
                    "kind": "lambda_function_url_aws_iam",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "AWS IAM authorization is required for the function URL or API route",
                }
            )
        if "sourcevpce" in text or "aws:sourcevpce" in text:
            augmented.append(
                {
                    "kind": "source_vpce_condition",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "AWS source VPC endpoint condition is present",
                }
            )
        if "source_security_group" in text or "source security group" in text or "referenced security group" in text:
            augmented.append(
                {
                    "kind": "source_security_group_restriction",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "AWS ingress is scoped to a source security group",
                }
            )
        if "source_cidr" in text or ("cidr_blocks" in text and "0.0.0.0/0" not in text and "::/0" not in text):
            augmented.append(
                {
                    "kind": "source_cidr_restriction",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "AWS ingress is scoped to specific CIDR ranges",
                }
            )
        if "web_acl" in text or "wafv2" in text or "aws_waf" in text:
            augmented.append(
                {
                    "kind": "waf_or_firewall_policy",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "AWS WAF evidence is linked to the path",
                }
            )
        if "authorizer_id" in text or "jwt_configuration" in text or "openid_connect_configuration" in text:
            augmented.append(
                {
                    "kind": "api_authorizer",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "AWS API authorizer evidence is linked to the path",
                }
            )
        exposure = str(network.get("exposure") or "").lower()
        if exposure in {"public", "external"} and ("vpc_endpoint_only" in text or "private_link" in text or "privatelink" in text):
            augmented.append(
                {
                    "kind": "vpc_endpoint_only",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "AWS path is restricted to VPC endpoint or PrivateLink access",
                }
            )
        return dedupe_objects(augmented)

    def augment_identity_blockers(
        self,
        record: dict[str, Any],
        blockers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        augmented = super().augment_identity_blockers(record, blockers)
        text = jsonish(record).lower()
        policy_layer = str(record.get("policy_layer") or "").lower()
        decision_basis = str(record.get("decision_basis") or "").lower()
        effect = str(record.get("effect") or "allow").lower()
        decision = str(record.get("decision") or "").lower()
        denied = effect == "deny" or decision.startswith("denied") or "explicit_deny" in decision_basis or "denied" in decision_basis
        has_conditions = bool(record.get("condition_keys"))

        if "explicit_deny" in decision_basis or "denied_by_explicit_deny" in decision_basis:
            augmented.append(
                {
                    "kind": "explicit_deny_precedence",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "AWS explicit deny takes precedence over matching allow evidence",
                }
            )
        if policy_layer in {"permissions_boundary", "permission_boundary"} or "permission_boundary" in text:
            augmented.append(
                {
                    "kind": "permission_boundary" if denied else "permission_boundary_scope",
                    "effect": "blocks" if denied else "constrains",
                    "provider": self.provider,
                    "evidence": "AWS permissions boundary limits the effective action",
                }
            )
        if policy_layer == "service_control_policy" or "service_control_policy" in text or "scp" in decision_basis:
            augmented.append(
                {
                    "kind": "scp_deny" if denied else "scp_scope",
                    "effect": "blocks" if denied else "constrains",
                    "provider": self.provider,
                    "evidence": "AWS Organizations service control policy affects the action",
                }
            )
        if policy_layer == "resource_policy" or "resource_policy" in text:
            augmented.append(
                {
                    "kind": "resource_policy_deny" if denied else "resource_policy_condition",
                    "effect": "blocks" if denied else "constrains",
                    "provider": self.provider,
                    "evidence": "AWS resource policy participates in the effective decision",
                }
            )
        if policy_layer == "trust_policy" or str(record.get("action") or "").lower() == "sts:assumerole":
            if denied:
                augmented.append(
                    {
                        "kind": "trust_policy_deny",
                        "effect": "blocks",
                        "provider": self.provider,
                        "evidence": "AWS trust policy blocks role assumption",
                    }
                )
            elif has_conditions or "condition" in text:
                augmented.append(
                    {
                        "kind": "trust_policy_condition",
                        "effect": "constrains",
                        "provider": self.provider,
                        "evidence": "AWS trust policy contains conditions",
                    }
                )
        if "session_policy" in text:
            augmented.append(
                {
                    "kind": "session_policy",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "AWS session policy limits the effective session",
                }
            )
        return dedupe_objects(augmented)

    def network_unknowns(self, network: dict[str, Any], exposure: str) -> list[str]:
        unknowns = super().network_unknowns(network, exposure)
        if exposure in {"public", "external", "internal"}:
            text = jsonish(network).lower()
            if "route_table" not in text and "aws_route" not in text:
                unknowns.append("AWS route-table precedence was not proven by a linked route edge.")
            if "network_acl" not in text and "nacl" not in text:
                unknowns.append("AWS network ACL ordering was not proven by rendered evidence.")
        return unknowns
