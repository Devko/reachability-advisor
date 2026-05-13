"""AWS effective exposure evaluator."""

from __future__ import annotations

import ipaddress
from typing import Any, ClassVar

from reachability_advisor.models import ContextEvidence

from .base import (
    ProviderEvaluator,
    ProviderExposurePolicy,
    dedupe_objects,
    jsonish,
    strongest_provider_effective_access,
)
from .policy_engine import evaluate_aws_policy_records


class AwsExposureEvaluator(ProviderEvaluator):
    policy: ClassVar[ProviderExposurePolicy] = ProviderExposurePolicy(
        provider="aws",
        blocking_network_kinds=frozenset(
            {
                "egress_only_gateway",
                "internal_ingress_only",
                "internal_only_endpoint",
                "lambda_function_url_disabled",
                "network_acl_deny",
                "network_acl_no_allow",
                "no_public_route",
                "private_endpoint",
                "private_link_only",
                "public_network_disabled",
                "route_blackhole",
                "security_group_no_ingress",
                "vpc_endpoint_only",
            }
        ),
        constraining_network_kinds=frozenset(
            {
                "api_authorizer",
                "api_key_required",
                "auth_required",
                "elb_listener_auth",
                "cloudfront_function_auth",
                "lambda_function_url_aws_iam",
                "nacl_rule_order_unknown",
                "route_table_precedence_unknown",
                "route_requires_private_transit",
                "source_cidr_restriction",
                "source_security_group_restriction",
                "security_group_scoped_ingress",
                "private_endpoint_egress_only",
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
        augmented = [*blockers, *self._structured_network_blockers(network)]
        routes_evaluated = _routes_are_evaluable(network)
        nacls_evaluated = _nacls_are_evaluable(network)
        security_groups_evaluated = _security_groups_are_evaluable(network)
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
        if (
            not security_groups_evaluated
            and ("source_security_group" in text or "source security group" in text or "referenced security group" in text)
        ):
            augmented.append(
                {
                    "kind": "source_security_group_restriction",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "AWS ingress is scoped to a source security group",
                }
            )
        if (
            not security_groups_evaluated
            and ("source_cidr" in text or ("cidr_blocks" in text and "0.0.0.0/0" not in text and "::/0" not in text))
        ):
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
        if "authenticate_oidc" in text or "authenticate_cognito" in text:
            augmented.append(
                {
                    "kind": "elb_listener_auth",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "AWS load balancer listener authentication action is linked to the path",
                }
            )
        if not nacls_evaluated and "network_acl" in text and "deny" in text:
            augmented.append(
                {
                    "kind": "network_acl_deny",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "AWS network ACL deny evidence is linked to the path",
                }
            )
        elif not nacls_evaluated and ("network_acl" in text or "nacl" in text):
            augmented.append(
                {
                    "kind": "nacl_rule_order_unknown",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "AWS NACL evidence is present but rule ordering must be evaluated",
                }
            )
        if not routes_evaluated and ("blackhole" in text or "route target unavailable" in text):
            augmented.append(
                {
                    "kind": "route_blackhole",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "AWS route target is unavailable or blackholed",
                }
            )
        elif not routes_evaluated and "precedence_evaluated" not in text and ("route_table" in text or "aws_route" in text):
            augmented.append(
                {
                    "kind": "route_table_precedence_unknown",
                    "effect": "constrains",
                    "provider": self.provider,
                    "evidence": "AWS route evidence is present; precedence needs rendered edge confirmation",
                }
            )
        exposure = str(network.get("exposure") or "").lower()
        if exposure in {"public", "external"} and ("vpc_endpoint_only" in text or "private_link" in text or "privatelink" in text):
            if "private_endpoint_egress_only" in text:
                augmented.append(
                    {
                        "kind": "private_endpoint_egress_only",
                        "effect": "constrains",
                        "provider": self.provider,
                        "evidence": "AWS VPC endpoint evidence is outbound/dependency traffic, not public ingress",
                    }
                )
                return dedupe_objects(augmented)
            augmented.append(
                {
                    "kind": "vpc_endpoint_only",
                    "effect": "blocks",
                    "provider": self.provider,
                    "evidence": "AWS path is restricted to VPC endpoint or PrivateLink access",
                }
            )
        return dedupe_objects(augmented)

    def select_effective_access(self, context: ContextEvidence) -> dict[str, Any] | None:
        records = [dict(item) for item in context.effective_access if isinstance(item, dict)]
        records = evaluate_aws_policy_records(records)
        return strongest_provider_effective_access(records, denies=_aws_record_denies, layer_rank=_aws_policy_layer_rank)

    def effective_identity_decision(self, record: dict[str, Any], blockers: list[dict[str, Any]]) -> str:
        if _aws_record_denies(record) or any(item.get("effect") == "blocks" for item in blockers):
            return "denied"
        if any(item.get("effect") == "constrains" for item in blockers):
            return "constrained_allow"
        return "allowed"

    def identity_evaluation_order(
        self,
        record: dict[str, Any],
        blockers: list[dict[str, Any]],
        decision: str,
    ) -> list[dict[str, str]]:
        blocking = {str(item.get("kind") or "unknown") for item in blockers if item.get("effect") == "blocks"}
        constraining = {str(item.get("kind") or "unknown") for item in blockers if item.get("effect") == "constrains"}
        return [
            {"step": "explicit_deny", "state": "matched" if _aws_record_denies(record) or blocking else "not_observed"},
            {"step": "identity_and_resource_policy_allow", "state": "matched" if str(record.get("effect") or "allow").lower() != "deny" else "not_observed"},
            {"step": "permissions_boundary", "state": "matched" if {"permission_boundary", "permission_boundary_scope"} & (blocking | constraining) else "not_observed"},
            {"step": "service_control_policy", "state": "matched" if {"scp_deny", "scp_scope"} & (blocking | constraining) else "not_observed"},
            {"step": "session_policy", "state": "matched" if "session_policy" in constraining else "not_observed"},
            {"step": "conditions_and_scope", "state": "matched" if {"condition", "scoped_resource", "unknown_resource_scope", "trust_policy_condition"} & constraining else "not_observed"},
            {"step": "effective_decision", "state": decision},
        ]

    def identity_decision_detail(
        self,
        record: dict[str, Any],
        blockers: list[dict[str, Any]],
        decision: str,
    ) -> dict[str, Any]:
        detail = super().identity_decision_detail(record, blockers, decision)
        blocking = {str(item.get("kind") or "unknown") for item in blockers if item.get("effect") == "blocks"}
        constraining = {str(item.get("kind") or "unknown") for item in blockers if item.get("effect") == "constrains"}
        policy_layer = str(record.get("policy_layer") or "unknown").lower()
        detail.update(
            {
                "authorization_model": "aws_iam",
                "explicit_deny_precedence": _aws_record_denies(record) or "explicit_deny_precedence" in blocking,
                "identity_or_resource_allow": str(record.get("effect") or "allow").lower() != "deny",
                "permissions_boundary": _matched_state(
                    blocking,
                    constraining,
                    {"permission_boundary", "permission_boundary_scope"},
                ),
                "service_control_policy": _matched_state(blocking, constraining, {"scp_deny", "scp_scope"}),
                "resource_policy": _matched_state(blocking, constraining, {"resource_policy_deny", "resource_policy_condition"}),
                "session_policy": _matched_state(blocking, constraining, {"session_policy"}),
                "trust_policy": _matched_state(blocking, constraining, {"trust_policy_deny", "trust_policy_condition"}),
                "policy_layer_authority": policy_layer,
            }
        )
        return detail

    def _structured_network_blockers(self, network: dict[str, Any]) -> list[dict[str, Any]]:
        exposure = str(network.get("exposure") or "").lower()
        blockers: list[dict[str, Any]] = []
        if exposure in {"public", "external"}:
            blockers.extend(_evaluate_routes(network))
            blockers.extend(_evaluate_security_groups(network))
            blockers.extend(_evaluate_network_acls(network))
        blockers.extend(_evaluate_listener_auth(network))
        blockers.extend(_evaluate_api_gateway_controls(network))
        blockers.extend(_evaluate_waf(network))
        return blockers

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
            if not _routes_are_evaluable(network) and "route_table" not in text and "aws_route" not in text:
                unknowns.append("AWS route-table precedence was not proven by a linked route edge.")
            if not _nacls_are_evaluable(network) and "network_acl" not in text and "nacl" not in text:
                unknowns.append("AWS network ACL ordering was not proven by rendered evidence.")
        return unknowns


def _aws_record_denies(record: dict[str, Any]) -> bool:
    effect = str(record.get("effect") or "allow").lower()
    decision = str(record.get("decision") or "").lower()
    decision_basis = str(record.get("decision_basis") or "").lower()
    return effect == "deny" or decision.startswith("denied") or "explicit_deny" in decision_basis or "denied" in decision_basis


def _aws_policy_layer_rank(layer: str) -> int:
    return {
        "resource_policy": 7,
        "identity_policy": 6,
        "trust_policy": 5,
        "permissions_boundary": 4,
        "permission_boundary": 4,
        "service_control_policy": 4,
        "session_policy": 3,
    }.get(layer.lower(), 1)


def _matched_state(blocking: set[str], constraining: set[str], kinds: set[str]) -> str:
    if blocking & kinds:
        return "blocks"
    if constraining & kinds:
        return "constrains"
    return "not_observed"


def _evaluate_routes(network: dict[str, Any]) -> list[dict[str, Any]]:
    routes = _route_records(network)
    if not routes:
        return []
    selected = _select_public_route(routes)
    if selected is None:
        return [
            {
                "kind": "no_public_route",
                "effect": "blocks",
                "provider": "aws",
                "evidence": "AWS route records do not include a default public route for the selected ingress path",
            }
        ]
    state = str(selected.get("state") or selected.get("status") or "").lower()
    target = _route_target(selected)
    if state == "blackhole":
        return [
            {
                "kind": "route_blackhole",
                "effect": "blocks",
                "provider": "aws",
                "evidence": "selected AWS route is blackholed",
            }
        ]
    if "eigw" in target or "egress_only" in target:
        return [
            {
                "kind": "egress_only_gateway",
                "effect": "blocks",
                "provider": "aws",
                "evidence": "selected AWS route uses an egress-only internet gateway",
            }
        ]
    if target and not any(marker in target for marker in ("igw", "internet_gateway", "local")):
        return [
            {
                "kind": "route_requires_private_transit",
                "effect": "constrains",
                "provider": "aws",
                "evidence": f"selected AWS route target is {target}",
            }
        ]
    return []


def _evaluate_security_groups(network: dict[str, Any]) -> list[dict[str, Any]]:
    rules = _security_group_rules(network)
    if not rules:
        return []
    ingress = [rule for rule in rules if _direction(rule) in {"ingress", "inbound"}]
    if not ingress:
        return [
            {
                "kind": "security_group_no_ingress",
                "effect": "blocks",
                "provider": "aws",
                "evidence": "linked AWS security group has no inbound rule evidence",
            }
        ]
    allows = [rule for rule in ingress if _action(rule) != "deny"]
    if not allows:
        return [
            {
                "kind": "security_group_no_ingress",
                "effect": "blocks",
                "provider": "aws",
                "evidence": "linked AWS security group has no allowing inbound rule",
            }
        ]
    public_allows = [rule for rule in allows if _rule_allows_public_source(rule)]
    if public_allows:
        return []
    if any(rule.get("source_security_group_id") or rule.get("source_security_group") or rule.get("referenced_security_group_id") for rule in allows):
        return [
            {
                "kind": "source_security_group_restriction",
                "effect": "constrains",
                "provider": "aws",
                "evidence": "AWS ingress is allowed only from a source security group",
            }
        ]
    return [
        {
            "kind": "source_cidr_restriction",
            "effect": "constrains",
            "provider": "aws",
            "evidence": "AWS ingress is allowed only from non-public CIDR ranges",
        }
    ]


def _evaluate_network_acls(network: dict[str, Any]) -> list[dict[str, Any]]:
    rules = _nacl_rules(network)
    if not rules:
        return []
    inbound = [rule for rule in rules if _direction(rule) in {"ingress", "inbound"}]
    numbered = [rule for rule in inbound if _rule_number(rule) is not None]
    if not numbered:
        return [
            {
                "kind": "nacl_rule_order_unknown",
                "effect": "constrains",
                "provider": "aws",
                "evidence": "AWS NACL rules are present without rule numbers",
            }
        ]
    first_match = min((rule for rule in numbered if _nacl_rule_matches_public(rule)), key=lambda item: _rule_number(item) or 32767, default=None)
    if first_match is None:
        return [
            {
                "kind": "network_acl_no_allow",
                "effect": "blocks",
                "provider": "aws",
                "evidence": "AWS NACL has no inbound rule matching the selected source",
            }
        ]
    if _action(first_match) == "deny":
        return [
            {
                "kind": "network_acl_deny",
                "effect": "blocks",
                "provider": "aws",
                "evidence": f"AWS NACL rule {first_match.get('rule_number')} denies the selected source before any allow",
            }
        ]
    return []


def _evaluate_listener_auth(network: dict[str, Any]) -> list[dict[str, Any]]:
    listeners = _items_from_keys(network, ("listeners", "listener", "listener_rules", "actions", "default_actions"))
    for listener in listeners:
        text = jsonish(listener).lower()
        if "authenticate-oidc" in text or "authenticate_oidc" in text or "authenticate-cognito" in text or "authenticate_cognito" in text:
            return [
                {
                    "kind": "elb_listener_auth",
                    "effect": "constrains",
                    "provider": "aws",
                    "evidence": "AWS load balancer listener has an authenticate action",
                }
            ]
    return []


def _evaluate_api_gateway_controls(network: dict[str, Any]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    authorization_type = str(network.get("authorization_type") or network.get("auth_type") or "").lower()
    if authorization_type and authorization_type not in {"none", "open"}:
        blockers.append({"kind": "api_authorizer", "effect": "constrains", "provider": "aws", "evidence": f"AWS API authorization type is {authorization_type}"})
    if network.get("authorizer_id") or network.get("jwt_configuration") or network.get("openid_connect_configuration"):
        blockers.append({"kind": "api_authorizer", "effect": "constrains", "provider": "aws", "evidence": "AWS API authorizer is configured"})
    if bool(network.get("api_key_required")):
        blockers.append({"kind": "api_key_required", "effect": "constrains", "provider": "aws", "evidence": "AWS API key is required"})
    return blockers


def _evaluate_waf(network: dict[str, Any]) -> list[dict[str, Any]]:
    if any(network.get(key) for key in ("web_acl_id", "web_acl", "waf", "wafv2_web_acl")):
        return [{"kind": "waf_or_firewall_policy", "effect": "constrains", "provider": "aws", "evidence": "AWS WAF is associated with the path"}]
    return []


def _route_records(network: dict[str, Any]) -> list[dict[str, Any]]:
    routes = _items_from_keys(network, ("routes", "route", "aws_routes"))
    for table in _items_from_keys(network, ("route_tables", "route_table", "aws_route_table")):
        routes.extend(_items_from_keys(table, ("routes", "route", "aws_routes")))
        if not _items_from_keys(table, ("routes", "route", "aws_routes")) and any(key in table for key in ("destination_cidr_block", "cidr_block", "target", "gateway_id")):
            routes.append(table)
    return routes


def _select_public_route(routes: list[dict[str, Any]]) -> dict[str, Any] | None:
    candidates = [route for route in routes if _route_prefix(route) is not None]
    default_routes = [route for route in candidates if _route_destination(route) in {"0.0.0.0/0", "::/0"}]
    if default_routes:
        return max(default_routes, key=lambda item: _route_prefix(item) or 0)
    return None


def _route_destination(route: dict[str, Any]) -> str:
    for key in ("destination_cidr_block", "destination_ipv6_cidr_block", "destination", "cidr_block", "cidr", "destination_prefix"):
        value = route.get(key)
        if value:
            return str(value).strip()
    return ""


def _route_prefix(route: dict[str, Any]) -> int | None:
    destination = _route_destination(route)
    if not destination:
        return None
    try:
        return ipaddress.ip_network(destination, strict=False).prefixlen
    except ValueError:
        return None


def _route_target(route: dict[str, Any]) -> str:
    for key in ("gateway_id", "nat_gateway_id", "transit_gateway_id", "vpc_peering_connection_id", "egress_only_gateway_id", "network_interface_id", "target"):
        value = route.get(key)
        if value:
            return str(value).lower()
    return ""


def _security_group_rules(network: dict[str, Any]) -> list[dict[str, Any]]:
    rules = _items_from_keys(network, ("security_group_rules", "security_group_rule", "ingress_rules", "rules"))
    for group in _items_from_keys(network, ("security_groups", "security_group", "aws_security_group")):
        rules.extend(_items_from_keys(group, ("ingress", "ingress_rules", "rules", "security_group_rules")))
    return rules


def _nacl_rules(network: dict[str, Any]) -> list[dict[str, Any]]:
    rules = _items_from_keys(network, ("network_acl_rules", "nacl_rules", "network_acl", "network_acls", "nacls"))
    flattened: list[dict[str, Any]] = []
    for rule in rules:
        nested = _items_from_keys(rule, ("ingress", "egress", "rules", "entries"))
        if nested:
            flattened.extend(nested)
        else:
            flattened.append(rule)
    return flattened


def _items_from_keys(value: dict[str, Any], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for key in keys:
        raw = value.get(key)
        if isinstance(raw, dict):
            items.append(raw)
        elif isinstance(raw, list):
            items.extend(dict(item) for item in raw if isinstance(item, dict))
    return items


def _direction(rule: dict[str, Any]) -> str:
    if rule.get("egress") is True or str(rule.get("type") or rule.get("direction") or "").lower() == "egress":
        return "egress"
    value = str(rule.get("type") or rule.get("direction") or rule.get("traffic_type") or "ingress").lower()
    if value in {"inbound", "ingress"}:
        return value
    return "ingress"


def _action(rule: dict[str, Any]) -> str:
    return str(rule.get("rule_action") or rule.get("action") or rule.get("access") or "allow").lower()


def _rule_number(rule: dict[str, Any]) -> int | None:
    value = rule.get("rule_number") or rule.get("number") or rule.get("priority")
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _rule_allows_public_source(rule: dict[str, Any]) -> bool:
    cidrs = _cidr_values(rule)
    return any(cidr in {"0.0.0.0/0", "::/0"} for cidr in cidrs)


def _nacl_rule_matches_public(rule: dict[str, Any]) -> bool:
    cidrs = _cidr_values(rule)
    if not cidrs:
        return True
    return any(cidr in {"0.0.0.0/0", "::/0"} for cidr in cidrs)


def _cidr_values(rule: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("cidr_block", "ipv6_cidr_block", "cidr", "source_cidr", "destination_cidr_block"):
        if rule.get(key):
            values.append(str(rule[key]).strip())
    for key in ("cidr_blocks", "ipv6_cidr_blocks", "source_cidrs"):
        raw = rule.get(key)
        if isinstance(raw, list):
            values.extend(str(item).strip() for item in raw if str(item).strip())
    return values


def _routes_are_evaluable(network: dict[str, Any]) -> bool:
    return any(_route_prefix(route) is not None for route in _route_records(network))


def _nacls_are_evaluable(network: dict[str, Any]) -> bool:
    return any(_rule_number(rule) is not None for rule in _nacl_rules(network))


def _security_groups_are_evaluable(network: dict[str, Any]) -> bool:
    return bool(_security_group_rules(network))
