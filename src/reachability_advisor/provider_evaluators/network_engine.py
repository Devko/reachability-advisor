"""Provider network graph solving for effective exposure records."""

from __future__ import annotations

import ipaddress
import json
from collections import deque
from dataclasses import dataclass
from typing import Any

NetworkRecord = dict[str, Any]
IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class NetworkEdge:
    source: str
    target: str
    edge_type: str
    provider: str
    raw: NetworkRecord
    precedence: int = 1000
    precedence_reason: str = ""


@dataclass(frozen=True)
class ProviderResourceGraph:
    provider: str
    nodes: tuple[NetworkRecord, ...]
    edges: tuple[NetworkEdge, ...]
    precedence_rules: tuple[NetworkRecord, ...]


@dataclass(frozen=True)
class GraphControl:
    node_id: str
    edge_type: str
    raw: NetworkRecord
    precedence: int
    precedence_reason: str


@dataclass(frozen=True)
class EdgeDecision:
    edge: NetworkEdge
    state: str
    blockers: tuple[NetworkRecord, ...]
    unknowns: tuple[str, ...]


def evaluate_provider_network_graph(provider: str, network: NetworkRecord, exposure: str) -> NetworkRecord:
    resource_graph = build_provider_resource_graph(provider, network, exposure)
    edges = _network_edges(provider, network, resource_graph)
    if not edges:
        return {"evaluated": False, "blockers": [], "unknowns": [], "evaluation_order": []}

    entry, target = _entry_and_target(network, edges)
    path = _solve_path(edges, entry, target)
    if not path:
        return {
            "evaluated": True,
            "provider": provider,
            "entry": entry,
            "target": target,
            "decision": "blocked",
            "blockers": [
                _blocker(
                    "unconnected_network_graph",
                    "blocks",
                    provider,
                    f"no linked network path from {entry} to {target}",
                )
            ],
            "unknowns": [],
            "evaluation_order": [{"step": "path_solver", "state": "no_path"}],
            "path": [],
            "edges": [],
            "resource_graph": _resource_graph_result(resource_graph),
        }

    decisions = [_evaluate_edge(provider, edge, exposure) for edge in path]
    blockers = _dedupe_objects([blocker for decision in decisions for blocker in decision.blockers])
    unknowns = _dedupe_strings([unknown for decision in decisions for unknown in decision.unknowns])
    order = [
        {
            "step": f"{decision.edge.edge_type}:{decision.edge.source}->{decision.edge.target}",
            "state": decision.state,
            "precedence": str(decision.edge.precedence),
        }
        for decision in decisions
    ]
    if any(decision.state == "blocks" for decision in decisions):
        graph_decision = "blocked"
    elif any(decision.state == "constrains" for decision in decisions):
        graph_decision = "constrained"
    elif any(decision.state == "unknown" for decision in decisions):
        graph_decision = "unknown"
    else:
        graph_decision = "reachable"
    return {
        "evaluated": True,
        "provider": provider,
        "entry": entry,
        "target": target,
        "decision": graph_decision,
        "blockers": blockers,
        "unknowns": unknowns,
        "evaluation_order": order,
        "path": [path[0].source, *[edge.target for edge in path]],
        "edges": [_edge_result(decision) for decision in decisions],
        "resource_graph": _resource_graph_result(resource_graph),
    }


def build_provider_resource_graph(provider: str, network: NetworkRecord, exposure: str) -> ProviderResourceGraph:
    if provider == "aws":
        return _build_aws_resource_graph(network, exposure)
    if provider == "azure":
        return _build_azure_resource_graph(network, exposure)
    if provider == "gcp":
        return _build_gcp_resource_graph(network, exposure)
    if provider == "kubernetes":
        return _build_kubernetes_resource_graph(network, exposure)
    return ProviderResourceGraph(provider=provider, nodes=(), edges=(), precedence_rules=())


def _network_edges(provider: str, network: NetworkRecord, resource_graph: ProviderResourceGraph) -> list[NetworkEdge]:
    explicit = _explicit_network_edges(provider, network)
    if explicit:
        return explicit
    if resource_graph.edges:
        return list(resource_graph.edges)
    return _steps_network_edges(provider, network)


def _explicit_network_edges(provider: str, network: NetworkRecord) -> list[NetworkEdge]:
    raw_edges: list[NetworkRecord] = []
    for key in ("network_edges", "edges"):
        raw = network.get(key)
        if isinstance(raw, list):
            raw_edges.extend(dict(item) for item in raw if isinstance(item, dict))
    for graph_key in ("network_graph", "resource_graph", "graph"):
        raw_graph = network.get(graph_key)
        if not isinstance(raw_graph, dict):
            continue
        raw = raw_graph.get("edges")
        if isinstance(raw, list):
            raw_edges.extend(dict(item) for item in raw if isinstance(item, dict))
    edges: list[NetworkEdge] = []
    for raw in raw_edges:
        source = _first_string(raw, ("from", "source", "src"))
        target = _first_string(raw, ("to", "target", "dst", "destination"))
        if not source or not target:
            continue
        edge_type = _edge_type(provider, _first_string(raw, ("type", "kind", "edge_type")) or f"{source} {target}", raw)
        edges.append(
            NetworkEdge(
                source=source,
                target=target,
                edge_type=edge_type,
                provider=provider,
                raw=raw,
                precedence=_edge_precedence(provider, edge_type, raw),
                precedence_reason=_edge_precedence_reason(provider, edge_type, raw),
            )
        )
    return edges


def _steps_network_edges(provider: str, network: NetworkRecord) -> list[NetworkEdge]:
    steps = _strings(network.get("steps"))
    if len(steps) < 2:
        return []
    edges: list[NetworkEdge] = []
    for source, target in zip(steps, steps[1:], strict=False):
        edge_type = _edge_type(provider, f"{source} {target}", network)
        edges.append(
            NetworkEdge(
                source=source,
                target=target,
                edge_type=edge_type,
                provider=provider,
                raw={"from": source, "to": target, "steps_inferred": True, **network},
                precedence=_edge_precedence(provider, edge_type, network),
                precedence_reason="inferred from normalized path steps",
            )
        )
    return edges


def _build_aws_resource_graph(network: NetworkRecord, exposure: str) -> ProviderResourceGraph:
    controls: list[GraphControl] = []
    rules: list[NetworkRecord] = []
    route = _select_aws_route(_aws_route_records(network), exposure, network)
    if route:
        controls.append(_control("aws", "route", route, "aws_route.selected"))
        rules.append(_precedence_rule("aws", "route", "matching longest destination prefix wins; public ingress falls back to the default internet route when no source CIDR is supplied", route))
    nacl = _select_aws_nacl_rule(_aws_nacl_rule_records(network), network)
    if nacl:
        controls.append(_control("aws", "network_acl", nacl, "aws_network_acl_rule.selected"))
        rules.append(_precedence_rule("aws", "network_acl", "lowest numbered matching inbound rule wins", nacl))
    security_group = _select_aws_security_group_rule(_aws_security_group_rule_records(network))
    if security_group:
        controls.append(_control("aws", "security_group", security_group, "aws_security_group_rule.selected"))
        rules.append(_precedence_rule("aws", "security_group", "public CIDR allows outrank source-group or private-CIDR scoped ingress", security_group))
    controls.extend(_first_controls("aws", "load_balancer", network, ("load_balancers", "load_balancer", "alb", "elb")))
    controls.extend(_first_controls("aws", "listener", network, ("listeners", "listener", "listener_rules")))
    controls.extend(_first_controls("aws", "api_gateway", network, ("api_gateways", "api_gateway", "apigateway_routes", "routes_api")))
    controls.extend(_first_controls("aws", "serverless_url", network, ("lambda_function_urls", "function_urls", "serverless_urls")))
    controls.extend(_first_controls("aws", "waf", network, ("web_acls", "web_acl", "waf", "wafv2_web_acl")))
    controls.extend(_first_controls("aws", "private_endpoint", network, ("vpc_endpoints", "vpc_endpoint", "private_links", "privatelink")))
    return _linear_resource_graph("aws", network, exposure, controls, rules)


def _build_azure_resource_graph(network: NetworkRecord, exposure: str) -> ProviderResourceGraph:
    controls: list[GraphControl] = []
    rules: list[NetworkRecord] = []
    route = _select_route_by_precedence(_graph_items(network, ("routes", "route", "route_table_routes", "route_table")), exposure, network)
    if route:
        controls.append(_control("azure", "route", route, "azurerm_route.selected"))
        rules.append(_precedence_rule("azure", "route", "matching longest address prefix wins; priority breaks equal-prefix route ties", route))
    nsg_rule = _select_azure_nsg_rule(_graph_items(network, ("network_security_rules", "network_security_rule", "nsg_rules", "security_rules")), network)
    if nsg_rule:
        controls.append(_control("azure", "network_security_group", nsg_rule, "azurerm_network_security_rule.selected"))
        rules.append(_precedence_rule("azure", "network_security_group", "lowest priority matching NSG rule wins before later allow rules", nsg_rule))
    controls.extend(_first_controls("azure", "gateway", network, ("application_gateways", "application_gateway", "load_balancers", "load_balancer")))
    controls.extend(_first_controls("azure", "access_restriction", network, ("access_restrictions", "access_restriction", "ip_restrictions", "ip_restriction")))
    controls.extend(_first_controls("azure", "auth", network, ("auth_settings", "auth", "authentication")))
    controls.extend(_first_controls("azure", "waf", network, ("waf_policies", "waf_policy", "front_door_waf", "web_application_firewall")))
    controls.extend(_first_controls("azure", "private_endpoint", network, ("private_endpoints", "private_endpoint", "private_links")))
    return _linear_resource_graph("azure", network, exposure, controls, rules)


def _build_gcp_resource_graph(network: NetworkRecord, exposure: str) -> ProviderResourceGraph:
    controls: list[GraphControl] = []
    rules: list[NetworkRecord] = []
    route = _select_route_by_precedence(_graph_items(network, ("routes", "route", "google_compute_route")), exposure, network)
    if route:
        controls.append(_control("gcp", "route", route, "google_compute_route.selected"))
        rules.append(_precedence_rule("gcp", "route", "matching longest destination range wins; priority decides equal-prefix routes", route))
    firewall = _select_gcp_firewall_rule(_graph_items(network, ("firewall_rules", "firewalls", "firewall", "google_compute_firewall")), network)
    if firewall:
        controls.append(_control("gcp", "firewall", firewall, "google_compute_firewall.selected"))
        rules.append(_precedence_rule("gcp", "firewall", "lowest priority matching firewall rule wins; deny blocks before later allows", firewall))
    controls.extend(_first_controls("gcp", "cloud_armor", network, ("cloud_armor", "security_policies", "security_policy")))
    controls.extend(_first_controls("gcp", "iap", network, ("iap", "identity_aware_proxy", "backend_iap")))
    controls.extend(_first_controls("gcp", "serverless_ingress", network, ("serverless_ingress", "ingress_settings", "ingress")))
    controls.extend(_first_controls("gcp", "vpc_connector", network, ("vpc_access_connectors", "vpc_access_connector", "vpc_connector")))
    controls.extend(_first_controls("gcp", "private_endpoint", network, ("private_service_connect", "psc", "private_endpoints")))
    return _linear_resource_graph("gcp", network, exposure, controls, rules)


def _build_kubernetes_resource_graph(network: NetworkRecord, exposure: str) -> ProviderResourceGraph:
    controls: list[GraphControl] = []
    rules: list[NetworkRecord] = []
    controls.extend(_first_controls("kubernetes", "ingress", network, ("ingresses", "ingress", "ingress_classes", "ingress_class")))
    controls.extend(_first_controls("kubernetes", "service", network, ("services", "service")))
    network_policy = _select_kubernetes_network_policy(_graph_items(network, ("network_policies", "network_policy", "networkpolicies")))
    if network_policy:
        controls.append(_control("kubernetes", "network_policy", network_policy, "kubernetes_network_policy.selected"))
        rules.append(_precedence_rule("kubernetes", "network_policy", "deny-all or no matching allow-list blocks ingress before service reachability", network_policy))
    service_mesh = _select_kubernetes_service_mesh_policy(_graph_items(network, ("authorization_policies", "authorization_policy", "service_mesh", "peer_authentications", "peerauthentication")))
    if service_mesh:
        controls.append(_control("kubernetes", "service_mesh", service_mesh, "kubernetes_service_mesh.selected"))
        rules.append(_precedence_rule("kubernetes", "service_mesh", "DENY authorization policies take precedence over mTLS and allow policies", service_mesh))
    return _linear_resource_graph("kubernetes", network, exposure, controls, rules)


def _linear_resource_graph(
    provider: str,
    network: NetworkRecord,
    exposure: str,
    controls: list[GraphControl],
    precedence_rules: list[NetworkRecord],
) -> ProviderResourceGraph:
    if not controls:
        return ProviderResourceGraph(provider=provider, nodes=(), edges=(), precedence_rules=())
    entry = _graph_entry(network, exposure)
    target = _graph_target(network)
    nodes: list[NetworkRecord] = [
        {"id": entry, "kind": "entry", "provider": provider},
        {"id": target, "kind": "target", "provider": provider},
    ]
    edges: list[NetworkEdge] = []
    current = entry
    for control in controls:
        nodes.append({"id": control.node_id, "kind": control.edge_type, "provider": provider, "raw": control.raw})
        edges.append(
            NetworkEdge(
                source=current,
                target=control.node_id,
                edge_type=control.edge_type,
                provider=provider,
                raw=control.raw,
                precedence=control.precedence,
                precedence_reason=control.precedence_reason,
            )
        )
        current = control.node_id
    edges.append(
        NetworkEdge(
            source=current,
            target=target,
            edge_type="workload",
            provider=provider,
            raw={"from": current, "to": target, "edge_type": "workload", "resource_graph_built": True},
            precedence=10000,
            precedence_reason="target workload terminates the provider resource graph",
        )
    )
    return ProviderResourceGraph(provider=provider, nodes=tuple(nodes), edges=tuple(edges), precedence_rules=tuple(precedence_rules))


def _graph_entry(network: NetworkRecord, exposure: str) -> str:
    explicit = _first_string(network, ("entry", "entry_kind", "source"))
    if explicit:
        return explicit
    return {
        "public": "internet",
        "external": "external_cidr",
        "internal": "internal_network",
        "private": "isolated_network",
        "isolated": "isolated_network",
        "none": "isolated_network",
    }.get(exposure, "unknown_entry")


def _graph_target(network: NetworkRecord) -> str:
    explicit = _first_string(network, ("target", "asset", "workload", "destination"))
    if explicit:
        return explicit
    steps = _strings(network.get("steps"))
    if steps:
        return steps[-1]
    return "target:workload"


def _control(provider: str, edge_type: str, raw: NetworkRecord, fallback: str) -> GraphControl:
    enriched = dict(raw)
    enriched["edge_type"] = edge_type
    enriched["provider"] = provider
    enriched["precedence_evaluated"] = True
    enriched["selected_by_precedence"] = True
    precedence = _edge_precedence(provider, edge_type, enriched)
    reason = _edge_precedence_reason(provider, edge_type, enriched)
    node_id = _resource_id(enriched, fallback)
    enriched["resource_id"] = node_id
    enriched["precedence"] = precedence
    enriched["precedence_reason"] = reason
    return GraphControl(node_id=node_id, edge_type=edge_type, raw=enriched, precedence=precedence, precedence_reason=reason)


def _first_controls(provider: str, edge_type: str, network: NetworkRecord, keys: tuple[str, ...]) -> list[GraphControl]:
    items = _graph_items(network, keys)
    if not items:
        return []
    return [_control(provider, edge_type, items[0], f"{provider}_{edge_type}.selected")]


def _precedence_rule(provider: str, edge_type: str, rule: str, selected: NetworkRecord) -> NetworkRecord:
    return {
        "provider": provider,
        "edge_type": edge_type,
        "rule": rule,
        "selected": _resource_id(selected, f"{provider}_{edge_type}.selected"),
        "precedence": _edge_precedence(provider, edge_type, selected),
    }


def _graph_items(network: NetworkRecord, keys: tuple[str, ...]) -> list[NetworkRecord]:
    items: list[NetworkRecord] = []
    for key in keys:
        raw = network.get(key)
        if isinstance(raw, dict):
            items.append(dict(raw))
        elif isinstance(raw, list):
            items.extend(dict(item) for item in raw if isinstance(item, dict))
    return items


def _aws_route_records(network: NetworkRecord) -> list[NetworkRecord]:
    routes = _graph_items(network, ("routes", "route", "aws_routes"))
    for table in _graph_items(network, ("route_tables", "route_table", "aws_route_table")):
        nested = _graph_items(table, ("routes", "route", "aws_routes"))
        routes.extend(nested or [table])
    return routes


def _aws_nacl_rule_records(network: NetworkRecord) -> list[NetworkRecord]:
    records = _graph_items(network, ("network_acl_rules", "nacl_rules"))
    for acl in _graph_items(network, ("network_acls", "network_acl", "nacls")):
        nested = _graph_items(acl, ("ingress", "entries", "rules"))
        records.extend(nested or [acl])
    return records


def _aws_security_group_rule_records(network: NetworkRecord) -> list[NetworkRecord]:
    records = _graph_items(network, ("security_group_rules", "security_group_rule", "ingress_rules"))
    for group in _graph_items(network, ("security_groups", "security_group", "aws_security_group")):
        nested = _graph_items(group, ("ingress", "ingress_rules", "rules", "security_group_rules"))
        records.extend(nested or [group])
    return records


def _select_aws_route(routes: list[NetworkRecord], exposure: str, network: NetworkRecord) -> NetworkRecord | None:
    return _select_route_by_precedence(routes, exposure, network)


def _select_aws_nacl_rule(rules: list[NetworkRecord], network: NetworkRecord) -> NetworkRecord | None:
    inbound = [rule for rule in rules if _direction(rule) in {"ingress", "inbound"}]
    matching = [rule for rule in inbound if _rule_matches_source(rule, network)]
    if not matching:
        return None
    return min(matching, key=lambda rule: _numeric_value(rule, ("rule_number", "number", "priority"), 32767))


def _select_aws_security_group_rule(rules: list[NetworkRecord]) -> NetworkRecord | None:
    inbound = [rule for rule in rules if _direction(rule) in {"ingress", "inbound"}]
    if not inbound:
        return None
    return min(inbound, key=_security_group_precedence)


def _select_route_by_precedence(routes: list[NetworkRecord], exposure: str, network: NetworkRecord) -> NetworkRecord | None:
    candidates: list[tuple[int, int, NetworkRecord]] = []
    for route in routes:
        prefix = _route_match_prefix(route, exposure, network)
        if prefix is None:
            continue
        candidates.append((prefix, _numeric_value(route, ("priority", "route_priority", "preference"), 1000), route))
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: (-item[0], item[1]))[0][2]


def _select_azure_nsg_rule(rules: list[NetworkRecord], network: NetworkRecord) -> NetworkRecord | None:
    inbound = [rule for rule in rules if _direction(rule) in {"ingress", "inbound"}]
    matching = [rule for rule in inbound if _rule_matches_source(rule, network)]
    if not matching:
        return None
    return min(matching, key=lambda item: _numeric_value(item, ("priority", "rule_number", "number"), 4096))


def _select_gcp_firewall_rule(rules: list[NetworkRecord], network: NetworkRecord) -> NetworkRecord | None:
    inbound = [rule for rule in rules if _direction(rule) in {"ingress", "inbound"}]
    matching = [rule for rule in inbound if _rule_matches_source(rule, network)]
    if not matching:
        return None
    return sorted(matching, key=lambda item: (_numeric_value(item, ("priority", "rule_number", "number"), 1000), 0 if _record_has_deny(item) else 1))[0]


def _select_kubernetes_network_policy(items: list[NetworkRecord]) -> NetworkRecord | None:
    if not items:
        return None
    return min(items, key=lambda item: 0 if _record_has_deny(item) or "deny all" in _record_text(item) else 20)


def _select_kubernetes_service_mesh_policy(items: list[NetworkRecord]) -> NetworkRecord | None:
    if not items:
        return None
    return min(items, key=lambda item: 0 if _record_has_deny(item) else 30)


def _entry_and_target(network: NetworkRecord, edges: list[NetworkEdge]) -> tuple[str, str]:
    entry = _first_string(network, ("entry", "entry_kind", "source")) or edges[0].source
    target = _first_string(network, ("target", "asset", "workload", "destination")) or edges[-1].target
    edge_sources = {edge.source for edge in edges}
    edge_targets = {edge.target for edge in edges}
    if entry not in edge_sources and edges:
        entry = next((source for source in edge_sources if source not in edge_targets), edges[0].source)
    if target not in edge_targets and edges:
        target = next((item for item in reversed([edge.target for edge in edges]) if item not in edge_sources), edges[-1].target)
    return entry, target


def _solve_path(edges: list[NetworkEdge], entry: str, target: str) -> list[NetworkEdge]:
    adjacency: dict[str, list[NetworkEdge]] = {}
    for edge in edges:
        adjacency.setdefault(edge.source, []).append(edge)
    for outgoing in adjacency.values():
        outgoing.sort(key=lambda edge: (edge.precedence, edge.edge_type, edge.target))
    queue: deque[tuple[str, list[NetworkEdge]]] = deque([(entry, [])])
    visited: set[str] = set()
    while queue:
        node, path = queue.popleft()
        if node == target and path:
            return path
        if node in visited:
            continue
        visited.add(node)
        for edge in adjacency.get(node, []):
            if edge.target not in visited:
                queue.append((edge.target, [*path, edge]))
    return []


def _evaluate_edge(provider: str, edge: NetworkEdge, exposure: str) -> EdgeDecision:
    if provider == "aws":
        return _evaluate_aws_edge(edge, exposure)
    if provider == "azure":
        return _evaluate_azure_edge(edge, exposure)
    if provider == "gcp":
        return _evaluate_gcp_edge(edge, exposure)
    if provider == "kubernetes":
        return _evaluate_kubernetes_edge(edge, exposure)
    return _allow(edge)


def _evaluate_aws_edge(edge: NetworkEdge, exposure: str) -> EdgeDecision:
    text = _edge_text(edge)
    edge_type = edge.edge_type
    if edge_type == "route":
        destination = _first_string(edge.raw, ("destination_cidr_block", "destination_ipv6_cidr_block", "destination", "cidr_block", "cidr"))
        target = _first_string(edge.raw, ("gateway_id", "nat_gateway_id", "transit_gateway_id", "vpc_peering_connection_id", "egress_only_gateway_id", "target"))
        if "blackhole" in text:
            return _block(edge, "route_blackhole", "selected AWS route is blackholed")
        if "eigw" in target.lower() or "egress_only" in text:
            return _block(edge, "egress_only_gateway", "selected AWS route uses an egress-only internet gateway")
        if exposure in {"public", "external"} and destination and destination not in {"0.0.0.0/0", "::/0"}:
            return _block(edge, "no_public_route", "AWS route edge is not a default public route")
        if target and not any(marker in target.lower() for marker in ("igw", "internet_gateway", "local")):
            return _constrain(edge, "route_requires_private_transit", f"selected AWS route target is {target}")
        return _allow(edge)
    if edge_type == "security_group":
        if _has_source_security_group(edge.raw, text):
            return _constrain(edge, "source_security_group_restriction", "AWS security-group edge is scoped to a source security group")
        cidrs = _cidrs(edge.raw)
        if cidrs and not _contains_public_cidr(cidrs):
            return _constrain(edge, "source_cidr_restriction", "AWS security-group edge is scoped to non-public CIDR ranges")
        if "no_ingress" in text or "no inbound" in text:
            return _block(edge, "security_group_no_ingress", "AWS security-group edge has no inbound allow")
        return _allow(edge)
    if edge_type == "network_acl":
        if "deny" in text:
            return _block(edge, "network_acl_deny", "AWS NACL edge denies the selected source")
        if not _first_string(edge.raw, ("rule_number", "number", "priority")):
            return _constrain(edge, "nacl_rule_order_unknown", "AWS NACL edge has no rule number")
        return _allow(edge)
    if edge_type in {"load_balancer", "listener"} and _has_auth(text):
        return _constrain(edge, "elb_listener_auth", "AWS load balancer listener requires authentication")
    if edge_type == "api_gateway":
        if "api_key" in text:
            return _constrain(edge, "api_key_required", "AWS API Gateway edge requires an API key")
        if _has_auth(text):
            return _constrain(edge, "api_authorizer", "AWS API Gateway edge has an authorizer")
    if edge_type == "serverless_url" and ("aws_iam" in text or "authorization_type" in text):
        return _constrain(edge, "lambda_function_url_aws_iam", "AWS Lambda function URL requires AWS IAM authorization")
    if edge_type == "waf":
        return _constrain(edge, "waf_or_firewall_policy", "AWS WAF edge is attached to the path")
    if edge_type == "private_endpoint":
        if _private_endpoint_direction(edge.raw) == "egress":
            return _constrain(edge, "private_endpoint_egress_only", "AWS VPC endpoint is outbound/dependency path evidence, not public ingress")
        if exposure in {"public", "external"}:
            return _block(edge, "vpc_endpoint_only", "AWS path is restricted to VPC endpoint or PrivateLink access")
        return _constrain(edge, "vpc_endpoint_only", "AWS VPC endpoint constrains the private path")
    return _allow(edge)


def _evaluate_azure_edge(edge: NetworkEdge, exposure: str) -> EdgeDecision:
    text = _edge_text(edge)
    edge_type = edge.edge_type
    if edge_type == "network_security_group":
        if "deny" in text:
            return _block(edge, "nsg_deny", "Azure NSG edge denies inbound traffic")
        if not _first_string(edge.raw, ("priority",)):
            return _constrain(edge, "nsg_priority_unknown", "Azure NSG edge has no priority")
        cidrs = _cidrs(edge.raw)
        if cidrs and not _contains_public_cidr(cidrs):
            return _constrain(edge, "source_cidr_restriction", "Azure NSG edge is scoped to non-public source ranges")
        return _allow(edge)
    if edge_type == "route":
        next_hop = _first_string(edge.raw, ("next_hop_type", "nextHopType", "target", "next_hop"))
        if next_hop.lower() in {"none", "blackhole"}:
            return _block(edge, "route_blackhole", "Azure route edge drops traffic")
        if edge.raw.get("precedence_evaluated") and _is_public_route_target(next_hop, "azure"):
            return _allow(edge)
        return _constrain(edge, "route_table_precedence_unknown", "Azure route edge requires route-table precedence evaluation")
    if edge_type == "private_endpoint":
        if _private_endpoint_direction(edge.raw) == "egress":
            return _constrain(edge, "private_endpoint_egress_only", "Azure Private Endpoint is outbound/dependency path evidence, not public ingress")
        if exposure in {"public", "external"}:
            return _block(edge, "private_endpoint", "Azure Private Endpoint restricts public access")
        return _constrain(edge, "private_endpoint", "Azure Private Endpoint constrains the private path")
    if edge_type == "access_restriction":
        if "deny" in text:
            return _block(edge, "access_restriction_deny", "Azure access restriction denies the path")
        return _constrain(edge, "access_restriction_scope", "Azure access restriction scopes ingress")
    if edge_type == "auth":
        return _constrain(edge, "app_service_auth", "Azure App Service authentication is enabled")
    if edge_type == "gateway" and _has_auth(text):
        return _constrain(edge, "application_gateway_auth", "Azure Application Gateway authentication is linked to the path")
    if edge_type == "waf":
        return _constrain(edge, "front_door_waf", "Azure Front Door or Application Gateway WAF is linked to the path")
    return _allow(edge)


def _evaluate_gcp_edge(edge: NetworkEdge, exposure: str) -> EdgeDecision:
    text = _edge_text(edge)
    edge_type = edge.edge_type
    if edge_type == "firewall":
        if "disabled" in text:
            return _block(edge, "disabled_firewall", "GCP firewall edge is disabled")
        if "egress" in text:
            return _block(edge, "egress_firewall", "GCP firewall edge is egress-only")
        if "deny" in text:
            return _block(edge, "firewall_deny", "GCP firewall edge denies ingress")
        cidrs = _cidrs(edge.raw)
        if cidrs and not _contains_public_cidr(cidrs):
            return _constrain(edge, "source_cidr_restriction", "GCP firewall edge is scoped to non-public source ranges")
        if _first_string(edge.raw, ("priority",)) and not edge.raw.get("precedence_evaluated"):
            return _constrain(edge, "firewall_priority_unknown", "GCP firewall edge requires priority and hierarchy evaluation")
        return _allow(edge)
    if edge_type == "route":
        next_hop = _first_string(edge.raw, ("next_hop_gateway", "next_hop_internet", "next_hop_instance", "next_hop_vpn_tunnel", "next_hop_ilb", "target", "next_hop"))
        if "blackhole" in text or next_hop.lower() in {"none", "blackhole"}:
            return _block(edge, "route_blackhole", "GCP route edge drops traffic")
        if edge.raw.get("precedence_evaluated") and _is_public_route_target(next_hop, "gcp"):
            return _allow(edge)
        return _constrain(edge, "route_precedence_unknown", "GCP route edge requires precedence evaluation")
    if edge_type == "iap":
        return _constrain(edge, "iap_required", "GCP IAP is linked to the path")
    if edge_type == "cloud_armor":
        return _constrain(edge, "cloud_armor_policy", "GCP Cloud Armor is linked to the path")
    if edge_type == "private_endpoint":
        if _private_endpoint_direction(edge.raw) == "egress":
            return _constrain(edge, "private_endpoint_egress_only", "GCP Private Service Connect is outbound/dependency path evidence, not public ingress")
        if exposure in {"public", "external"}:
            return _block(edge, "private_endpoint", "GCP Private Service Connect restricts public access")
        return _constrain(edge, "private_endpoint", "GCP Private Service Connect constrains the private path")
    if edge_type == "serverless_ingress" and ("internal" in text or "ingress_internal" in text):
        return _block(edge, "ingress_internal_only", "GCP serverless ingress is internal only") if exposure in {"public", "external"} else _constrain(edge, "ingress_internal_only", "GCP serverless ingress is internal only")
    if edge_type == "vpc_connector" and "egress" in text and "all" in text:
        return _block(edge, "serverless_vpc_connector_egress_only", "GCP serverless VPC connector routes traffic privately") if exposure in {"public", "external"} else _constrain(edge, "serverless_vpc_connector_egress_only", "GCP serverless VPC connector routes traffic privately")
    return _allow(edge)


def _evaluate_kubernetes_edge(edge: NetworkEdge, exposure: str) -> EdgeDecision:
    text = _edge_text(edge)
    edge_type = edge.edge_type
    if edge_type == "network_policy":
        if "deny" in text and ("all" in text or "ingress" in text):
            return _block(edge, "network_policy_deny_all", "Kubernetes NetworkPolicy denies ingress")
        return _constrain(edge, "network_policy_allow_list", "Kubernetes NetworkPolicy allow-list constrains ingress")
    if edge_type == "ingress":
        if "internal" in text:
            return _block(edge, "ingress_class_internal", "Kubernetes ingress class is internal") if exposure in {"public", "external"} else _constrain(edge, "ingress_class_internal", "Kubernetes ingress class is internal")
        if _has_auth(text):
            return _constrain(edge, "ingress_controller_auth", "Kubernetes ingress controller authentication is configured")
    if edge_type == "service_mesh":
        if _service_mesh_denies(edge.raw):
            return _block(edge, "authorization_policy_deny", "Kubernetes service-mesh policy denies the path")
        if _service_mesh_allow_misses_source(edge.raw):
            return _block(edge, "service_mesh_authz_no_allow", "Kubernetes service-mesh AuthorizationPolicy has no matching ALLOW source")
        if "mtls" in text and "strict" in text:
            return _constrain(edge, "service_mesh_mtls_strict", "Kubernetes service mesh requires strict mTLS")
        return _constrain(edge, "service_mesh_policy", "Kubernetes service mesh policy is linked to the path")
    if edge_type == "pod_security":
        return _constrain(edge, "pod_security_boundary", "Kubernetes pod security boundary is linked to runtime")
    return _allow(edge)


def _edge_type(provider: str, text: str, raw: NetworkRecord) -> str:
    explicit = _first_string(raw, ("edge_type", "type", "kind"))
    if explicit:
        return explicit.lower()
    value = text.lower()
    if provider == "aws":
        if "route" in value:
            return "route"
        if "security_group" in value or "security group" in value:
            return "security_group"
        if "network_acl" in value or "nacl" in value:
            return "network_acl"
        if "api_gateway" in value or "apigateway" in value or "authorizer" in value:
            return "api_gateway"
        if "lambda" in value and "url" in value:
            return "serverless_url"
        if "listener" in value:
            return "listener"
        if "lb" in value or "load_balancer" in value or "alb" in value or "elb" in value:
            return "load_balancer"
        if "waf" in value or "web_acl" in value:
            return "waf"
        if "vpc_endpoint" in value or "privatelink" in value or "private_link" in value:
            return "private_endpoint"
    if provider == "azure":
        if "network_security" in value or "nsg" in value:
            return "network_security_group"
        if "route" in value:
            return "route"
        if "private_endpoint" in value or "privatelink" in value:
            return "private_endpoint"
        if "access_restriction" in value or "ip_restriction" in value:
            return "access_restriction"
        if "auth" in value:
            return "auth"
        if "waf" in value or "front_door" in value:
            return "waf"
        if "gateway" in value or "load_balancer" in value or "lb" in value:
            return "gateway"
    if provider == "gcp":
        if "firewall" in value:
            return "firewall"
        if "route" in value:
            return "route"
        if "iap" in value:
            return "iap"
        if "cloud_armor" in value or "security_policy" in value:
            return "cloud_armor"
        if "private_service_connect" in value or "psc" in value:
            return "private_endpoint"
        if "ingress" in value and "internal" in value:
            return "serverless_ingress"
        if "vpc_access_connector" in value or "vpc connector" in value:
            return "vpc_connector"
    if provider == "kubernetes":
        if "networkpolicy" in value or "network_policy" in value:
            return "network_policy"
        if "authorizationpolicy" in value or "service_mesh" in value or "mtls" in value:
            return "service_mesh"
        if "ingress" in value:
            return "ingress"
        if "podsecurity" in value or "pod_security" in value or "securitycontext" in value:
            return "pod_security"
        if "service" in value:
            return "service"
    return "link"


def _edge_precedence(provider: str, edge_type: str, raw: NetworkRecord) -> int:
    explicit = _numeric_value(raw, ("precedence", "priority", "rule_number", "number"), -1)
    if explicit >= 0:
        return explicit
    if edge_type == "route":
        prefix = _route_prefix_length(raw)
        return 1000 - prefix if prefix is not None else 1000
    if provider == "aws" and edge_type == "security_group":
        return _security_group_precedence(raw)
    if provider == "kubernetes" and edge_type in {"network_policy", "service_mesh"} and (_record_has_deny(raw) or "deny all" in _record_text(raw)):
        return 0
    order = {
        "route": 100,
        "network_acl": 150,
        "network_security_group": 160,
        "firewall": 160,
        "security_group": 200,
        "load_balancer": 300,
        "gateway": 300,
        "listener": 320,
        "api_gateway": 320,
        "serverless_url": 320,
        "ingress": 300,
        "service": 340,
        "access_restriction": 360,
        "network_policy": 380,
        "service_mesh": 390,
        "auth": 400,
        "waf": 420,
        "cloud_armor": 420,
        "iap": 430,
        "private_endpoint": 450,
        "vpc_connector": 460,
        "serverless_ingress": 470,
        "workload": 10000,
    }
    return order.get(edge_type, 1000)


def _edge_precedence_reason(provider: str, edge_type: str, raw: NetworkRecord) -> str:
    explicit = _first_string(raw, ("precedence_reason",))
    if explicit:
        return explicit
    if provider == "aws" and edge_type == "route":
        return "AWS route selection uses longest destination prefix; public ingress requires default internet route"
    if provider == "aws" and edge_type == "network_acl":
        return "AWS NACL selection uses the lowest numbered matching inbound rule"
    if provider == "aws" and edge_type == "security_group":
        return "AWS security-group ingress is evaluated after route and NACL controls"
    if provider == "azure" and edge_type == "network_security_group":
        return "Azure NSG selection uses the lowest priority matching rule"
    if provider == "gcp" and edge_type == "firewall":
        return "GCP firewall selection uses the lowest priority matching rule"
    if provider == "kubernetes" and edge_type == "network_policy":
        return "Kubernetes NetworkPolicy deny-all or missing allow-list constrains service reachability"
    if provider == "kubernetes" and edge_type == "service_mesh":
        return "Kubernetes service-mesh DENY policy takes precedence over allow and mTLS constraints"
    return "provider default edge order"


def _resource_id(raw: NetworkRecord, fallback: str) -> str:
    for key in ("id", "address", "name", "resource_id", "arn", "self_link"):
        value = _first_string(raw, (key,))
        if value:
            return value
    return fallback


def _route_destination(route: NetworkRecord) -> str:
    return _first_string(
        route,
        (
            "destination_cidr_block",
            "destination_ipv6_cidr_block",
            "destination_range",
            "dest_range",
            "destination",
            "address_prefix",
            "cidr_block",
            "cidr",
        ),
    )


def _route_prefix_length(route: NetworkRecord) -> int | None:
    destination = _route_destination(route)
    if not destination:
        return None
    if "/" not in destination:
        return None
    try:
        return int(destination.rsplit("/", 1)[1])
    except ValueError:
        return None


def _route_match_prefix(route: NetworkRecord, exposure: str, network: NetworkRecord) -> int | None:
    destination = _route_destination(route)
    route_network = _parse_ip_network(destination)
    source_networks = _network_source_networks(network)
    if route_network is None:
        return 0 if not source_networks else None
    if source_networks:
        for source in source_networks:
            if source.version == route_network.version and source.overlaps(route_network):
                return route_network.prefixlen
        return None
    if exposure in {"public", "external"}:
        return route_network.prefixlen if str(route_network) in {"0.0.0.0/0", "::/0"} else None
    return route_network.prefixlen


def _network_source_networks(network: NetworkRecord) -> list[IpNetwork]:
    networks: list[IpNetwork] = []
    for key in ("source_cidr", "source_cidrs", "source_ip", "source_ips", "source_range", "source_ranges", "client_cidr", "client_ip"):
        raw = network.get(key)
        values = raw if isinstance(raw, list) else [raw]
        for value in values:
            parsed = _parse_ip_network(value)
            if parsed is not None:
                networks.append(parsed)
    return networks


def _parse_ip_network(value: Any) -> IpNetwork | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "*":
        return None
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=False)
        return ipaddress.ip_network(text)
    except ValueError:
        return None


def _direction(rule: NetworkRecord) -> str:
    if rule.get("egress") is True:
        return "egress"
    value = str(rule.get("type") or rule.get("direction") or rule.get("traffic_type") or "ingress").lower()
    if value in {"egress", "outbound"}:
        return "egress"
    return "inbound" if value == "inbound" else "ingress"


def _numeric_value(raw: NetworkRecord, keys: tuple[str, ...], default: int) -> int:
    for key in keys:
        value = raw.get(key)
        if value is None:
            continue
        try:
            return int(str(value))
        except ValueError:
            continue
    return default


def _security_group_precedence(rule: NetworkRecord) -> int:
    if _record_has_deny(rule):
        return 0
    if _contains_public_cidr(_cidrs(rule)):
        return 10
    if _has_source_security_group(rule, _record_text(rule)):
        return 20
    if _cidrs(rule):
        return 30
    return 40


def _rule_matches_public_source(rule: NetworkRecord) -> bool:
    cidrs = _cidrs(rule)
    return not cidrs or _contains_public_cidr(cidrs)


def _rule_matches_source(rule: NetworkRecord, network: NetworkRecord) -> bool:
    source_networks = _network_source_networks(network)
    cidrs = _cidrs(rule)
    if not source_networks:
        return _rule_matches_public_source(rule)
    rule_networks = [parsed for cidr in cidrs if (parsed := _parse_ip_network(cidr)) is not None]
    if not rule_networks:
        return True
    return any(source.version == rule.version and source.overlaps(rule) for source in source_networks for rule in rule_networks)


def _record_has_deny(raw: NetworkRecord) -> bool:
    text = _record_text(raw)
    return any(str(raw.get(key) or "").lower() == "deny" for key in ("action", "rule_action", "access", "effect")) or "deny" in text


def _record_text(raw: NetworkRecord) -> str:
    return json.dumps(raw, sort_keys=True, default=str).lower()


def _allow(edge: NetworkEdge) -> EdgeDecision:
    return EdgeDecision(edge=edge, state="allows", blockers=(), unknowns=())


def _block(edge: NetworkEdge, kind: str, evidence: str) -> EdgeDecision:
    return EdgeDecision(edge=edge, state="blocks", blockers=(_blocker(kind, "blocks", edge.provider, evidence),), unknowns=())


def _constrain(edge: NetworkEdge, kind: str, evidence: str) -> EdgeDecision:
    return EdgeDecision(edge=edge, state="constrains", blockers=(_blocker(kind, "constrains", edge.provider, evidence),), unknowns=())


def _edge_result(decision: EdgeDecision) -> NetworkRecord:
    return {
        "from": decision.edge.source,
        "to": decision.edge.target,
        "type": decision.edge.edge_type,
        "state": decision.state,
        "provider": decision.edge.provider,
        "precedence": decision.edge.precedence,
        "precedence_reason": decision.edge.precedence_reason,
        "blockers": list(decision.blockers),
        "unknowns": list(decision.unknowns),
    }


def _resource_graph_result(graph: ProviderResourceGraph) -> NetworkRecord:
    return {
        "evaluated": bool(graph.edges),
        "provider": graph.provider,
        "nodes": list(graph.nodes),
        "edges": [
            {
                "from": edge.source,
                "to": edge.target,
                "type": edge.edge_type,
                "provider": edge.provider,
                "precedence": edge.precedence,
                "precedence_reason": edge.precedence_reason,
                "resource": _resource_id(edge.raw, edge.target),
            }
            for edge in graph.edges
        ],
        "precedence_rules": list(graph.precedence_rules),
    }


def _blocker(kind: str, effect: str, provider: str, evidence: str) -> NetworkRecord:
    return {"kind": kind, "effect": effect, "provider": provider, "evidence": evidence}


def _edge_text(edge: NetworkEdge) -> str:
    return f"{edge.source} {edge.target} {edge.edge_type} {json.dumps(edge.raw, sort_keys=True, default=str)}".lower()


def _has_auth(text: str) -> bool:
    return any(marker in text for marker in ("auth", "authorizer", "oidc", "jwt", "cognito", "oauth"))


def _has_source_security_group(raw: NetworkRecord, text: str) -> bool:
    return any(raw.get(key) for key in ("source_security_group_id", "source_security_group", "referenced_security_group_id")) or "source_security_group" in text


def _cidrs(raw: NetworkRecord) -> list[str]:
    values: list[str] = []
    for key in ("cidr", "cidr_block", "source_cidr", "source_range", "source_address_prefix", "destination_cidr_block", "destination_prefix"):
        if raw.get(key):
            values.append(str(raw[key]))
    for key in ("cidr_blocks", "ipv6_cidr_blocks", "source_cidrs", "source_ranges", "sourceRanges", "source_address_prefixes", "destination_prefixes"):
        if isinstance(raw.get(key), list):
            values.extend(str(item) for item in raw[key] if str(item))
    return values


def _contains_public_cidr(cidrs: list[str]) -> bool:
    return any(cidr.strip().lower() in {"*", "internet", "any", "0.0.0.0/0", "::/0"} for cidr in cidrs)


def _is_public_route_target(target: str, provider: str) -> bool:
    value = target.lower()
    if provider == "azure":
        return value in {"internet", "defaultinternetgateway"} or "internet" in value
    if provider == "gcp":
        return "default-internet-gateway" in value or "internet" in value
    return "igw" in value or "internet" in value


def _private_endpoint_direction(raw: NetworkRecord) -> str:
    value = _first_string(raw, ("direction", "traffic_direction", "path_direction", "connection_direction", "endpoint_direction", "applies_to", "target_role")).lower()
    if any(marker in value for marker in ("egress", "outbound", "dependency", "client")):
        return "egress"
    return "ingress"


def _service_mesh_denies(raw: NetworkRecord) -> bool:
    action = _first_string(raw, ("action", "effect")).upper()
    if action == "DENY":
        return True
    return _record_has_deny(raw) and "allow" not in action.lower()


def _service_mesh_allow_misses_source(raw: NetworkRecord) -> bool:
    action = _first_string(raw, ("action", "effect")).upper()
    if action and action != "ALLOW":
        return False
    source = _first_string(raw, ("source_principal", "source", "principal", "request_principal"))
    if not source:
        return False
    principals = _service_mesh_principals(raw)
    return bool(principals) and source not in principals and "*" not in principals


def _service_mesh_principals(raw: NetworkRecord) -> set[str]:
    principals: set[str] = set()
    for key in ("principals", "source_principals", "request_principals", "namespaces"):
        value = raw.get(key)
        values = value if isinstance(value, list) else [value]
        principals.update(str(item) for item in values if item)
    for item in raw.get("from", []) if isinstance(raw.get("from"), list) else []:
        if not isinstance(item, dict):
            continue
        source = item.get("source")
        if not isinstance(source, dict):
            continue
        for key in ("principals", "requestPrincipals", "namespaces"):
            nested_values = source.get(key)
            if isinstance(nested_values, list):
                principals.update(str(value) for value in nested_values if value)
    return principals


def _first_string(value: NetworkRecord, keys: tuple[str, ...]) -> str:
    for key in keys:
        raw = value.get(key)
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        if raw is not None and not isinstance(raw, (dict, list)):
            return str(raw).strip()
    return ""


def _strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [value]
    return []


def _dedupe_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    for value in values:
        if value and value not in deduped:
            deduped.append(value)
    return deduped


def _dedupe_objects(values: list[NetworkRecord]) -> list[NetworkRecord]:
    deduped: list[NetworkRecord] = []
    seen: set[str] = set()
    for value in values:
        token = json.dumps(value, sort_keys=True, default=str)
        if token in seen:
            continue
        seen.add(token)
        deduped.append(value)
    return deduped
