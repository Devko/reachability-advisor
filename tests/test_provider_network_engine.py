from __future__ import annotations

import json
import unittest
from pathlib import Path

from reachability_advisor.provider_evaluators.network_engine import (
    build_provider_resource_graph,
    evaluate_provider_network_graph,
)

ROOT = Path(__file__).resolve().parents[1]


def _blocker_kinds(record: dict[str, object]) -> set[str]:
    blockers = record.get("blockers")
    if not isinstance(blockers, list):
        return set()
    return {str(item.get("kind")) for item in blockers if isinstance(item, dict)}


def _selected_resources(record: dict[str, object]) -> set[str]:
    graph = record.get("resource_graph")
    if not isinstance(graph, dict):
        return set()
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return set()
    return {str(edge.get("resource")) for edge in edges if isinstance(edge, dict)}


class ProviderNetworkEngineTests(unittest.TestCase):
    def test_explicit_graph_edges_skip_malformed_edges_and_apply_gateway_controls(self) -> None:
        record = evaluate_provider_network_graph(
            "aws",
            {
                "network_graph": {
                    "edges": [
                        {"from": "internet"},
                        {"from": "internet", "to": "gateway", "kind": "api_gateway", "api_key_required": True},
                        {"from": "gateway", "to": "api", "kind": "workload"},
                    ]
                }
            },
            "public",
        )

        self.assertEqual(record["decision"], "constrained")
        self.assertIn("api_key_required", _blocker_kinds(record))
        self.assertEqual(record["path"], ["internet", "gateway", "api"])

    def test_aws_explicit_edges_cover_route_security_and_private_controls(self) -> None:
        cases = [
            ({"edge_type": "route", "destination_cidr_block": "0.0.0.0/0", "gateway_id": "blackhole"}, "route_blackhole", "blocked"),
            ({"edge_type": "route", "destination_cidr_block": "0.0.0.0/0", "egress_only_gateway_id": "eigw-123"}, "egress_only_gateway", "blocked"),
            ({"edge_type": "route", "destination_cidr_block": "0.0.0.0/0", "transit_gateway_id": "tgw-123"}, "route_requires_private_transit", "constrained"),
            ({"edge_type": "security_group", "no_ingress": True}, "security_group_no_ingress", "blocked"),
            ({"edge_type": "network_acl", "cidr_block": "0.0.0.0/0"}, "nacl_rule_order_unknown", "constrained"),
            ({"edge_type": "load_balancer", "authenticate_oidc": True}, "elb_listener_auth", "constrained"),
            ({"edge_type": "serverless_url", "authorization_type": "AWS_IAM"}, "lambda_function_url_aws_iam", "constrained"),
            ({"edge_type": "waf", "name": "edge-waf"}, "waf_or_firewall_policy", "constrained"),
            ({"edge_type": "private_endpoint", "name": "vpce-api"}, "vpc_endpoint_only", "blocked"),
        ]

        for raw, expected_kind, expected_decision in cases:
            with self.subTest(kind=expected_kind):
                edge = {"from": "internet", "to": "api", **raw}
                record = evaluate_provider_network_graph("aws", {"network_edges": [edge]}, "public")

                self.assertEqual(record["decision"], expected_decision)
                self.assertIn(expected_kind, _blocker_kinds(record))

    def test_azure_gcp_and_kubernetes_explicit_edges_cover_provider_blockers(self) -> None:
        cases = [
            ("azure", {"edge_type": "network_security_group"}, "nsg_priority_unknown", "constrained"),
            ("azure", {"edge_type": "network_security_group", "priority": 100, "source_cidr": "10.0.0.0/8"}, "source_cidr_restriction", "constrained"),
            ("azure", {"edge_type": "route", "next_hop_type": "none"}, "route_blackhole", "blocked"),
            ("azure", {"edge_type": "private_endpoint", "name": "pe-api"}, "private_endpoint", "blocked"),
            ("azure", {"edge_type": "access_restriction", "action": "allow"}, "access_restriction_scope", "constrained"),
            ("azure", {"edge_type": "auth", "enabled": True}, "app_service_auth", "constrained"),
            ("azure", {"edge_type": "gateway", "auth": "oauth"}, "application_gateway_auth", "constrained"),
            ("azure", {"edge_type": "waf", "name": "frontdoor-waf"}, "front_door_waf", "constrained"),
            ("gcp", {"edge_type": "firewall", "disabled": True}, "disabled_firewall", "blocked"),
            ("gcp", {"edge_type": "firewall", "direction": "EGRESS"}, "egress_firewall", "blocked"),
            ("gcp", {"edge_type": "firewall", "source_ranges": ["10.0.0.0/8"]}, "source_cidr_restriction", "constrained"),
            ("gcp", {"edge_type": "firewall", "priority": 1000}, "firewall_priority_unknown", "constrained"),
            ("gcp", {"edge_type": "route", "priority": 1000}, "route_precedence_unknown", "constrained"),
            ("gcp", {"edge_type": "iap", "enabled": True}, "iap_required", "constrained"),
            ("gcp", {"edge_type": "cloud_armor", "name": "policy"}, "cloud_armor_policy", "constrained"),
            ("gcp", {"edge_type": "private_endpoint", "name": "psc"}, "private_endpoint", "blocked"),
            ("gcp", {"edge_type": "serverless_ingress", "ingress": "internal"}, "ingress_internal_only", "blocked"),
            ("gcp", {"edge_type": "vpc_connector", "egress": "all"}, "serverless_vpc_connector_egress_only", "blocked"),
            ("kubernetes", {"edge_type": "network_policy", "policy": "deny all ingress"}, "network_policy_deny_all", "blocked"),
            ("kubernetes", {"edge_type": "ingress", "class": "internal"}, "ingress_class_internal", "blocked"),
            ("kubernetes", {"edge_type": "ingress", "auth": "oauth"}, "ingress_controller_auth", "constrained"),
            ("kubernetes", {"edge_type": "service_mesh", "mode": "mtls strict"}, "service_mesh_mtls_strict", "constrained"),
            ("kubernetes", {"edge_type": "service_mesh", "mode": "allow-list"}, "service_mesh_policy", "constrained"),
            ("kubernetes", {"edge_type": "pod_security", "profile": "restricted"}, "pod_security_boundary", "constrained"),
        ]

        for provider, raw, expected_kind, expected_decision in cases:
            with self.subTest(provider=provider, kind=expected_kind):
                edge = {"from": "internet", "to": "workload", **raw}
                record = evaluate_provider_network_graph(provider, {"edges": [edge]}, "public")

                self.assertEqual(record["decision"], expected_decision)
                self.assertIn(expected_kind, _blocker_kinds(record))

    def test_resource_graph_builders_accept_singleton_and_nested_provider_records(self) -> None:
        aws = build_provider_resource_graph(
            "aws",
            {
                "route_table": {"id": "rtb", "destination_cidr_block": "0.0.0.0/0", "gateway_id": "igw-123"},
                "network_acl": {"id": "acl", "ingress": [{"id": "acl-100", "rule_number": 100, "rule_action": "allow"}]},
                "security_group": {"id": "sg", "ingress": [{"id": "sg-public", "cidr_blocks": ["0.0.0.0/0"]}]},
                "target": "aws_ecs_service.api",
            },
            "public",
        )
        azure = build_provider_resource_graph("azure", {"route": {"name": "route", "priority": 100}, "target": "azurerm_linux_web_app.api"}, "public")
        gcp = build_provider_resource_graph("gcp", {"route": {"name": "route", "priority": 100}, "target": "google_cloud_run_v2_service.api"}, "public")

        self.assertEqual([edge.edge_type for edge in aws.edges[:3]], ["route", "network_acl", "security_group"])
        self.assertEqual(azure.edges[0].edge_type, "route")
        self.assertEqual(gcp.edges[0].edge_type, "route")
        self.assertTrue(all(edge.precedence_reason for edge in [*aws.edges, *azure.edges, *gcp.edges]))

    def test_provider_network_golden_fixtures(self) -> None:
        fixtures = json.loads((ROOT / "fixtures" / "network" / "provider-network-golden.json").read_text(encoding="utf-8"))
        for case in fixtures["cases"]:
            with self.subTest(case=case["id"]):
                record = evaluate_provider_network_graph(case["provider"], case["network"], case["exposure"])
                expected = case["expected"]

                self.assertEqual(record["decision"], expected["decision"])
                self.assertTrue(set(expected["blockers"]).issubset(_blocker_kinds(record)))
                self.assertTrue(set(expected["selected_resources"]).issubset(_selected_resources(record)))

    def test_provider_route_precedence_allows_selected_public_routes(self) -> None:
        cases = [
            (
                "aws",
                {
                    "target": "aws_instance.api",
                    "source_ips": ["203.0.113.10"],
                    "routes": [{"id": "aws_route.default", "destination_cidr_block": "0.0.0.0/0", "gateway_id": "igw-123"}],
                    "network_acl_rules": [{"id": "acl-100", "rule_number": 100, "rule_action": "allow", "cidr_block": "0.0.0.0/0"}],
                    "security_group_rules": [{"id": "sg-https", "type": "ingress", "cidr_blocks": ["0.0.0.0/0"]}],
                },
            ),
            (
                "azure",
                {
                    "target": "azurerm_linux_web_app.api",
                    "source_ip": "203.0.113.11",
                    "routes": [{"id": "azurerm_route.default", "address_prefix": "0.0.0.0/0", "next_hop_type": "Internet"}],
                    "network_security_rules": [{"id": "nsg-allow", "direction": "Inbound", "access": "Allow", "priority": 100, "source_address_prefix": "Internet"}],
                },
            ),
            (
                "gcp",
                {
                    "target": "google_compute_instance.api",
                    "client_ip": "203.0.113.12",
                    "routes": [{"id": "google_compute_route.default", "dest_range": "0.0.0.0/0", "next_hop_gateway": "default-internet-gateway"}],
                    "firewall_rules": [{"id": "fw-allow", "direction": "INGRESS", "priority": 1000, "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp"}]}],
                },
            ),
        ]

        for provider, network in cases:
            with self.subTest(provider=provider):
                record = evaluate_provider_network_graph(provider, network, "public")

                self.assertEqual(record["decision"], "reachable")
                self.assertEqual(_blocker_kinds(record), set())
                self.assertTrue(record["resource_graph"]["precedence_rules"])

    def test_private_endpoint_direction_is_provider_specific(self) -> None:
        cases = [
            ("aws", "public", {"edge_type": "private_endpoint", "direction": "egress"}, "constrained", "private_endpoint_egress_only"),
            ("aws", "internal", {"edge_type": "private_endpoint", "direction": "ingress"}, "constrained", "vpc_endpoint_only"),
            ("gcp", "public", {"edge_type": "private_endpoint", "target_role": "dependency"}, "constrained", "private_endpoint_egress_only"),
            ("gcp", "internal", {"edge_type": "private_endpoint", "direction": "ingress"}, "constrained", "private_endpoint"),
        ]

        for provider, exposure, raw, expected_decision, expected_kind in cases:
            with self.subTest(provider=provider, exposure=exposure, kind=expected_kind):
                record = evaluate_provider_network_graph(provider, {"network_edges": [{"from": "entry", "to": "api", **raw}]}, exposure)

                self.assertEqual(record["decision"], expected_decision)
                self.assertIn(expected_kind, _blocker_kinds(record))

    def test_service_mesh_authorization_allows_matching_nested_source(self) -> None:
        record = evaluate_provider_network_graph(
            "kubernetes",
            {
                "target": "kubernetes_deployment.api",
                "source_principal": "cluster.local/ns/frontend/sa/frontend",
                "services": [{"id": "kubernetes_service.api"}],
                "authorization_policies": [
                    {
                        "id": "authorizationpolicy.allow_frontend",
                        "action": "ALLOW",
                        "source_principal": "cluster.local/ns/frontend/sa/frontend",
                        "from": [
                            {
                                "source": {
                                    "principals": ["cluster.local/ns/frontend/sa/frontend"],
                                    "namespaces": ["frontend"],
                                }
                            }
                        ],
                    }
                ],
            },
            "internal",
        )

        self.assertEqual(record["decision"], "constrained")
        self.assertEqual(_blocker_kinds(record), {"service_mesh_policy"})

    def test_unconnected_explicit_graph_blocks_with_path_evidence(self) -> None:
        record = evaluate_provider_network_graph(
            "aws",
            {
                "entry": "internet",
                "target": "api",
                "network_edges": [
                    {"from": "internet", "to": "gateway", "edge_type": "api_gateway", "api_key_required": True},
                    {"from": "isolated", "to": "api", "edge_type": "workload"},
                ],
            },
            "public",
        )

        self.assertEqual(record["decision"], "blocked")
        self.assertIn("unconnected_network_graph", _blocker_kinds(record))
        self.assertEqual(record["path"], [])


if __name__ == "__main__":
    unittest.main()
