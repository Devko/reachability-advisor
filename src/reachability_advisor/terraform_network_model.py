"""Terraform network graph model primitives."""

from __future__ import annotations

from dataclasses import dataclass, field

NETWORK_BRIDGE_RESOURCE_TYPES = {
    "aws_vpc_peering_connection",
    "aws_customer_gateway",
    "aws_vpn_gateway",
    "aws_vpn_connection",
    "aws_ec2_transit_gateway",
    "aws_ec2_transit_gateway_vpc_attachment",
    "aws_ec2_transit_gateway_peering_attachment",
    "azurerm_virtual_network_peering",
    "azurerm_virtual_network_gateway",
    "azurerm_virtual_network_gateway_connection",
    "azurerm_express_route_circuit",
    "azurerm_express_route_connection",
    "google_compute_network_peering",
    "google_compute_shared_vpc_service_project",
    "google_compute_vpn_gateway",
    "google_compute_ha_vpn_gateway",
    "google_compute_vpn_tunnel",
    "google_compute_interconnect_attachment",
    "google_compute_router_peer",
}
PRIVATE_NETWORK_RESOURCE_TYPES = {
    "aws_vpc",
    "aws_subnet",
    "aws_network_interface",
    "azurerm_virtual_network",
    "azurerm_subnet",
    "azurerm_network_interface",
    "azurerm_private_endpoint",
    "google_compute_network",
    "google_compute_subnetwork",
    "google_vpc_access_connector",
}


@dataclass(frozen=True)
class NetworkPathEdge:
    target: str
    reason: str
    exposure_cap: str | None = None
    hidden: bool = False


@dataclass
class NetworkPathAnalysis:
    exposure_by_address: dict[str, str] = field(default_factory=dict)
    evidence_by_address: dict[str, list[str]] = field(default_factory=dict)
    privilege_by_address: dict[str, str] = field(default_factory=dict)
    privilege_evidence_by_address: dict[str, list[str]] = field(default_factory=dict)
    iam_impacts_by_address: dict[str, set[str]] = field(default_factory=dict)
    iam_target_evidence_by_address: dict[str, list[str]] = field(default_factory=dict)


__all__ = [
    "NETWORK_BRIDGE_RESOURCE_TYPES",
    "PRIVATE_NETWORK_RESOURCE_TYPES",
    "NetworkPathAnalysis",
    "NetworkPathEdge",
]
