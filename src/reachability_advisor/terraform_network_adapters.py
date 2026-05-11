"""Provider-specific network adapter hints for Terraform resources."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .terraform_exposure import network_source_exposure
from .terraform_values import listify, value_reference_candidates


@dataclass(frozen=True)
class NetworkAdapterSignal:
    kind: str
    exposure: str
    refs: tuple[str, ...] = ()
    reason: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "exposure": self.exposure,
            "refs": list(self.refs),
            "reason": self.reason,
        }


def network_adapter_signals(resource_type: str, values: dict[str, Any]) -> tuple[NetworkAdapterSignal, ...]:
    """Return graph hints for provider resources that are not workloads.

    These signals are intentionally not exposure verdicts by themselves. The
    Terraform graph has to connect the referenced route table, subnet, tag, or
    private endpoint to a workload before they influence a finding.
    """

    if resource_type == "aws_route":
        return _aws_route_signals(values)
    if resource_type in {"azurerm_route", "google_compute_route"}:
        return _provider_route_signals(resource_type, values)
    if resource_type == "aws_route_table_association":
        return _aws_route_table_association_signals(values)
    if resource_type == "azurerm_subnet_route_table_association":
        return _route_table_association_signals(values)
    if resource_type in {"azurerm_private_endpoint", "google_vpc_access_connector"}:
        return _private_endpoint_signals(resource_type, values)
    if resource_type == "google_compute_firewall":
        return _gcp_firewall_signals(values)
    if resource_type in {"azurerm_network_security_rule", "azurerm_network_security_group"}:
        return _azure_nsg_signals(resource_type, values)
    return ()


def _aws_route_signals(values: dict[str, Any]) -> tuple[NetworkAdapterSignal, ...]:
    route_refs = _refs(values, "route_table_id", "route_table_ids", "route_table", "route_table_name")
    target_text = " ".join(
        str(values.get(key) or "")
        for key in (
            "gateway_id",
            "nat_gateway_id",
            "transit_gateway_id",
            "vpc_peering_connection_id",
            "network_interface_id",
            "vpc_endpoint_id",
            "egress_only_gateway_id",
        )
    ).lower()
    if not route_refs:
        return ()
    if any(token in target_text for token in ("tgw", "transit", "peering", "vpn", "nat", "vpce", "endpoint", "eni-")):
        return (NetworkAdapterSignal("private_route_bridge", "internal", route_refs, "private route table bridge"),)
    if "igw" in target_text or "internet" in target_text:
        return (NetworkAdapterSignal("internet_route", "public", route_refs, "route table has an internet gateway route; workload exposure still requires ingress evidence"),)
    return ()


def _aws_route_table_association_signals(values: dict[str, Any]) -> tuple[NetworkAdapterSignal, ...]:
    refs = _refs(values, "route_table_id", "route_table_ids", "route_table", "route_table_name")
    refs += _refs(values, "subnet_id", "subnet_ids", "subnet")
    return (NetworkAdapterSignal("route_table_association", "internal", refs, "route table associated to subnet"),) if refs else ()


def _provider_route_signals(resource_type: str, values: dict[str, Any]) -> tuple[NetworkAdapterSignal, ...]:
    route_refs = _refs(values, "route_table_id", "route_table_ids", "route_table_name", "network", "network_id")
    target_text = " ".join(
        str(values.get(key) or "")
        for key in (
            "next_hop_type",
            "next_hop_in_ip_address",
            "next_hop_gateway",
            "next_hop_instance",
            "next_hop_vpn_tunnel",
            "next_hop_ilb",
            "next_hop_network",
        )
    ).lower()
    if not route_refs:
        return ()
    if any(token in target_text for token in ("virtualnetworkgateway", "virtual_network_gateway", "vpn", "interconnect", "peering", "ilb", "appliance", "instance")):
        return (NetworkAdapterSignal("private_route_bridge", "internal", route_refs, f"{resource_type} private route bridge"),)
    if "internet" in target_text or "defaultinternetgateway" in target_text:
        return (NetworkAdapterSignal("internet_route", "public", route_refs, f"{resource_type} internet route; workload exposure still requires ingress evidence"),)
    return ()


def _route_table_association_signals(values: dict[str, Any]) -> tuple[NetworkAdapterSignal, ...]:
    refs = _refs(values, "route_table_id", "route_table_ids", "route_table_name")
    refs += _refs(values, "subnet_id", "subnet_ids", "subnet")
    return (NetworkAdapterSignal("route_table_association", "internal", refs, "route table associated to subnet"),) if refs else ()


def _private_endpoint_signals(resource_type: str, values: dict[str, Any]) -> tuple[NetworkAdapterSignal, ...]:
    refs = _refs(values, "subnet_id", "subnet_ids", "subnetwork", "subnetwork_id", "network", "network_id")
    reason = "VPC access connector attaches private network" if resource_type == "google_vpc_access_connector" else f"{resource_type} attaches private network endpoint"
    return (NetworkAdapterSignal("private_endpoint", "internal", refs, reason),)


def _gcp_firewall_signals(values: dict[str, Any]) -> tuple[NetworkAdapterSignal, ...]:
    if values.get("disabled") is True:
        return (NetworkAdapterSignal("disabled_firewall", "none", (), "disabled firewall rule ignored for exposure"),)
    if str(values.get("direction") or "INGRESS").upper() == "EGRESS":
        return (NetworkAdapterSignal("egress_firewall", "none", (), "egress firewall rule ignored for inbound exposure"),)
    exposure = "unknown"
    for source in listify(values.get("source_ranges")) + listify(values.get("source_tags")) + listify(values.get("source_service_accounts")):
        exposure = _max_exposure(exposure, network_source_exposure(source))
    refs = _refs(values, "target_tags", "target_service_accounts", "target_service_account")
    priority = values.get("priority")
    reason = "GCP ingress firewall target"
    if priority is not None:
        reason += f" priority={priority}"
    return (NetworkAdapterSignal("firewall_target", exposure, refs, reason),) if refs and exposure != "unknown" else ()


def _azure_nsg_signals(resource_type: str, values: dict[str, Any]) -> tuple[NetworkAdapterSignal, ...]:
    rules = values.get("security_rule") if resource_type == "azurerm_network_security_group" else [values]
    signals: list[NetworkAdapterSignal] = []
    for rule in listify(rules):
        if not isinstance(rule, dict):
            continue
        if str(rule.get("direction") or "Inbound").lower() != "inbound":
            continue
        if str(rule.get("access") or "Allow").lower() == "deny":
            signals.append(NetworkAdapterSignal("deny_inbound", "none", (), "Azure NSG deny rule is not treated as exposure"))
            continue
        exposure = "unknown"
        for key in ("source_address_prefix", "source_address_prefixes", "source_application_security_group_ids"):
            for source in listify(rule.get(key)):
                exposure = _max_exposure(exposure, network_source_exposure(source))
        if exposure != "unknown":
            signals.append(NetworkAdapterSignal("allow_inbound", exposure, (), "Azure NSG inbound allow rule"))
    return tuple(signals)


def _refs(values: dict[str, Any], *keys: str) -> tuple[str, ...]:
    refs: set[str] = set()
    for key in keys:
        refs.update(value_reference_candidates(values.get(key)))
    return tuple(sorted(refs))


def _max_exposure(left: str, right: str) -> str:
    ranks = {"unknown": 0, "none": 1, "private": 2, "internal": 3, "external": 4, "public": 5}
    return left if ranks.get(left, 0) >= ranks.get(right, 0) else right


__all__ = ["NetworkAdapterSignal", "network_adapter_signals"]
