"""Shared exposure ordering and network source classification helpers."""

from __future__ import annotations

import ipaddress
from typing import Any

PUBLIC_TOKEN_VALUES = {"0.0.0.0/0", "::/0", "*", "internet", "all", "allusers", "allauthenticatedusers"}
INTERNAL_TOKEN_VALUES = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "virtualnetwork",
    "vnet",
    "vpc",
    "private",
    "privatelink",
    "azureloadbalancer",
    "vpn",
    "onprem",
    "on-prem",
}


def exposure_rank(value: str) -> int:
    return {"unknown": 0, "none": 1, "private": 2, "internal": 3, "external": 4, "public": 5}.get(value, 0)


def max_exposure(left: str, right: str) -> str:
    return left if exposure_rank(left) >= exposure_rank(right) else right


def cap_exposure(value: str, cap: str | None) -> str:
    if not cap or exposure_rank(value) <= exposure_rank(cap):
        return value
    return cap


def network_source_exposure(value: Any) -> str:
    if value is None:
        return "unknown"
    text = str(value).strip().strip('"').strip("'").lower()
    if not text:
        return "unknown"
    if text in PUBLIC_TOKEN_VALUES:
        return "public"
    if text in INTERNAL_TOKEN_VALUES or text.startswith("sg-"):
        return "internal"
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return "unknown"
    if network.version in {4, 6} and network.is_global:
        return "external"
    return "internal"


__all__ = [
    "INTERNAL_TOKEN_VALUES",
    "PUBLIC_TOKEN_VALUES",
    "cap_exposure",
    "exposure_rank",
    "max_exposure",
    "network_source_exposure",
]
