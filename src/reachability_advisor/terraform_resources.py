"""Terraform resource data model and plan traversal."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .terraform_manifest import classification_for_resource, resource_type_supported

#: Attribute-path fragments whose unknown-after-apply status makes a "private /
#: no observed ingress" verdict unsupportable: the plan simply does not say what
#: the workload will be attached to.
NETWORK_ATTACHMENT_UNKNOWN_HINTS = (
    "security_group",
    "subnet",
    "network_configuration",
    "network_interface",
    "vpc_config",
    "vpc_access",
    "ip_configuration",
    "network",
    "load_balancer",
    "target_group",
)


def network_attachment_unknown_paths(unknown_paths: frozenset[str]) -> list[str]:
    """Return the unknown-after-apply paths that describe a network attachment."""

    return sorted(path for path in unknown_paths if any(hint in path for hint in NETWORK_ATTACHMENT_UNKNOWN_HINTS))


def network_attachment_is_unknown(unknown_paths: frozenset[str]) -> bool:
    """True when the plan marks a network-attachment attribute unknown-after-apply."""

    return bool(network_attachment_unknown_paths(unknown_paths))


@dataclass(frozen=True)
class TerraformResource:
    address: str
    type: str
    name: str
    values: dict[str, Any]
    #: Dotted attribute paths that `terraform show -json` flagged as
    #: unknown-after-apply. Terraform omits such attributes from `after` /
    #: `values` entirely, so without this the analyzer cannot tell "attribute is
    #: absent because it is unset" from "attribute is explicitly unknown" - and
    #: would report the second as an affirmative private/isolated verdict.
    unknown_paths: frozenset[str] = frozenset()

    @property
    def provider(self) -> str:
        return classification_for_resource(self.type, self.values)[0]

    @property
    def category(self) -> str:
        return classification_for_resource(self.type, self.values)[1]

    @property
    def supported(self) -> bool:
        return resource_type_supported(self.type, self.values)

def flatten_unknown_paths(node: Any, prefix: str = "") -> frozenset[str]:
    """Flatten a Terraform ``after_unknown`` mirror into dotted attribute paths.

    List elements collapse onto the parent path (no index) because the analyzer
    reads nested blocks such as ``network_configuration`` as either a dict or a
    single-element list and never keys off the index.
    """

    paths: set[str] = set()

    def walk(value: Any, path: str) -> None:
        if value is True:
            if path:
                paths.add(path)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}" if path else str(key))
        elif isinstance(value, list):
            for item in value:
                walk(item, path)

    walk(node, prefix)
    return frozenset(paths)


def extract_resources(plan: dict[str, Any]) -> list[TerraformResource]:
    resources: dict[str, TerraformResource] = {}

    def add(raw: dict[str, Any], unknown_paths: frozenset[str] = frozenset()) -> None:
        if not isinstance(raw, dict):
            return
        rtype = str(raw.get("type") or "")
        if not rtype:
            return
        address = str(raw.get("address") or f"{rtype}.{raw.get('name') or len(resources)}")
        raw_values = raw.get("values")
        values: dict[str, Any] = raw_values if isinstance(raw_values, dict) else {}
        resources[address] = TerraformResource(
            address=address,
            type=rtype,
            name=str(raw.get("name") or ""),
            values=values,
            unknown_paths=unknown_paths,
        )

    root = plan.get("planned_values", {}).get("root_module", {}) if isinstance(plan.get("planned_values"), dict) else {}

    def walk_module(module: dict[str, Any]) -> None:
        for raw_resource in module.get("resources", []) or []:
            add(raw_resource)
        for child in module.get("child_modules", []) or []:
            if isinstance(child, dict):
                walk_module(child)

    if isinstance(root, dict):
        walk_module(root)

    for change in plan.get("resource_changes", []) or []:
        if not isinstance(change, dict):
            continue
        raw_change = change.get("change") if isinstance(change.get("change"), dict) else None
        after = raw_change.get("after") if raw_change else None
        if isinstance(after, dict):
            # `after_unknown` only ever exists on the resource_changes side, and
            # this pass intentionally overwrites the planned_values entry for the
            # same address, so the unknown payload is attached here.
            unknown_paths = flatten_unknown_paths(raw_change.get("after_unknown")) if raw_change else frozenset()
            add(
                {"address": change.get("address"), "type": change.get("type"), "name": change.get("name"), "values": after},
                unknown_paths,
            )

    return list(resources.values())


__all__ = [
    "NETWORK_ATTACHMENT_UNKNOWN_HINTS",
    "TerraformResource",
    "extract_resources",
    "flatten_unknown_paths",
    "network_attachment_is_unknown",
    "network_attachment_unknown_paths",
]
