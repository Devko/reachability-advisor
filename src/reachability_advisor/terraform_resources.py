"""Terraform resource data model and plan traversal."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .terraform_manifest import classification_for_resource, resource_type_supported


@dataclass(frozen=True)
class TerraformResource:
    address: str
    type: str
    name: str
    values: dict[str, Any]

    @property
    def provider(self) -> str:
        return classification_for_resource(self.type, self.values)[0]

    @property
    def category(self) -> str:
        return classification_for_resource(self.type, self.values)[1]

    @property
    def supported(self) -> bool:
        return resource_type_supported(self.type, self.values)

def extract_resources(plan: dict[str, Any]) -> list[TerraformResource]:
    resources: dict[str, TerraformResource] = {}

    def add(raw: dict[str, Any]) -> None:
        if not isinstance(raw, dict):
            return
        rtype = str(raw.get("type") or "")
        if not rtype:
            return
        address = str(raw.get("address") or f"{rtype}.{raw.get('name') or len(resources)}")
        raw_values = raw.get("values")
        values: dict[str, Any] = raw_values if isinstance(raw_values, dict) else {}
        resources[address] = TerraformResource(address=address, type=rtype, name=str(raw.get("name") or ""), values=values)

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
        after = change.get("change", {}).get("after") if isinstance(change.get("change"), dict) else None
        if isinstance(after, dict):
            add({"address": change.get("address"), "type": change.get("type"), "name": change.get("name"), "values": after})

    return list(resources.values())


__all__ = ["TerraformResource", "extract_resources"]
