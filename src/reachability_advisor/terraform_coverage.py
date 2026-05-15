"""Terraform coverage report construction."""

from __future__ import annotations

from typing import Any

from .models import Artifact
from .terraform_manifest import OPAQUE_MANIFEST_WRAPPER_TYPES, manifest_report
from .terraform_network_adapters import network_adapter_signals


def coverage_report(
    resources: list[Any],
    artifacts: list[Artifact],
    matches: list[dict[str, Any]],
    network_analysis: Any | None = None,
) -> dict[str, Any]:
    total = len(resources)
    classified = sum(1 for resource in resources if resource.supported)
    provider_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    visibility_gaps: list[dict[str, str]] = []
    unsupported: list[dict[str, str]] = []
    resource_rows: list[dict[str, Any]] = []
    for resource in resources:
        provider_counts[resource.provider] = provider_counts.get(resource.provider, 0) + 1
        category_counts[resource.category] = category_counts.get(resource.category, 0) + 1
        row = {
            "address": resource.address,
            "type": resource.type,
            "provider": resource.provider,
            "category": resource.category,
            "supported": resource.supported,
        }
        adapter_signals = network_adapter_signals(resource.type, resource.values)
        if adapter_signals:
            row["network_adapter_signals"] = [signal.to_json() for signal in adapter_signals]
        if network_analysis:
            if resource.address in network_analysis.network_paths_by_address:
                row["network_paths"] = network_analysis.network_paths_by_address[resource.address]
            if resource.address in network_analysis.effective_access_by_address:
                row["effective_access"] = network_analysis.effective_access_by_address[resource.address]
        resource_rows.append(row)
        if not resource.supported:
            gap = {
                "address": resource.address,
                "type": resource.type,
                "provider": resource.provider,
                "gap_type": "unclassified_resource",
                "reason": "resource type is accounted for but not semantically classified",
            }
            unsupported.append(gap)
            visibility_gaps.append(gap)
        elif resource.type in OPAQUE_MANIFEST_WRAPPER_TYPES:
            visibility_gaps.append(
                {
                    "address": resource.address,
                    "type": resource.type,
                    "provider": resource.provider,
                    "gap_type": "opaque_manifest_wrapper",
                    "reason": "resource is a Helm/Kubectl manifest wrapper; rendered Kubernetes child workloads, images, exposure, and RBAC are not inspected",
                }
            )
    matched_artifacts = sorted({row["artifact"] for row in matches})
    unmatched_artifacts = sorted(artifact.name for artifact in artifacts if artifact.name not in matched_artifacts)
    manifest = manifest_report()
    return {
        "schema_version": "2.0",
        "summary": {
            "total_resources": total,
            "accounted_resources": total,
            "resource_accounting_coverage": 1.0,
            "semantically_classified_resources": classified,
            "semantic_classification_coverage": round(classified / total, 4) if total else 1.0,
            "unsupported_or_unclassified_resources": len(unsupported),
            "artifacts_requested": len(artifacts),
            "artifacts_matched": len(matched_artifacts),
            "artifact_match_coverage": round(len(matched_artifacts) / len(artifacts), 4) if artifacts else 1.0,
            "providers_seen": provider_counts,
            "categories_seen": category_counts,
            "network_paths_observed": sum(len(paths) for paths in network_analysis.network_paths_by_address.values()) if network_analysis else 0,
            "effective_access_records": sum(len(records) for records in network_analysis.effective_access_by_address.values()) if network_analysis else 0,
        },
        "manifest": manifest,
        "resource_types_seen": sorted({resource.type for resource in resources}),
        "artifact_matches": matches,
        "matched_artifacts": matched_artifacts,
        "unmatched_artifacts": unmatched_artifacts,
        "resources": resource_rows,
        "visibility_gaps": visibility_gaps,
        "notes": [
            "100% resource accounting means every Terraform resource in the plan is represented in this report.",
            "Semantic coverage is limited to the declared manifest; unclassified resources are visibility gaps.",
            "Opaque manifest wrappers such as Helm releases are classified as Kubernetes support resources but still require rendered manifest evidence for child workloads.",
            "Use source reachability and explicit context files for evidence that Terraform cannot infer from a static plan.",
        ],
    }


def empty_coverage_report() -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "summary": {
            "total_resources": 0,
            "accounted_resources": 0,
            "resource_accounting_coverage": 1.0,
            "semantically_classified_resources": 0,
            "semantic_classification_coverage": 1.0,
            "unsupported_or_unclassified_resources": 0,
            "artifacts_requested": 0,
            "artifacts_matched": 0,
            "artifact_match_coverage": 1.0,
            "providers_seen": {},
            "categories_seen": {},
            "network_paths_observed": 0,
            "effective_access_records": 0,
        },
        "manifest": manifest_report(),
        "resource_types_seen": [],
        "artifact_matches": [],
        "matched_artifacts": [],
        "unmatched_artifacts": [],
        "resources": [],
        "visibility_gaps": [],
        "notes": [],
    }


__all__ = ["coverage_report", "empty_coverage_report"]
