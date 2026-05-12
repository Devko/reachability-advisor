"""Mapping report helpers.

The mapping report is the easiest way to verify the scanner logic in a CI/IDE
setup. It shows how SBOM artifacts were named, what references were used for
matching, which source roots were supplied, and how rendered deployment evidence
from Terraform plans and Kubernetes manifests matched those artifacts to
workloads.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .artifacts import artifact_candidates, artifact_identity_proof
from .models import SbomDocument


def build_mapping_report(
    sboms: list[SbomDocument],
    source_roots: dict[str, Path],
    terraform_coverage: dict[str, Any],
    kubernetes_coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    terraform_matches_by_artifact = _matches_by_artifact(terraform_coverage)
    kubernetes_matches_by_artifact = _matches_by_artifact(kubernetes_coverage or {})
    deployment_matches_by_artifact: dict[str, list[dict[str, Any]]] = {}
    for artifact_name, matches in terraform_matches_by_artifact.items():
        deployment_matches_by_artifact.setdefault(artifact_name, []).extend(matches)
    for artifact_name, matches in kubernetes_matches_by_artifact.items():
        deployment_matches_by_artifact.setdefault(artifact_name, []).extend(matches)
    artifacts = []
    warning_count = 0
    strong_terraform_matches = 0
    strong_kubernetes_matches = 0
    strong_deployment_matches = 0
    for sbom in sboms:
        root = source_roots.get(sbom.artifact.name)
        candidates = sorted(artifact_candidates(sbom.artifact))
        identity_proof = artifact_identity_proof(sbom.artifact)
        tf_matches = terraform_matches_by_artifact.get(sbom.artifact.name, [])
        k8s_matches = kubernetes_matches_by_artifact.get(sbom.artifact.name, [])
        deployment_matches = deployment_matches_by_artifact.get(sbom.artifact.name, [])
        strong_identity = not identity_proof.get("warnings")
        strong_tf_match = any(float(match.get("match_score") or 0) >= 90 for match in tf_matches)
        strong_k8s_match = any(float(match.get("match_score") or 0) >= 90 for match in k8s_matches)
        strong_deployment_match = any(float(match.get("match_score") or 0) >= 90 for match in deployment_matches)
        if strong_tf_match:
            strong_terraform_matches += 1
        if strong_k8s_match:
            strong_kubernetes_matches += 1
        if strong_deployment_match:
            strong_deployment_matches += 1
        warnings = _warnings(identity_proof, root, deployment_matches)
        warning_count += len(warnings)
        artifacts.append(
            {
                "name": sbom.artifact.name,
                "version": sbom.artifact.version,
                "reference": sbom.artifact.reference,
                "sbom_path": str(sbom.path),
                "component_count": len(sbom.components),
                "artifact_candidates": candidates,
                "artifact_identity": identity_proof,
                "strong_artifact_identity": strong_identity,
                "source_root": str(root) if root else None,
                "source_root_exists": bool(root and root.exists()),
                "deployment_matched": bool(deployment_matches),
                "strong_deployment_match": strong_deployment_match,
                "deployment_matches": deployment_matches,
                "terraform_matched": bool(tf_matches),
                "strong_terraform_match": strong_tf_match,
                "terraform_matches": tf_matches,
                "kubernetes_matched": bool(k8s_matches),
                "strong_kubernetes_match": strong_k8s_match,
                "kubernetes_matches": k8s_matches,
                "mapping_warnings": warnings,
            }
        )
    artifact_count = len(sboms)
    terraform_matched_count = sum(1 for sbom in sboms if sbom.artifact.name in terraform_matches_by_artifact)
    kubernetes_matched_count = sum(1 for sbom in sboms if sbom.artifact.name in kubernetes_matches_by_artifact)
    deployment_matched_count = sum(1 for sbom in sboms if sbom.artifact.name in deployment_matches_by_artifact)
    strong_identity_count = sum(1 for sbom in sboms if not artifact_identity_proof(sbom.artifact).get("warnings"))
    return {
        "schema_version": "4.0",
        "summary": {
            "artifact_count": artifact_count,
            "artifacts_with_source_roots": sum(1 for sbom in sboms if sbom.artifact.name in source_roots),
            "source_root_coverage": round(sum(1 for sbom in sboms if sbom.artifact.name in source_roots) / artifact_count, 4) if artifact_count else 1.0,
            "artifacts_with_deployment_matches": deployment_matched_count,
            "artifact_match_coverage": round(deployment_matched_count / artifact_count, 4) if artifact_count else 1.0,
            "deployment_match_coverage": round(deployment_matched_count / artifact_count, 4) if artifact_count else 1.0,
            "artifacts_with_terraform_matches": terraform_matched_count,
            "terraform_match_coverage": round(terraform_matched_count / artifact_count, 4) if artifact_count else 1.0,
            "artifacts_with_kubernetes_matches": kubernetes_matched_count,
            "kubernetes_match_coverage": round(kubernetes_matched_count / artifact_count, 4) if artifact_count else 1.0,
            "artifacts_with_strong_deployment_matches": strong_deployment_matches,
            "strong_deployment_match_coverage": round(strong_deployment_matches / artifact_count, 4) if artifact_count else 1.0,
            "artifacts_with_strong_terraform_matches": strong_terraform_matches,
            "strong_terraform_match_coverage": round(strong_terraform_matches / artifact_count, 4) if artifact_count else 1.0,
            "artifacts_with_strong_kubernetes_matches": strong_kubernetes_matches,
            "strong_kubernetes_match_coverage": round(strong_kubernetes_matches / artifact_count, 4) if artifact_count else 1.0,
            "artifacts_with_strong_identity": strong_identity_count,
            "strong_artifact_identity_coverage": round(strong_identity_count / artifact_count, 4) if artifact_count else 1.0,
            "artifacts_with_mapping_warnings": sum(1 for artifact in artifacts if artifact["mapping_warnings"]),
            "mapping_warnings_count": warning_count,
            "unmatched_deployment_artifacts": [sbom.artifact.name for sbom in sboms if sbom.artifact.name not in deployment_matches_by_artifact],
            "unmatched_terraform_artifacts": terraform_coverage.get("unmatched_artifacts", []),
            "unmatched_kubernetes_artifacts": (kubernetes_coverage or {}).get("unmatched_artifacts", []),
        },
        "artifacts": artifacts,
        "terraform_coverage_summary": terraform_coverage.get("summary", {}),
        "kubernetes_coverage_summary": (kubernetes_coverage or {}).get("summary", {}),
    }


def _matches_by_artifact(coverage: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    matches_by_artifact: dict[str, list[dict[str, Any]]] = {}
    for match in coverage.get("artifact_matches", []) or []:
        if isinstance(match, dict) and match.get("artifact"):
            matches_by_artifact.setdefault(str(match.get("artifact")), []).append(match)
    return matches_by_artifact


def _warnings(identity_proof: dict[str, Any], root: Path | None, deployment_matches: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    warnings.extend(str(item) for item in identity_proof.get("warnings", []) if item)
    if root is None:
        warnings.append("no source root supplied for source reachability")
    elif not root.exists():
        warnings.append("source root path does not exist")
    if not deployment_matches:
        warnings.append("artifact was not matched to a Terraform or Kubernetes workload")
    return warnings


__all__ = ["build_mapping_report"]
