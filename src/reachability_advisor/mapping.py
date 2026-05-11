"""Mapping report helpers.

The mapping report is the easiest way to verify the scanner logic in a CI/IDE
setup.  It shows how SBOM artifacts were named, what references were used for
matching, which source roots were supplied, and how Terraform matched those
artifacts to workloads.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .artifacts import artifact_candidates, artifact_identity_proof
from .models import SbomDocument


def build_mapping_report(sboms: list[SbomDocument], source_roots: dict[str, Path], terraform_coverage: dict[str, Any]) -> dict[str, Any]:
    matches_by_artifact: dict[str, list[dict[str, Any]]] = {}
    for match in terraform_coverage.get("artifact_matches", []) or []:
        if isinstance(match, dict):
            matches_by_artifact.setdefault(str(match.get("artifact")), []).append(match)
    artifacts = []
    warning_count = 0
    strong_terraform_matches = 0
    for sbom in sboms:
        root = source_roots.get(sbom.artifact.name)
        candidates = sorted(artifact_candidates(sbom.artifact))
        identity_proof = artifact_identity_proof(sbom.artifact)
        tf_matches = matches_by_artifact.get(sbom.artifact.name, [])
        strong_identity = not identity_proof.get("warnings")
        strong_tf_match = any(float(match.get("match_score") or 0) >= 90 for match in tf_matches)
        if strong_tf_match:
            strong_terraform_matches += 1
        warnings = _warnings(identity_proof, root, tf_matches)
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
                "terraform_matched": bool(tf_matches),
                "strong_terraform_match": strong_tf_match,
                "terraform_matches": tf_matches,
                "mapping_warnings": warnings,
            }
        )
    artifact_count = len(sboms)
    matched_count = sum(1 for sbom in sboms if sbom.artifact.name in matches_by_artifact)
    strong_identity_count = sum(1 for sbom in sboms if not artifact_identity_proof(sbom.artifact).get("warnings"))
    return {
        "schema_version": "4.0",
        "summary": {
            "artifact_count": artifact_count,
            "artifacts_with_source_roots": sum(1 for sbom in sboms if sbom.artifact.name in source_roots),
            "source_root_coverage": round(sum(1 for sbom in sboms if sbom.artifact.name in source_roots) / artifact_count, 4) if artifact_count else 1.0,
            "artifacts_with_terraform_matches": matched_count,
            "artifact_match_coverage": round(matched_count / artifact_count, 4) if artifact_count else 1.0,
            "artifacts_with_strong_terraform_matches": strong_terraform_matches,
            "strong_terraform_match_coverage": round(strong_terraform_matches / artifact_count, 4) if artifact_count else 1.0,
            "artifacts_with_strong_identity": strong_identity_count,
            "strong_artifact_identity_coverage": round(strong_identity_count / artifact_count, 4) if artifact_count else 1.0,
            "artifacts_with_mapping_warnings": sum(1 for artifact in artifacts if artifact["mapping_warnings"]),
            "mapping_warnings_count": warning_count,
            "unmatched_terraform_artifacts": terraform_coverage.get("unmatched_artifacts", []),
        },
        "artifacts": artifacts,
        "terraform_coverage_summary": terraform_coverage.get("summary", {}),
    }


def _warnings(identity_proof: dict[str, Any], root: Path | None, tf_matches: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    warnings.extend(str(item) for item in identity_proof.get("warnings", []) if item)
    if root is None:
        warnings.append("no source root supplied for source reachability")
    elif not root.exists():
        warnings.append("source root path does not exist")
    if not tf_matches:
        warnings.append("artifact was not matched to a Terraform workload")
    return warnings


__all__ = ["build_mapping_report"]
