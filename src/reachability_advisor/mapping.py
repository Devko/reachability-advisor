"""Mapping report helpers.

The mapping report is the easiest way to verify the scanner logic in a CI/IDE
setup.  It shows how SBOM artifacts were named, what references were used for
matching, which source roots were supplied, and how Terraform matched those
artifacts to workloads.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .artifacts import artifact_candidates
from .models import SbomDocument


def build_mapping_report(sboms: list[SbomDocument], source_roots: dict[str, Path], terraform_coverage: dict[str, Any]) -> dict[str, Any]:
    matches_by_artifact: dict[str, list[dict[str, Any]]] = {}
    for match in terraform_coverage.get("artifact_matches", []) or []:
        if isinstance(match, dict):
            matches_by_artifact.setdefault(str(match.get("artifact")), []).append(match)
    artifacts = []
    for sbom in sboms:
        root = source_roots.get(sbom.artifact.name)
        candidates = sorted(artifact_candidates(sbom.artifact))
        tf_matches = matches_by_artifact.get(sbom.artifact.name, [])
        artifacts.append(
            {
                "name": sbom.artifact.name,
                "version": sbom.artifact.version,
                "reference": sbom.artifact.reference,
                "sbom_path": str(sbom.path),
                "component_count": len(sbom.components),
                "artifact_candidates": candidates,
                "source_root": str(root) if root else None,
                "source_root_exists": bool(root and root.exists()),
                "terraform_matched": bool(tf_matches),
                "terraform_matches": tf_matches,
                "mapping_warnings": _warnings(candidates, root, tf_matches),
            }
        )
    return {
        "schema_version": "4.0",
        "summary": {
            "artifact_count": len(sboms),
            "artifacts_with_source_roots": sum(1 for sbom in sboms if sbom.artifact.name in source_roots),
            "artifacts_with_terraform_matches": sum(1 for sbom in sboms if sbom.artifact.name in matches_by_artifact),
            "unmatched_terraform_artifacts": terraform_coverage.get("unmatched_artifacts", []),
        },
        "artifacts": artifacts,
        "terraform_coverage_summary": terraform_coverage.get("summary", {}),
    }


def _warnings(candidates: list[str], root: Path | None, tf_matches: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    if not any("/" in candidate or ":" in candidate or "@sha256:" in candidate for candidate in candidates):
        warnings.append("artifact has no strong image/distribution reference; matching may rely on name-only evidence")
    if root is None:
        warnings.append("no source root supplied for source reachability")
    elif not root.exists():
        warnings.append("source root path does not exist")
    if not tf_matches:
        warnings.append("artifact was not matched to a Terraform workload")
    return warnings


__all__ = ["build_mapping_report"]
