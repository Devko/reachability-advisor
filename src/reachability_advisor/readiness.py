"""Release evidence readiness reporting."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def release_readiness_report(
    *,
    mapping_report: dict[str, Any],
    source_coverage: dict[str, Any],
    terraform_coverage: dict[str, Any] | None = None,
    kubernetes_coverage: dict[str, Any] | None = None,
    findings: list[Any] | None = None,
) -> dict[str, Any]:
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    artifact_rows: list[dict[str, Any]] = []
    k8s_matches = _artifact_match_names(kubernetes_coverage)
    terraform_summary = (terraform_coverage or {}).get("summary", {}) if isinstance((terraform_coverage or {}).get("summary"), dict) else {}
    kubernetes_summary = (kubernetes_coverage or {}).get("summary", {}) if isinstance((kubernetes_coverage or {}).get("summary"), dict) else {}
    finding_contexts = _contexts_by_artifact(findings or [])

    for artifact in mapping_report.get("artifacts", []) or []:
        if not isinstance(artifact, dict):
            continue
        name = str(artifact.get("name") or "")
        tf_match = bool(artifact.get("terraform_matched"))
        strong_tf_match = bool(artifact.get("strong_terraform_match"))
        k8s_match = name in k8s_matches
        contexts = finding_contexts.get(name, [])
        missing: list[str] = []
        status_warnings: list[str] = []
        if not artifact.get("strong_artifact_identity"):
            missing.extend(_identity_gaps(artifact))
        if not artifact.get("sbom_path"):
            missing.append("SBOM path")
        if not tf_match and not k8s_match:
            missing.append("deployment workload match")
        elif tf_match and not strong_tf_match and not k8s_match:
            missing.append("strong deployment workload match")
        if contexts and not _has_network_evidence(contexts):
            missing.append("network path evidence")
        elif contexts and _only_low_confidence_network(contexts):
            status_warnings.append("network path confidence")
        if contexts and not _has_identity_evidence(contexts):
            missing.append("identity/effective-access evidence")
        elif contexts and _only_low_confidence_identity(contexts):
            status_warnings.append("identity/effective-access confidence")
        mapping_warnings = [str(item) for item in artifact.get("mapping_warnings", []) if str(item)] if isinstance(artifact.get("mapping_warnings"), list) else []
        artifact_warnings = [*status_warnings, *mapping_warnings]
        artifact_rows.append(
            {
                "artifact": name,
                "terraform_matched": tf_match,
                "strong_terraform_match": strong_tf_match,
                "kubernetes_matched": k8s_match,
                "artifact_identity_strength": _identity_strength(artifact),
                "missing": missing,
                "warnings": artifact_warnings,
            }
        )
        for item in missing:
            severity = "warning" if item == "identity/effective-access evidence" else "blocker"
            target = warnings if severity == "warning" else blockers
            target.append({"artifact": name, "kind": _message_kind(item), "message": f"{name}: missing {item}"})
        for item in status_warnings:
            warnings.append({"artifact": name, "kind": _message_kind(item), "message": f"{name}: {item}"})

    source_summary = source_coverage.get("summary", {}) if isinstance(source_coverage.get("summary"), dict) else {}
    raw_critical_external = source_summary.get("critical_external_evidence_coverage")
    critical_external = float(raw_critical_external) if raw_critical_external is not None else 1.0
    if critical_external < 1.0:
        blockers.append(
            {
                "kind": "critical_source_coverage",
                "message": f"critical external source evidence coverage is {critical_external:.4f}; expected 1.0",
            }
        )
    raw_query_family = source_summary.get("critical_query_family_coverage")
    critical_query_family = float(raw_query_family) if raw_query_family is not None else 1.0
    if critical_query_family < 1.0:
        blockers.append(
            {
                "kind": "critical_source_query_family_coverage",
                "message": f"critical source query-family coverage is {critical_query_family:.4f}; expected 1.0",
            }
        )
    raw_proven_query_family = source_summary.get("critical_proven_query_family_coverage")
    critical_proven_query_family = float(raw_proven_query_family) if raw_proven_query_family is not None else critical_query_family
    if critical_proven_query_family < 1.0:
        blockers.append(
            {
                "kind": "critical_source_proven_query_family_coverage",
                "message": f"critical proven query-family coverage is {critical_proven_query_family:.4f}; expected 1.0",
            }
        )
    security_summary = {}
    security_report = source_coverage.get("security_evidence")
    if isinstance(security_report, dict) and isinstance(security_report.get("summary"), dict):
        security_summary = security_report["summary"]
    raw_security_profile = security_summary.get("critical_profile_coverage")
    if raw_security_profile is not None:
        critical_security_profile = float(raw_security_profile)
        if critical_security_profile < 1.0:
            blockers.append(
                {
                    "kind": "critical_security_profile_coverage",
                    "message": f"critical SAST/DAST profile coverage is {critical_security_profile:.4f}; expected 1.0",
                }
            )

    for gap in _visibility_gaps(terraform_coverage):
        kind = str(gap.get("type") or gap.get("reason") or "visibility_gap")
        if "opaque" in kind or "module" in kind or "helm" in kind:
            blockers.append({"kind": "unrendered_or_opaque_iac", "message": f"Terraform visibility gap requires rendered evidence: {gap}"})
    for gap in _visibility_gaps(kubernetes_coverage):
        kind = str(gap.get("type") or gap.get("reason") or "visibility_gap")
        if "opaque" in kind or "helm" in kind or "template" in kind:
            blockers.append({"kind": "unrendered_or_opaque_kubernetes", "message": f"Kubernetes visibility gap requires rendered evidence: {gap}"})

    status = "blocked" if blockers else "warning" if warnings else "ready"
    return {
        "schema_version": "1.0",
        "status": status,
        "summary": {
            "blockers": len(blockers),
            "warnings": len(warnings),
            "artifacts": len(artifact_rows),
            "critical_external_evidence_coverage": critical_external,
            "critical_query_family_coverage": critical_query_family,
            "critical_proven_query_family_coverage": critical_proven_query_family,
            "critical_security_profile_coverage": security_summary.get("critical_profile_coverage"),
            "terraform_resources": terraform_summary.get("total_resources", 0),
            "kubernetes_resources": kubernetes_summary.get("total_resources", 0),
            "artifacts_missing_release_identity": sum(1 for artifact in artifact_rows if "image digest or exact image reference" in artifact["missing"]),
            "artifacts_missing_workload_match": sum(1 for artifact in artifact_rows if _has_missing(artifact, "deployment workload match", "strong deployment workload match")),
            "artifacts_missing_network_path": sum(1 for artifact in artifact_rows if "network path evidence" in artifact["missing"]),
            "artifacts_missing_identity_path": sum(1 for artifact in artifact_rows if "identity/effective-access evidence" in artifact["missing"]),
        },
        "blockers": blockers,
        "warnings": warnings,
        "artifacts": artifact_rows,
    }


def load_release_readiness_inputs(
    *,
    mapping: str,
    source_coverage: str,
    terraform_coverage: str | None = None,
    kubernetes_coverage: str | None = None,
    findings: str | None = None,
) -> dict[str, Any]:
    return release_readiness_report(
        mapping_report=_load_json_object(mapping),
        source_coverage=_load_json_object(source_coverage),
        terraform_coverage=_load_json_object(terraform_coverage) if terraform_coverage else None,
        kubernetes_coverage=_load_json_object(kubernetes_coverage) if kubernetes_coverage else None,
        findings=_load_findings(findings) if findings else None,
    )


def _load_json_object(path: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def _load_findings(path: str) -> list[dict[str, Any]]:
    data = _load_json_object(path)
    findings = data.get("findings")
    return [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []


def _artifact_match_names(coverage: dict[str, Any] | None) -> set[str]:
    names: set[str] = set()
    for match in (coverage or {}).get("artifact_matches", []) or []:
        if isinstance(match, dict) and match.get("artifact"):
            names.add(str(match.get("artifact")))
    return names


def _identity_strength(artifact: dict[str, Any]) -> str:
    proof = artifact.get("artifact_identity")
    if not isinstance(proof, dict):
        return "unknown"
    return str(proof.get("strongest_strength") or "unknown")


def _identity_gaps(artifact: dict[str, Any]) -> list[str]:
    proof = artifact.get("artifact_identity")
    if not isinstance(proof, dict):
        return ["image digest or exact image reference"]
    strengths = {
        str(candidate.get("strength") or "")
        for candidate in proof.get("candidates", [])
        if isinstance(candidate, dict)
    }
    if strengths & {"digest", "image_reference"}:
        return []
    return ["image digest or exact image reference"]


def _visibility_gaps(coverage: dict[str, Any] | None) -> list[dict[str, Any]]:
    gaps = (coverage or {}).get("visibility_gaps", [])
    return [gap for gap in gaps if isinstance(gap, dict)] if isinstance(gaps, list) else []


def _has_network_evidence(contexts: list[dict[str, Any]]) -> bool:
    return any(context.get("network_paths") or context.get("effective_exposure") for context in contexts)


def _has_identity_evidence(contexts: list[dict[str, Any]]) -> bool:
    return any(context.get("effective_access") or context.get("iam_capabilities") for context in contexts)


def _only_low_confidence_network(contexts: list[dict[str, Any]]) -> bool:
    paths: list[dict[str, Any]] = []
    for context in contexts:
        for path in context.get("network_paths", []) if isinstance(context.get("network_paths"), list) else []:
            if isinstance(path, dict):
                paths.append(path)
        for record in context.get("effective_exposure", []) if isinstance(context.get("effective_exposure"), list) else []:
            if isinstance(record, dict) and isinstance(record.get("network"), dict):
                paths.append(dict(record["network"]))
    return bool(paths) and all(str(path.get("confidence") or "").lower() == "low" for path in paths)


def _only_low_confidence_identity(contexts: list[dict[str, Any]]) -> bool:
    records: list[dict[str, Any]] = []
    for context in contexts:
        for key in ("effective_access", "iam_capabilities"):
            for record in context.get(key, []) if isinstance(context.get(key), list) else []:
                if isinstance(record, dict):
                    records.append(record)
    return bool(records) and all(str(record.get("confidence") or "").lower() == "low" for record in records)


def _message_kind(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "release_evidence"


def _has_missing(artifact: dict[str, Any], *items: str) -> bool:
    missing = artifact.get("missing")
    return isinstance(missing, list) and any(item in missing for item in items)


def _contexts_by_artifact(findings: list[Any]) -> dict[str, list[dict[str, Any]]]:
    contexts: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        context: dict[str, Any]
        if isinstance(finding, dict):
            raw_artifact = finding.get("artifact")
            artifact = str(raw_artifact.get("name") if isinstance(raw_artifact, dict) else "")
            raw_context = finding.get("context")
            context = dict(raw_context) if isinstance(raw_context, dict) else {}
        else:
            artifact = str(getattr(getattr(finding, "artifact", None), "name", "") or "")
            context_obj = getattr(finding, "context", None)
            context = {
                "network_paths": getattr(context_obj, "network_paths", []),
                "effective_exposure": getattr(context_obj, "effective_exposure", []),
                "effective_access": getattr(context_obj, "effective_access", []),
                "iam_capabilities": getattr(context_obj, "iam_capabilities", []),
            }
        if artifact:
            contexts.setdefault(artifact, []).append(context)
    return contexts


__all__ = ["load_release_readiness_inputs", "release_readiness_report"]
