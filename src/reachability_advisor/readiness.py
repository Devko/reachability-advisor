"""Release evidence readiness reporting."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .input_limits import read_text_limited


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
                "next_steps": [_artifact_next_step(item) for item in [*missing, *artifact_warnings]],
            }
        )
        for item in missing:
            severity = "warning" if item == "identity/effective-access evidence" else "blocker"
            target = warnings if severity == "warning" else blockers
            target.append(_artifact_message(name, item, severity=severity))
        for item in status_warnings:
            warnings.append(_artifact_message(name, item, severity="warning"))

    source_summary = source_coverage.get("summary", {}) if isinstance(source_coverage.get("summary"), dict) else {}
    raw_critical_external = source_summary.get("critical_external_evidence_coverage")
    critical_external = float(raw_critical_external) if raw_critical_external is not None else 1.0
    if critical_external < 1.0:
        blockers.append(
            {
                "kind": "critical_source_coverage",
                "message": (
                    "Critical findings are missing external source analyzer evidence. "
                    f"Coverage is {critical_external:.4f}; release gates require 1.0000."
                ),
                "impact": "A release gate cannot tell whether the critical package is actually imported, called, or reachable from request-controlled code.",
                "next_step": "Run Semgrep, CodeQL/SARIF, or govulncheck for the source tree and pass the output with --source-evidence-in, --sast-in, or --security-evidence-in.",
            }
        )
    raw_query_family = source_summary.get("critical_query_family_coverage")
    critical_query_family = float(raw_query_family) if raw_query_family is not None else 1.0
    if critical_query_family < 1.0:
        blockers.append(
            {
                "kind": "critical_source_query_family_coverage",
                "message": (
                    "Critical findings are missing source evidence from the required maintained query family. "
                    f"Coverage is {critical_query_family:.4f}; release gates require 1.0000."
                ),
                "impact": "Generic scanner evidence is not enough to prove the maintained source rule family ran for this package class.",
                "next_step": "Generate the source evidence pack for this language and import evidence that includes query_family or query_families metadata.",
            }
        )
    raw_proven_query_family = source_summary.get("critical_proven_query_family_coverage")
    critical_proven_query_family = float(raw_proven_query_family) if raw_proven_query_family is not None else critical_query_family
    if critical_proven_query_family < 1.0:
        blockers.append(
            {
                "kind": "critical_source_proven_query_family_coverage",
                "message": (
                    "Critical findings are missing proven maintained query-family evidence. "
                    f"Coverage is {critical_proven_query_family:.4f}; release gates require 1.0000."
                ),
                "impact": "The release gate cannot confirm that a maintained rule set covered the package family associated with the critical finding.",
                "next_step": "Use reachability-advisor source-evidence-pack or an equivalent maintained Semgrep/CodeQL/govulncheck profile, then re-import the evidence.",
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
                    "message": (
                        "Critical SAST/DAST records are missing a maintained security profile. "
                        f"Coverage is {critical_security_profile:.4f}; release gates require 1.0000."
                    ),
                    "impact": "The gate cannot distinguish an ad hoc scanner record from a vetted release-gate profile.",
                    "next_step": "Run a maintained security evidence profile or include profile metadata when importing SAST/DAST evidence.",
                }
            )

    for gap in _visibility_gaps(terraform_coverage):
        kind = str(gap.get("type") or gap.get("reason") or "visibility_gap")
        if "opaque" in kind or "module" in kind or "helm" in kind:
            blockers.append(_rendering_gap_message("Terraform", gap, message_kind="unrendered_or_opaque_iac"))
    for gap in _visibility_gaps(kubernetes_coverage):
        kind = str(gap.get("type") or gap.get("reason") or "visibility_gap")
        if "opaque" in kind or "helm" in kind or "template" in kind:
            blockers.append(_rendering_gap_message("Kubernetes", gap, message_kind="unrendered_or_opaque_kubernetes"))

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
    data = json.loads(read_text_limited(Path(path), "readiness"))
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


def _artifact_message(artifact: str, item: str, *, severity: str) -> dict[str, Any]:
    kind = _message_kind(item)
    next_step = _artifact_next_step(item)
    impact = _artifact_impact(item)
    message = _artifact_message_text(artifact, item, severity=severity)
    return {
        "artifact": artifact,
        "kind": kind,
        "message": message,
        "impact": impact,
        "next_step": next_step,
    }


def _artifact_message_text(artifact: str, item: str, *, severity: str) -> str:
    label = artifact or "artifact"
    if item == "image digest or exact image reference":
        return f"{label}: artifact identity is too weak for a release gate. Add an exact deployed image reference or image digest."
    if item == "SBOM path":
        return f"{label}: the release gate cannot trace this artifact back to the SBOM file that was scanned."
    if item == "deployment workload match":
        return f"{label}: no rendered deployment workload was matched to this SBOM artifact."
    if item == "strong deployment workload match":
        return f"{label}: deployment matching used weak evidence. Provide image or digest metadata so the workload match is release-grade."
    if item == "network path evidence":
        return f"{label}: no network path evidence was found for the matched workload."
    if item == "network path confidence":
        return f"{label}: only low-confidence network path evidence was found; review before using this as release evidence."
    if item == "identity/effective-access evidence":
        return f"{label}: no workload identity or effective-access evidence was found."
    if item == "identity/effective-access confidence":
        return f"{label}: only low-confidence identity or effective-access evidence was found; review before using this as release evidence."
    prefix = "warning" if severity == "warning" else "blocker"
    return f"{label}: release evidence {prefix}: {item}"


def _artifact_impact(item: str) -> str:
    if item == "image digest or exact image reference":
        return "Findings may be attached by artifact name instead of the exact release image, which is not precise enough for a release gate."
    if item == "SBOM path":
        return "Auditors and CI cannot verify which SBOM produced the finding set."
    if item in {"deployment workload match", "strong deployment workload match"}:
        return "The gate cannot prove that the vulnerable SBOM artifact is the workload being deployed."
    if item in {"network path evidence", "network path confidence"}:
        return "The gate cannot confidently decide whether an attacker or internal actor can reach the workload."
    if item in {"identity/effective-access evidence", "identity/effective-access confidence"}:
        return "The gate cannot confidently estimate blast radius such as secret access, data access, or control-plane privileges."
    return "The release evidence is incomplete or ambiguous."


def _artifact_next_step(item: str) -> str:
    if item == "image digest or exact image reference":
        return "Add image, digest, registry_ref, or terraform_module_output_image to --artifact-manifest, or include equivalent CycloneDX artifact metadata."
    if item == "SBOM path":
        return "Set sbom_path in --artifact-manifest so the release artifact points to the SBOM used by this scan."
    if item == "deployment workload match":
        return "Provide a rendered Terraform plan with --terraform-plan or rendered Kubernetes YAML/JSON with --kubernetes-manifest, and include image metadata that matches the SBOM artifact."
    if item == "strong deployment workload match":
        return "Prefer digest or exact image-reference matching over name-only or alias-only matching."
    if item == "network path evidence":
        return "Include rendered network evidence from Terraform, Kubernetes, or context JSON so the scanner can link ingress, private, internal, or blocked paths to the workload."
    if item == "network path confidence":
        return "Add provider-specific route, firewall, security-group, ingress, NetworkPolicy, or service-mesh evidence to raise confidence."
    if item == "identity/effective-access evidence":
        return "Include IAM/RBAC evidence from Terraform, rendered Kubernetes manifests, or context JSON so effective access can be evaluated."
    if item == "identity/effective-access confidence":
        return "Add scoped policy documents, role bindings, deny rules, conditions, and target resources so identity evidence is not inferred from weak hints only."
    return "Review the mapping report, source coverage report, and deployment evidence for this artifact."


def _rendering_gap_message(source: str, gap: dict[str, Any], *, message_kind: str) -> dict[str, Any]:
    address = str(gap.get("address") or gap.get("path") or gap.get("type") or gap.get("reason") or "unrendered IaC wrapper")
    return {
        "kind": message_kind,
        "message": f"{source}: unrendered or opaque IaC wrapper found at {address}. Render child resources before using this as release evidence.",
        "impact": "The scanner can see the wrapper, but not the workload images, services, ingress rules, network policies, or RBAC created inside it.",
        "next_step": "Run the render step for Terraform modules, Helm charts, Kustomize overlays, or kubectl manifests and pass the rendered plan/manifests to the scan.",
        "evidence": gap,
    }


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
