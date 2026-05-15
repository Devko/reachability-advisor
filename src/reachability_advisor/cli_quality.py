"""Quality gate helpers for CLI scan output."""

from __future__ import annotations

import argparse
import math
from typing import Any

from .models import Tier


def _findings_fail(findings: list[Any], tier: Tier) -> bool:
    order = {Tier.INFORMATIONAL: 0, Tier.LOW: 1, Tier.MEDIUM: 2, Tier.HIGH: 3, Tier.URGENT: 4}
    threshold = order[tier]
    return any(finding.policy_status != "excepted" and order[finding.tier] >= threshold for finding in findings)


def _quality_gate_failures(
    args: argparse.Namespace,
    mapping_report: dict[str, Any],
    source_coverage: dict[str, Any],
    artifact_provenance_reports: list[dict[str, Any]] | None = None,
) -> list[str]:
    failures: list[str] = []
    mapping_summary = mapping_report.get("summary", {}) if isinstance(mapping_report.get("summary"), dict) else {}
    source_summary = source_coverage.get("summary", {}) if isinstance(source_coverage.get("summary"), dict) else {}

    def ratio_gate(label: str, value: Any, minimum: float | None) -> None:
        if minimum is None:
            return
        if not math.isfinite(minimum) or minimum < 0 or minimum > 1:
            failures.append(f"{label} gate must be between 0 and 1. Got {minimum}.")
            return
        observed = float(value or 0.0)
        if not math.isfinite(observed):
            failures.append(f"{label} observed value is not a usable number: {observed}.")
            return
        if observed < minimum:
            failures.append(f"{label} is {observed:.4f}, below required {minimum:.4f}. {_quality_gate_next_step(label)}")

    ratio_gate("artifact match coverage", mapping_summary.get("artifact_match_coverage"), args.min_artifact_match_coverage)
    ratio_gate("strong artifact identity coverage", mapping_summary.get("strong_artifact_identity_coverage"), args.min_strong_artifact_identity_coverage)
    production = getattr(args, "analysis_profile", "advisory") == "production"
    source_rule_minimum = _profile_minimum(args.min_source_rule_coverage, 0.8 if production else None)
    external_usable_minimum = _profile_minimum(args.min_external_evidence_usable_ratio, 0.8 if production else None)
    critical_external_minimum = _profile_minimum(args.min_critical_external_source_coverage, 1.0 if production else None)
    critical_query_family_minimum = _profile_minimum(args.min_critical_query_family_coverage, 1.0 if production else None)
    critical_proven_query_family_minimum = _profile_minimum(args.min_critical_proven_query_family_coverage, 1.0 if production else None)
    ratio_gate("source rule coverage", source_summary.get("source_rule_coverage"), source_rule_minimum)
    ratio_gate("external source evidence usable ratio", source_summary.get("external_evidence_usable_ratio"), external_usable_minimum)
    ratio_gate("critical external source evidence coverage", source_summary.get("critical_external_evidence_coverage"), critical_external_minimum)
    ratio_gate("critical source query-family coverage", source_summary.get("critical_query_family_coverage"), critical_query_family_minimum)
    ratio_gate("critical proven source query-family coverage", source_summary.get("critical_proven_query_family_coverage"), critical_proven_query_family_minimum)
    security_report_raw = source_coverage.get("security_evidence")
    security_report = security_report_raw if isinstance(security_report_raw, dict) else {}
    security_summary_raw = security_report.get("summary")
    security_summary = security_summary_raw if isinstance(security_summary_raw, dict) else {}
    security_profile_minimum = _profile_minimum(
        args.min_critical_security_profile_coverage,
        1.0 if production and int(security_summary.get("records") or 0) > 0 else None,
    )
    ratio_gate("critical security profile coverage", security_summary.get("critical_profile_coverage"), security_profile_minimum)
    if args.fail_on_mapping_warnings and int(mapping_summary.get("mapping_warnings_count") or 0) > 0:
        failures.append(f"mapping report contains {mapping_summary.get('mapping_warnings_count')} warning(s). Review --mapping-out for weak artifact identity, missing source roots, or weak deployment matches.")
    if (args.require_external_source_evidence or production) and int(source_summary.get("external_evidence_records") or 0) == 0:
        failures.append("No external source analyzer evidence was imported. Run Semgrep, CodeQL/SARIF, govulncheck, or an equivalent analyzer and pass the output with --source-evidence-in, --sast-in, or --security-evidence-in.")
    weak_critical = int(source_summary.get("critical_findings_with_dependency_only_source") or 0)
    if (args.require_strong_source_for_critical or production) and weak_critical > 0:
        failures.append(f"{weak_critical} critical finding(s) only have dependency-level or weaker source evidence. Add external analyzer evidence that proves import, vulnerable API use, or request-controlled reachability.")
    if production and not args.terraform_plan and not args.kubernetes_manifest:
        failures.append("Production profile requires rendered deployment evidence. Provide --terraform-plan from `terraform show -json` or --kubernetes-manifest with rendered YAML/JSON.")
    if production and args.terraform_source and not args.terraform_plan:
        failures.append("Production profile treats --terraform-source as advisory only. Provide --terraform-plan for Terraform-managed resources.")
    if getattr(args, "require_artifact_provenance", False):
        if not getattr(args, "artifact_manifest", []):
            failures.append("Strict artifact provenance requires at least one --artifact-manifest with image identity, SBOM path, Git SHA, and signature or attestation markers.")
        for report in artifact_provenance_reports or []:
            if report.get("status") != "ready":
                blockers = report.get("summary", {}).get("provenance_blockers", 0)
                failures.append(f"artifact provenance has {blockers} blocker(s). Validate the manifest and add missing digest, SBOM path, Git SHA, or signature/attestation evidence.")
    return failures


def _quality_gate_next_step(label: str) -> str:
    if "artifact match" in label:
        return "Provide rendered Terraform/Kubernetes evidence and image metadata that matches each SBOM artifact."
    if "strong artifact identity" in label:
        return "Add image digests or exact image references through SBOM metadata or --artifact-manifest."
    if "source rule" in label:
        return "Add built-in or custom source reachability rules for packages that currently have no rule coverage."
    if "external source evidence" in label:
        return "Import Semgrep, CodeQL/SARIF, govulncheck, or equivalent source analyzer output."
    if "query-family" in label:
        return "Use a maintained source evidence pack and import records with query_family metadata."
    if "security profile" in label:
        return "Run a maintained SAST/DAST evidence profile or include profile metadata in imported scanner records."
    return "Review the generated coverage report for missing evidence."


def _profile_minimum(user_value: float | None, profile_default: float | None) -> float | None:
    if user_value is None:
        return profile_default
    if profile_default is None:
        return user_value
    if not math.isfinite(user_value):
        return user_value
    return max(user_value, profile_default)


def _annotate_analysis_profile(
    args: argparse.Namespace,
    source_coverage: dict[str, Any],
    terraform_coverage: dict[str, Any],
    kubernetes_coverage: dict[str, Any],
) -> None:
    production = args.analysis_profile == "production"
    source_summary = source_coverage.setdefault("summary", {})
    source_summary["analysis_profile"] = args.analysis_profile
    blockers: list[str] = []
    if production:
        if int(source_summary.get("external_evidence_records") or 0) == 0:
            blockers.append("External source analyzer evidence is required for production gates.")
        if not args.terraform_plan and not args.kubernetes_manifest:
            blockers.append("Rendered deployment evidence is required for production gates.")
        if args.terraform_source and not args.terraform_plan:
            blockers.append("Terraform source mode is advisory only; use a rendered Terraform plan for production gates.")
    source_coverage["production_readiness"] = {
        "status": "blocked" if blockers else "ready" if production else "advisory",
        "blockers": blockers,
        "source_mode": "external-first" if production else "builtin-fallback",
        "deployment_evidence": {
            "terraform_plan": bool(args.terraform_plan),
            "terraform_source": bool(args.terraform_source),
            "kubernetes_manifest": bool(args.kubernetes_manifest),
            "terraform_resources": terraform_coverage.get("summary", {}).get("total_resources", 0),
            "kubernetes_resources": kubernetes_coverage.get("summary", {}).get("total_resources", 0),
        },
    }


__all__ = [
    "_annotate_analysis_profile",
    "_findings_fail",
    "_profile_minimum",
    "_quality_gate_failures",
    "_quality_gate_next_step",
]
