"""Input validation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ValidationIssue:
    severity: str
    target: str
    message: str


def validate_paths(
    sboms: list[str],
    vulns: str | list[str] | None,
    context: str | None = None,
    terraform_plan: str | None = None,
    source_roots: list[str] | None = None,
    terraform_source: str | None = None,
    kubernetes_manifests: list[str] | None = None,
    policy: str | None = None,
    reachability_rules: str | None = None,
    source_evidence: list[str] | None = None,
    security_evidence: list[str] | None = None,
    artifact_manifests: list[str] | None = None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for path in sboms:
        _validate_file(path, "sbom", issues)
    for path in _as_paths(vulns):
        _validate_file(path, "vuln-in", issues)
    if context:
        _validate_file(context, "context", issues)
    if terraform_plan:
        _validate_file(terraform_plan, "terraform-plan", issues)
    for manifest in kubernetes_manifests or []:
        manifest_path = Path(manifest)
        if not manifest_path.exists():
            issues.append(ValidationIssue("error", "kubernetes-manifest", f"Rendered Kubernetes manifest path was not found: {manifest}. Provide a rendered YAML/JSON file or directory."))
        elif manifest_path.is_file() and manifest_path.suffix.lower() not in {".yaml", ".yml", ".json"}:
            issues.append(ValidationIssue("error", "kubernetes-manifest", f"Kubernetes manifest must be YAML or JSON: {manifest}. Render Helm/Kustomize output before scanning."))
        elif manifest_path.is_dir() and not any(item.suffix.lower() in {".yaml", ".yml", ".json"} for item in manifest_path.rglob("*") if item.is_file()):
            issues.append(ValidationIssue("warning", "kubernetes-manifest", f"Kubernetes manifest directory contains no YAML or JSON files: {manifest}. No Kubernetes deployment evidence will be added."))
    if policy:
        _validate_file(policy, "policy", issues)
    if reachability_rules:
        _validate_file(reachability_rules, "reachability-rules", issues)
    for path in source_evidence or []:
        _validate_file(path, "source-evidence", issues)
    for path in security_evidence or []:
        _validate_file(path, "security-evidence", issues)
    for path in artifact_manifests or []:
        _validate_file(path, "artifact-manifest", issues)
    if terraform_source:
        source_path = Path(terraform_source)
        if not source_path.exists():
            issues.append(ValidationIssue("error", "terraform-source", f"Terraform source path was not found: {terraform_source}. Provide a .tf file or directory."))
        elif source_path.is_file() and source_path.suffix != ".tf":
            issues.append(ValidationIssue("error", "terraform-source", f"Terraform source must be a .tf file or directory: {terraform_source}."))
        elif source_path.is_dir() and not any(source_path.rglob("*.tf")):
            issues.append(ValidationIssue("warning", "terraform-source", f"Terraform source directory contains no .tf files: {terraform_source}. No Terraform source evidence will be added."))
    for source_root in source_roots or []:
        if "=" not in source_root:
            issues.append(ValidationIssue("error", source_root, "Source root must use artifact=path syntax, for example payments-api=src/payments-api."))
            continue
        artifact, raw_path = source_root.split("=", 1)
        if not artifact.strip():
            issues.append(ValidationIssue("error", source_root, "Source root artifact name is empty. Put the SBOM artifact name before '='."))
        root_path = Path(raw_path)
        if not root_path.exists():
            issues.append(ValidationIssue("warning", source_root, "Source root path was not found. Source reachability will fall back to SBOM/package evidence only."))
        elif not root_path.is_dir():
            issues.append(ValidationIssue("error", source_root, "Source root must point to a directory containing the artifact source code."))
    return issues


def _as_paths(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return value


def _validate_file(path: str, label: str, issues: list[ValidationIssue]) -> None:
    file_path = Path(path)
    if not file_path.exists():
        issues.append(ValidationIssue("error", label, f"Required input file was not found: {path}. Check the path or generate the file before scanning."))
    elif not file_path.is_file():
        issues.append(ValidationIssue("error", label, f"Expected a file but got a directory or special path: {path}."))
    elif file_path.stat().st_size == 0:
        issues.append(ValidationIssue("error", label, f"Input file is empty: {path}. Generate a valid JSON/YAML report before scanning."))


def has_errors(issues: list[ValidationIssue]) -> bool:
    return any(issue.severity == "error" for issue in issues)


def issues_report(issues: list[ValidationIssue]) -> dict[str, object]:
    return {
        "summary": {
            "error": sum(1 for issue in issues if issue.severity == "error"),
            "warning": sum(1 for issue in issues if issue.severity == "warning"),
        },
        "issues": [issue.__dict__ for issue in issues],
    }
