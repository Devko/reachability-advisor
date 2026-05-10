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
    vulns: str | None,
    context: str | None = None,
    terraform_plan: str | None = None,
    source_roots: list[str] | None = None,
    terraform_source: str | None = None,
    policy: str | None = None,
    reachability_rules: str | None = None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for path in sboms:
        _validate_file(path, "sbom", issues)
    if vulns:
        _validate_file(vulns, "vulns", issues)
    if context:
        _validate_file(context, "context", issues)
    if terraform_plan:
        _validate_file(terraform_plan, "terraform-plan", issues)
    if policy:
        _validate_file(policy, "policy", issues)
    if reachability_rules:
        _validate_file(reachability_rules, "reachability-rules", issues)
    if terraform_source:
        source_path = Path(terraform_source)
        if not source_path.exists():
            issues.append(ValidationIssue("error", "terraform-source", f"path does not exist: {terraform_source}"))
        elif source_path.is_file() and source_path.suffix != ".tf":
            issues.append(ValidationIssue("error", "terraform-source", f"file is not a .tf file: {terraform_source}"))
        elif source_path.is_dir() and not any(source_path.rglob("*.tf")):
            issues.append(ValidationIssue("warning", "terraform-source", f"directory contains no .tf files: {terraform_source}"))
    for source_root in source_roots or []:
        if "=" not in source_root:
            issues.append(ValidationIssue("error", source_root, "source root must use artifact=path syntax"))
            continue
        artifact, raw_path = source_root.split("=", 1)
        if not artifact.strip():
            issues.append(ValidationIssue("error", source_root, "source root artifact name is empty"))
        path = Path(raw_path)
        if not path.exists():
            issues.append(ValidationIssue("warning", source_root, "source root does not exist; reachability will be package_present only"))
        elif not path.is_dir():
            issues.append(ValidationIssue("error", source_root, "source root is not a directory"))
    return issues


def _validate_file(path: str, label: str, issues: list[ValidationIssue]) -> None:
    file_path = Path(path)
    if not file_path.exists():
        issues.append(ValidationIssue("error", label, f"file does not exist: {path}"))
    elif not file_path.is_file():
        issues.append(ValidationIssue("error", label, f"not a file: {path}"))
    elif file_path.stat().st_size == 0:
        issues.append(ValidationIssue("error", label, f"file is empty: {path}"))


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
