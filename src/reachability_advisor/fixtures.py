"""Community Terraform fixture-pack support.

Fixture packs make multi-cloud Terraform coverage reproducible without requiring
cloud credentials or live infrastructure.  A pack contains a reduced
``terraform show -json`` plan, one or more SBOMs, vulnerability intelligence,
source roots, and explicit expectations.  The scanner treats fixtures
as executable documentation: maintainers can add a pack for a real-world module
shape, run it in CI, and see whether artifact matching, coverage accounting,
and finding prioritization still behave as expected.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding, Tier
from .sbom import load_sboms
from .scoring import generate_findings_with_source_report
from .source import parse_source_roots
from .terraform import TerraformContextError, analyze_terraform_plan
from .vulnerability import load_vulnerabilities


class FixtureError(ValueError):
    """Raised when a fixture pack cannot be loaded or executed."""


@dataclass(frozen=True)
class FixturePack:
    """Loaded fixture-pack metadata and resolved paths."""

    id: str
    name: str
    root: Path
    data: dict[str, Any]
    plan: Path
    sboms: tuple[Path, ...]
    vulnerabilities: Path
    source_roots: dict[str, Path] = field(default_factory=dict)
    expected: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FixtureIssue:
    severity: str
    message: str
    path: str | None = None

    def to_json(self) -> dict[str, str]:
        row = {"severity": self.severity, "message": self.message}
        if self.path:
            row["path"] = self.path
        return row


TIER_ORDER = {Tier.INFORMATIONAL.value: 0, Tier.LOW.value: 1, Tier.MEDIUM.value: 2, Tier.HIGH.value: 3, Tier.URGENT.value: 4}


def default_fixtures_root() -> Path:
    """Return the conventional repository-local Terraform fixtures directory."""

    return Path.cwd() / "fixtures" / "terraform"


def discover_fixture_packs(root: str | Path | None = None) -> list[Path]:
    """Discover fixture-pack manifests under ``root``.

    If ``index.json`` exists, it controls ordering.  Otherwise, packs are
    discovered by scanning for ``fixture.json`` below the root.
    """

    fixture_root = Path(root) if root else default_fixtures_root()
    index_path = fixture_root / "index.json"
    if index_path.exists():
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise FixtureError(f"{index_path}: invalid JSON: {exc}") from exc
        packs = index.get("packs", []) if isinstance(index, dict) else []
        result: list[Path] = []
        for item in packs:
            if not isinstance(item, dict) or not item.get("path"):
                continue
            result.append((fixture_root / str(item["path"]) / "fixture.json").resolve())
        return result
    return sorted(path.resolve() for path in fixture_root.glob("packs/*/fixture.json"))


def load_fixture_pack(path_or_dir: str | Path) -> FixturePack:
    """Load one fixture pack from a directory or ``fixture.json`` path."""

    raw_path = Path(path_or_dir)
    manifest_path = raw_path / "fixture.json" if raw_path.is_dir() else raw_path
    if not manifest_path.exists():
        raise FixtureError(f"fixture manifest not found: {manifest_path}")
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FixtureError(f"{manifest_path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise FixtureError(f"{manifest_path}: expected a JSON object")
    root = manifest_path.parent
    pack_id = str(data.get("id") or root.name)
    name = str(data.get("name") or pack_id)
    plan = _resolve_pack_path(root, data.get("terraform_plan") or data.get("plan") or "tfplan.json")
    sbom_values = data.get("sboms") or []
    if not isinstance(sbom_values, list):
        raise FixtureError(f"{manifest_path}: sboms must be a list")
    sboms = tuple(_resolve_pack_path(root, value) for value in sbom_values)
    vulnerabilities = _resolve_pack_path(root, data.get("vulnerabilities") or "vulnerabilities.json")
    source_roots_raw = data.get("source_roots") or {}
    if not isinstance(source_roots_raw, dict):
        raise FixtureError(f"{manifest_path}: source_roots must be an object")
    source_roots = {str(artifact): _resolve_pack_path(root, raw) for artifact, raw in source_roots_raw.items()}
    raw_expected = data.get("expected")
    expected: dict[str, Any] = raw_expected if isinstance(raw_expected, dict) else {}
    return FixturePack(
        id=pack_id,
        name=name,
        root=root,
        data=data,
        plan=plan,
        sboms=sboms,
        vulnerabilities=vulnerabilities,
        source_roots=source_roots,
        expected=expected,
    )


def _resolve_pack_path(root: Path, raw: Any) -> Path:
    path = Path(str(raw))
    if path.is_absolute():
        return path
    return (root / path).resolve()


def validate_fixture_pack(pack: FixturePack) -> list[FixtureIssue]:
    """Validate structure and parseability of a fixture pack."""

    issues: list[FixtureIssue] = []
    if not pack.id.strip():
        issues.append(FixtureIssue("error", "fixture id is empty", str(pack.root)))
    _require_file(pack.plan, "terraform plan", issues)
    _require_file(pack.vulnerabilities, "vulnerability intelligence", issues)
    if not pack.sboms:
        issues.append(FixtureIssue("error", "fixture must declare at least one SBOM", str(pack.root)))
    for sbom in pack.sboms:
        _require_file(sbom, "SBOM", issues)
    for artifact, root in pack.source_roots.items():
        if not root.exists() or not root.is_dir():
            issues.append(FixtureIssue("warning", f"source root for {artifact!r} is missing or not a directory", str(root)))
    if issues and any(issue.severity == "error" for issue in issues):
        return issues
    try:
        sboms = load_sboms([str(path) for path in pack.sboms])
    except Exception as exc:  # noqa: BLE001 - validation should report user-facing parser errors.
        issues.append(FixtureIssue("error", f"SBOM parse failed: {exc}", str(pack.root)))
        sboms = []
    try:
        load_vulnerabilities(pack.vulnerabilities)
    except Exception as exc:  # noqa: BLE001
        issues.append(FixtureIssue("error", f"vulnerability parse failed: {exc}", str(pack.vulnerabilities)))
    try:
        if sboms:
            analyze_terraform_plan(pack.plan, [sbom.artifact for sbom in sboms])
    except TerraformContextError as exc:
        issues.append(FixtureIssue("error", f"Terraform parse failed: {exc}", str(pack.plan)))
    if not pack.expected:
        issues.append(FixtureIssue("warning", "fixture has no expected assertions", str(pack.root)))
    return issues


def _require_file(path: Path, label: str, issues: list[FixtureIssue]) -> None:
    if not path.exists() or not path.is_file():
        issues.append(FixtureIssue("error", f"missing {label}", str(path)))


def run_fixture_pack(pack: FixturePack, output_dir: str | Path | None = None) -> dict[str, Any]:
    """Run one fixture pack and return an assertion-aware report."""

    validation_issues = validate_fixture_pack(pack)
    if any(issue.severity == "error" for issue in validation_issues):
        return _pack_report(pack, status="failed", validation_issues=validation_issues, error="fixture validation failed")
    sboms = load_sboms([str(path) for path in pack.sboms])
    vulnerabilities = load_vulnerabilities(pack.vulnerabilities)
    source_args = [f"{artifact}={path}" for artifact, path in pack.source_roots.items()]
    source_roots = parse_source_roots(source_args)
    terraform_analysis = analyze_terraform_plan(pack.plan, [sbom.artifact for sbom in sboms])
    findings, source_coverage = generate_findings_with_source_report(sboms, vulnerabilities, source_roots, terraform_analysis.contexts)
    assertions = evaluate_fixture_expectations(pack, findings, terraform_analysis.coverage)
    status = "passed" if not assertions["failed"] else "failed"
    report = _pack_report(
        pack,
        status=status,
        validation_issues=validation_issues,
        coverage=terraform_analysis.coverage,
        findings=[finding.to_json() for finding in findings],
        assertions=assertions,
    )
    if output_dir:
        out_root = Path(output_dir) / pack.id
        out_root.mkdir(parents=True, exist_ok=True)
        (out_root / "findings.json").write_text(json.dumps({"findings": report["findings"]}, indent=2), encoding="utf-8")
        (out_root / "terraform-coverage.json").write_text(json.dumps(terraform_analysis.coverage, indent=2), encoding="utf-8")
        (out_root / "source-coverage.json").write_text(json.dumps(source_coverage, indent=2), encoding="utf-8")
        (out_root / "fixture-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def run_fixture_packs(root: str | Path | None = None, output_dir: str | Path | None = None, only: str | None = None) -> dict[str, Any]:
    """Run all discovered fixture packs or a single pack id."""

    reports: list[dict[str, Any]] = []
    for path in discover_fixture_packs(root):
        pack = load_fixture_pack(path)
        if only and pack.id != only:
            continue
        reports.append(run_fixture_pack(pack, output_dir=output_dir))
    if only and not reports:
        raise FixtureError(f"fixture not found: {only}")
    failed = [report for report in reports if report.get("status") != "passed"]
    return {
        "schema_version": "3.0",
        "status": "passed" if not failed else "failed",
        "fixture_count": len(reports),
        "failed_count": len(failed),
        "fixtures": reports,
    }


def evaluate_fixture_expectations(pack: FixturePack, findings: list[Finding], coverage: dict[str, Any]) -> dict[str, Any]:
    """Evaluate pack-level expected assertions."""

    expected = pack.expected
    passed: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    def check(name: str, ok: bool, details: dict[str, Any]) -> None:
        row = {"name": name, "details": details}
        (passed if ok else failed).append(row)

    summary = coverage.get("summary", {}) if isinstance(coverage, dict) else {}
    for key in ("resource_accounting_coverage", "semantic_classification_coverage", "artifact_match_coverage"):
        if key in expected:
            actual = float(summary.get(key, 0.0))
            required = float(expected[key])
            check(key, actual >= required, {"required": required, "actual": actual})
    if "min_findings" in expected:
        actual = len(findings)
        required = int(expected["min_findings"])
        check("min_findings", actual >= required, {"required": required, "actual": actual})
    if "must_match_artifacts" in expected:
        actual_artifacts = set(coverage.get("matched_artifacts", []))
        required_artifacts = {str(item) for item in expected.get("must_match_artifacts", [])}
        check("must_match_artifacts", required_artifacts.issubset(actual_artifacts), {"required": sorted(required_artifacts), "actual": sorted(actual_artifacts)})
    if "required_resource_types" in expected:
        actual_resource_types = set(coverage.get("resource_types_seen", []))
        required_resource_types = {str(item) for item in expected.get("required_resource_types", [])}
        check("required_resource_types", required_resource_types.issubset(actual_resource_types), {"required": sorted(required_resource_types), "actual": sorted(actual_resource_types)})
    for item in expected.get("min_tier_by_finding", []) or []:
        if not isinstance(item, dict):
            continue
        artifact = str(item.get("artifact") or "")
        component = str(item.get("component") or "")
        vulnerability = str(item.get("vulnerability") or "")
        min_tier = str(item.get("tier") or "informational")
        actual_tier = _find_tier(findings, artifact, component, vulnerability)
        ok = actual_tier is not None and TIER_ORDER.get(actual_tier, 0) >= TIER_ORDER.get(min_tier, 0)
        check(
            f"min_tier:{artifact}:{component}:{vulnerability}",
            ok,
            {"required": min_tier, "actual": actual_tier, "artifact": artifact, "component": component, "vulnerability": vulnerability},
        )
    return {"passed": passed, "failed": failed}


def _find_tier(findings: list[Finding], artifact: str, component: str, vulnerability: str) -> str | None:
    for finding in findings:
        if finding.artifact.name == artifact and finding.component.name == component and finding.vulnerability.id == vulnerability:
            return finding.tier.value
    return None


def _pack_report(
    pack: FixturePack,
    *,
    status: str,
    validation_issues: list[FixtureIssue],
    error: str | None = None,
    coverage: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
    assertions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": "3.0",
        "id": pack.id,
        "name": pack.name,
        "status": status,
        "root": str(pack.root),
        "provider": pack.data.get("provider"),
        "module_reference": pack.data.get("module_reference", {}),
        "validation_issues": [issue.to_json() for issue in validation_issues],
    }
    if error:
        report["error"] = error
    if coverage is not None:
        report["coverage_summary"] = coverage.get("summary", {})
        report["coverage"] = coverage
    if findings is not None:
        report["finding_count"] = len(findings)
        report["top_findings"] = findings[:5]
        report["findings"] = findings
    if assertions is not None:
        report["assertions"] = assertions
    return report


__all__ = [
    "FixtureError",
    "FixtureIssue",
    "FixturePack",
    "default_fixtures_root",
    "discover_fixture_packs",
    "load_fixture_pack",
    "run_fixture_pack",
    "run_fixture_packs",
    "validate_fixture_pack",
]
