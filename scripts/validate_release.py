"""Run local release-readiness checks for the stable CLI package.

The project intentionally avoids runtime dependencies beyond the Python
standard library. This script therefore implements the small JSON Schema subset
used by the repository schemas instead of depending on jsonschema.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from reachability_advisor import __version__  # noqa: E402
from reachability_advisor.cli import main as cli_main  # noqa: E402
from scripts import run_complex_app_validation as complex_validation  # noqa: E402


class ReleaseCheckError(RuntimeError):
    """Raised when a release check fails."""


class SchemaError(ValueError):
    """Raised when a document does not match the repository schema subset."""


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_schema(instance: Any, schema: dict[str, Any], path: str = "$") -> None:
    if "const" in schema and instance != schema["const"]:
        raise SchemaError(f"{path}: expected const {schema['const']!r}, got {instance!r}")
    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaError(f"{path}: expected one of {schema['enum']!r}, got {instance!r}")

    expected_type = schema.get("type")
    if expected_type is not None and not _type_matches(instance, expected_type):
        raise SchemaError(f"{path}: expected type {expected_type!r}, got {type(instance).__name__}")

    if isinstance(instance, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in instance:
                raise SchemaError(f"{path}: missing required property {key!r}")
        properties = schema.get("properties", {})
        for key, subschema in properties.items():
            if key in instance and isinstance(subschema, dict):
                validate_schema(instance[key], subschema, f"{path}.{key}")
        additional = schema.get("additionalProperties", True)
        known = set(properties)
        extras = [key for key in instance if key not in known]
        if additional is False and extras:
            raise SchemaError(f"{path}: unexpected properties {extras!r}")
        if isinstance(additional, dict):
            for key in extras:
                validate_schema(instance[key], additional, f"{path}.{key}")

    if isinstance(instance, list):
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(instance) < min_items:
            raise SchemaError(f"{path}: expected at least {min_items} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                validate_schema(item, item_schema, f"{path}[{index}]")

    if isinstance(instance, str):
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(instance) < min_length:
            raise SchemaError(f"{path}: expected string length >= {min_length}")

    if _is_number(instance):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and instance < minimum:
            raise SchemaError(f"{path}: expected value >= {minimum}")
        if maximum is not None and instance > maximum:
            raise SchemaError(f"{path}: expected value <= {maximum}")


def _type_matches(instance: Any, expected: str | list[str]) -> bool:
    if isinstance(expected, list):
        return any(_type_matches(instance, item) for item in expected)
    if expected == "object":
        return isinstance(instance, dict)
    if expected == "array":
        return isinstance(instance, list)
    if expected == "string":
        return isinstance(instance, str)
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected == "number":
        return _is_number(instance)
    if expected == "boolean":
        return isinstance(instance, bool)
    if expected == "null":
        return instance is None
    raise SchemaError(f"unsupported schema type {expected!r}")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_json_file(document: Path, schema: Path) -> None:
    validate_schema(load_json(document), load_json(schema))


def run_cli(args: list[str]) -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli_main(args)
    if code != 0:
        raise ReleaseCheckError(
            "CLI command failed: "
            + " ".join(args)
            + f"\nstdout:\n{stdout.getvalue()}\nstderr:\n{stderr.getvalue()}"
        )


def require_text(path: Path, *needles: str) -> None:
    if not path.exists():
        raise ReleaseCheckError(f"expected output file was not written: {path}")
    text = path.read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise ReleaseCheckError(f"{path} is missing expected text: {', '.join(missing)}")


def require_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ReleaseCheckError(f"expected JSON output file was not written: {path}")
    data = load_json(path)
    if not isinstance(data, dict):
        raise ReleaseCheckError(f"{path}: expected a JSON object")
    return data


def check_release_metadata() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version_match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, flags=re.MULTILINE)
    if not version_match:
        raise ReleaseCheckError("pyproject.toml has no project version")
    pyproject_version = version_match.group(1)
    if pyproject_version != __version__:
        raise ReleaseCheckError(f"version mismatch: pyproject={pyproject_version}, package={__version__}")
    major = int(pyproject_version.split(".", 1)[0])
    if major < 1:
        raise ReleaseCheckError(f"stable release version must be >= 1.0.0, got {pyproject_version}")
    if "Development Status :: 5 - Production/Stable" not in pyproject:
        raise ReleaseCheckError("pyproject.toml must use the Production/Stable classifier")
    if "Development Status :: 4 - Beta" in pyproject or "Development Status :: 3 - Alpha" in pyproject:
        raise ReleaseCheckError("pyproject.toml still contains alpha/beta development status")
    if 'license = "GPL-3.0-or-later"' not in pyproject:
        raise ReleaseCheckError("pyproject.toml must declare GPL-3.0-or-later")
    if "Apache-2.0" in pyproject or "Apache License" in pyproject:
        raise ReleaseCheckError("pyproject.toml still contains Apache license metadata")
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8").lstrip()
    if not license_text.startswith("GNU GENERAL PUBLIC LICENSE"):
        raise ReleaseCheckError("LICENSE must contain the GNU General Public License text")
    _check_no_former_project_positioning()


def check_action_metadata() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    required_fragments = [
        "$GITHUB_ACTION_PATH",
        "--mapping-out",
        "--diagnostics-out",
        "--html-out",
        "terraform-source",
        "kubernetes-manifest",
        "reachability-rules",
        "artifact-alias",
        "baseline",
        "fail-on-new-tier",
        "--baseline-out",
        "output-dir",
        "scan_code=$?",
        "outputs:",
    ]
    missing = [fragment for fragment in required_fragments if fragment not in action]
    if missing:
        raise ReleaseCheckError("action.yml is missing required fragments: " + ", ".join(missing))


def _check_no_former_project_positioning() -> None:
    checked_roots = [
        ROOT / "README.md",
        ROOT / "CHANGELOG.md",
        ROOT / "pyproject.toml",
        ROOT / "NOTICE",
        ROOT / "SECURITY.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "CODE_OF_CONDUCT.md",
        ROOT / ".github",
        ROOT / "docs",
        ROOT / "schemas",
        ROOT / "scripts",
        ROOT / "src",
        ROOT / "tests",
    ]
    suffixes = {".json", ".md", ".py", ".toml", ".txt", ".yaml", ".yml"}
    needle = "ow" + "asp"
    offenders: list[str] = []
    for root in checked_roots:
        paths = [root] if root.is_file() else sorted(path for path in root.rglob("*") if path.is_file())
        for path in paths:
            if path.suffix.lower() not in suffixes:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if needle in text.lower():
                offenders.append(str(path.relative_to(ROOT)))
    if offenders:
        raise ReleaseCheckError("former project positioning references remain: " + ", ".join(offenders))


def run_release_validation(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    schema_dir = ROOT / "schemas"
    checks: list[dict[str, str]] = []

    def check(name: str, document: Path, schema_name: str) -> None:
        validate_json_file(document, schema_dir / schema_name)
        checks.append({"name": name, "status": "passed", "document": str(document), "schema": schema_name})

    check_release_metadata()
    checks.append({"name": "release metadata", "status": "passed"})
    check_action_metadata()
    checks.append({"name": "composite action metadata", "status": "passed"})

    check("sample vulnerability intelligence", ROOT / "samples" / "vulnerabilities.json", "vulnerability-intelligence.schema.json")
    check("sample context", ROOT / "samples" / "context.json", "context.schema.json")
    check("example runtime policy", ROOT / "configs" / "policy.example.json", "runtime-policy.schema.json")
    for fixture in sorted((ROOT / "fixtures" / "terraform" / "packs").glob("*/fixture.json")):
        check(f"fixture pack {fixture.parent.name}", fixture, "fixture-pack.schema.json")

    sbom_plan = out_dir / "sbom-plan.json"
    run_cli(
        [
            "sbom-plan",
            "--artifact",
            "payments-api",
            "--image",
            "ghcr.io/acme/payments-api:1.2.3",
            "--source-root",
            str(ROOT / "samples" / "source" / "payments-api"),
            "--ecosystem",
            "maven",
            "--out-json",
            str(sbom_plan),
            "--out-md",
            str(out_dir / "sbom-plan.md"),
        ]
    )
    check("generated SBOM plan", sbom_plan, "sbom-plan.schema.json")
    require_text(out_dir / "sbom-plan.md", "syft", "trivy", "cyclonedx-maven-plugin")
    checks.append({"name": "generated SBOM plan Markdown", "status": "passed", "document": str(out_dir / "sbom-plan.md")})

    policy = out_dir / "policy.json"
    run_cli(["init-policy", "--out", str(policy)])
    check("generated runtime policy", policy, "runtime-policy.schema.json")

    hcl_audit = out_dir / "hcl-audit.json"
    hcl_audit_md = out_dir / "hcl-audit.md"
    run_cli(["hcl-audit", "--path", str(ROOT / "samples" / "terraform-source"), "--out", str(hcl_audit), "--markdown-out", str(hcl_audit_md)])
    check("generated HCL audit", hcl_audit, "hcl-audit-report.schema.json")
    require_text(hcl_audit_md, "HCL Static Audit")
    checks.append({"name": "generated HCL audit Markdown", "status": "passed", "document": str(hcl_audit_md)})

    _check_vulnerability_imports(out_dir, checks)
    _check_external_source_evidence_imports(out_dir, checks)
    _check_context_alias_and_custom_rule_imports(out_dir, checks)

    findings = out_dir / "findings.json"
    baseline = out_dir / "baseline.json"
    html = out_dir / "graph.html"
    sarif = out_dir / "findings.sarif"
    diagnostics = out_dir / "diagnostics.json"
    markdown = out_dir / "summary.md"
    annotations = out_dir / "annotations.txt"
    terraform_coverage = out_dir / "terraform-coverage.json"
    kubernetes_coverage = out_dir / "kubernetes-coverage.json"
    source_coverage = out_dir / "source-coverage.json"
    mapping = out_dir / "mapping.json"
    run_cli(
        [
            "scan",
            "--sbom",
            str(ROOT / "samples" / "sboms" / "payments-api.cdx.json"),
            "--sbom",
            str(ROOT / "samples" / "sboms" / "notifier.cdx.json"),
            "--sbom",
            str(ROOT / "samples" / "sboms" / "orders-api.cdx.json"),
            "--sbom",
            str(ROOT / "samples" / "sboms" / "audit-api.cdx.json"),
            "--sbom",
            str(ROOT / "samples" / "sboms" / "inventory-api.cdx.json"),
            "--sbom",
            str(ROOT / "samples" / "sboms" / "batch-worker.cdx.json"),
            "--sbom",
            str(ROOT / "samples" / "sboms" / "reports-api.cdx.json"),
            "--vulns",
            str(ROOT / "samples" / "vulnerabilities.json"),
            "--terraform-plan",
            str(ROOT / "samples" / "tfplan-multicloud.json"),
            "--terraform-coverage-out",
            str(terraform_coverage),
            "--kubernetes-manifest",
            str(ROOT / "samples" / "kubernetes-manifest.yaml"),
            "--kubernetes-coverage-out",
            str(kubernetes_coverage),
            "--source-coverage-out",
            str(source_coverage),
            "--mapping-out",
            str(mapping),
            "--source-root",
            f"payments-api={ROOT / 'samples' / 'source' / 'payments-api'}",
            "--source-root",
            f"notifier={ROOT / 'samples' / 'source' / 'notifier'}",
            "--source-root",
            f"orders-api={ROOT / 'samples' / 'source' / 'orders-api'}",
            "--source-root",
            f"audit-api={ROOT / 'samples' / 'source' / 'audit-api'}",
            "--source-root",
            f"inventory-api={ROOT / 'samples' / 'source' / 'inventory-api'}",
            "--source-root",
            f"batch-worker={ROOT / 'samples' / 'source' / 'batch-worker'}",
            "--source-root",
            f"reports-api={ROOT / 'samples' / 'source' / 'reports-api'}",
            "--out",
            str(findings),
            "--baseline-out",
            str(baseline),
            "--sarif-out",
            str(sarif),
            "--diagnostics-out",
            str(diagnostics),
            "--markdown-out",
            str(markdown),
            "--html-out",
            str(html),
            "--annotations-out",
            str(annotations),
            "--no-table",
        ]
    )
    check("generated findings", findings, "findings.schema.json")
    check("generated baseline", baseline, "baseline.schema.json")
    _check_sarif_output(sarif)
    checks.append({"name": "generated SARIF output", "status": "passed", "document": str(sarif)})
    _check_diagnostics_output(diagnostics)
    checks.append({"name": "generated diagnostics output", "status": "passed", "document": str(diagnostics)})
    require_text(markdown, "Reachability Advisor PR Summary", "Remediation queue")
    checks.append({"name": "generated PR summary Markdown", "status": "passed", "document": str(markdown)})
    require_text(annotations, "::error")
    checks.append({"name": "generated GitHub annotations", "status": "passed", "document": str(annotations)})

    explanation = out_dir / "explain" / "log4j.md"
    run_cli(["explain", "--findings", str(findings), "--artifact", "payments-api", "--component", "log4j-core", "--vulnerability", "CVE-2021-44228", "--out", str(explanation)])
    require_text(explanation, "Explanation", "CVE-2021-44228")
    checks.append({"name": "generated single-finding explanation", "status": "passed", "document": str(explanation)})

    delta = out_dir / "delta.json"
    delta_md = out_dir / "delta.md"
    run_cli(["compare", "--baseline", str(baseline), "--head-findings", str(findings), "--out", str(delta), "--markdown-out", str(delta_md), "--fail-on-new-tier", "high"])
    checks.append({"name": "generated PR baseline delta", "status": "passed", "document": str(delta)})
    require_text(delta_md, "Reachability Advisor PR Delta")
    checks.append({"name": "generated PR delta Markdown", "status": "passed", "document": str(delta_md)})
    if not html.exists() or "report-data" not in html.read_text(encoding="utf-8"):
        raise ReleaseCheckError("generated HTML graph report is missing report data")
    checks.append({"name": "generated HTML graph report", "status": "passed", "document": str(html)})
    check("generated Terraform coverage", terraform_coverage, "terraform-coverage.schema.json")
    check("generated Kubernetes coverage", kubernetes_coverage, "kubernetes-coverage.schema.json")
    check("generated source coverage", source_coverage, "source-coverage.schema.json")
    check("generated mapping report", mapping, "mapping-report.schema.json")

    semgrep_rules = out_dir / "semgrep" / "reachability.yml"
    run_cli(["export-semgrep-rules", "--out", str(semgrep_rules)])
    require_text(semgrep_rules, "reachability_advisor", "pattern")
    checks.append({"name": "generated Semgrep starter rules", "status": "passed", "document": str(semgrep_rules)})

    fixture_validation = out_dir / "fixtures-validate.json"
    run_cli(["fixtures", "validate", "--json-out", str(fixture_validation)])
    fixture_validation_data = require_json(fixture_validation)
    if fixture_validation_data.get("failed_count") != 0:
        raise ReleaseCheckError("fixture validation reported failures")
    checks.append({"name": "generated fixture validation report", "status": "passed", "document": str(fixture_validation)})

    fixture_report = out_dir / "fixtures-report.json"
    run_cli(["fixtures", "run", "--out", str(fixture_report), "--output-dir", str(out_dir / "fixtures")])
    check("generated fixture run report", fixture_report, "fixture-run-report.schema.json")

    complex_benchmark = out_dir / "complex-benchmark.json"
    complex_benchmark_md = out_dir / "complex-benchmark.md"
    benchmark = complex_validation._benchmark_snapshot(
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "corpus": str(ROOT / "external_corpus" / "complex_app_cases.json"),
            "case_count": 1,
            "passed_count": 1,
            "failed_count": 0,
            "skipped_count": 0,
            "cases": [
                {
                    "id": "release-contract",
                    "status": "passed",
                    "metrics": {
                        "sbom_count": 2,
                        "vulnerability_matches": 3,
                        "finding_count": 3,
                        "remediation_count": 2,
                        "services_with_findings": 2,
                        "terraform_resources": 5,
                        "terraform_artifacts_matched": 1,
                        "terraform_artifact_match_coverage": 0.5,
                        "mapping_warnings": 1,
                        "tier_counts": {"medium": 2, "high": 1},
                        "remediation_tier_counts": {"medium": 1, "high": 1},
                        "source_reachability_counts": {"import_observed": 2, "no_rule": 1},
                        "exposure_counts": {"public": 1, "internal": 2},
                        "privilege_counts": {"limited": 1, "sensitive": 1},
                    },
                    "expectations": [{"status": "passed"}],
                }
            ],
        }
    )
    complex_benchmark.write_text(json.dumps(benchmark, indent=2), encoding="utf-8")
    complex_validation._write_benchmark_markdown(benchmark, complex_benchmark_md)
    check("generated complex benchmark", complex_benchmark, "complex-benchmark.schema.json")
    require_text(complex_benchmark_md, "Complex App Benchmark", "Aggregate", "Terraform matches")
    checks.append({"name": "generated complex benchmark Markdown", "status": "passed", "document": str(complex_benchmark_md)})

    summary = {"schema_version": "1.0", "status": "passed", "checks": checks}
    (out_dir / "release-validation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _check_sarif_output(path: Path) -> None:
    data = require_json(path)
    if data.get("version") != "2.1.0" or not data.get("runs"):
        raise ReleaseCheckError(f"{path}: invalid SARIF output")
    results = data["runs"][0].get("results", [])
    if not isinstance(results, list) or not results:
        raise ReleaseCheckError(f"{path}: SARIF output contains no results")


def _check_diagnostics_output(path: Path) -> None:
    data = require_json(path)
    diagnostics = data.get("diagnostics")
    if not isinstance(diagnostics, list) or not diagnostics:
        raise ReleaseCheckError(f"{path}: diagnostics output contains no diagnostics")


def _check_vulnerability_imports(out_dir: Path, checks: list[dict[str, str]]) -> None:
    grype = out_dir / "grype-import.json"
    grype.write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "GHSA-lodash-import",
                            "severity": "High",
                            "description": "Grype import contract check.",
                            "cvss": [{"metrics": {"baseScore": 7.4}}],
                            "fix": {"versions": ["4.17.21"]},
                        },
                        "artifact": {"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    grype_findings = out_dir / "grype-import-findings.json"
    run_cli([
        "scan",
        "--sbom",
        str(ROOT / "samples" / "sboms" / "notifier.cdx.json"),
        "--vulns",
        str(grype),
        "--out",
        str(grype_findings),
        "--no-table",
    ])
    if "GHSA-lodash-import" not in {finding["vulnerability"]["id"] for finding in require_json(grype_findings)["findings"]}:
        raise ReleaseCheckError("Grype vulnerability import did not produce the expected finding")
    checks.append({"name": "Grype vulnerability import", "status": "passed", "document": str(grype_findings)})

    osv = out_dir / "osv-import.json"
    osv.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "packages": [
                            {
                                "package": {"name": "minimist", "version": "1.2.5", "purl": "pkg:npm/minimist@1.2.5"},
                                "vulnerabilities": [
                                    {
                                        "id": "GHSA-minimist-import",
                                        "aliases": ["CVE-2020-7598"],
                                        "severity": [{"type": "CVSS_V3", "score": "5.3"}],
                                        "summary": "OSV import contract check.",
                                        "fixed_versions": ["1.2.6"],
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    osv_findings = out_dir / "osv-import-findings.json"
    run_cli([
        "scan",
        "--sbom",
        str(ROOT / "samples" / "sboms" / "notifier.cdx.json"),
        "--vulns",
        str(osv),
        "--out",
        str(osv_findings),
        "--no-table",
    ])
    if "GHSA-minimist-import" not in {finding["vulnerability"]["id"] for finding in require_json(osv_findings)["findings"]}:
        raise ReleaseCheckError("OSV-style vulnerability import did not produce the expected finding")
    checks.append({"name": "OSV-style vulnerability import", "status": "passed", "document": str(osv_findings)})


def _check_external_source_evidence_imports(out_dir: Path, checks: list[dict[str, str]]) -> None:
    root = out_dir / "external-source-evidence"
    source = root / "src"
    source.mkdir(parents=True, exist_ok=True)
    (source / "app.js").write_text("const axios = require('axios');\nconst leftPad = require('left-pad');\n", encoding="utf-8")
    (source / "app.py").write_text("import requests\n", encoding="utf-8")
    (source / "main.go").write_text("package main\n", encoding="utf-8")

    sbom = root / "app.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "metadata": {"component": {"type": "application", "name": "evidence-app"}},
                "components": [
                    {"name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0"},
                    {"name": "urllib3", "version": "1.26.0", "purl": "pkg:pypi/urllib3@1.26.0"},
                    {"name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0"},
                    {"name": "axios", "version": "1.6.0", "purl": "pkg:npm/axios@1.6.0"},
                    {"name": "example.com/mod", "version": "1.0.0", "purl": "pkg:golang/example.com/mod@1.0.0"},
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    vulns = root / "vulns.json"
    vulns.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {"id": "GHSA-requests-import", "package": {"name": "requests"}, "affected_versions": ["2.19.0"], "severity": "high"},
                    {"id": "GHSA-urllib3-import", "package": {"name": "urllib3"}, "affected_versions": ["1.26.0"], "severity": "high"},
                    {"id": "GHSA-leftpad-import", "package": {"name": "left-pad"}, "affected_versions": ["1.0.0"], "severity": "high"},
                    {"id": "GHSA-axios-import", "package": {"name": "axios"}, "affected_versions": ["1.6.0"], "severity": "high"},
                    {"id": "GO-2024-0001", "package": {"name": "example.com/mod"}, "affected_versions": ["1.0.0"], "severity": "high"},
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    native = root / "native-evidence.json"
    native.write_text(
        json.dumps(
            {
                "evidence": [
                    {
                        "artifact": "evidence-app",
                        "component": "requests",
                        "vulnerability": "GHSA-requests-import",
                        "state": "imported",
                        "confidence": "high",
                        "source": "plain-tool",
                        "locations": [{"path": str(source / "app.py"), "line": 1}],
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    ra_findings = root / "reachability-findings-evidence.json"
    ra_findings.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "artifact": {"name": "evidence-app"},
                        "component": {"name": "urllib3", "purl": "pkg:pypi/urllib3@1.26.0"},
                        "vulnerability": {"id": "GHSA-urllib3-import"},
                        "source_reachability": {
                            "state": "imported",
                            "confidence": "high",
                            "language": "python",
                            "reason": "Reachability Advisor findings JSON import",
                            "locations": [{"path": str(source / "app.py"), "line": 1}],
                            "matched_symbols": ["urllib3"],
                            "evidence_source": "reachability-advisor",
                        },
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    semgrep = root / "semgrep.json"
    semgrep.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "reachability.npm.left-pad.attacker_controlled",
                        "path": "src/app.js",
                        "start": {"line": 2, "col": 1},
                        "extra": {
                            "message": "left-pad taint path",
                            "metadata": {"vulnerability": "GHSA-leftpad-import"},
                            "dataflow_trace": {
                                "taint_source": [{"path": "src/app.js", "start": {"line": 1, "col": 1}, "content": "req.query"}],
                                "taint_sink": [{"path": "src/app.js", "start": {"line": 2, "col": 1}, "content": "leftPad(value)"}],
                            },
                        },
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    codeql = root / "codeql.sarif"
    codeql.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "js/request-forgery", "properties": {"reachability_advisor": {"package": "axios"}}}]}},
                        "results": [
                            {
                                "ruleId": "js/request-forgery",
                                "message": {"text": "axios request URL reaches HTTP client"},
                                "properties": {"vulnerability": "GHSA-axios-import"},
                                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.js"}, "region": {"startLine": 1, "startColumn": 1}}}],
                                "codeFlows": [
                                    {
                                        "threadFlows": [
                                            {
                                                "locations": [
                                                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/app.js"}, "region": {"startLine": 1, "startColumn": 1}}}},
                                                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/app.js"}, "region": {"startLine": 2, "startColumn": 1}}}},
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    govuln = root / "govuln.jsonl"
    govuln.write_text(
        json.dumps(
            {
                "finding": {
                    "osv": "GO-2024-0001",
                    "trace": [
                        {
                            "module": "example.com/mod",
                            "position": {"filename": str(source / "main.go"), "line": 1, "column": 1},
                        }
                    ],
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    findings = root / "findings.json"
    coverage = root / "source-coverage.json"
    run_cli([
        "scan",
        "--sbom",
        str(sbom),
        "--vulns",
        str(vulns),
        "--source-root",
        f"evidence-app={source}",
        "--source-evidence-in",
        str(native),
        "--source-evidence-in",
        str(ra_findings),
        "--source-evidence-in",
        str(semgrep),
        "--source-evidence-in",
        str(codeql),
        "--source-evidence-in",
        str(govuln),
        "--out",
        str(findings),
        "--source-coverage-out",
        str(coverage),
        "--no-table",
    ])
    data = require_json(findings)
    sources = {finding["source_reachability"].get("evidence_source") for finding in data.get("findings", [])}
    expected = {"plain-tool", "reachability-advisor", "semgrep", "CodeQL", "govulncheck"}
    if not expected.issubset(sources):
        raise ReleaseCheckError(f"external source evidence imports missing sources: {sorted(expected - sources)}")
    coverage_data = require_json(coverage)
    if coverage_data.get("summary", {}).get("external_evidence_records") != 5:
        raise ReleaseCheckError("external source evidence coverage did not count all imported records")
    checks.append({"name": "external source evidence imports", "status": "passed", "document": str(findings)})


def _check_context_alias_and_custom_rule_imports(out_dir: Path, checks: list[dict[str, str]]) -> None:
    root = out_dir / "context-alias-rules"
    source = root / "src"
    source.mkdir(parents=True, exist_ok=True)
    (source / "index.js").write_text(
        "\n".join(
            [
                "const leftPad = require('left-pad');",
                "exports.handler = (event) => {",
                "  return leftPad(event.body, 10);",
                "};",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    sbom = root / "app.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "metadata": {"component": {"type": "application", "name": "alias-app"}},
                "components": [{"name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0"}],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    vulns = root / "vulns.json"
    vulns.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "id": "GHSA-leftpad-custom-rule",
                        "package": {"name": "left-pad"},
                        "affected_versions": ["1.0.0"],
                        "severity": "high",
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    context = root / "context.json"
    context.write_text(
        json.dumps(
            {
                "artifacts": {
                    "alias-app": {
                        "environment": "prod",
                        "exposure": "internal",
                        "privilege": "sensitive",
                        "criticality": "high",
                        "iam_impacts": ["data_access"],
                        "owner": "@team-contract",
                        "confidence": "high",
                        "evidence": ["context import contract"],
                    }
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    rules = root / "rules.json"
    rules.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "ecosystem": "npm",
                        "package": "left-pad",
                        "vulnerabilities": ["GHSA-leftpad-custom-rule"],
                        "import_patterns": [r"require\(['\"]left-pad['\"]\)"],
                        "function_patterns": [r"leftPad\s*\("],
                        "attacker_patterns": [r"event\.body", r"exports\.handler"],
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    tfplan = root / "tfplan.json"
    tfplan.write_text(
        json.dumps(
            {
                "format_version": "1.2",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": "aws_lambda_function.alias",
                                "type": "aws_lambda_function",
                                "name": "alias",
                                "values": {"function_name": "alias-app", "image_uri": "repo/alias-app:1"},
                            }
                        ]
                    }
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    policy = root / "policy.json"
    policy.write_text(json.dumps({"schema_version": "1.0", "fail_on_tier": "high", "exceptions": []}, indent=2), encoding="utf-8")
    validation = root / "validate.json"
    run_cli([
        "validate",
        "--sbom",
        str(sbom),
        "--vulns",
        str(vulns),
        "--source-root",
        f"alias-app={source}",
        "--context",
        str(context),
        "--terraform-plan",
        str(tfplan),
        "--reachability-rules",
        str(rules),
        "--policy",
        str(policy),
        "--json-out",
        str(validation),
    ])
    if require_json(validation).get("summary", {}).get("error") != 0:
        raise ReleaseCheckError("validate did not accept context/rules/policy import paths")
    findings = root / "findings.json"
    mapping = root / "mapping.json"
    terraform_coverage = root / "terraform-coverage.json"
    run_cli([
        "scan",
        "--sbom",
        str(sbom),
        "--vulns",
        str(vulns),
        "--source-root",
        f"alias-app={source}",
        "--context",
        str(context),
        "--terraform-plan",
        str(tfplan),
        "--artifact-alias",
        "alias-app=repo/alias-app:1",
        "--reachability-rules",
        str(rules),
        "--out",
        str(findings),
        "--mapping-out",
        str(mapping),
        "--terraform-coverage-out",
        str(terraform_coverage),
        "--no-table",
    ])
    finding_items = require_json(findings).get("findings", [])
    if not finding_items:
        raise ReleaseCheckError("context/alias/custom-rule import scan produced no findings")
    finding = finding_items[0]
    if finding.get("context", {}).get("owner") != "@team-contract":
        raise ReleaseCheckError("context JSON import did not appear in generated findings")
    source_state = finding.get("source_reachability", {}).get("state")
    source_reason = finding.get("source_reachability", {}).get("reason", "")
    if source_state not in {"function_reachable", "attacker_controlled"} or "rule" not in source_reason:
        raise ReleaseCheckError("custom reachability rule did not affect source reachability")
    mapping_data = require_json(mapping)
    if mapping_data.get("summary", {}).get("artifacts_with_terraform_matches") != 1:
        raise ReleaseCheckError("artifact alias did not enable Terraform artifact matching")
    checks.append({"name": "context, artifact alias, custom rule, and policy imports", "status": "passed", "document": str(findings)})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate stable release metadata and output schemas.")
    parser.add_argument("--out-dir", default=str(ROOT / "outputs" / "release-validation"), help="Directory for generated validation outputs.")
    args = parser.parse_args(argv)
    try:
        summary = run_release_validation(Path(args.out_dir))
    except Exception as exc:  # noqa: BLE001 - release scripts should print concise failure messages.
        print(f"Release validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Release validation passed: {len(summary['checks'])} checks")
    print(Path(args.out_dir) / "release-validation.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
