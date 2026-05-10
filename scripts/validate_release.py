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
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from reachability_advisor import __version__  # noqa: E402
from reachability_advisor.cli import main as cli_main  # noqa: E402


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

    check("sample vulnerability intelligence", ROOT / "samples" / "vulnerabilities.json", "vulnerability-intelligence.schema.json")
    check("sample context", ROOT / "samples" / "context.json", "context.schema.json")
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
        ]
    )
    check("generated SBOM plan", sbom_plan, "sbom-plan.schema.json")

    hcl_audit = out_dir / "hcl-audit.json"
    run_cli(["hcl-audit", "--path", str(ROOT / "samples" / "terraform-source"), "--out", str(hcl_audit)])
    check("generated HCL audit", hcl_audit, "hcl-audit-report.schema.json")

    findings = out_dir / "findings.json"
    terraform_coverage = out_dir / "terraform-coverage.json"
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
            "--vulns",
            str(ROOT / "samples" / "vulnerabilities.json"),
            "--terraform-plan",
            str(ROOT / "samples" / "tfplan-multicloud.json"),
            "--terraform-coverage-out",
            str(terraform_coverage),
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
            "--out",
            str(findings),
            "--no-table",
        ]
    )
    check("generated findings", findings, "findings.schema.json")
    check("generated Terraform coverage", terraform_coverage, "terraform-coverage.schema.json")
    check("generated mapping report", mapping, "mapping-report.schema.json")

    fixture_report = out_dir / "fixtures-report.json"
    run_cli(["fixtures", "run", "--out", str(fixture_report), "--output-dir", str(out_dir / "fixtures")])
    check("generated fixture run report", fixture_report, "fixture-run-report.schema.json")

    summary = {"schema_version": "1.0", "status": "passed", "checks": checks}
    (out_dir / "release-validation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


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
