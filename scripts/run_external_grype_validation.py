#!/usr/bin/env python
"""Rerun real-world Grype handoff validation cases.

This script expects the Grype/CycloneDX files under ``outputs/external-grype``
to already exist. It does not call Grype or download a vulnerability database;
it only reruns Reachability Advisor against those scanner outputs and records
the source/IaC scoring result.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from reachability_advisor.cli import main  # noqa: E402


@dataclass(frozen=True)
class ValidationCase:
    case_id: str
    artifact: str
    sbom: Path
    vulns: Path
    source_root: Path
    terraform_source: Path
    expected_top_component: str


OUT = ROOT / "outputs" / "external-grype"

CASES = (
    ValidationCase(
        case_id="petclinic",
        artifact="petclinic",
        sbom=OUT / "petclinic.cdx.json",
        vulns=OUT / "petclinic.grype.json",
        source_root=ROOT / "external_corpus" / "worktrees" / "aws-ecs-cicd-petclinic" / "petclinic",
        terraform_source=ROOT / "external_corpus" / "worktrees" / "aws-ecs-cicd-petclinic" / "terraform",
        expected_top_component="bootstrap",
    ),
    ValidationCase(
        case_id="aws-ecs-demo-backend",
        artifact="aws-ecs-demo-backend",
        sbom=OUT / "aws-ecs-demo-backend.cdx.json",
        vulns=OUT / "aws-ecs-demo-backend.grype.json",
        source_root=ROOT / "external_corpus" / "worktrees" / "aws-ecs-fullstack-app-terraform" / "Code" / "server",
        terraform_source=ROOT / "external_corpus" / "worktrees" / "aws-ecs-fullstack-app-terraform" / "Infrastructure",
        expected_top_component="express",
    ),
    ValidationCase(
        case_id="azure-chatapp",
        artifact="chatapp",
        sbom=OUT / "azure-chatapp.cdx.json",
        vulns=OUT / "azure-chatapp.grype.json",
        source_root=ROOT / "external_corpus" / "worktrees" / "azure-container-apps-openai" / "src",
        terraform_source=ROOT / "external_corpus" / "worktrees" / "azure-container-apps-openai" / "terraform" / "apps",
        expected_top_component="chainlit",
    ),
)


def _require_inputs(case: ValidationCase) -> list[str]:
    missing: list[str] = []
    for path in (case.sbom, case.vulns, case.source_root, case.terraform_source):
        if not path.exists():
            missing.append(str(path))
    return missing


def _run_case(case: ValidationCase) -> dict[str, Any]:
    missing = _require_inputs(case)
    if missing:
        return {"id": case.case_id, "status": "skipped", "missing": missing}

    findings_out = OUT / f"{case.case_id}.findings.json"
    markdown_out = OUT / f"{case.case_id}.summary.md"
    coverage_out = OUT / f"{case.case_id}.terraform-coverage.json"
    source_coverage_out = OUT / f"{case.case_id}.source-coverage.json"
    mapping_out = OUT / f"{case.case_id}.mapping.json"
    code = main(
        [
            "scan",
            "--sbom",
            str(case.sbom),
            "--vuln-in",
            str(case.vulns),
            "--source-root",
            f"{case.artifact}={case.source_root}",
            "--terraform-source",
            str(case.terraform_source),
            "--out",
            str(findings_out),
            "--markdown-out",
            str(markdown_out),
            "--terraform-coverage-out",
            str(coverage_out),
            "--source-coverage-out",
            str(source_coverage_out),
            "--mapping-out",
            str(mapping_out),
            "--no-table",
        ]
    )
    findings = json.loads(findings_out.read_text(encoding="utf-8"))
    coverage = json.loads(coverage_out.read_text(encoding="utf-8"))
    mapping = json.loads(mapping_out.read_text(encoding="utf-8"))
    remediations = findings.get("remediations") or []
    top = remediations[0] if remediations else {}
    top_component = ((top.get("component") or {}).get("name") or "")
    return {
        "id": case.case_id,
        "status": "passed" if code == 0 and top_component == case.expected_top_component else "failed",
        "exit_code": code,
        "expected_top_component": case.expected_top_component,
        "top_component": top_component,
        "top_reachability": top.get("reachability"),
        "top_tier": top.get("tier"),
        "top_score": top.get("max_score"),
        "finding_count": len(findings.get("findings") or []),
        "remediation_count": len(remediations),
        "terraform_semantic_coverage": coverage.get("summary", {}).get("semantic_classification_coverage"),
        "terraform_artifact_match_coverage": coverage.get("summary", {}).get("artifact_match_coverage"),
        "terraform_match_count": mapping.get("summary", {}).get("artifacts_with_terraform_matches"),
    }


def _write_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        "# External Grype Validation Summary",
        "",
        "| Case | Status | Top component | Reachability | Tier | Score | Terraform semantic | Terraform artifact match |",
        "|---|---|---|---|---|---:|---:|---:|",
    ]
    for row in report["cases"]:
        if row["status"] == "skipped":
            lines.append(f"| `{row['id']}` | skipped | missing inputs | n/a | n/a | 0 | n/a | n/a |")
            continue
        lines.append(
            "| `{id}` | {status} | `{top_component}` | {top_reachability} | {top_tier} | {top_score} | {terraform_semantic_coverage} | {terraform_artifact_match_coverage} |".format(
                **row
            )
        )
    lines.extend(
        [
            "",
            "These runs reuse existing Grype JSON and CycloneDX files. They validate the Reachability Advisor handoff, source rules, Terraform source coverage, mapping report, and remediation grouping without refreshing the Grype DB.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main_script() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    cases = [_run_case(case) for case in CASES]
    failed = [case for case in cases if case["status"] == "failed"]
    report = {
        "schema_version": "1.0",
        "case_count": len(cases),
        "passed_count": sum(1 for case in cases if case["status"] == "passed"),
        "failed_count": len(failed),
        "skipped_count": sum(1 for case in cases if case["status"] == "skipped"),
        "cases": cases,
    }
    (OUT / "summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    _write_markdown(report, OUT / "summary.md")
    print(f"Summary written to {OUT / 'summary.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main_script())
