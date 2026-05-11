#!/usr/bin/env python3
"""Clone public Terraform corpus projects and run HCL static audits.

This is intentionally standard-library only so it works on Windows, macOS, and
Linux without requiring Bash or Terraform credentials. It audits published HCL
source as a real-world coverage check; it does not initialize Terraform modules
or claim plan-level reachability.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from reachability_advisor.hcl_static import (  # noqa: E402
    audit_hcl_project,
    render_hcl_audit_markdown,
)


def _default_corpus() -> Path:
    return ROOT / "external_corpus" / "popular_terraform_projects.json"


def _default_workdir() -> Path:
    return ROOT / "external_corpus" / "worktrees"


def _default_outdir() -> Path:
    return ROOT / "outputs" / "external-hcl-audit"


def _run(command: list[str], cwd: Path | None = None) -> None:
    subprocess.run(command, check=True, cwd=str(cwd) if cwd else None)


def _clone_or_reuse(project: dict[str, Any], workdir: Path, no_clone: bool) -> Path:
    checkout = workdir / str(project["id"])
    if checkout.exists():
        print(f"[reuse] {project['id']}: {checkout}")
        return checkout
    if no_clone:
        raise FileNotFoundError(f"{project['id']}: checkout does not exist and --no-clone was set")
    print(f"[clone] {project['id']}: {project['repo']}")
    _run(["git", "clone", "--depth", "1", str(project["repo"]), str(checkout)])
    return checkout


def _coverage_summary(report: dict[str, Any], expected_types: list[str]) -> dict[str, Any]:
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    summary = coverage.get("summary") if isinstance(coverage.get("summary"), dict) else {}
    seen = set(report.get("resource_types_seen") or [])
    resources = coverage.get("resources") if isinstance(coverage.get("resources"), list) else []
    classified = {str(row.get("type")) for row in resources if isinstance(row, dict) and row.get("supported")}
    unsupported = sorted(
        {
            str(row.get("type"))
            for row in resources
            if isinstance(row, dict) and not row.get("supported") and row.get("type")
        }
    )
    return {
        "tf_files": report.get("summary", {}).get("tf_files", 0),
        "resource_blocks": report.get("summary", {}).get("resource_blocks", 0),
        "module_blocks": report.get("summary", {}).get("module_blocks", 0),
        "data_blocks": report.get("summary", {}).get("data_blocks", 0),
        "literal_image_references": report.get("summary", {}).get("literal_image_references", 0),
        "unresolved_image_references": report.get("summary", {}).get("unresolved_image_references", 0),
        "semantic_classification_coverage": summary.get("semantic_classification_coverage", 1.0),
        "visibility_gaps": len(coverage.get("visibility_gaps") or []),
        "unsupported_types": unsupported,
        "missing_expected_types": [rtype for rtype in expected_types if rtype not in seen],
        "unclassified_expected_types": [rtype for rtype in expected_types if rtype in seen and rtype not in classified],
    }


def _source_path_rows(project: dict[str, Any], checkout: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rel in project.get("source_paths") or []:
        path = checkout / str(rel)
        rows.append({"path": str(path), "exists": path.exists(), "files": _source_file_count(path) if path.exists() else 0})
    return rows


def _source_file_count(path: Path) -> int:
    extensions = {".java", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go"}
    if path.is_file():
        return 1 if path.suffix.lower() in extensions else 0
    return sum(1 for item in path.rglob("*") if item.is_file() and item.suffix.lower() in extensions)


def _render_summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# External HCL Audit Summary",
        "",
        "This report audits public Terraform source without running `terraform init` or cloud-provider APIs.",
        "",
        "| Project | Provider | Resources | Semantic coverage | Gaps | Unsupported types | Expected missing |",
        "|---|---:|---:|---:|---:|---|---|",
    ]
    for row in summary["projects"]:
        if row["status"] != "passed":
            lines.append(f"| `{row['id']}` | {row.get('provider', '')} | n/a | n/a | n/a | error: {row.get('error', '')} | n/a |")
            continue
        cov = row["coverage"]
        unsupported = ", ".join(f"`{item}`" for item in cov["unsupported_types"][:8]) or "none"
        if len(cov["unsupported_types"]) > 8:
            unsupported += f", +{len(cov['unsupported_types']) - 8} more"
        missing = ", ".join(f"`{item}`" for item in cov["missing_expected_types"]) or "none"
        lines.append(
            "| "
            f"`{row['id']}` | {row.get('provider', '')} | {cov['resource_blocks']} | "
            f"{cov['semantic_classification_coverage']} | {cov['visibility_gaps']} | {unsupported} | {missing} |"
        )
    lines.extend(["", "## Notes", ""])
    lines.append("- Module blocks and unresolved expressions are reported as visibility gaps by design.")
    lines.append("- A full `terraform show -json` plan remains the stronger release-gate evidence path.")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    corpus_path = Path(args.corpus)
    workdir = Path(args.workdir)
    outdir = Path(args.outdir)
    workdir.mkdir(parents=True, exist_ok=True)
    outdir.mkdir(parents=True, exist_ok=True)
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for project in corpus.get("projects", []):
        if args.project and project.get("id") != args.project:
            continue
        row: dict[str, Any] = {
            "id": project.get("id"),
            "name": project.get("name"),
            "repo": project.get("repo"),
            "web": project.get("web"),
            "provider": project.get("provider"),
            "terraform_path": project.get("path", "."),
            "status": "failed",
        }
        try:
            checkout = _clone_or_reuse(project, workdir, args.no_clone)
            audit_path = checkout / str(project.get("path", "."))
            print(f"[audit] {project['id']}: {audit_path}")
            report = audit_hcl_project(audit_path).to_json()
            json_out = outdir / f"{project['id']}.hcl-audit.json"
            md_out = outdir / f"{project['id']}.hcl-audit.md"
            json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
            md_out.write_text(render_hcl_audit_markdown(report), encoding="utf-8")
            row.update(
                {
                    "status": "passed",
                    "checkout": str(checkout),
                    "report": str(json_out),
                    "markdown_report": str(md_out),
                    "source_paths": _source_path_rows(project, checkout),
                    "coverage": _coverage_summary(report, list(project.get("expected_resource_types") or [])),
                }
            )
        except Exception as exc:  # noqa: BLE001 - validation should continue across projects.
            row["error"] = str(exc)
            print(f"[error] {project.get('id')}: {exc}", file=sys.stderr)
        rows.append(row)
    summary = {
        "schema_version": "1.0",
        "corpus": str(corpus_path),
        "project_count": len(rows),
        "passed_count": sum(1 for row in rows if row["status"] == "passed"),
        "failed_count": sum(1 for row in rows if row["status"] != "passed"),
        "projects": rows,
    }
    summary_json = outdir / "summary.json"
    summary_md = outdir / "summary.md"
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    summary_md.write_text(_render_summary_markdown(summary), encoding="utf-8")
    print(f"Summary written to {summary_json}")
    if args.fail_on_errors and summary["failed_count"]:
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(_default_corpus()), help="External corpus JSON path.")
    parser.add_argument("--workdir", default=str(_default_workdir()), help="Directory for shallow clones.")
    parser.add_argument("--outdir", default=str(_default_outdir()), help="Directory for audit reports.")
    parser.add_argument("--project", help="Run only one corpus project id.")
    parser.add_argument("--no-clone", action="store_true", help="Use existing checkouts only.")
    parser.add_argument("--fail-on-errors", action="store_true", help="Exit non-zero when any project fails.")
    return parser


def main() -> int:
    return run(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
