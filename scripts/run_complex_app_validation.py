#!/usr/bin/env python3
"""Run complex real-world validation with Grype, source roots, and Terraform.

The harness is intentionally local-first. It reuses existing checkouts under
``external_corpus/worktrees`` and existing Grype cache locations when present.
Network is only needed when a requested worktree is missing and cloning is
allowed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from reachability_advisor.benchmark_snapshots import validate_benchmark_snapshots  # noqa: E402
from reachability_advisor.cli import main as advisor_main  # noqa: E402
from reachability_advisor.hcl_static import (  # noqa: E402
    audit_hcl_project,
    render_hcl_audit_markdown,
)
from reachability_advisor.kubernetes import analyze_kubernetes_manifests  # noqa: E402
from reachability_advisor.models import Artifact  # noqa: E402

DEFAULT_CORPUS = ROOT / "external_corpus" / "complex_app_cases.json"
DEFAULT_WORKTREES = ROOT / "external_corpus" / "worktrees"
DEFAULT_OUT = ROOT / "outputs" / "external-complex"
DEFAULT_GRYPE = Path("C:/tmp/grype-install/bin/grype.exe")
DEFAULT_GRYPE_DB = Path("C:/tmp/grype-db")


def _root_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _relative_cli_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _safe_name(value: str) -> str:
    safe = "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in value.strip())
    return safe or "artifact"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _resolve_grype(explicit: str | None) -> Path | None:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env_value = os.environ.get("GRYPE")
    if env_value:
        candidates.append(Path(env_value))
    path_value = shutil.which("grype")
    if path_value:
        candidates.append(Path(path_value))
    candidates.append(DEFAULT_GRYPE)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _grype_env(cache_dir: str | None) -> dict[str, str]:
    env = os.environ.copy()
    if cache_dir:
        env["GRYPE_DB_CACHE_DIR"] = str(_root_path(cache_dir))
    elif "GRYPE_DB_CACHE_DIR" not in env and DEFAULT_GRYPE_DB.exists():
        env["GRYPE_DB_CACHE_DIR"] = str(DEFAULT_GRYPE_DB)
    env.setdefault("GRYPE_CHECK_FOR_APP_UPDATE", "false")
    env.setdefault("GRYPE_DB_AUTO_UPDATE", "false")
    return env


def _run(command: list[str], cwd: Path = ROOT, env: dict[str, str] | None = None, log_base: Path | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=str(cwd), env=env, text=True, capture_output=True, check=False)
    if log_base:
        log_base.parent.mkdir(parents=True, exist_ok=True)
        (log_base.parent / f"{log_base.name}.stdout.txt").write_text(result.stdout or "", encoding="utf-8")
        (log_base.parent / f"{log_base.name}.stderr.txt").write_text(result.stderr or "", encoding="utf-8")
    return result


def _clone_or_reuse(case: dict[str, Any], worktrees: Path, no_clone: bool) -> Path:
    checkout = worktrees / str(case.get("worktree") or case["id"])
    if checkout.exists():
        print(f"[reuse] {case['id']}: {checkout}")
        return checkout
    if no_clone:
        raise FileNotFoundError(f"{case['id']}: checkout does not exist and --no-clone was set")
    print(f"[clone] {case['id']}: {case['repo']}")
    result = _run(["git", "clone", "--depth", "1", str(case["repo"]), str(checkout)])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git clone failed for {case['id']}")
    return checkout


def _scan_workload(
    workload: dict[str, Any],
    checkout: Path,
    case_out: Path,
    grype: Path,
    env: dict[str, str],
    refresh: bool,
    skip_grype: bool,
) -> dict[str, Any]:
    artifact = str(workload["artifact"])
    source = checkout / str(workload["source"])
    sbom_path = case_out / "sboms" / f"{_safe_name(artifact)}.cdx.json"
    grype_path = case_out / "vulns" / f"{_safe_name(artifact)}.grype.json"
    row: dict[str, Any] = {
        "artifact": artifact,
        "source": str(source),
        "sbom": str(sbom_path),
        "grype": str(grype_path),
        "status": "pending",
        "matches": 0,
        "warnings": [],
    }
    if not source.exists():
        row.update({"status": "failed", "error": f"source path does not exist: {source}"})
        return row
    if skip_grype and (not sbom_path.exists() or not grype_path.exists()):
        row.update({"status": "skipped", "error": "missing cached SBOM or Grype JSON while --skip-grype is set"})
        return row

    if refresh or not sbom_path.exists():
        sbom_path.parent.mkdir(parents=True, exist_ok=True)
        result = _run(
            [
                str(grype),
                f"dir:{_relative_cli_path(source)}",
                "-o",
                "cyclonedx-json",
                "--name",
                artifact,
                "--file",
                str(sbom_path),
            ],
            env=env,
            log_base=case_out / "logs" / f"{_safe_name(artifact)}.sbom",
        )
        if result.returncode != 0:
            row.update({"status": "failed", "error": result.stderr.strip() or result.stdout.strip() or "Grype SBOM generation failed"})
            return row
        if result.stderr.strip():
            row["warnings"].append(result.stderr.strip())

    if refresh or not grype_path.exists():
        grype_path.parent.mkdir(parents=True, exist_ok=True)
        result = _run(
            [str(grype), f"sbom:{_relative_cli_path(sbom_path)}", "-o", "json", "--file", str(grype_path)],
            env=env,
            log_base=case_out / "logs" / f"{_safe_name(artifact)}.vulns",
        )
        if result.returncode != 0:
            row.update({"status": "failed", "error": result.stderr.strip() or result.stdout.strip() or "Grype vulnerability scan failed"})
            return row
        if result.stderr.strip():
            row["warnings"].append(result.stderr.strip())

    matches = _read_json(grype_path).get("matches")
    row.update({"status": "passed", "matches": len(matches) if isinstance(matches, list) else 0})
    return row


def _merge_grype_reports(workload_rows: list[dict[str, Any]], output: Path) -> dict[str, Any]:
    merged_matches: list[dict[str, Any]] = []
    inputs: list[dict[str, Any]] = []
    for row in workload_rows:
        if row.get("status") != "passed":
            continue
        grype_path = Path(str(row["grype"]))
        data = _read_json(grype_path)
        matches = data.get("matches") if isinstance(data.get("matches"), list) else []
        inputs.append({"artifact": row["artifact"], "path": str(grype_path), "matches": len(matches)})
        for match in matches:
            if not isinstance(match, dict):
                continue
            stamped = dict(match)
            metadata = dict(stamped.get("reachability_advisor") or {})
            metadata["artifact"] = row["artifact"]
            stamped["reachability_advisor"] = metadata
            merged_matches.append(stamped)
    merged = {
        "schema_version": "1.0",
        "source": {"type": "reachability-advisor-complex-validation", "generated_at": dt.datetime.now(dt.timezone.utc).isoformat()},
        "inputs": inputs,
        "matches": merged_matches,
    }
    _write_json(output, merged)
    return {"path": str(output), "matches": len(merged_matches), "inputs": inputs}


def _run_hcl_audit(terraform_source: Path, case_out: Path) -> dict[str, Any]:
    audit_json = case_out / "hcl-audit.json"
    audit_md = case_out / "hcl-audit.md"
    report = audit_hcl_project(terraform_source).to_json()
    _write_json(audit_json, report)
    audit_md.write_text(render_hcl_audit_markdown(report), encoding="utf-8")
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    coverage_summary = coverage.get("summary") if isinstance(coverage.get("summary"), dict) else {}
    return {
        "path": str(audit_json),
        "markdown": str(audit_md),
        "tf_files": summary.get("tf_files", 0),
        "resource_blocks": summary.get("resource_blocks", 0),
        "module_blocks": summary.get("module_blocks", 0),
        "semantic_classification_coverage": coverage_summary.get("semantic_classification_coverage"),
        "visibility_gaps": len(coverage.get("visibility_gaps") or []),
    }


def _case_manifest_paths(case: dict[str, Any], checkout: Path) -> list[Path]:
    manifest_value = case.get("kubernetes_manifest")
    if not manifest_value:
        return []
    values = manifest_value if isinstance(manifest_value, list) else [manifest_value]
    paths: list[Path] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        paths.append(checkout / value)
    return paths


def _strip_yaml_value(value: str) -> str:
    value = value.strip()
    if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
        return value[1:-1]
    return value


def _parse_simple_yaml_documents(path: Path) -> list[dict[str, Any]]:
    """Parse the small scalar subset needed from Kubernetes manifests.

    The validation harness only needs names, labels, selectors, and service
    types. Keeping this local avoids adding a runtime YAML dependency just for
    external corpus validation.
    """

    docs: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").split("\n---"):
        root: dict[str, Any] = {}
        stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
        for line in raw.splitlines():
            without_comment = line.split("#", 1)[0].rstrip()
            if not without_comment.strip() or without_comment.lstrip().startswith("- "):
                continue
            if ":" not in without_comment:
                continue
            indent = len(line) - len(line.lstrip(" "))
            key, raw_value = without_comment.strip().split(":", 1)
            key = key.strip()
            if not key:
                continue
            while stack and indent <= stack[-1][0]:
                stack.pop()
            parent = stack[-1][1] if stack else root
            value = raw_value.strip()
            if value:
                parent[key] = _strip_yaml_value(value)
            else:
                child: dict[str, Any] = {}
                parent[key] = child
                stack.append((indent, child))
        if root.get("kind"):
            docs.append(root)
    return docs


def _nested(mapping: dict[str, Any], *path: str) -> Any:
    current: Any = mapping
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _manifest_metadata_name(doc: dict[str, Any]) -> str:
    return str(_nested(doc, "metadata", "name") or "")


def _label_values(mapping: Any) -> set[str]:
    if not isinstance(mapping, dict):
        return set()
    keys = {"app", "name", "k8s-app", "app.kubernetes.io/name", "component"}
    return {str(value) for key, value in mapping.items() if key in keys and value}


def _deployment_names(doc: dict[str, Any]) -> set[str]:
    names = {_manifest_metadata_name(doc)}
    names.update(_label_values(_nested(doc, "metadata", "labels")))
    names.update(_label_values(_nested(doc, "spec", "selector", "matchLabels")))
    names.update(_label_values(_nested(doc, "spec", "template", "metadata", "labels")))
    return {name for name in names if name}


def _service_selector_names(doc: dict[str, Any]) -> set[str]:
    names = {_manifest_metadata_name(doc)}
    names.update(_label_values(_nested(doc, "spec", "selector")))
    return {name for name in names if name}


def _service_exposure(doc: dict[str, Any]) -> str:
    service_type = str(_nested(doc, "spec", "type") or "ClusterIP")
    name = _manifest_metadata_name(doc).lower()
    if service_type in {"LoadBalancer", "NodePort"}:
        return "public"
    if service_type == "ExternalName" or "external" in name:
        return "external"
    return "internal"


def _max_exposure(values: list[str]) -> str:
    rank = {"unknown": 0, "isolated": 1, "private": 1, "internal": 2, "external": 3, "public": 4}
    return max(values or ["unknown"], key=lambda value: rank.get(value, 0))


def _generate_kubernetes_context(case: dict[str, Any], checkout: Path, workload_rows: list[dict[str, Any]], case_out: Path) -> dict[str, Any] | None:
    manifest_paths = _case_manifest_paths(case, checkout)
    if not manifest_paths:
        return None
    missing = [path for path in manifest_paths if not path.exists()]
    if missing:
        return {"status": "missing", "paths": [str(path) for path in missing], "contexts": 0}

    passed_artifacts = {str(row["artifact"]) for row in workload_rows if row.get("status") == "passed"}
    artifacts: list[Artifact] = []
    for workload in case.get("workloads") or []:
        artifact = str(workload["artifact"])
        if artifact not in passed_artifacts:
            continue
        aliases = ",".join(str(alias) for alias in workload.get("aliases") or [])
        artifacts.append(Artifact(name=artifact, properties={"reachability:aliases": aliases} if aliases else {}))

    analysis = analyze_kubernetes_manifests(
        manifest_paths,
        artifacts,
        infer_lateral_from_public_entry=bool(case.get("infer_cluster_lateral_from_public_entry")),
    )
    context: dict[str, Any] = {"schema_version": "1.0", "artifacts": {}}
    for artifact, evidence in analysis.contexts.items():
        context["artifacts"][artifact] = {
            "environment": evidence.environment,
            "exposure": evidence.exposure,
            "privilege": evidence.privilege,
            "criticality": evidence.criticality,
            "iam_impacts": evidence.iam_impacts,
            "confidence": evidence.confidence.value,
            "evidence": evidence.evidence,
        }

    output = case_out / "kubernetes-context.json"
    _write_json(output, context)
    summary = analysis.coverage.get("summary", {})
    return {
        "status": "passed",
        "path": str(output),
        "manifest": str(manifest_paths[0]) if len(manifest_paths) == 1 else [str(path) for path in manifest_paths],
        "manifests": [str(path) for path in manifest_paths],
        "workloads": len(context["artifacts"]),
        "services": summary.get("service_resources", 0),
        "service_matches": summary.get("artifacts_matched", 0),
        "exposure_counts": summary.get("exposure_counts", {}),
    }


def _run_advisor(
    case: dict[str, Any],
    checkout: Path,
    workload_rows: list[dict[str, Any]],
    merged_vulns: Path,
    case_out: Path,
    context_path: Path | None = None,
    kubernetes_manifests: list[Path] | None = None,
    infer_kubernetes_lateral: bool = False,
) -> dict[str, Any]:
    terraform_source_value = case.get("terraform_source")
    terraform_source = checkout / str(terraform_source_value) if terraform_source_value else None
    findings_out = case_out / "findings.json"
    markdown_out = case_out / "summary.md"
    html_out = case_out / "reachability-graph.html"
    coverage_out = case_out / "terraform-coverage.json"
    kubernetes_coverage_out = case_out / "kubernetes-coverage.json"
    source_coverage_out = case_out / "source-coverage.json"
    mapping_out = case_out / "mapping.json"
    args = ["scan"]
    for row in workload_rows:
        if row.get("status") == "passed":
            args.extend(["--sbom", str(row["sbom"])])
    if context_path:
        args.extend(["--context", str(context_path)])
    kubernetes_manifests = kubernetes_manifests or []
    if kubernetes_manifests:
        for manifest in kubernetes_manifests:
            args.extend(["--kubernetes-manifest", str(manifest)])
        args.extend(["--kubernetes-coverage-out", str(kubernetes_coverage_out)])
        if infer_kubernetes_lateral:
            args.append("--kubernetes-infer-lateral")
    args.extend(["--vuln-in", str(merged_vulns)])
    if terraform_source:
        args.extend(["--terraform-source", str(terraform_source), "--terraform-coverage-out", str(coverage_out)])
    args.extend(
        [
            "--source-coverage-out",
            str(source_coverage_out),
            "--mapping-out",
            str(mapping_out),
            "--out",
            str(findings_out),
            "--markdown-out",
            str(markdown_out),
            "--html-out",
            str(html_out),
            "--no-table",
        ]
    )
    for workload in case.get("workloads") or []:
        artifact = str(workload["artifact"])
        row = next((item for item in workload_rows if item.get("artifact") == artifact and item.get("status") == "passed"), None)
        if not row:
            continue
        args.extend(["--source-root", f"{artifact}={checkout / str(workload['source'])}"])
        for alias in workload.get("aliases") or []:
            args.extend(["--artifact-alias", f"{artifact}={alias}"])
    exit_code = advisor_main(args)
    return {
        "exit_code": exit_code,
        "findings": str(findings_out),
        "markdown": str(markdown_out),
        "html": str(html_out),
        "terraform_coverage": str(coverage_out),
        "kubernetes_coverage": str(kubernetes_coverage_out),
        "mapping": str(mapping_out),
    }


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = item.get(key)
        if value is None:
            continue
        counts[str(value)] = counts.get(str(value), 0) + 1
    return dict(sorted(counts.items()))


def _advisor_summary(advisor: dict[str, Any]) -> dict[str, Any]:
    findings_path = Path(str(advisor["findings"]))
    coverage_path = Path(str(advisor["terraform_coverage"]))
    mapping_path = Path(str(advisor["mapping"]))
    findings_doc = _read_json(findings_path) if findings_path.exists() else {}
    coverage_doc = _read_json(coverage_path) if coverage_path.exists() else {}
    mapping_doc = _read_json(mapping_path) if mapping_path.exists() else {}
    findings = findings_doc.get("findings") if isinstance(findings_doc.get("findings"), list) else []
    remediations = findings_doc.get("remediations") if isinstance(findings_doc.get("remediations"), list) else []
    services_with_findings = sorted({str(item.get("artifact", {}).get("name")) for item in findings if isinstance(item.get("artifact"), dict)})
    source_states: list[dict[str, Any]] = []
    contexts: list[dict[str, Any]] = []
    for finding in findings:
        if isinstance(finding.get("source_reachability"), dict):
            source_states.append({"state": finding["source_reachability"].get("state")})
        if isinstance(finding.get("context"), dict):
            contexts.append({"exposure": finding["context"].get("exposure"), "privilege": finding["context"].get("privilege")})
    coverage_summary = coverage_doc.get("summary") if isinstance(coverage_doc.get("summary"), dict) else {}
    mapping_summary = mapping_doc.get("summary") if isinstance(mapping_doc.get("summary"), dict) else {}
    return {
        "finding_count": len(findings),
        "remediation_count": len(remediations),
        "services_with_findings": len(services_with_findings),
        "service_names_with_findings": services_with_findings,
        "tier_counts": _count_by(findings, "tier"),
        "remediation_tier_counts": _count_by(remediations, "tier"),
        "source_reachability_counts": _count_by(source_states, "state"),
        "exposure_counts": _count_by(contexts, "exposure"),
        "privilege_counts": _count_by(contexts, "privilege"),
        "terraform_resources": coverage_summary.get("total_resources", 0),
        "terraform_semantic_coverage": coverage_summary.get("semantic_classification_coverage"),
        "deployment_artifact_match_coverage": mapping_summary.get("artifact_match_coverage"),
        "deployment_artifacts_matched": mapping_summary.get("artifacts_with_deployment_matches", 0),
        "terraform_artifact_match_coverage": mapping_summary.get("terraform_match_coverage", coverage_summary.get("artifact_match_coverage")),
        "terraform_artifacts_matched": mapping_summary.get("artifacts_with_terraform_matches", coverage_summary.get("artifacts_matched", 0)),
        "kubernetes_artifact_match_coverage": mapping_summary.get("kubernetes_match_coverage"),
        "kubernetes_artifacts_matched": mapping_summary.get("artifacts_with_kubernetes_matches", 0),
        "mapping_warnings": mapping_summary.get("mapping_warnings_count", len(mapping_doc.get("warnings") or [])),
        "mapping_artifacts_with_matches": mapping_summary.get("artifacts_with_deployment_matches", 0),
        "top_remediations": [
            {
                "artifact": item.get("artifact", {}).get("name"),
                "component": item.get("component", {}).get("display_name") or item.get("component", {}).get("name"),
                "tier": item.get("tier"),
                "score": item.get("max_score"),
                "reachability": item.get("reachability"),
                "exposure": item.get("context", {}).get("exposure") if isinstance(item.get("context"), dict) else None,
            }
            for item in remediations[:10]
        ],
    }


def _evaluate_expectations(metrics: dict[str, Any], expectations: dict[str, Any]) -> list[dict[str, Any]]:
    checks = [
        ("min_sboms", metrics.get("sbom_count", 0), "SBOMs generated"),
        ("min_vulnerability_matches", metrics.get("vulnerability_matches", 0), "Grype vulnerability matches"),
        ("min_findings", metrics.get("finding_count", 0), "Reachability Advisor findings"),
        ("min_services_with_findings", metrics.get("services_with_findings", 0), "services with findings"),
        ("min_terraform_resources", metrics.get("terraform_resources", 0), "Terraform resources"),
    ]
    results: list[dict[str, Any]] = []
    for key, actual, label in checks:
        if key not in expectations:
            continue
        expected = expectations[key]
        passed = float(actual or 0) >= float(expected)
        results.append({"id": key, "label": label, "expected_min": expected, "actual": actual, "status": "passed" if passed else "failed"})
    if metrics.get("html_exists") is not None:
        results.append({"id": "html_report", "label": "HTML graph report exists", "expected": True, "actual": metrics["html_exists"], "status": "passed" if metrics["html_exists"] else "failed"})
    return results


def _merge_counts(left: dict[str, int], right: Any) -> None:
    if not isinstance(right, dict):
        return
    for key, value in right.items():
        try:
            increment = int(value)
        except (TypeError, ValueError):
            continue
        left[str(key)] = left.get(str(key), 0) + increment


def _benchmark_snapshot(report: dict[str, Any]) -> dict[str, Any]:
    aggregate: dict[str, Any] = {
        "case_count": report.get("case_count", 0),
        "passed_count": report.get("passed_count", 0),
        "failed_count": report.get("failed_count", 0),
        "skipped_count": report.get("skipped_count", 0),
        "sbom_count": 0,
        "vulnerability_matches": 0,
        "finding_count": 0,
        "remediation_count": 0,
        "services_with_findings": 0,
        "terraform_resources": 0,
        "deployment_artifacts_matched": 0,
        "terraform_artifacts_matched": 0,
        "kubernetes_artifacts_matched": 0,
        "mapping_warnings": 0,
        "tier_counts": {},
        "remediation_tier_counts": {},
        "source_reachability_counts": {},
        "exposure_counts": {},
        "privilege_counts": {},
    }
    cases: list[dict[str, Any]] = []
    for row in report.get("cases") or []:
        if not isinstance(row, dict):
            continue
        metrics = row.get("metrics") if isinstance(row.get("metrics"), dict) else {}
        expectations = row.get("expectations") if isinstance(row.get("expectations"), list) else []
        case = {
            "id": row.get("id"),
            "status": row.get("status"),
            "sbom_count": metrics.get("sbom_count", 0),
            "vulnerability_matches": metrics.get("vulnerability_matches", 0),
            "finding_count": metrics.get("finding_count", 0),
            "remediation_count": metrics.get("remediation_count", 0),
            "services_with_findings": metrics.get("services_with_findings", 0),
            "terraform_resources": metrics.get("terraform_resources", 0),
            "deployment_artifacts_matched": metrics.get("deployment_artifacts_matched", 0),
            "deployment_artifact_match_coverage": metrics.get("deployment_artifact_match_coverage"),
            "terraform_artifacts_matched": metrics.get("terraform_artifacts_matched", 0),
            "terraform_artifact_match_coverage": metrics.get("terraform_artifact_match_coverage"),
            "kubernetes_artifacts_matched": metrics.get("kubernetes_artifacts_matched", 0),
            "kubernetes_artifact_match_coverage": metrics.get("kubernetes_artifact_match_coverage"),
            "mapping_warnings": metrics.get("mapping_warnings", 0),
            "tier_counts": metrics.get("tier_counts", {}),
            "remediation_tier_counts": metrics.get("remediation_tier_counts", {}),
            "source_reachability_counts": metrics.get("source_reachability_counts", {}),
            "exposure_counts": metrics.get("exposure_counts", {}),
            "privilege_counts": metrics.get("privilege_counts", {}),
            "expectations_passed": sum(1 for item in expectations if isinstance(item, dict) and item.get("status") == "passed"),
            "expectations_failed": sum(1 for item in expectations if isinstance(item, dict) and item.get("status") != "passed"),
        }
        cases.append(case)
        for key in (
            "sbom_count",
            "vulnerability_matches",
            "finding_count",
            "remediation_count",
            "services_with_findings",
            "terraform_resources",
            "deployment_artifacts_matched",
            "terraform_artifacts_matched",
            "kubernetes_artifacts_matched",
            "mapping_warnings",
        ):
            aggregate[key] += int(metrics.get(key) or 0)
        _merge_counts(aggregate["tier_counts"], metrics.get("tier_counts"))
        _merge_counts(aggregate["remediation_tier_counts"], metrics.get("remediation_tier_counts"))
        _merge_counts(aggregate["source_reachability_counts"], metrics.get("source_reachability_counts"))
        _merge_counts(aggregate["exposure_counts"], metrics.get("exposure_counts"))
        _merge_counts(aggregate["privilege_counts"], metrics.get("privilege_counts"))
    return {
        "schema_version": "1.0",
        "generated_at": report.get("generated_at"),
        "corpus": report.get("corpus"),
        "aggregate": aggregate,
        "cases": cases,
    }


def _write_benchmark_markdown(benchmark: dict[str, Any], path: Path) -> None:
    aggregate = benchmark["aggregate"]
    lines = [
        "# Complex App Benchmark",
        "",
        "This benchmark captures deterministic metrics from the complex validation corpus.",
        "",
        "## Aggregate",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Cases | {aggregate.get('case_count', 0)} |",
        f"| Passed | {aggregate.get('passed_count', 0)} |",
        f"| Skipped | {aggregate.get('skipped_count', 0)} |",
        f"| Failed | {aggregate.get('failed_count', 0)} |",
        f"| SBOMs | {aggregate.get('sbom_count', 0)} |",
        f"| Grype matches | {aggregate.get('vulnerability_matches', 0)} |",
        f"| Findings | {aggregate.get('finding_count', 0)} |",
        f"| Remediation groups | {aggregate.get('remediation_count', 0)} |",
        f"| Services with findings | {aggregate.get('services_with_findings', 0)} |",
        f"| Terraform resources | {aggregate.get('terraform_resources', 0)} |",
        f"| Deployment artifacts matched | {aggregate.get('deployment_artifacts_matched', 0)} |",
        f"| Terraform artifacts matched | {aggregate.get('terraform_artifacts_matched', 0)} |",
        f"| Kubernetes artifacts matched | {aggregate.get('kubernetes_artifacts_matched', 0)} |",
        "",
        "## Cases",
        "",
        "| Case | Status | SBOMs | Matches | Findings | Services | Terraform resources | Deployment matches | Terraform matches | Kubernetes matches | Expectation failures |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in benchmark["cases"]:
        lines.append(
            f"| `{row.get('id')}` | {row.get('status')} | {row.get('sbom_count', 0)} | {row.get('vulnerability_matches', 0)} | "
            f"{row.get('finding_count', 0)} | {row.get('services_with_findings', 0)} | {row.get('terraform_resources', 0)} | "
            f"{row.get('deployment_artifacts_matched', 0)} | "
            f"{row.get('terraform_artifacts_matched', 0)} | "
            f"{row.get('kubernetes_artifacts_matched', 0)} | "
            f"{row.get('expectations_failed', 0)} |"
        )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _run_case(case: dict[str, Any], args: argparse.Namespace, grype: Path | None) -> dict[str, Any]:
    case_out = _root_path(args.outdir) / str(case["id"])
    case_out.mkdir(parents=True, exist_ok=True)
    row: dict[str, Any] = {
        "id": case["id"],
        "name": case.get("name"),
        "repo": case.get("repo"),
        "web": case.get("web"),
        "status": "failed",
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "output_dir": str(case_out),
    }
    try:
        checkout = _clone_or_reuse(case, _root_path(args.worktrees), args.no_clone)
        terraform_source_value = case.get("terraform_source")
        terraform_source = checkout / str(terraform_source_value) if terraform_source_value else None
        if terraform_source and not terraform_source.exists():
            raise FileNotFoundError(f"Terraform source does not exist: {terraform_source}")
        if grype is None and not args.skip_grype:
            row.update({"status": "skipped", "error": "grype executable was not found"})
            return row

        env = _grype_env(args.grype_db_cache_dir)
        workload_rows: list[dict[str, Any]] = []
        for workload in case.get("workloads") or []:
            if args.workload and workload.get("artifact") != args.workload:
                continue
            if args.skip_grype:
                result = _scan_workload(workload, checkout, case_out, grype or Path("grype"), env, refresh=False, skip_grype=True)
            else:
                assert grype is not None
                result = _scan_workload(workload, checkout, case_out, grype, env, args.refresh, skip_grype=False)
            print(f"[{result['status']}] {case['id']}/{result['artifact']}: {result.get('matches', 0)} matches")
            workload_rows.append(result)
        passed_workloads = [item for item in workload_rows if item.get("status") == "passed"]
        if not passed_workloads:
            row.update({"status": "skipped", "workloads": workload_rows, "error": "no workload scans passed"})
            return row

        merged_vulns = case_out / "merged-grype.json"
        merged_summary = _merge_grype_reports(passed_workloads, merged_vulns)
        hcl_summary = _run_hcl_audit(terraform_source, case_out) if terraform_source else None
        kubernetes_context = _generate_kubernetes_context(case, checkout, passed_workloads, case_out)
        kubernetes_manifests = _case_manifest_paths(case, checkout)
        if any(not manifest.exists() for manifest in kubernetes_manifests):
            kubernetes_manifests = []
        advisor = _run_advisor(
            case,
            checkout,
            passed_workloads,
            merged_vulns,
            case_out,
            kubernetes_manifests=kubernetes_manifests,
            infer_kubernetes_lateral=bool(case.get("infer_cluster_lateral_from_public_entry")),
        )
        advisor_metrics = _advisor_summary(advisor)
        metrics = {
            "sbom_count": len(passed_workloads),
            "vulnerability_matches": merged_summary["matches"],
            "html_exists": Path(str(advisor["html"])).exists(),
            **advisor_metrics,
        }
        expectation_results = _evaluate_expectations(metrics, case.get("expectations") or {})
        failed_expectations = [item for item in expectation_results if item["status"] != "passed"]
        failed_workloads = [item for item in workload_rows if item.get("status") not in {"passed"}]
        status = "passed" if advisor["exit_code"] == 0 and not failed_expectations and not failed_workloads else "failed"
        row.update(
            {
                "status": status,
                "checkout": str(checkout),
                "terraform_source": str(terraform_source) if terraform_source else None,
                "workloads": workload_rows,
                "merged_vulnerabilities": merged_summary,
                "hcl_audit": hcl_summary,
                "kubernetes_context": kubernetes_context,
                "advisor": advisor,
                "metrics": metrics,
                "expectations": expectation_results,
                "expected_limitations": case.get("expected_limitations") or [],
            }
        )
    except Exception as exc:  # noqa: BLE001 - validation should record all case failures.
        row.update({"status": "failed", "error": str(exc)})
    finally:
        row["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    _write_json(case_out / "case-summary.json", row)
    _write_case_markdown(row, case_out / "case-summary.md")
    return row


def _write_case_markdown(row: dict[str, Any], path: Path) -> None:
    lines = [f"# {row.get('name') or row['id']}", "", f"Status: `{row['status']}`", ""]
    if row.get("error"):
        lines.extend(["## Error", "", str(row["error"]), ""])
    if row.get("metrics"):
        metrics = row["metrics"]
        lines.extend(
            [
                "## Metrics",
                "",
                "| Metric | Value |",
                "|---|---:|",
                f"| SBOMs | {metrics.get('sbom_count', 0)} |",
                f"| Grype matches | {metrics.get('vulnerability_matches', 0)} |",
                f"| Findings | {metrics.get('finding_count', 0)} |",
                f"| Remediation groups | {metrics.get('remediation_count', 0)} |",
                f"| Finding tier counts | `{json.dumps(metrics.get('tier_counts', {}), sort_keys=True)}` |",
                f"| Remediation tier counts | `{json.dumps(metrics.get('remediation_tier_counts', {}), sort_keys=True)}` |",
                f"| Services with findings | {metrics.get('services_with_findings', 0)} |",
                f"| Terraform resources | {metrics.get('terraform_resources', 0)} |",
                f"| Terraform semantic coverage | {metrics.get('terraform_semantic_coverage')} |",
                f"| Deployment artifact match coverage | {metrics.get('deployment_artifact_match_coverage')} |",
                f"| Terraform artifact match coverage | {metrics.get('terraform_artifact_match_coverage')} |",
                f"| Kubernetes artifact match coverage | {metrics.get('kubernetes_artifact_match_coverage')} |",
                "",
            ]
        )
    if row.get("expectations"):
        lines.extend(["## Expectations", "", "| Check | Expected | Actual | Status |", "|---|---:|---:|---|"])
        for check in row["expectations"]:
            expected = check.get("expected_min", check.get("expected"))
            lines.append(f"| {check['label']} | {expected} | {check.get('actual')} | {check['status']} |")
        lines.append("")
    top = (row.get("metrics") or {}).get("top_remediations") or []
    if top:
        lines.extend(["## Top Remediations", "", "| Artifact | Component | Tier | Score | Reachability | Exposure |", "|---|---|---|---:|---|---|"])
        for item in top:
            lines.append(
                f"| `{item.get('artifact')}` | `{item.get('component')}` | {item.get('tier')} | {item.get('score')} | {item.get('reachability')} | {item.get('exposure')} |"
            )
        lines.append("")
    if row.get("advisor"):
        advisor = row["advisor"]
        lines.extend(
            [
                "## Outputs",
                "",
                f"- Findings JSON: `{advisor.get('findings')}`",
                f"- HTML graph: `{advisor.get('html')}`",
                f"- Terraform coverage: `{advisor.get('terraform_coverage')}`",
                f"- Kubernetes coverage: `{advisor.get('kubernetes_coverage')}`",
                f"- Mapping report: `{advisor.get('mapping')}`",
                "",
            ]
        )
    if row.get("expected_limitations"):
        lines.extend(["## Known Limitations", ""])
        lines.extend(f"- {item}" for item in row["expected_limitations"])
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_aggregate_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        "# Complex App Validation Summary",
        "",
        "| Case | Status | Workloads | Grype matches | Findings | Services | Terraform resources | Deployment match | Terraform match | Kubernetes match |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["cases"]:
        metrics = row.get("metrics") or {}
        lines.append(
            f"| `{row['id']}` | {row['status']} | {metrics.get('sbom_count', 0)} | {metrics.get('vulnerability_matches', 0)} | "
            f"{metrics.get('finding_count', 0)} | {metrics.get('services_with_findings', 0)} | {metrics.get('terraform_resources', 0)} | "
            f"{metrics.get('deployment_artifact_match_coverage')} | "
            f"{metrics.get('terraform_artifact_match_coverage')} | "
            f"{metrics.get('kubernetes_artifact_match_coverage')} |"
        )
    lines.extend(["", "Outputs are written below `outputs/external-complex/<case-id>/`.", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def run(args: argparse.Namespace) -> int:
    corpus_path = _root_path(args.corpus)
    outdir = _root_path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    corpus = _read_json(corpus_path)
    grype = _resolve_grype(args.grype)
    if grype:
        print(f"[tool] grype: {grype}")
    elif not args.skip_grype:
        print("[tool] grype: not found")
    cases = []
    for case in corpus.get("cases") or []:
        if args.case and case.get("id") != args.case:
            continue
        cases.append(_run_case(case, args, grype))
    report = {
        "schema_version": "1.0",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "corpus": str(corpus_path),
        "case_count": len(cases),
        "passed_count": sum(1 for case in cases if case["status"] == "passed"),
        "failed_count": sum(1 for case in cases if case["status"] == "failed"),
        "skipped_count": sum(1 for case in cases if case["status"] == "skipped"),
        "cases": cases,
    }
    _write_json(outdir / "summary.json", report)
    _write_aggregate_markdown(report, outdir / "summary.md")
    benchmark = _benchmark_snapshot(report)
    _write_json(outdir / "benchmark.json", benchmark)
    _write_benchmark_markdown(benchmark, outdir / "benchmark.md")
    benchmark_regression_failed = False
    if args.benchmark_expectations:
        regression_report = validate_benchmark_snapshots(benchmark, _root_path(args.benchmark_expectations))
        _write_json(outdir / "benchmark-regression.json", regression_report)
        benchmark_regression_failed = regression_report.get("status") != "passed"
    print(f"Summary written to {outdir / 'summary.json'}")
    if benchmark_regression_failed and args.fail_on_benchmark_regression:
        return 2
    if report["failed_count"] or (args.strict and report["skipped_count"]):
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS), help="Complex app corpus JSON path.")
    parser.add_argument("--case", help="Run only one case id.")
    parser.add_argument("--workload", help="Run only one workload artifact from the selected case.")
    parser.add_argument("--worktrees", default=str(DEFAULT_WORKTREES), help="Directory containing or receiving repository checkouts.")
    parser.add_argument("--outdir", default=str(DEFAULT_OUT), help="Directory for validation reports.")
    parser.add_argument("--grype", help="Path to grype executable. Defaults to GRYPE, PATH, or C:/tmp/grype-install/bin/grype.exe.")
    parser.add_argument("--grype-db-cache-dir", help="Grype DB cache directory. Defaults to GRYPE_DB_CACHE_DIR or C:/tmp/grype-db when present.")
    parser.add_argument("--refresh", action="store_true", help="Regenerate SBOM and Grype JSON even when cached outputs exist.")
    parser.add_argument("--skip-grype", action="store_true", help="Reuse existing SBOM and Grype JSON files only.")
    parser.add_argument("--no-clone", action="store_true", help="Do not clone missing repositories.")
    parser.add_argument("--strict", action="store_true", help="Return non-zero on skipped cases as well as failed cases.")
    parser.add_argument("--benchmark-expectations", help="Validate generated benchmark.json against checked-in tier snapshot expectations.")
    parser.add_argument("--fail-on-benchmark-regression", action="store_true", help="Return non-zero when benchmark snapshot validation fails.")
    return parser


def main() -> int:
    return run(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
