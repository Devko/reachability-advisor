"""Command-line interface for Reachability Advisor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .artifact_manifest import (
    ArtifactManifestError,
    apply_artifact_manifests,
    create_artifact_manifest_payload,
    validate_artifact_manifest,
    write_artifact_manifest,
)
from .baseline import (
    baseline_as_findings_json,
    create_baseline_from_findings,
    load_baseline,
    write_baseline,
)
from .benchmark_snapshots import BenchmarkSnapshotError, validate_benchmark_snapshots
from .cli_parser import build_parser
from .cli_quality import (
    _annotate_analysis_profile,
    _findings_fail,
    _quality_gate_failures,
)
from .compare import compare_findings, delta_fails, pr_delta, write_delta, write_delta_markdown
from .context import ContextError, load_context_file
from .correlation import apply_correlations
from .demo_assets import write_demo_inputs
from .effective_exposure import enrich_context_map_with_effective_exposure
from .evidence_graph import build_evidence_graph
from .finding_types import (
    CLOUD_POSTURE_FINDING,
    DYNAMIC_RUNTIME_OBSERVATION,
    STATIC_CODE_WEAKNESS,
    count_canonical_types,
)
from .fixtures import (
    FixtureError,
    discover_fixture_packs,
    load_fixture_pack,
    run_fixture_packs,
    validate_fixture_pack,
)
from .hcl_static import (
    HclAuditError,
    analyze_terraform_source,
    audit_hcl_project,
    render_hcl_audit_markdown,
)
from .iac_render import (
    recommend_iac_render_commands,
    render_iac_render_plan_markdown,
    write_iac_render_plan_json,
)
from .kubernetes import (
    KubernetesManifestError,
    analyze_kubernetes_manifests,
    empty_kubernetes_coverage_report,
    merge_context_maps,
)
from .mapping import build_mapping_report
from .models import ContextEvidence, Tier
from .outputs import (
    explain_finding,
    load_findings_json,
    render_table,
    write_annotations,
    write_diagnostics,
    write_json_findings,
    write_markdown_report,
    write_sarif,
)
from .policy import apply_exceptions, load_runtime_policy
from .posture import native_posture_records
from .readiness import load_release_readiness_inputs, release_readiness_report
from .sbom import SbomError, load_sboms
from .sbom_plan import recommend_sbom_commands, render_sbom_plan_markdown, write_sbom_plan_json
from .scoring import generate_findings_with_source_report
from .security_evidence import (
    SecurityEvidenceError,
    generate_security_findings,
    load_security_evidence,
)
from .security_profiles import write_security_evidence_pack
from .source import (
    BUILTIN_RULES,
    load_external_source_evidence,
    load_reachability_rules,
    parse_source_roots,
    semgrep_rules_yaml,
)
from .source_evidence_pack import write_source_evidence_pack
from .source_evidence_plan import (
    recommend_source_evidence_commands,
    render_source_evidence_plan_markdown,
    write_source_evidence_plan_json,
)
from .terraform import TerraformContextError, analyze_terraform_plan, empty_coverage_report
from .validators import has_errors, issues_report, validate_paths
from .visual import write_html_report
from .vulnerability import VulnerabilityError, load_vulnerabilities


class UserFacingError(Exception):
    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def run_fixtures(args: argparse.Namespace) -> int:
    if args.fixtures_command == "list":
        rows = []
        for manifest_path in discover_fixture_packs(args.root):
            pack = load_fixture_pack(manifest_path)
            rows.append({"id": pack.id, "name": pack.name, "provider": pack.data.get("provider"), "path": str(pack.root)})
        if args.json:
            print(json.dumps({"fixtures": rows}, indent=2))
        else:
            if not rows:
                print("No fixture packs found.")
            else:
                widths = {
                    "id": max(len("id"), *(len(str(row["id"])) for row in rows)),
                    "provider": max(len("provider"), *(len(str(row["provider"])) for row in rows)),
                    "name": max(len("name"), *(len(str(row["name"])) for row in rows)),
                }
                print(f"{'id'.ljust(widths['id'])} | {'provider'.ljust(widths['provider'])} | name")
                print(f"{'-'*widths['id']}-+-{'-'*widths['provider']}-+-----")
                for row in rows:
                    print(f"{str(row['id']).ljust(widths['id'])} | {str(row['provider']).ljust(widths['provider'])} | {row['name']}")
        return 0
    if args.fixtures_command == "validate":
        reports = []
        for manifest_path in discover_fixture_packs(args.root):
            pack = load_fixture_pack(manifest_path)
            if args.fixture and pack.id != args.fixture:
                continue
            issues = validate_fixture_pack(pack)
            reports.append({"id": pack.id, "status": "failed" if any(issue.severity == "error" for issue in issues) else "passed", "issues": [issue.to_json() for issue in issues]})
        if args.fixture and not reports:
            raise FixtureError(f"fixture not found: {args.fixture}")
        report = {"schema_version": "3.0", "fixture_count": len(reports), "failed_count": sum(1 for row in reports if row["status"] != "passed"), "fixtures": reports}
        if args.json_out:
            out = Path(args.json_out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        else:
            print(json.dumps(report, indent=2))
        return 0 if report["failed_count"] == 0 else 2
    if args.fixtures_command == "run":
        report = run_fixture_packs(args.root, output_dir=args.output_dir, only=args.fixture)
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        else:
            print(json.dumps(report, indent=2))
        return 0 if report["status"] == "passed" else 2
    raise FixtureError(f"unknown fixtures command: {args.fixtures_command}")


def _apply_artifact_aliases(sboms: list[Any], aliases: list[str]) -> None:
    for value in aliases:
        if "=" not in value:
            raise UserFacingError(f"Artifact alias must use artifact=reference syntax, for example payments-api=registry.example/payments:1. Got: {value}", 2)
        artifact_name, reference = value.split("=", 1)
        artifact_name = artifact_name.strip()
        reference = reference.strip()
        if not artifact_name or not reference:
            raise UserFacingError(f"Artifact alias must include both sides of artifact=reference. Got: {value}", 2)
        matched = False
        for sbom in sboms:
            if sbom.artifact.name == artifact_name:
                existing = sbom.artifact.properties.get("reachability:aliases", "")
                aliases_list = [item for item in existing.split(",") if item]
                aliases_list.append(reference)
                sbom.artifact.properties["reachability:aliases"] = ",".join(dict.fromkeys(aliases_list))
                sbom.artifact.properties.setdefault("reachability:artifact_ref", reference)
                if not sbom.artifact.reference:
                    sbom.artifact.reference = reference
                matched = True
        if not matched:
            raise UserFacingError(f"Artifact alias refers to an SBOM artifact that was not loaded: {artifact_name}. Check the artifact name in the SBOM metadata.", 2)


def _load_vulnerability_inputs(paths: list[str]) -> list[Any]:
    vulnerabilities: list[Any] = []
    for path in paths:
        vulnerabilities.extend(load_vulnerabilities(path))
    return vulnerabilities


def run_scan(args: argparse.Namespace) -> int:
    vulnerability_inputs = list(args.vulns or [])
    security_evidence_inputs = [
        *list(args.security_evidence_in or []),
        *list(args.sast_in or []),
        *list(args.dast_in or []),
        *list(args.cspm_in or []),
    ]
    if not args.skip_validation:
        issues = validate_paths(
            args.sbom,
            vulnerability_inputs,
            args.context,
            args.terraform_plan,
            args.source_root,
            args.terraform_source,
            args.kubernetes_manifest,
            args.policy,
            args.reachability_rules,
            args.source_evidence_in,
            security_evidence_inputs,
            args.artifact_manifest,
        )
        for issue in issues:
            print(f"{issue.severity}: {issue.target}: {issue.message}", file=sys.stderr)
        if has_errors(issues):
            raise UserFacingError("Input validation failed. Fix the errors above, then rerun the scan.", 2)
    runtime_policy = load_runtime_policy(args.policy)
    sboms = load_sboms(args.sbom)
    artifact_manifest_report = (
        apply_artifact_manifests(sboms, args.artifact_manifest)
        if args.artifact_manifest
        else {"schema_version": "1.0", "manifests": [], "entries": 0, "applied": 0, "unmatched": []}
    )
    artifact_provenance_reports = [
        validate_artifact_manifest(path, strict_provenance=args.require_artifact_provenance)
        for path in args.artifact_manifest
    ]
    _apply_artifact_aliases(sboms, args.artifact_alias)
    vulnerabilities = _load_vulnerability_inputs(vulnerability_inputs)
    source_roots = parse_source_roots(args.source_root)
    reachability_rules = load_reachability_rules(args.reachability_rules)
    contexts: dict[str, ContextEvidence] = {}
    merge_context_maps(contexts, load_context_file(args.context))
    terraform_coverage = empty_coverage_report()
    kubernetes_coverage = empty_kubernetes_coverage_report()
    if args.terraform_plan and args.terraform_source:
        raise UserFacingError("Choose one Terraform input: use --terraform-plan for release-grade rendered evidence, or --terraform-source for advisory source fallback.", 2)
    if args.terraform_plan:
        try:
            terraform_analysis = analyze_terraform_plan(args.terraform_plan, [sbom.artifact for sbom in sboms])
        except TerraformContextError as exc:
            raise ContextError(str(exc)) from exc
        merge_context_maps(contexts, terraform_analysis.contexts)
        terraform_coverage = terraform_analysis.coverage
    elif args.terraform_source:
        try:
            terraform_analysis = analyze_terraform_source(args.terraform_source, [sbom.artifact for sbom in sboms])
        except HclAuditError as exc:
            raise ContextError(str(exc)) from exc
        merge_context_maps(contexts, terraform_analysis.contexts)
        terraform_coverage = terraform_analysis.coverage
    if args.kubernetes_manifest:
        kubernetes_analysis = analyze_kubernetes_manifests(
            args.kubernetes_manifest,
            [sbom.artifact for sbom in sboms],
            infer_lateral_from_public_entry=args.kubernetes_infer_lateral,
        )
        merge_context_maps(contexts, kubernetes_analysis.contexts)
        kubernetes_coverage = kubernetes_analysis.coverage
    contexts = enrich_context_map_with_effective_exposure(contexts)
    external_source_evidence = load_external_source_evidence(args.source_evidence_in)
    security_evidence = [
        *load_security_evidence(args.security_evidence_in),
        *load_security_evidence(args.sast_in, default_scanner_type="sast"),
        *load_security_evidence(args.dast_in, default_scanner_type="dast"),
        *load_security_evidence(args.cspm_in, default_scanner_type="cspm"),
        *native_posture_records(terraform_coverage, kubernetes_coverage, contexts),
    ]
    findings, source_coverage = generate_findings_with_source_report(
        sboms,
        vulnerabilities,
        source_roots,
        contexts,
        policy=runtime_policy.score_policy,
        reachability_rules=reachability_rules,
        external_source_evidence=external_source_evidence,
    )
    security_findings, security_evidence_report = generate_security_findings(
        security_evidence,
        sboms,
        contexts,
        policy=runtime_policy.score_policy,
    )
    findings = apply_correlations(sorted([*findings, *security_findings], key=lambda finding: finding.score, reverse=True))
    findings = sorted(findings, key=lambda finding: finding.score, reverse=True)
    findings = apply_exceptions(findings, runtime_policy)
    mapping_report = build_mapping_report(sboms, source_roots, terraform_coverage, kubernetes_coverage)
    if args.artifact_manifest:
        mapping_report["artifact_manifest"] = artifact_manifest_report
        mapping_report["artifact_provenance"] = {
            "required": bool(args.require_artifact_provenance),
            "reports": artifact_provenance_reports,
        }
    security_finding_type_counts = count_canonical_types(finding.finding_type for finding in security_findings)
    metadata = {
        "sbom_count": len(sboms),
        "vulnerability_records": len(vulnerabilities),
        "context_artifacts": len(contexts),
        "terraform_resources": terraform_coverage.get("summary", {}).get("total_resources", 0),
        "kubernetes_resources": kubernetes_coverage.get("summary", {}).get("total_resources", 0),
        "source_files": source_coverage.get("summary", {}).get("files_scanned", 0),
        "external_source_evidence_records": source_coverage.get("summary", {}).get("external_evidence_records", 0),
        "security_evidence_records": security_evidence_report.get("records", 0),
        "security_evidence_mapped": security_evidence_report.get("mapped", 0),
        "security_evidence_unmapped": security_evidence_report.get("unmapped", 0),
        "static_code_weakness_findings": security_finding_type_counts.get(STATIC_CODE_WEAKNESS, 0),
        "dynamic_runtime_observation_findings": security_finding_type_counts.get(DYNAMIC_RUNTIME_OBSERVATION, 0),
        "cloud_posture_findings": security_finding_type_counts.get(CLOUD_POSTURE_FINDING, 0),
        "analysis_profile": args.analysis_profile,
        "artifact_manifest_entries": artifact_manifest_report.get("entries", 0),
    }
    if security_evidence:
        source_coverage["security_evidence"] = security_evidence_report
    _annotate_analysis_profile(args, source_coverage, terraform_coverage, kubernetes_coverage)
    if args.out:
        write_json_findings(findings, args.out, metadata=metadata)
    if args.baseline_out:
        write_baseline(create_baseline_from_findings(findings, metadata=metadata), args.baseline_out)
    if args.sarif_out:
        write_sarif(findings, args.sarif_out)
    if args.diagnostics_out:
        write_diagnostics(findings, args.diagnostics_out)
    if args.markdown_out:
        write_markdown_report(findings, args.markdown_out)
    evidence_graph = build_evidence_graph(findings, metadata=metadata) if args.html_out or args.evidence_graph_out else None
    if args.html_out:
        write_html_report(findings, args.html_out, metadata=metadata, evidence_graph=evidence_graph)
    if args.annotations_out:
        write_annotations(findings, args.annotations_out)
    if args.terraform_coverage_out:
        out = Path(args.terraform_coverage_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(terraform_coverage, indent=2), encoding="utf-8")
    if args.kubernetes_coverage_out:
        out = Path(args.kubernetes_coverage_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(kubernetes_coverage, indent=2), encoding="utf-8")
    if args.source_coverage_out:
        out = Path(args.source_coverage_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(source_coverage, indent=2), encoding="utf-8")
    if args.evidence_graph_out:
        out = Path(args.evidence_graph_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(evidence_graph, indent=2), encoding="utf-8")
    if args.mapping_out:
        out = Path(args.mapping_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(mapping_report, indent=2), encoding="utf-8")
    readiness_report = None
    if args.readiness_out or args.require_release_ready or args.fail_on_readiness_warnings:
        readiness_report = release_readiness_report(
            mapping_report=mapping_report,
            source_coverage=source_coverage,
            terraform_coverage=terraform_coverage,
            kubernetes_coverage=kubernetes_coverage,
            findings=findings,
        )
    if args.readiness_out and readiness_report is not None:
        out = Path(args.readiness_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(readiness_report, indent=2), encoding="utf-8")
    if not args.no_table:
        print(render_table(findings, args.limit))
    quality_failures = _quality_gate_failures(args, mapping_report, source_coverage, artifact_provenance_reports)
    if readiness_report is not None:
        readiness_summary = readiness_report.get("summary", {}) if isinstance(readiness_report.get("summary"), dict) else {}
        if args.require_release_ready and int(readiness_summary.get("blockers") or 0) > 0:
            quality_failures.append(_readiness_gate_failure("release evidence is blocked", readiness_report, "blockers"))
        if args.fail_on_readiness_warnings and int(readiness_summary.get("warnings") or 0) > 0:
            quality_failures.append(_readiness_gate_failure("release evidence has warnings", readiness_report, "warnings"))
    for failure in quality_failures:
        print(f"Reachability Advisor quality gate failed: {failure}", file=sys.stderr)
    if quality_failures:
        return 10
    fail_tier = Tier(args.fail_on_tier) if args.fail_on_tier else runtime_policy.fail_on_tier if args.policy else None
    if fail_tier and _findings_fail(findings, fail_tier):
        print(f"Reachability Advisor threshold failed: at least one active finding reached priority {fail_tier.value}.", file=sys.stderr)
        return 10
    return 0


def run_validate(args: argparse.Namespace) -> int:
    issues = validate_paths(
        args.sbom,
        args.vulns,
        args.context,
        args.terraform_plan,
        args.source_root,
        args.terraform_source,
        args.kubernetes_manifest,
        args.policy,
        args.reachability_rules,
        args.source_evidence_in,
        [*args.security_evidence_in, *args.sast_in, *args.dast_in, *args.cspm_in],
        args.artifact_manifest,
    )
    report = issues_report(issues)
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        print(json.dumps(report, indent=2))
    return 2 if has_errors(issues) else 0


def run_demo(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    demo_inputs = write_demo_inputs(output_dir / "_inputs")
    argv = [
        "scan",
        "--sbom", demo_inputs["sbom"],
        "--vuln-in", demo_inputs["vulnerabilities"],
        "--sast-in", demo_inputs["sast"],
        "--dast-in", demo_inputs["dast_zap"],
        "--dast-in", demo_inputs["dast_nuclei"],
        "--kubernetes-manifest", demo_inputs["kubernetes"],
        "--source-root", f"demo-api={demo_inputs['source_root']}",
        "--artifact-alias", "demo-api=registry.example.test/demo-api:1.0.0",
        "--out", str(output_dir / "findings.json"),
        "--sarif-out", str(output_dir / "reachability.sarif"),
        "--diagnostics-out", str(output_dir / "diagnostics.json"),
        "--markdown-out", str(output_dir / "summary.md"),
        "--html-out", str(output_dir / "reachability-graph.html"),
        "--evidence-graph-out", str(output_dir / "evidence-graph.json"),
        "--mapping-out", str(output_dir / "mapping.json"),
        "--source-coverage-out", str(output_dir / "source-coverage.json"),
        "--kubernetes-coverage-out", str(output_dir / "kubernetes-coverage.json"),
        "--no-table",
    ]
    code = main(argv)
    if code != 0:
        return code
    data = load_findings_json(output_dir / "findings.json")
    findings = data.get("findings", []) if isinstance(data, dict) else []
    by_type: dict[str, int] = {}
    for finding in findings:
        if isinstance(finding, dict):
            finding_type = str(finding.get("finding_type") or "dependency_vulnerability")
            by_type[finding_type] = by_type.get(finding_type, 0) + 1
    highest = str(findings[0].get("tier", "none")) if findings and isinstance(findings[0], dict) else "none"
    print(f"Demo complete. Findings found: {len(findings)}")
    print(f"Findings by evidence type: {json.dumps(by_type, sort_keys=True)}")
    print(f"Highest priority: {highest}")
    for finding in findings[:3]:
        if isinstance(finding, dict):
            print(f"- {finding.get('tier')} {finding.get('vulnerability', {}).get('id')}: artifact {finding.get('artifact', {}).get('name')}")
    print(f"Review artifacts written to {output_dir}")
    return 0


def run_evidence_profile(args: argparse.Namespace) -> int:
    report = load_release_readiness_inputs(
        mapping=args.mapping,
        source_coverage=args.source_coverage,
        terraform_coverage=args.terraform_coverage,
        kubernetes_coverage=args.kubernetes_coverage,
        findings=args.findings,
    )
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        print(json.dumps(report, indent=2))
    if args.fail_on_blockers and report.get("status") == "blocked":
        print(f"Reachability Advisor evidence profile failed: {_readiness_gate_failure('release evidence is blocked', report, 'blockers')}", file=sys.stderr)
        return 10
    if args.fail_on_warnings and int(report.get("summary", {}).get("warnings") or 0) > 0:
        print(f"Reachability Advisor evidence profile failed: {_readiness_gate_failure('release evidence has warnings', report, 'warnings')}", file=sys.stderr)
        return 10
    return 0


def _readiness_gate_failure(label: str, report: dict[str, Any], field: str) -> str:
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    count = int(summary.get(field) or 0)
    messages = _readiness_messages(report.get(field))
    if not messages:
        return f"{label}: {count} {field}"
    suffix = "; ".join(messages[:3])
    more = f"; plus {len(messages) - 3} more" if len(messages) > 3 else ""
    return f"{label}: {count} {field}. {suffix}{more}"


def _readiness_messages(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    messages: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        message = str(item.get("message") or "").strip()
        next_step = str(item.get("next_step") or "").strip()
        if message and next_step:
            messages.append(f"{message} Next step: {next_step}")
        elif message:
            messages.append(message)
    return messages


def run_explain(args: argparse.Namespace) -> int:
    data = load_findings_json(args.findings)
    text = explain_finding(data, key=args.key, artifact=args.artifact, component=args.component, vulnerability=args.vulnerability)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


def run_compare(args: argparse.Namespace) -> int:
    if args.baseline:
        base = baseline_as_findings_json(load_baseline(args.baseline))
    else:
        base = load_findings_json(args.base_findings)
    head = load_findings_json(args.head_findings)
    delta = compare_findings(base, head, score_delta=args.score_delta)
    output_delta = pr_delta(delta) if args.only_new_or_worsened or args.baseline else delta
    if args.out:
        write_delta(output_delta, args.out)
    else:
        print(json.dumps(output_delta, indent=2))
    if args.markdown_out:
        write_delta_markdown(output_delta, args.markdown_out)
    if args.fail_on_new_tier and delta_fails(output_delta, args.fail_on_new_tier):
        print(f"Reachability Advisor PR delta failed: a new or worsened active finding reached priority {args.fail_on_new_tier}.", file=sys.stderr)
        return 10
    return 0


def run_sbom_plan(args: argparse.Namespace) -> int:
    commands = recommend_sbom_commands(
        artifact=args.artifact,
        source_root=args.source_root,
        image=args.image,
        ecosystem=args.ecosystem,
        output_dir=args.output_dir,
    )
    markdown = render_sbom_plan_markdown(args.artifact, commands)
    if args.out_json:
        write_sbom_plan_json(args.out_json, args.artifact, commands)
    if args.out_md:
        out = Path(args.out_md)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown, encoding="utf-8")
    if not args.out_json and not args.out_md:
        print(markdown)
    return 0


def run_source_evidence_plan(args: argparse.Namespace) -> int:
    commands = recommend_source_evidence_commands(
        source_root=args.source_root,
        output_dir=args.output_dir,
        language=args.language,
        package_manager=args.package_manager,
    )
    markdown = render_source_evidence_plan_markdown(commands)
    if args.out_json:
        write_source_evidence_plan_json(args.out_json, commands)
    if args.out_md:
        out = Path(args.out_md)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown, encoding="utf-8")
    if not args.out_json and not args.out_md:
        print(markdown)
    return 0


def run_source_evidence_pack(args: argparse.Namespace) -> int:
    pack = write_source_evidence_pack(
        args.output_dir,
        language=args.language,
        package_manager=args.package_manager,
    )
    if args.json:
        print(json.dumps(pack.to_json(), indent=2))
    else:
        print(f"Wrote source evidence pack to {pack.root}")
        for path in pack.files:
            print(path)
    return 0


def run_security_evidence_pack(args: argparse.Namespace) -> int:
    pack = write_security_evidence_pack(args.output_dir)
    if args.json:
        print(json.dumps(pack.to_json(), indent=2))
    else:
        print(f"Wrote security evidence pack to {pack.root}")
        for path in pack.files:
            print(path)
    return 0


def run_artifact_manifest(args: argparse.Namespace) -> int:
    if args.artifact_manifest_command == "init":
        payload = create_artifact_manifest_payload(
            args.artifact,
            image=args.image,
            digest=args.digest,
            registry_ref=args.registry_ref,
            git_sha=args.git_sha,
            sbom=args.sbom,
            signed=args.signed,
        )
        write_artifact_manifest(args.out, payload)
        return 0
    if args.artifact_manifest_command == "validate":
        report = validate_artifact_manifest(args.manifest, strict_provenance=args.strict_provenance)
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        else:
            print(json.dumps(report, indent=2))
        return 10 if args.fail_on_warning and report.get("status") != "ready" else 0
    raise UserFacingError(f"unknown artifact-manifest command: {args.artifact_manifest_command}", 2)


def run_rendered_iac_plan(args: argparse.Namespace) -> int:
    commands = recommend_iac_render_commands(
        terraform_dir=args.terraform_dir,
        helm_chart=args.helm_chart,
        helm_release=args.helm_release,
        helm_namespace=args.helm_namespace,
        helm_values=args.helm_values,
        kustomize_dir=args.kustomize_dir,
        output_dir=args.output_dir,
    )
    markdown = render_iac_render_plan_markdown(commands)
    if args.out_json:
        write_iac_render_plan_json(args.out_json, commands)
    if args.out_md:
        out = Path(args.out_md)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown, encoding="utf-8")
    if not args.out_json and not args.out_md:
        print(markdown)
    return 0


def run_hcl_audit(args: argparse.Namespace) -> int:
    audit = audit_hcl_project(args.path)
    report = audit.to_json()
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        print(json.dumps(report, indent=2))
    if args.markdown_out:
        out = Path(args.markdown_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_hcl_audit_markdown(report), encoding="utf-8")
    if args.fail_on_gaps and report.get("coverage", {}).get("visibility_gaps"):
        print("Reachability Advisor HCL audit failed: Terraform source visibility gaps were reported. Use rendered Terraform plan JSON for release-grade deployment evidence.", file=sys.stderr)
        return 10
    return 0


def run_benchmark_snapshots(args: argparse.Namespace) -> int:
    report = validate_benchmark_snapshots(args.benchmark, args.expectations)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        print(json.dumps(report, indent=2))
    return 0 if args.warn_only or report.get("status") == "passed" else 10


def run_export_semgrep_rules(args: argparse.Namespace) -> int:
    custom_rules = load_reachability_rules(args.reachability_rules)
    rules = custom_rules if args.custom_only else (*BUILTIN_RULES, *custom_rules)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(semgrep_rules_yaml(rules), encoding="utf-8")
    return 0


def run_init_policy(args: argparse.Namespace) -> int:
    policy = {
        "$schema": "schemas/runtime-policy.schema.json",
        "schema_version": "1.0",
        "fail_on_tier": "high",
        "exceptions": [
            {
                "vulnerability": "CVE-EXAMPLE-0001",
                "artifact": "example-service",
                "component": "example-lib",
                "expires": "2026-12-31",
                "reason": "Accepted by service owner while upgrade is validated.",
            }
        ],
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return run_scan(args)
        if args.command == "validate":
            return run_validate(args)
        if args.command == "explain":
            return run_explain(args)
        if args.command == "compare":
            return run_compare(args)
        if args.command == "evidence-profile":
            return run_evidence_profile(args)
        if args.command == "init-policy":
            return run_init_policy(args)
        if args.command == "sbom-plan":
            return run_sbom_plan(args)
        if args.command == "source-evidence-plan":
            return run_source_evidence_plan(args)
        if args.command == "source-evidence-pack":
            return run_source_evidence_pack(args)
        if args.command == "security-evidence-pack":
            return run_security_evidence_pack(args)
        if args.command == "artifact-manifest":
            return run_artifact_manifest(args)
        if args.command == "rendered-iac-plan":
            return run_rendered_iac_plan(args)
        if args.command == "fixtures":
            return run_fixtures(args)
        if args.command == "hcl-audit":
            return run_hcl_audit(args)
        if args.command == "benchmark-snapshots":
            return run_benchmark_snapshots(args)
        if args.command == "demo":
            return run_demo(args)
        if args.command == "export-semgrep-rules":
            return run_export_semgrep_rules(args)
        if args.command == "version":
            print(__version__)
            return 0
        parser.error("unknown command")
        return 2
    except (UserFacingError, SbomError, VulnerabilityError, ContextError, FixtureError, HclAuditError, KubernetesManifestError, ArtifactManifestError, BenchmarkSnapshotError, SecurityEvidenceError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code if isinstance(exc, UserFacingError) else 2


if __name__ == "__main__":
    raise SystemExit(main())
