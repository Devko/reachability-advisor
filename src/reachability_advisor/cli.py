"""Command-line interface for Reachability Advisor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .baseline import (
    baseline_as_findings_json,
    create_baseline_from_findings,
    load_baseline,
    write_baseline,
)
from .compare import compare_findings, delta_fails, pr_delta, write_delta, write_delta_markdown
from .context import ContextError, load_context_file
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
from .sbom import SbomError, load_sboms
from .sbom_plan import recommend_sbom_commands, render_sbom_plan_markdown, write_sbom_plan_json
from .scoring import generate_findings_with_source_report
from .source import (
    BUILTIN_RULES,
    load_external_source_evidence,
    load_reachability_rules,
    parse_source_roots,
    semgrep_rules_yaml,
)
from .terraform import TerraformContextError, analyze_terraform_plan, empty_coverage_report
from .validators import has_errors, issues_report, validate_paths
from .visual import write_html_report
from .vulnerability import VulnerabilityError, load_vulnerabilities


class UserFacingError(Exception):
    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reachability-advisor", description="Dependency vulnerability prioritization with source, Terraform, network, and IAM context.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan SBOMs and produce CI/IDE-friendly outputs.")
    scan.add_argument("--sbom", action="append", required=True, help="CycloneDX JSON SBOM path. Repeat for multiple artifacts.")
    scan.add_argument("--vulns", required=True, help="Local vulnerability intelligence JSON, Grype JSON, or OSV-Scanner-style JSON.")
    scan.add_argument("--source-root", action="append", default=[], help="Source mapping: artifact=path. Repeat for multiple artifacts.")
    scan.add_argument("--context", help="Context JSON keyed by artifact name for overrides or enrichment.")
    scan.add_argument("--terraform-plan", help="Terraform plan JSON for AWS/Azure/GCP/Kubernetes deployment context.")
    scan.add_argument("--terraform-source", help="Terraform .tf source directory for conservative static HCL fallback when no plan is available.")
    scan.add_argument("--terraform-coverage-out", help="Write Terraform coverage/accounting report JSON.")
    scan.add_argument("--kubernetes-manifest", action="append", default=[], help="Rendered Kubernetes YAML/JSON manifest file or directory. Repeat for multiple paths.")
    scan.add_argument("--kubernetes-infer-lateral", action="store_true", help="Treat internal services as laterally reachable when a public Kubernetes entrypoint is present.")
    scan.add_argument("--kubernetes-coverage-out", help="Write Kubernetes manifest coverage/context report JSON.")
    scan.add_argument("--mapping-out", help="Write SBOM/source/Terraform mapping verification report JSON.")
    scan.add_argument("--source-coverage-out", help="Write source-analysis coverage and evidence report JSON.")
    scan.add_argument("--artifact-alias", action="append", default=[], help="Add artifact mapping alias: artifact=reference. Repeatable; use when SBOM metadata lacks image refs.")
    scan.add_argument("--reachability-rules", help="Custom source reachability rules JSON.")
    scan.add_argument("--source-evidence-in", action="append", default=[], help="External source evidence JSON, Semgrep JSON, SARIF, or govulncheck JSONL. Repeatable.")
    scan.add_argument("--policy", help="Policy JSON with exceptions and fail tier.")
    scan.add_argument("--out", help="Findings JSON output path.")
    scan.add_argument("--baseline-out", help="Write a stable baseline artifact for future PR delta gates.")
    scan.add_argument("--sarif-out", help="SARIF 2.1.0 output path.")
    scan.add_argument("--diagnostics-out", help="IDE diagnostics JSON output path.")
    scan.add_argument("--markdown-out", help="Developer PR summary Markdown output path.")
    scan.add_argument("--html-out", help="Self-contained interactive HTML graph report output path.")
    scan.add_argument("--annotations-out", help="GitHub Actions workflow-command annotations output path.")
    scan.add_argument("--limit", type=int, default=20, help="Maximum rows printed to stdout.")
    scan.add_argument("--no-table", action="store_true", help="Do not print stdout table.")
    scan.add_argument("--fail-on-tier", choices=[tier.value for tier in Tier], help="Exit 10 when any non-excepted finding reaches this tier.")
    scan.add_argument("--skip-validation", action="store_true", help="Skip path validation before parsing.")

    validate = sub.add_parser("validate", help="Validate paths and source-root syntax.")
    validate.add_argument("--sbom", action="append", required=True)
    validate.add_argument("--vulns")
    validate.add_argument("--source-root", action="append", default=[])
    validate.add_argument("--context")
    validate.add_argument("--terraform-plan")
    validate.add_argument("--terraform-source")
    validate.add_argument("--kubernetes-manifest", action="append", default=[])
    validate.add_argument("--policy")
    validate.add_argument("--reachability-rules")
    validate.add_argument("--source-evidence-in", action="append", default=[])
    validate.add_argument("--json-out")

    explain = sub.add_parser("explain", help="Explain one finding from findings JSON.")
    explain.add_argument("--findings", required=True)
    explain.add_argument("--key")
    explain.add_argument("--artifact")
    explain.add_argument("--component")
    explain.add_argument("--vulnerability")
    explain.add_argument("--out")

    compare = sub.add_parser("compare", help="Compare base and head findings for pull-request workflows.")
    compare_base = compare.add_mutually_exclusive_group(required=True)
    compare_base.add_argument("--base-findings", help="Base findings JSON from the default branch.")
    compare_base.add_argument("--baseline", help="Stable baseline artifact from the default branch.")
    compare.add_argument("--head-findings", required=True)
    compare.add_argument("--score-delta", type=float, default=5.0)
    compare.add_argument("--out")
    compare.add_argument("--markdown-out")
    compare.add_argument("--only-new-or-worsened", action="store_true", help="Emit only new and worsened findings in JSON and Markdown output.")
    compare.add_argument("--fail-on-new-tier", choices=[tier.value for tier in Tier])

    init_policy = sub.add_parser("init-policy", help="Write an example runtime policy JSON.")
    init_policy.add_argument("--out", required=True)

    sbom_plan = sub.add_parser("sbom-plan", help="Print recommended SBOM generation commands for an artifact.")
    sbom_plan.add_argument("--artifact", required=True, help="Artifact/service name.")
    sbom_plan.add_argument("--image", help="Deployed image reference.")
    sbom_plan.add_argument("--source-root", help="Source root path.")
    sbom_plan.add_argument("--ecosystem", choices=["maven", "java", "npm", "node", "javascript", "typescript", "pypi", "python"], help="Primary ecosystem.")
    sbom_plan.add_argument("--output-dir", default="sboms", help="Directory to place generated SBOMs in examples.")
    sbom_plan.add_argument("--out-json", help="Write command plan JSON.")
    sbom_plan.add_argument("--out-md", help="Write command plan Markdown.")

    hcl_audit = sub.add_parser("hcl-audit", help="Audit Terraform .tf source coverage without running Terraform.")
    hcl_audit.add_argument("--path", required=True, help="Terraform source directory or .tf file.")
    hcl_audit.add_argument("--out", help="Write HCL audit JSON report.")
    hcl_audit.add_argument("--markdown-out", help="Write HCL audit Markdown report.")
    hcl_audit.add_argument("--fail-on-gaps", action="store_true", help="Exit 10 when static audit reports visibility gaps.")

    semgrep = sub.add_parser("export-semgrep-rules", help="Write Semgrep starter rules from reachability rules.")
    semgrep.add_argument("--reachability-rules", help="Custom source reachability rules JSON to include.")
    semgrep.add_argument("--custom-only", action="store_true", help="Export only custom rules, not built-in rules.")
    semgrep.add_argument("--out", required=True, help="Output YAML path.")

    fixtures = sub.add_parser("fixtures", help="List, validate, or run community Terraform fixture packs.")
    fixture_sub = fixtures.add_subparsers(dest="fixtures_command", required=True)
    fixtures_list = fixture_sub.add_parser("list", help="List discovered fixture packs.")
    fixtures_list.add_argument("--root", default="fixtures/terraform", help="Fixture root directory.")
    fixtures_list.add_argument("--json", action="store_true", help="Emit JSON instead of a table.")

    fixtures_validate = fixture_sub.add_parser("validate", help="Validate fixture-pack metadata and parseability.")
    fixtures_validate.add_argument("--root", default="fixtures/terraform", help="Fixture root directory.")
    fixtures_validate.add_argument("--fixture", help="Validate only this fixture id.")
    fixtures_validate.add_argument("--json-out", help="Write validation report JSON.")

    fixtures_run = fixture_sub.add_parser("run", help="Run fixture packs and assert expected outcomes.")
    fixtures_run.add_argument("--root", default="fixtures/terraform", help="Fixture root directory.")
    fixtures_run.add_argument("--fixture", help="Run only this fixture id.")
    fixtures_run.add_argument("--out", help="Write aggregate fixture report JSON.")
    fixtures_run.add_argument("--output-dir", help="Write per-fixture findings and coverage artifacts.")

    sub.add_parser("version", help="Print version.")
    return parser



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
            raise UserFacingError(f"artifact alias must use artifact=reference syntax: {value}", 2)
        artifact_name, reference = value.split("=", 1)
        artifact_name = artifact_name.strip()
        reference = reference.strip()
        if not artifact_name or not reference:
            raise UserFacingError(f"artifact alias must use artifact=reference syntax: {value}", 2)
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
            raise UserFacingError(f"artifact alias refers to unknown SBOM artifact: {artifact_name}", 2)


def run_scan(args: argparse.Namespace) -> int:
    if not args.skip_validation:
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
        )
        for issue in issues:
            print(f"{issue.severity}: {issue.target}: {issue.message}", file=sys.stderr)
        if has_errors(issues):
            raise UserFacingError("input validation failed", 2)
    runtime_policy = load_runtime_policy(args.policy)
    sboms = load_sboms(args.sbom)
    _apply_artifact_aliases(sboms, args.artifact_alias)
    vulnerabilities = load_vulnerabilities(args.vulns)
    source_roots = parse_source_roots(args.source_root)
    reachability_rules = load_reachability_rules(args.reachability_rules)
    contexts: dict[str, ContextEvidence] = {}
    merge_context_maps(contexts, load_context_file(args.context))
    terraform_coverage = empty_coverage_report()
    kubernetes_coverage = empty_kubernetes_coverage_report()
    if args.terraform_plan and args.terraform_source:
        raise UserFacingError("use either --terraform-plan or --terraform-source, not both", 2)
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
    external_source_evidence = load_external_source_evidence(args.source_evidence_in)
    findings, source_coverage = generate_findings_with_source_report(
        sboms,
        vulnerabilities,
        source_roots,
        contexts,
        policy=runtime_policy.score_policy,
        reachability_rules=reachability_rules,
        external_source_evidence=external_source_evidence,
    )
    findings = apply_exceptions(findings, runtime_policy)
    metadata = {
        "sbom_count": len(sboms),
        "vulnerability_records": len(vulnerabilities),
        "context_artifacts": len(contexts),
        "terraform_resources": terraform_coverage.get("summary", {}).get("total_resources", 0),
        "kubernetes_resources": kubernetes_coverage.get("summary", {}).get("total_resources", 0),
        "source_files": source_coverage.get("summary", {}).get("files_scanned", 0),
        "external_source_evidence_records": source_coverage.get("summary", {}).get("external_evidence_records", 0),
    }
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
    if args.html_out:
        write_html_report(findings, args.html_out, metadata=metadata)
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
    if args.mapping_out:
        out = Path(args.mapping_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(build_mapping_report(sboms, source_roots, terraform_coverage), indent=2), encoding="utf-8")
    if not args.no_table:
        print(render_table(findings, args.limit))
    fail_tier = Tier(args.fail_on_tier) if args.fail_on_tier else runtime_policy.fail_on_tier if args.policy else None
    if fail_tier and _findings_fail(findings, fail_tier):
        print(f"Reachability Advisor threshold failed: finding reached tier {fail_tier.value}.", file=sys.stderr)
        return 10
    return 0


def _findings_fail(findings: list[Any], tier: Tier) -> bool:
    order = {Tier.INFORMATIONAL: 0, Tier.LOW: 1, Tier.MEDIUM: 2, Tier.HIGH: 3, Tier.URGENT: 4}
    threshold = order[tier]
    return any(finding.policy_status != "excepted" and order[finding.tier] >= threshold for finding in findings)


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
    )
    report = issues_report(issues)
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        print(json.dumps(report, indent=2))
    return 2 if has_errors(issues) else 0


def run_explain(args: argparse.Namespace) -> int:
    data = load_findings_json(args.findings)
    text = explain_finding(data, key=args.key, artifact=args.artifact, component=args.component, vulnerability=args.vulnerability)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
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
        print(f"Reachability Advisor PR delta failed: new/worsened finding reached {args.fail_on_new_tier}.", file=sys.stderr)
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
        print("Reachability Advisor HCL audit failed: visibility gaps reported.", file=sys.stderr)
        return 10
    return 0


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
        if args.command == "init-policy":
            return run_init_policy(args)
        if args.command == "sbom-plan":
            return run_sbom_plan(args)
        if args.command == "fixtures":
            return run_fixtures(args)
        if args.command == "hcl-audit":
            return run_hcl_audit(args)
        if args.command == "export-semgrep-rules":
            return run_export_semgrep_rules(args)
        if args.command == "version":
            print(__version__)
            return 0
        parser.error("unknown command")
        return 2
    except (UserFacingError, SbomError, VulnerabilityError, ContextError, FixtureError, HclAuditError, KubernetesManifestError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code if isinstance(exc, UserFacingError) else 2


if __name__ == "__main__":
    raise SystemExit(main())
