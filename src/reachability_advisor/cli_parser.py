"""Argument parser construction for the Reachability Advisor CLI."""

from __future__ import annotations

import argparse

from .models import Tier


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reachability-advisor",
        description=(
            "Prioritize security findings with local evidence from SBOMs, source analyzers, "
            "scanner reports, Terraform plans, Kubernetes manifests, network paths, and IAM/RBAC context."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Analyze local evidence and write prioritized findings for CI, IDEs, and review.")
    scan.add_argument("--sbom", action="append", required=True, help="CycloneDX JSON SBOM for one deployable artifact. Repeat for multiple artifacts.")
    scan.add_argument("--vuln-in", dest="vulns", action="append", required=True, help="Vulnerability input: local JSON, Grype JSON, or OSV-Scanner-style JSON. Repeatable.")
    scan.add_argument("--source-root", action="append", default=[], help="Source mapping in artifact=path form, for example payments-api=src/payments. Repeatable.")
    scan.add_argument("--context", help="Context JSON keyed by artifact name. Use it for owner, environment, exposure, privilege, or manual evidence overrides.")
    scan.add_argument("--terraform-plan", help="Rendered Terraform plan JSON from `terraform show -json`. Use this for release-grade Terraform deployment evidence.")
    scan.add_argument("--terraform-source", help="Terraform .tf source directory for conservative advisory fallback when no rendered plan is available.")
    scan.add_argument("--terraform-coverage-out", help="Write Terraform resource accounting and visibility-gap report JSON.")
    scan.add_argument("--kubernetes-manifest", action="append", default=[], help="Rendered Kubernetes YAML/JSON manifest file or directory. Render Helm/Kustomize first. Repeatable.")
    scan.add_argument("--kubernetes-infer-lateral", action="store_true", help="Treat internal Kubernetes services as laterally reachable when a public Kubernetes entrypoint is present.")
    scan.add_argument("--kubernetes-coverage-out", help="Write Kubernetes resource accounting and visibility-gap report JSON.")
    scan.add_argument("--mapping-out", help="Write artifact/source/deployment mapping report JSON, including weak matches and missing identity evidence.")
    scan.add_argument("--source-coverage-out", help="Write source evidence coverage report JSON, including missing rules and external analyzer coverage.")
    scan.add_argument("--evidence-graph-out", help="Write machine-readable asset, source, network, IAM/RBAC, finding, and score graph JSON.")
    scan.add_argument("--artifact-alias", action="append", default=[], help="Add an artifact mapping alias in artifact=reference form. Use when SBOM metadata lacks image references. Repeatable.")
    scan.add_argument("--artifact-manifest", action="append", default=[], help="CI artifact identity manifest JSON with image refs, digests, Git SHA, SBOM path, and renderer metadata. Repeatable.")
    scan.add_argument("--require-artifact-provenance", action="store_true", help="Exit 10 unless artifact manifests provide digest identity, SBOM path, Git SHA, and signature/attestation markers.")
    scan.add_argument("--reachability-rules", help="Custom source reachability rules JSON.")
    scan.add_argument("--source-evidence-in", action="append", default=[], help="External source evidence JSON, Semgrep JSON, SARIF, or govulncheck JSONL. Repeatable.")
    scan.add_argument("--security-evidence-in", action="append", default=[], help="Generic first-party SAST/DAST/CSPM evidence JSON, Semgrep JSON, SARIF, ZAP JSON, Nuclei JSONL, or posture scanner JSON. Repeatable.")
    scan.add_argument("--sast-in", action="append", default=[], help="SAST scanner evidence JSON, Semgrep JSON, or SARIF. Repeatable; defaults imported records to scanner_type=sast.")
    scan.add_argument("--dast-in", action="append", default=[], help="DAST scanner evidence JSON, ZAP JSON, or Nuclei JSONL. Repeatable; defaults imported records to scanner_type=dast.")
    scan.add_argument("--cspm-in", action="append", default=[], help="CSPM/posture evidence JSON or SARIF from Checkov, Trivy config, KICS, tfsec, or normalized JSON. Repeatable; defaults imported records to scanner_type=cspm.")
    scan.add_argument(
        "--analysis-profile",
        choices=["advisory", "production"],
        default="advisory",
        help="Use advisory for local triage. Use production for release gates; it requires external source evidence and rendered deployment evidence.",
    )
    scan.add_argument("--min-artifact-match-coverage", type=float, help="Exit 10 when SBOM-to-deployment artifact match coverage is below this 0..1 ratio.")
    scan.add_argument("--min-strong-artifact-identity-coverage", type=float, help="Exit 10 when strong image/digest identity coverage is below this 0..1 ratio.")
    scan.add_argument("--fail-on-mapping-warnings", action="store_true", help="Exit 10 when the mapping report contains artifact identity, source-root, or Terraform match warnings.")
    scan.add_argument("--min-source-rule-coverage", type=float, help="Exit 10 when source package-rule coverage is below this 0..1 ratio.")
    scan.add_argument("--require-external-source-evidence", action="store_true", help="Exit 10 when no Semgrep, CodeQL/SARIF, govulncheck, or equivalent external source analyzer evidence was imported.")
    scan.add_argument("--min-external-evidence-usable-ratio", type=float, help="Exit 10 when imported external source evidence selector usability is below this 0..1 ratio.")
    scan.add_argument("--min-critical-external-source-coverage", type=float, help="Exit 10 when critical finding coverage by external source evidence is below this 0..1 ratio. Production defaults to 1.0.")
    scan.add_argument("--min-critical-query-family-coverage", type=float, help="Exit 10 when critical findings lack relevant source query-family evidence. Production defaults to 1.0.")
    scan.add_argument("--min-critical-proven-query-family-coverage", type=float, help="Exit 10 when critical findings lack proven maintained query-family coverage. Production defaults to 1.0.")
    scan.add_argument("--min-critical-security-profile-coverage", type=float, help="Exit 10 when imported critical SAST/DAST findings lack a maintained security profile.")
    scan.add_argument("--require-strong-source-for-critical", action="store_true", help="Exit 10 when critical findings only have dependency-level or weaker source evidence. Production profile enables this gate.")
    scan.add_argument("--policy", help="Policy JSON with exceptions and fail tier.")
    scan.add_argument("--out", help="Findings JSON output path.")
    scan.add_argument("--baseline-out", help="Write a stable baseline artifact for future PR delta gates.")
    scan.add_argument("--sarif-out", help="SARIF 2.1.0 output path.")
    scan.add_argument("--diagnostics-out", help="IDE diagnostics JSON output path.")
    scan.add_argument("--markdown-out", help="Developer PR summary Markdown output path.")
    scan.add_argument("--html-out", help="Self-contained interactive HTML report with risk table, attack paths, evidence paths, and architecture view.")
    scan.add_argument("--annotations-out", help="GitHub Actions workflow-command annotations output path.")
    scan.add_argument("--readiness-out", help="Write release evidence readiness JSON with blockers, warnings, impact, and next steps.")
    scan.add_argument("--require-release-ready", action="store_true", help="Exit 10 when release evidence is blocked, and print concrete blockers with next steps.")
    scan.add_argument("--fail-on-readiness-warnings", action="store_true", help="Exit 10 when release evidence has warnings, and print concrete warnings with next steps.")
    scan.add_argument("--limit", type=int, default=20, help="Maximum rows printed to stdout.")
    scan.add_argument("--no-table", action="store_true", help="Do not print stdout table.")
    scan.add_argument("--fail-on-tier", choices=[tier.value for tier in Tier], help="Exit 10 when any non-excepted finding reaches this tier.")
    scan.add_argument("--skip-validation", action="store_true", help="Skip path validation before parsing.")

    validate = sub.add_parser("validate", help="Validate paths and source-root syntax.")
    validate.add_argument("--sbom", action="append", required=True)
    validate.add_argument("--vuln-in", dest="vulns", action="append")
    validate.add_argument("--source-root", action="append", default=[])
    validate.add_argument("--context")
    validate.add_argument("--terraform-plan")
    validate.add_argument("--terraform-source")
    validate.add_argument("--kubernetes-manifest", action="append", default=[])
    validate.add_argument("--policy")
    validate.add_argument("--reachability-rules")
    validate.add_argument("--source-evidence-in", action="append", default=[])
    validate.add_argument("--security-evidence-in", action="append", default=[])
    validate.add_argument("--sast-in", action="append", default=[])
    validate.add_argument("--dast-in", action="append", default=[])
    validate.add_argument("--cspm-in", action="append", default=[])
    validate.add_argument("--artifact-manifest", action="append", default=[])
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

    readiness = sub.add_parser("evidence-profile", help="Check whether existing scan outputs are complete enough for a release gate.")
    readiness.add_argument("--mapping", required=True, help="Mapping report JSON from --mapping-out.")
    readiness.add_argument("--source-coverage", required=True, help="Source coverage JSON from --source-coverage-out.")
    readiness.add_argument("--terraform-coverage", help="Terraform coverage JSON from --terraform-coverage-out.")
    readiness.add_argument("--kubernetes-coverage", help="Kubernetes coverage JSON from --kubernetes-coverage-out.")
    readiness.add_argument("--findings", help="Findings JSON from --out.")
    readiness.add_argument("--out", help="Write readiness JSON.")
    readiness.add_argument("--fail-on-blockers", action="store_true", help="Exit 10 when release evidence blockers are present, and print concrete next steps.")
    readiness.add_argument("--fail-on-warnings", action="store_true", help="Exit 10 when release evidence warnings are present, and print concrete next steps.")

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

    source_plan = sub.add_parser("source-evidence-plan", help="Print recommended Semgrep/CodeQL/govulncheck source evidence commands.")
    source_plan.add_argument("--source-root", default=".", help="Source root used in generated analyzer commands.")
    source_plan.add_argument("--output-dir", default="reachability", help="Directory for generated source-evidence artifacts.")
    source_plan.add_argument("--language", choices=["javascript", "typescript", "java", "python", "go", "golang"], help="Primary language for CodeQL or govulncheck command selection. Omit for generic Semgrep-only output.")
    source_plan.add_argument("--package-manager", choices=["npm", "pnpm", "yarn", "maven", "gradle", "pypi", "poetry", "pip", "go", "golang"], help="Package manager/ecosystem hint.")
    source_plan.add_argument("--out-json", help="Write command plan JSON.")
    source_plan.add_argument("--out-md", help="Write command plan Markdown.")

    source_pack = sub.add_parser("source-evidence-pack", help="Write maintained Semgrep, CodeQL, and govulncheck source evidence assets.")
    source_pack.add_argument("--output-dir", default="reachability/source-evidence-pack", help="Directory for the generated evidence pack.")
    source_pack.add_argument("--language", choices=["javascript", "typescript", "java", "python", "go", "golang"], help="Primary language profile.")
    source_pack.add_argument("--package-manager", choices=["npm", "pnpm", "yarn", "maven", "gradle", "pypi", "poetry", "pip", "go", "golang"], help="Package manager/ecosystem hint.")
    source_pack.add_argument("--json", action="store_true", help="Print pack manifest JSON.")

    security_pack = sub.add_parser("security-evidence-pack", help="Write maintained SAST/DAST profile assets and coverage metadata.")
    security_pack.add_argument("--output-dir", default="reachability/security-evidence-pack", help="Directory for generated SAST/DAST evidence profiles.")
    security_pack.add_argument("--json", action="store_true", help="Print pack manifest JSON.")

    artifact_manifest = sub.add_parser("artifact-manifest", help="Create or validate CI artifact identity manifests.")
    artifact_manifest_sub = artifact_manifest.add_subparsers(dest="artifact_manifest_command", required=True)
    artifact_manifest_init = artifact_manifest_sub.add_parser("init", help="Write an artifact identity manifest skeleton.")
    artifact_manifest_init.add_argument("--artifact", action="append", required=True, help="Artifact/service name. Repeat for multiple artifacts.")
    artifact_manifest_init.add_argument("--image", help="Built image reference.")
    artifact_manifest_init.add_argument("--digest", help="Built image digest, for example sha256:...")
    artifact_manifest_init.add_argument("--registry-ref", help="Repository digest reference, for example registry/app@sha256:...")
    artifact_manifest_init.add_argument("--git-sha", help="Git revision used to build the artifact.")
    artifact_manifest_init.add_argument("--sbom", help="SBOM path when the same path applies to the artifact.")
    artifact_manifest_init.add_argument("--signed", action="store_true", help="Mark the manifest as signed by the CI workflow.")
    artifact_manifest_init.add_argument("--out", required=True, help="Manifest output path.")
    artifact_manifest_validate = artifact_manifest_sub.add_parser("validate", help="Validate artifact identity manifest coverage.")
    artifact_manifest_validate.add_argument("--manifest", required=True)
    artifact_manifest_validate.add_argument("--strict-provenance", action="store_true", help="Require digest identity, SBOM path, Git SHA, and signature/attestation marker.")
    artifact_manifest_validate.add_argument("--out", help="Write validation JSON.")
    artifact_manifest_validate.add_argument("--fail-on-warning", action="store_true", help="Exit 10 unless every artifact has strong identity.")

    iac_plan = sub.add_parser("rendered-iac-plan", help="Print helper commands for Terraform plan JSON and rendered Kubernetes manifests.")
    iac_plan.add_argument("--terraform-dir", help="Terraform root/module directory to plan.")
    iac_plan.add_argument("--helm-chart", help="Helm chart path to render.")
    iac_plan.add_argument("--helm-release", default="app", help="Helm release name for template rendering.")
    iac_plan.add_argument("--helm-namespace", default="default", help="Helm namespace for template rendering.")
    iac_plan.add_argument("--helm-values", action="append", default=[], help="Helm values file. Repeatable.")
    iac_plan.add_argument("--kustomize-dir", help="Kustomize overlay directory to render.")
    iac_plan.add_argument("--output-dir", default="reachability", help="Output directory used in generated commands.")
    iac_plan.add_argument("--out-json", help="Write command plan JSON.")
    iac_plan.add_argument("--out-md", help="Write command plan Markdown.")

    hcl_audit = sub.add_parser("hcl-audit", help="Audit Terraform .tf source coverage without running Terraform.")
    hcl_audit.add_argument("--path", required=True, help="Terraform source directory or .tf file.")
    hcl_audit.add_argument("--out", help="Write HCL audit JSON report.")
    hcl_audit.add_argument("--markdown-out", help="Write HCL audit Markdown report.")
    hcl_audit.add_argument("--fail-on-gaps", action="store_true", help="Exit 10 when static audit reports visibility gaps.")

    benchmark_snapshots = sub.add_parser("benchmark-snapshots", help="Validate real-app benchmark tier distributions and over-prioritization limits.")
    benchmark_snapshots.add_argument("--benchmark", required=True, help="Complex benchmark JSON from scripts/run_complex_app_validation.py.")
    benchmark_snapshots.add_argument("--expectations", default="fixtures/benchmarks/real-app-tier-snapshots.json", help="Benchmark snapshot expectation JSON.")
    benchmark_snapshots.add_argument("--out", help="Write validation report JSON.")
    benchmark_snapshots.add_argument("--warn-only", action="store_true", help="Return 0 even when a benchmark regression is detected.")

    demo = sub.add_parser("demo", help="Run the checked-in multi-scanner demo with no network or cloud credentials.")
    demo.add_argument("--output-dir", default="outputs/demo", help="Directory for demo outputs.")

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


__all__ = ["build_parser"]
