# CI Pipeline Integration

Reachability Advisor runs after SBOM and vulnerability generation. A production gate requires four inputs for each deployable artifact:

1. CycloneDX SBOM.
2. Grype JSON generated from that SBOM.
3. Source root for code reachability.
4. Terraform plan JSON and/or rendered Kubernetes manifests for workload, network, and IAM context.

The scanner itself does not call external services. Keep Syft, Grype, Terraform, and artifact upload steps in the pipeline so teams can pin versions, cache databases, and control credentials.

## GitHub Actions Workflow

This workflow is designed for GitHub-hosted Linux runners. It uses source-mode SBOM generation for pull requests because it works before an image has been built. The release variant below uses an image SBOM.

```yaml
name: reachability-advisor

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  reachability:
    runs-on: ubuntu-latest

    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Reachability Advisor
        run: |
          python -m pip install --upgrade pip
          python -m pip install git+https://github.com/Devko/reachability-advisor.git@main

      - name: Install Syft and Grype
        run: |
          mkdir -p "$HOME/.local/bin"
          curl -sSfL https://get.anchore.io/syft | sh -s -- -b "$HOME/.local/bin"
          curl -sSfL https://get.anchore.io/grype | sh -s -- -b "$HOME/.local/bin"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      - name: Generate SBOM and vulnerability matches
        run: |
          mkdir -p sboms vulns reachability
          syft dir:. -o cyclonedx-json=sboms/app.cdx.json
          grype sbom:sboms/app.cdx.json -o json --file vulns/app.grype.json

      - name: Set up Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_wrapper: false

      - name: Generate Terraform plan context
        run: |
          terraform -chdir=infra init -backend=false
          terraform -chdir=infra plan -refresh=false -out=tfplan.binary
          terraform -chdir=infra show -json tfplan.binary > reachability/tfplan.json

      - name: Render Kubernetes manifests
        run: |
          # Replace this with `helm template`, `kustomize build`, or the checked-in rendered YAML path used by your repository.
          test ! -d k8s || cp k8s/*.yaml reachability/ || true

      - name: Run reachability prioritization
        run: |
          k8s_args=()
          if compgen -G "reachability/*.yaml" > /dev/null; then
            k8s_args+=(--kubernetes-manifest reachability --kubernetes-coverage-out reachability/kubernetes-coverage.json)
          fi
          reachability-advisor scan \
            --sbom sboms/app.cdx.json \
            --vulns vulns/app.grype.json \
            --source-root app=. \
            --terraform-plan reachability/tfplan.json \
            --terraform-coverage-out reachability/terraform-coverage.json \
            "${k8s_args[@]}" \
            --source-coverage-out reachability/source-coverage.json \
            --mapping-out reachability/mapping.json \
            --out reachability/findings.json \
            --evidence-graph-out reachability/evidence-graph.json \
            --sarif-out reachability/reachability.sarif \
            --markdown-out reachability/summary.md \
            --html-out reachability/reachability-graph.html \
            --annotations-out reachability/annotations.txt \
            --fail-on-tier high

      - name: Publish annotations and job summary
        if: always()
        run: |
          test ! -f reachability/annotations.txt || cat reachability/annotations.txt
          test ! -f reachability/summary.md || cat reachability/summary.md >> "$GITHUB_STEP_SUMMARY"

      - name: Upload SARIF
        if: always() && hashFiles('reachability/reachability.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reachability/reachability.sarif

      - name: Upload reachability artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: reachability-advisor
          path: |
            sboms/*.json
            vulns/*.json
            reachability/*.json
            reachability/*.sarif
            reachability/*.md
            reachability/*.html
            reachability/*.txt
```

For repositories that vendor Reachability Advisor as a development dependency, replace the install command with:

```bash
python -m pip install -e .
```

## Composite Action Variant

When you want the scanner installed directly from this repository, use the composite action. It accepts newline-separated SBOMs, source roots, artifact aliases, rendered Kubernetes manifests, and an optional default-branch baseline, then exposes stable output paths for SARIF/artifact upload steps.

```yaml
      - name: Run Reachability Advisor
        id: reachability
        uses: Devko/reachability-advisor@main
        with:
          sbom: |
            sboms/app.cdx.json
          vulns: vulns/app.grype.json
          source-root: |
            app=.
          terraform-source: infra
          kubernetes-manifest: |
            k8s/rendered.yaml
          policy: configs/policy.example.json
          baseline: reachability-baseline.json
          min-artifact-match-coverage: "0.9"
          min-strong-artifact-identity-coverage: "0.9"
          min-source-rule-coverage: "0.8"
          min-external-evidence-usable-ratio: "0.8"
          fail-on-mapping-warnings: "true"
          fail-on-new-tier: high

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.reachability.outputs.sarif }}

      - name: Upload reachability artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: reachability-advisor
          path: |
            ${{ steps.reachability.outputs.findings }}
            ${{ steps.reachability.outputs.mapping }}
            ${{ steps.reachability.outputs.terraform_coverage }}
            ${{ steps.reachability.outputs.kubernetes_coverage }}
            ${{ steps.reachability.outputs.baseline }}
            ${{ steps.reachability.outputs.delta }}
            ${{ steps.reachability.outputs.delta_markdown }}
            ${{ steps.reachability.outputs.markdown }}
            ${{ steps.reachability.outputs.html }}
```

Pin this to a release tag when one is available.

## Release Gate Variant

For release branches and deployment gates, scan the built artifact instead of the source checkout. The source checkout is still passed to Reachability Advisor so source reachability evidence can be collected.

```yaml
      - name: Build image
        run: docker build -t local/app:${{ github.sha }} .

      - name: Generate image SBOM and vulnerability matches
        run: |
          mkdir -p sboms vulns reachability
          syft local/app:${{ github.sha }} -o cyclonedx-json=sboms/app.cdx.json
          grype sbom:sboms/app.cdx.json -o json --file vulns/app.grype.json

      - name: Generate Terraform plan context
        run: |
          terraform -chdir=infra init -backend=false
          terraform -chdir=infra plan -refresh=false -out=tfplan.binary
          terraform -chdir=infra show -json tfplan.binary > reachability/tfplan.json

      - name: Run release gate
        run: |
          reachability-advisor scan \
            --sbom sboms/app.cdx.json \
            --vulns vulns/app.grype.json \
            --source-root app=. \
            --artifact-alias app=local/app:${{ github.sha }} \
            --terraform-plan reachability/tfplan.json \
            --terraform-coverage-out reachability/terraform-coverage.json \
            --kubernetes-manifest k8s/rendered.yaml \
            --kubernetes-coverage-out reachability/kubernetes-coverage.json \
            --source-coverage-out reachability/source-coverage.json \
            --mapping-out reachability/mapping.json \
            --out reachability/findings.json \
            --evidence-graph-out reachability/evidence-graph.json \
            --sarif-out reachability/reachability.sarif \
            --markdown-out reachability/summary.md \
            --html-out reachability/reachability-graph.html \
            --annotations-out reachability/annotations.txt \
            --fail-on-tier high
```

Use `--terraform-source infra` only when a plan cannot be generated in the job. Source mode cannot evaluate modules, `count`, `for_each`, data sources, provider defaults, or dynamic expressions.

## Recommended Pattern

1. Generate one CycloneDX SBOM per deployable artifact.
2. Generate Grype JSON from the same SBOM.
3. Pass the matching source checkout with `--source-root name=path`.
4. Pass Terraform plan JSON for release gates.
5. Pass rendered Kubernetes YAML/JSON when workloads are deployed through Kubernetes, Helm, or Kustomize.
6. Write `--mapping-out`, `--source-coverage-out`, `--terraform-coverage-out`, `--kubernetes-coverage-out`, and `--evidence-graph-out` when the related inputs are present.
7. Upload SARIF to GitHub code scanning and upload JSON/Markdown/HTML artifacts for audit.
8. Fail on `--fail-on-tier high` only when the team is ready to enforce the prioritized queue.

Terraform plan JSON can include sensitive values. Prefer not to upload it. Upload `terraform-coverage.json`, `kubernetes-coverage.json`, `source-coverage.json`, `mapping.json`, and `evidence-graph.json` instead.

## Account-Free Terraform E2E Test

Reachability Advisor analyzes `terraform show -json` output. It does not call Terraform providers or cloud APIs during `scan`, so an end-to-end test can use a reduced plan JSON shaped like Terraform output.

The repository includes `samples/e2e-no-cloud/` for this path:

```bash
reachability-advisor scan \
  --sbom samples/e2e-no-cloud/app.cdx.json \
  --vulns samples/e2e-no-cloud/vulnerabilities.json \
  --source-root no-cloud-app=samples/e2e-no-cloud/source \
  --terraform-plan samples/e2e-no-cloud/tfplan.json \
  --terraform-coverage-out outputs/no-cloud/terraform-coverage.json \
  --source-coverage-out outputs/no-cloud/source-coverage.json \
  --mapping-out outputs/no-cloud/mapping.json \
  --evidence-graph-out outputs/no-cloud/evidence-graph.json \
  --html-out outputs/no-cloud/reachability-graph.html \
  --out outputs/no-cloud/findings.json
```

This proves the scanner path, artifact matching, public network context, IAM capability extraction, source reachability, evidence graph, and HTML output without a real cloud account. It does not prove that a real environment matches the fixture.

## Fallback Without a Plan

Use this only for early feedback when the repository cannot generate a plan in CI:

```bash
reachability-advisor scan \
  --sbom sboms/app.cdx.json \
  --vulns vulns/app.grype.json \
  --source-root app=. \
  --terraform-source infra \
  --terraform-coverage-out reachability/terraform-coverage.json \
  --source-coverage-out reachability/source-coverage.json \
  --mapping-out reachability/mapping.json \
  --evidence-graph-out reachability/evidence-graph.json \
  --out reachability/findings.json
```

Treat source-mode Terraform gaps as work to resolve before release gating.

## External Source Evidence

The built-in source analyzer is fast and local. For higher source coverage, run a dedicated analyzer and import its result:

```bash
reachability-advisor export-semgrep-rules \
  --reachability-rules reachability-rules.json \
  --out reachability/semgrep-reachability.yml

semgrep scan \
  --config reachability/semgrep-reachability.yml \
  --json \
  --output reachability/semgrep.json

reachability-advisor scan \
  --sbom sboms/app.cdx.json \
  --vulns vulns/app.grype.json \
  --source-root app=. \
  --source-evidence-in reachability/semgrep.json \
  --require-external-source-evidence \
  --min-external-evidence-usable-ratio 1.0 \
  --source-coverage-out reachability/source-coverage.json \
  --out reachability/findings.json
```

For CodeQL, pass SARIF output as `--source-evidence-in`. CodeQL `codeFlows` are imported as high-confidence data-flow evidence when the result or rule metadata includes a package, package URL, or vulnerability selector. Generic CodeQL query ids are retained as symbols and are not treated as vulnerability ids unless they look like CVE/GHSA/OSV-style ids.

For Go services, pass `govulncheck -json` output as `--source-evidence-in`. Imported evidence must match a component/package, package URL, or vulnerability before it can upgrade a finding. Artifact is a narrowing selector, not a match by itself.

## Mapping Quality Gate

Use these gates once the pipeline emits image/runtime SBOMs and Terraform or rendered Kubernetes context:

```bash
reachability-advisor scan \
  --sbom sboms/app.cdx.json \
  --vulns vulns/app.grype.json \
  --source-root app=. \
  --terraform-plan tfplan.json \
  --mapping-out reachability/mapping.json \
  --source-coverage-out reachability/source-coverage.json \
  --min-artifact-match-coverage 1.0 \
  --min-strong-artifact-identity-coverage 1.0 \
  --min-source-rule-coverage 0.8 \
  --fail-on-mapping-warnings \
  --out reachability/findings.json
```

Start with advisory thresholds on existing repositories, then tighten them after SBOM metadata and artifact aliases are stable.

## PR Delta Gate

For mature repositories, publish `reachability-baseline.json` from the default branch and compare pull requests against that artifact. The PR report contains only new and worsened findings, so historical backlog does not block every PR:

```bash
reachability-advisor scan \
  --sbom sboms/app.cdx.json \
  --vulns vulns/app.grype.json \
  --source-root app=. \
  --out reachability/findings.json \
  --baseline-out reachability/reachability-baseline.json

reachability-advisor compare \
  --baseline main.reachability-baseline.json \
  --head-findings reachability/findings.json \
  --markdown-out reachability-delta.md \
  --fail-on-new-tier high
```

See `docs/policy_playbooks.md` for strict release, advisory pull request, and backlog migration policy files.

## Terraform Coverage Gate

This check fails if a valid Terraform plan is not fully accounted for. Visibility gaps indicate unsupported resources, unresolved modules, or opaque rendered manifests.

```bash
python - <<'PY'
import json
from pathlib import Path

coverage = json.loads(Path("reachability/terraform-coverage.json").read_text())
summary = coverage["summary"]
assert summary["resource_accounting_coverage"] == 1.0

if coverage["visibility_gaps"]:
    print("Terraform visibility gaps require review:")
    for gap in coverage["visibility_gaps"]:
        print("-", gap["type"], gap["address"])
    raise SystemExit(1)
PY
```
