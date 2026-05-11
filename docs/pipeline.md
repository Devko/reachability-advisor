# CI Pipeline Integration

Reachability Advisor runs after SBOM and vulnerability generation. A production gate requires four inputs for each deployable artifact:

1. CycloneDX SBOM.
2. Grype JSON generated from that SBOM.
3. Source root for code reachability.
4. Terraform plan JSON for workload, network, and IAM context.

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

      - name: Run reachability prioritization
        run: |
          reachability-advisor scan \
            --sbom sboms/app.cdx.json \
            --vulns vulns/app.grype.json \
            --source-root app=. \
            --terraform-plan reachability/tfplan.json \
            --terraform-coverage-out reachability/terraform-coverage.json \
            --source-coverage-out reachability/source-coverage.json \
            --mapping-out reachability/mapping.json \
            --out reachability/findings.json \
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

When you want the scanner installed directly from this repository, use the composite action. It accepts newline-separated SBOMs, source roots, and artifact aliases, then exposes stable output paths for SARIF/artifact upload steps.

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
          policy: configs/policy.example.json
          fail-on-tier: high

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
            --source-coverage-out reachability/source-coverage.json \
            --mapping-out reachability/mapping.json \
            --out reachability/findings.json \
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
5. Write `--mapping-out`, `--source-coverage-out`, and `--terraform-coverage-out` on every run.
6. Upload SARIF to GitHub code scanning and upload JSON/Markdown/HTML artifacts for audit.
7. Fail on `--fail-on-tier high` only when the team is ready to enforce the prioritized queue.

Terraform plan JSON can include sensitive values. Prefer not to upload it. Upload `terraform-coverage.json`, `source-coverage.json`, and `mapping.json` instead.

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
  --source-coverage-out reachability/source-coverage.json \
  --out reachability/findings.json
```

For Go services, pass `govulncheck -json` output as `--source-evidence-in`. Imported evidence must match a component/package, package URL, or vulnerability before it can upgrade a finding. Artifact is a narrowing selector, not a match by itself.

## PR Delta Gate

For mature repositories, compare the pull request result against a baseline from the default branch so historical findings do not block every PR:

```bash
reachability-advisor compare \
  --base-findings main.findings.json \
  --head-findings pr.findings.json \
  --markdown-out reachability-delta.md \
  --fail-on-new-tier high
```

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
