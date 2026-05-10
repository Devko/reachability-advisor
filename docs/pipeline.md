# CI Pipeline Integration

Reachability Advisor runs after SBOM and vulnerability generation. A typical CI job produces a CycloneDX SBOM with Syft, scans that SBOM with Grype, then adds Reachability Advisor's source and Terraform context so the pipeline can rank what is reachable and exposed.

The scanner itself does not call external services. Keep Syft, Grype, Terraform, and artifact upload steps in the pipeline so teams can pin versions, cache databases, and control credentials.

## GitHub Actions Workflow

This workflow is designed for GitHub-hosted Linux runners. It uses source-mode SBOM generation for pull requests because it works before an image has been built. For release gates, use the image/runtime variant below.

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
        if: ${{ hashFiles('infra/**/*.tf') != '' }}
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_wrapper: false

      - name: Generate Terraform plan context
        if: ${{ hashFiles('infra/**/*.tf') != '' }}
        run: |
          terraform -chdir=infra init -backend=false
          terraform -chdir=infra plan -refresh=false -out=tfplan.binary
          terraform -chdir=infra show -json tfplan.binary > reachability/tfplan.json

      - name: Run reachability prioritization with Terraform plan
        if: ${{ hashFiles('infra/**/*.tf') != '' }}
        run: |
          reachability-advisor scan \
            --sbom sboms/app.cdx.json \
            --vulns vulns/app.grype.json \
            --source-root app=. \
            --terraform-plan reachability/tfplan.json \
            --terraform-coverage-out reachability/terraform-coverage.json \
            --mapping-out reachability/mapping.json \
            --out reachability/findings.json \
            --sarif-out reachability/reachability.sarif \
            --markdown-out reachability/summary.md \
            --annotations-out reachability/annotations.txt \
            --fail-on-tier high

      - name: Run reachability prioritization without Terraform plan
        if: ${{ hashFiles('infra/**/*.tf') == '' }}
        run: |
          reachability-advisor scan \
            --sbom sboms/app.cdx.json \
            --vulns vulns/app.grype.json \
            --source-root app=. \
            --out reachability/findings.json \
            --sarif-out reachability/reachability.sarif \
            --markdown-out reachability/summary.md \
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
            reachability/*.txt
```

For repositories that vendor Reachability Advisor as a development dependency, replace the install command with:

```bash
python -m pip install -e .
```

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

      - name: Run release gate
        run: |
          reachability-advisor scan \
            --sbom sboms/app.cdx.json \
            --vulns vulns/app.grype.json \
            --source-root app=. \
            --artifact-alias app=local/app:${{ github.sha }} \
            --terraform-source infra \
            --terraform-coverage-out reachability/terraform-coverage.json \
            --mapping-out reachability/mapping.json \
            --out reachability/findings.json \
            --sarif-out reachability/reachability.sarif \
            --markdown-out reachability/summary.md \
            --annotations-out reachability/annotations.txt \
            --fail-on-tier high
```

Use `--terraform-plan reachability/tfplan.json` when a plan is available. Use `--terraform-source infra` for early feedback when plans require protected cloud credentials.

## Recommended Pattern

1. Generate one CycloneDX SBOM per deployable artifact.
2. Generate Grype JSON from the same SBOM.
3. Pass the matching source checkout with `--source-root name=path`.
4. Pass Terraform plan JSON for release gates, or Terraform source for early PR feedback.
5. Write `--mapping-out` and `--terraform-coverage-out` on every run.
6. Upload SARIF to GitHub code scanning and upload JSON/Markdown artifacts for audit.
7. Fail on `--fail-on-tier high` only when the team is ready to enforce the prioritized queue.

Terraform plan JSON can include sensitive values. Store it only as a short-lived job artifact when needed, or avoid uploading it and keep the generated coverage/mapping reports instead.

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

This check fails if a valid Terraform plan is not fully accounted for. Visibility gaps should be reviewed because they indicate unsupported resources, unresolved modules, or opaque rendered manifests.

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
