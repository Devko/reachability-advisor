# CI Pipeline Integration

Reachability Advisor is designed to run after SBOM and vulnerability-intelligence generation. Terraform context is optional but recommended when teams want code-to-cloud prioritization without a live cloud connector.

## GitHub Actions example

```yaml
name: reachability-advisor
on: [pull_request]

jobs:
  reachability:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: python -m pip install -e .
      - run: |
          terraform init
          terraform plan -out=tfplan.binary
          terraform show -json tfplan.binary > tfplan.json
      - run: |
          reachability-advisor scan \
            --sbom app.cdx.json \
            --vulns vulnerabilities.json \
            --terraform-plan tfplan.json \
            --terraform-coverage-out terraform-coverage.json \
            --mapping-out mapping.json \
            --source-root app=. \
            --sarif-out reachability.sarif \
            --markdown-out reachability-pr-summary.md \
            --annotations-out reachability-annotations.txt \
            --fail-on-tier high
      - run: cat reachability-annotations.txt
      - run: cat reachability-pr-summary.md >> "$GITHUB_STEP_SUMMARY"
```

## Recommended pipeline pattern

1. Generate one CycloneDX SBOM per deployable artifact. Use `reachability-advisor sbom-plan` to document the commands if your project does not already have them.
2. Generate vulnerability intelligence with the scanner of your choice.
3. Optionally generate `terraform show -json` plan output. Treat the plan JSON as sensitive.
4. Run Reachability Advisor with `--mapping-out` and `--terraform-coverage-out`.
5. Upload SARIF to your code scanning platform.
6. Publish `mapping.json` and `terraform-coverage.json` as artifacts.
7. Fail only on new or actionable high-risk findings.

## PR delta workflow

For mature programs, avoid failing every PR on historical findings. Store a baseline findings file from the default branch, generate a head findings file for the PR branch, then run:

```bash
reachability-advisor compare \
  --base-findings main.findings.json \
  --head-findings pr.findings.json \
  --markdown-out reachability-delta.md \
  --fail-on-new-tier high
```

## Terraform coverage gate

A simple coverage check can enforce that the plan is fully accounted for while still allowing known semantic gaps to be reviewed:

```bash
python - <<'PY'
import json
from pathlib import Path
coverage = json.loads(Path('terraform-coverage.json').read_text())
summary = coverage['summary']
assert summary['resource_accounting_coverage'] == 1.0
if coverage['visibility_gaps']:
    print('Terraform visibility gaps require review:')
    for gap in coverage['visibility_gaps']:
        print('-', gap['type'], gap['address'])
PY
```
