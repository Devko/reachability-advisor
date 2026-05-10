# Quickstart

This guide shows the shortest path from demo data to developer-facing outputs.

## 1. Install locally

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## 2. Run the demo scan

```bash
./scripts/run_sample.sh
```

The command writes:

- `outputs/findings.json` - canonical machine-readable finding set;
- `outputs/findings.sarif` - CI/code-scanning output;
- `outputs/diagnostics.json` - editor diagnostics output;
- `outputs/pr-summary.md` - developer summary for pull requests;
- `outputs/reachability-graph.html` - searchable graph of assets, vulnerabilities, network/IAM context, and findings;
- `outputs/annotations.txt` - GitHub Actions workflow-command annotations;
- `outputs/terraform-coverage.json` - AWS/Azure/GCP/Kubernetes Terraform accounting and semantic coverage report;
- `outputs/mapping.json` - SBOM/source/Terraform mapping verification report.


## 3. Inspect mapping logic

```bash
python - <<'PY'
import json
from pathlib import Path
mapping = json.loads(Path('outputs/mapping.json').read_text())
for artifact in mapping['artifacts']:
    print(artifact['name'], 'source=', artifact['source_root_exists'], 'terraform=', artifact['terraform_matched'])
    for warning in artifact['mapping_warnings']:
        print('  warning:', warning)
PY
```

Use this report when a finding looks wrong. It shows artifact candidates, source roots, Terraform match methods/scores, and warnings.

## 4. Inspect Terraform coverage

```bash
python - <<'PY'
import json
from pathlib import Path
coverage = json.loads(Path('outputs/terraform-coverage.json').read_text())
print(json.dumps(coverage['summary'], indent=2))
PY
```

The sample plan has 100% resource accounting, 100% semantic classification coverage, and 100% artifact matching across AWS, Azure, GCP, and Kubernetes resources.

## 5. Explain one finding

```bash
reachability-advisor explain \
  --findings outputs/findings.json \
  --artifact payments-api \
  --component log4j-core \
  --vulnerability CVE-2021-44228
```

## 6. Fail a pipeline only on actionable risk

```bash
reachability-advisor scan \
  --sbom samples/sboms/payments-api.cdx.json \
  --vulns samples/vulnerabilities.json \
  --terraform-plan samples/tfplan-multicloud.json \
  --terraform-coverage-out outputs/terraform-coverage.json \
  --mapping-out outputs/mapping.json \
  --source-root payments-api=samples/source/payments-api \
  --sarif-out outputs/findings.sarif \
  --html-out outputs/reachability-graph.html \
  --fail-on-tier high \
  --no-table
```

## 7. Compare base and pull request findings

```bash
reachability-advisor compare \
  --base-findings main.findings.json \
  --head-findings pr.findings.json \
  --markdown-out reachability-delta.md \
  --fail-on-new-tier high
```

## 8. Run community Terraform fixture packs

```bash
./scripts/run_fixture_packs.sh
```

The fixture harness writes:

- `outputs/fixtures-validate.json` - fixture metadata and parseability validation;
- `outputs/fixtures-report.json` - aggregate pass/fail report;
- `outputs/fixtures/<pack>/findings.json` - per-fixture findings;
- `outputs/fixtures/<pack>/terraform-coverage.json` - per-fixture Terraform coverage.

List packs:

```bash
reachability-advisor fixtures list
```

Run one pack:

```bash
reachability-advisor fixtures run --fixture gcp-cloud-run
```
