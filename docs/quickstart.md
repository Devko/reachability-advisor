# Quickstart

This guide runs the checked-in sample and shows the files to inspect. The sample includes SBOMs, vulnerability data, source roots, a multi-cloud Terraform plan, and rendered Kubernetes manifests.

## 1. Install locally

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## 2. Run the sample scan

```bash
./scripts/run_sample.sh
```

The command writes:

- `outputs/findings.json` - canonical machine-readable finding set;
- `outputs/reachability-baseline.json` - stable baseline artifact for default-branch PR comparisons;
- `outputs/findings.sarif` - CI/code-scanning output;
- `outputs/diagnostics.json` - editor diagnostics output;
- `outputs/pr-summary.md` - pull request summary;
- `outputs/reachability-graph.html` - searchable graph of assets, vulnerabilities, network/IAM context, code exposure, and findings;
- `outputs/annotations.txt` - GitHub Actions workflow-command annotations;
- `outputs/terraform-coverage.json` - Terraform resource accounting, semantic coverage, artifact matches, and visibility gaps;
- `outputs/kubernetes-coverage.json` - rendered Kubernetes workload, service, ingress, RBAC, and artifact-match coverage;
- `outputs/source-coverage.json` - source files and package-manager manifests scanned, skipped files, evidence states, dependency-graph evidence, manifest evidence, and external evidence counts;
- `outputs/mapping.json` - SBOM, source-root, and Terraform workload mapping.


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

Use this report first when a finding looks wrong. It shows the artifact candidates, source root status, Terraform match methods, match scores, and warnings.

## 4. Inspect deployment coverage

```bash
python - <<'PY'
import json
from pathlib import Path
coverage = json.loads(Path('outputs/terraform-coverage.json').read_text())
print(json.dumps(coverage['summary'], indent=2))
k8s = json.loads(Path('outputs/kubernetes-coverage.json').read_text())
print(json.dumps(k8s['summary'], indent=2))
PY
```

The sample plan has full resource accounting, full semantic classification coverage, and full artifact matching across AWS, Azure, GCP, and Kubernetes resources. The rendered manifest sample shows direct public service exposure and Kubernetes RBAC impact for matched workloads.

## 5. Explain one finding

```bash
reachability-advisor explain \
  --findings outputs/findings.json \
  --artifact payments-api \
  --component log4j-core \
  --vulnerability CVE-2021-44228
```

## 6. Run a release-style gate

```bash
reachability-advisor scan \
  --sbom samples/sboms/payments-api.cdx.json \
  --vulns samples/vulnerabilities.json \
  --terraform-plan samples/tfplan-multicloud.json \
  --terraform-coverage-out outputs/terraform-coverage.json \
  --kubernetes-manifest samples/kubernetes-manifest.yaml \
  --kubernetes-coverage-out outputs/kubernetes-coverage.json \
  --source-coverage-out outputs/source-coverage.json \
  --mapping-out outputs/mapping.json \
  --source-root payments-api=samples/source/payments-api \
  --sarif-out outputs/findings.sarif \
  --html-out outputs/reachability-graph.html \
  --baseline-out outputs/reachability-baseline.json \
  --fail-on-tier high \
  --no-table
```

## 7. Compare a pull request with the default-branch baseline

```bash
reachability-advisor compare \
  --baseline reachability-baseline.json \
  --head-findings pr.findings.json \
  --markdown-out reachability-delta.md \
  --fail-on-new-tier high
```

The baseline file is written by `scan --baseline-out` on the default branch. With `--baseline`, the delta report contains only new and worsened findings.

## 8. Run Terraform fixture packs

```bash
./scripts/run_fixture_packs.sh
```

The fixture harness writes:

- `outputs/fixtures-validate.json` - fixture metadata and parseability validation;
- `outputs/fixtures-report.json` - aggregate pass/fail report;
- `outputs/fixtures/<pack>/findings.json` - per-fixture findings;
- `outputs/fixtures/<pack>/terraform-coverage.json` - per-fixture Terraform coverage;
- `outputs/fixtures/<pack>/source-coverage.json` - per-fixture source coverage.

List packs:

```bash
reachability-advisor fixtures list
```

Run one pack:

```bash
reachability-advisor fixtures run --fixture gcp-cloud-run
```
