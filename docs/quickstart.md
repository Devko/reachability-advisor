# Quickstart

This guide runs the checked-in demo and sample data, then shows the files to inspect. The sample includes SBOMs, vulnerability data, source roots, a multi-cloud Terraform plan, rendered Kubernetes manifests, and scanner evidence.

## Install Locally

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## Run The Demo

The demo uses checked-in files only. It does not require cloud credentials or network access.

```bash
python -m reachability_advisor demo
```

The command writes the report set to `outputs/demo/`, including:

- `outputs/demo/findings.json`
- `outputs/demo/summary.md`
- `outputs/demo/reachability.sarif`
- `outputs/demo/diagnostics.json`
- `outputs/demo/reachability-graph.html`
- `outputs/demo/mapping.json`
- `outputs/demo/source-coverage.json`
- `outputs/demo/kubernetes-coverage.json`

## Common Workflows

Dependency-only prioritization:

```bash
reachability-advisor scan \
  --sbom sboms/app.cdx.json \
  --vuln-in grype.json \
  --out outputs/findings.json \
  --markdown-out outputs/summary.md
```

AppSec triage with SAST and DAST:

```bash
reachability-advisor scan \
  --sbom sboms/app.cdx.json \
  --vuln-in grype.json \
  --sast-in semgrep.json \
  --dast-in zap.json \
  --source-root app=. \
  --out outputs/findings.json \
  --html-out outputs/reachability-graph.html
```

Deployment-aware release gate:

```bash
reachability-advisor scan \
  --sbom sboms/app.cdx.json \
  --vuln-in grype.json \
  --sast-in semgrep.json \
  --dast-in zap.json \
  --cspm-in checkov.json \
  --source-root app=. \
  --terraform-plan tfplan.json \
  --kubernetes-manifest rendered.yaml \
  --analysis-profile production \
  --fail-on-tier high \
  --out outputs/findings.json
```

Use Terraform plans and rendered Kubernetes manifests for release gates. Static source files are useful for early PR feedback, but plans and rendered manifests carry the deployment evidence needed for stronger decisions.

## Run The Sample Scan

```bash
./scripts/run_sample.sh
```

The command writes:

- `outputs/findings.json` - machine-readable finding set;
- `outputs/reachability-baseline.json` - baseline artifact for default-branch PR comparisons;
- `outputs/findings.sarif` - CI/code-scanning output;
- `outputs/diagnostics.json` - editor diagnostics output;
- `outputs/pr-summary.md` - pull request summary;
- `outputs/reachability-graph.html` - interactive attack-path report with asset context, findings, network/IAM evidence, source/runtime evidence, and traceable evidence paths;
- `outputs/evidence-graph.json` - structured asset/component/vulnerability/network/IAM/code graph used by the HTML report;
- `outputs/annotations.txt` - GitHub Actions workflow-command annotations;
- `outputs/terraform-coverage.json` - Terraform resource accounting, semantic coverage, artifact matches, and visibility gaps;
- `outputs/kubernetes-coverage.json` - rendered Kubernetes workload, service, ingress, RBAC, and artifact-match coverage;
- `outputs/source-coverage.json` - source files and package-manager manifests scanned, skipped files, evidence states, dependency-graph evidence, manifest evidence, and external evidence counts;
- `outputs/mapping.json` - SBOM, source-root, and Terraform workload mapping.


## Inspect Mapping Logic

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

## Inspect Deployment Coverage

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

The sample plan reports `1.0` resource accounting, semantic classification, and artifact matching across AWS, Azure, GCP, and Kubernetes resources. The rendered manifest sample shows direct public service exposure and Kubernetes RBAC impact for matched workloads.

## Explain One Finding

```bash
reachability-advisor explain \
  --findings outputs/findings.json \
  --artifact payments-api \
  --component log4j-core \
  --vulnerability CVE-2021-44228
```

## Run A Release-Style Gate

```bash
reachability-advisor scan \
  --sbom samples/sboms/payments-api.cdx.json \
  --vuln-in samples/vulnerabilities.json \
  --terraform-plan samples/tfplan-multicloud.json \
  --terraform-coverage-out outputs/terraform-coverage.json \
  --kubernetes-manifest samples/kubernetes-manifest.yaml \
  --kubernetes-coverage-out outputs/kubernetes-coverage.json \
  --source-evidence-in samples/source-evidence.json \
  --analysis-profile production \
  --source-coverage-out outputs/source-coverage.json \
  --mapping-out outputs/mapping.json \
  --evidence-graph-out outputs/evidence-graph.json \
  --source-root payments-api=samples/source/payments-api \
  --sarif-out outputs/findings.sarif \
  --html-out outputs/reachability-graph.html \
  --baseline-out outputs/reachability-baseline.json \
  --fail-on-tier high \
  --no-table
```

## Compare A Pull Request With The Default-Branch Baseline

```bash
reachability-advisor compare \
  --baseline reachability-baseline.json \
  --head-findings pr.findings.json \
  --markdown-out reachability-delta.md \
  --fail-on-new-tier high
```

The baseline file is written by `scan --baseline-out` on the default branch. With `--baseline`, the delta report contains only new and worsened findings.

## Run Terraform Fixture Packs

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

## Run The Full Local Gate

Before publishing a release or large behavior change, run the same gate used by maintainers:

```bash
make compile
make lint
make type-check
make test
make coverage
make sample
make fixtures
make release-check
make package
make demo
```
