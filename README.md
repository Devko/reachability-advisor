# Reachability Advisor

Reachability Advisor is a **developer-first** dependency vulnerability prioritization tool for CI pipelines and IDEs. It reads CycloneDX SBOMs, Grype or local vulnerability intelligence, source roots, and optional Terraform deployment context, then produces actionable outputs for engineers:

- ranked findings JSON;
- remediation-grouped fix queue;
- SARIF 2.1.0 for code scanning;
- IDE diagnostics JSON;
- GitHub Actions annotations;
- PR summary Markdown;
- PR delta comparison;
- single-finding explanations;
- Terraform multi-cloud coverage reports;
- SBOM/source/Terraform mapping reports.

Package status: **stable v1.0.0**.
License: **GNU GPL v3.0 or later**.

## Design principles

1. **Developer workflow first.** The tool should run in pull requests, local terminals, and editor integrations without requiring a cloud inventory platform.
2. **Privacy by default.** No network calls are made by the scanner. Vulnerability intelligence is supplied by a file produced by another tool or internal process.
3. **Conservative reachability.** Source and Terraform evidence improve prioritization, but weak evidence never auto-suppresses a vulnerability.
4. **Explainable scoring.** Every score includes rationale that a developer can inspect.
5. **Auditable mapping.** SBOM identity, source roots, and Terraform matches are visible through `--mapping-out`.
6. **Auditable Terraform coverage.** Every Terraform resource in a valid plan is accounted for; unsupported resources are reported as visibility gaps.
7. **Small, reviewable scope.** The focused edition intentionally avoids live cloud posture management, ticketing integrations, dashboards, secrets scanning, malware scanning, and DSPM.

## Install

From GitHub:

```bash
python -m pip install git+https://github.com/Devko/reachability-advisor.git@main
reachability-advisor version
```

For local development:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
reachability-advisor version
```

For local development without installation:

```bash
PYTHONPATH=src python -m reachability_advisor version
```

## How do we get SBOMs?

Reachability Advisor consumes CycloneDX JSON SBOMs; it does not generate them during the scan. Use the new planning command to get reproducible commands for your artifact:

```bash
PYTHONPATH=src python -m reachability_advisor sbom-plan \
  --artifact payments-api \
  --image ghcr.io/example/payments-api:1.8.2 \
  --source-root . \
  --ecosystem maven \
  --out-md outputs/payments-api-sbom-plan.md \
  --out-json outputs/payments-api-sbom-plan.json
```

Recommended practice:

- create one SBOM per deployable artifact;
- prefer container/image/runtime SBOMs for release gates;
- use filesystem/source SBOMs for early IDE or PR feedback;
- preserve artifact metadata such as image reference, digest, owner, and environment.

See `docs/sbom_generation.md`.

## Quick start

In production, generate vulnerability matches from the same SBOM with Grype:

```bash
grype sbom:sboms/payments-api.cdx.json -o json > vulns/payments-api.grype.json
```

For source-only validation, Grype can also emit both sides of the handoff from the same directory scan:

```bash
grype dir:path/to/app -o cyclonedx-json --name app --file sboms/app.cdx.json
grype dir:path/to/app -o json --name app --file vulns/app.grype.json
```

The sample command below uses the checked-in demo vulnerability file so it can run without downloading a scanner database.

```bash
PYTHONPATH=src python -m reachability_advisor scan \
  --sbom samples/sboms/payments-api.cdx.json \
  --sbom samples/sboms/notifier.cdx.json \
  --sbom samples/sboms/orders-api.cdx.json \
  --sbom samples/sboms/audit-api.cdx.json \
  --vulns samples/vulnerabilities.json \
  --terraform-plan samples/tfplan-multicloud.json \
  --terraform-coverage-out outputs/terraform-coverage.json \
  --mapping-out outputs/mapping.json \
  --source-root payments-api=samples/source/payments-api \
  --source-root notifier=samples/source/notifier \
  --source-root orders-api=samples/source/orders-api \
  --source-root audit-api=samples/source/audit-api \
  --out outputs/findings.json \
  --sarif-out outputs/findings.sarif \
  --diagnostics-out outputs/diagnostics.json \
  --markdown-out outputs/pr-summary.md \
  --annotations-out outputs/annotations.txt
```

Expected top signals:

```text
payments-api / log4j-core: urgent
  AWS ECS + public SG/API context + sensitive IAM + attacker-controlled source path

orders-api / requests: urgent
  Azure Container App + external ingress + contributor role + attacker-controlled source path

audit-api / jackson-databind: urgent
  GCP Cloud Run + allUsers invoker + secret accessor + attacker-controlled source path
```

## How mapping works

```text
SBOM artifact
  -> component / package URL
  -> vulnerability intelligence
  -> source reachability evidence
  -> artifact identity candidates
  -> Terraform workload match
  -> exposure / identity / data context
  -> score and developer output
```

The mapper uses three guardrails:

| Area | Improvement |
|---|---|
| SBOM identity | Reads metadata component properties and external references; supports artifact aliases. |
| Artifact matching | Uses explicit image/reference/digest/repository-tag scoring instead of permissive substring matching. |
| Source reachability | Uses vulnerability-aware rules and requires same-file input evidence for `attacker_controlled`. |

Verify the logic with:

```bash
--mapping-out outputs/mapping.json
```

The mapping report shows artifact candidates, source roots, Terraform match methods/scores, and warnings. See `docs/reachability_mapping.md`.

## Artifact aliases

If a generated SBOM lacks a strong image reference, add one at scan time:

```bash
reachability-advisor scan \
  --sbom sboms/payments-api.cdx.json \
  --artifact-alias payments-api=ghcr.io/example/payments-api:1.8.2 \
  --vulns vulnerabilities.json
```

Aliases are visible in the mapping report.

## Custom reachability rules

Add package- or vulnerability-specific source rules without patching the scanner:

```bash
reachability-advisor scan \
  --sbom app.cdx.json \
  --vulns vulnerabilities.json \
  --source-root app=. \
  --reachability-rules reachability-rules.json
```

See `docs/data_formats.md` for the rule JSON format.

## Terraform coverage model

Reachability Advisor supports AWS, Azure, GCP, and Kubernetes provider resources through a manifest-driven Terraform analyzer and executable community fixture packs.

Two coverage numbers are reported:

| Metric | Meaning |
|---|---|
| `resource_accounting_coverage` | Every Terraform resource observed in the plan is represented in the coverage report. This should be `1.0` for valid plans. |
| `semantic_classification_coverage` | Fraction of observed resources covered by the declared semantic manifest. Unsupported resources become `visibility_gaps`, not safe assumptions. |

The sample multi-cloud plan reaches:

```text
resource_accounting_coverage: 1.0
semantic_classification_coverage: 1.0
artifact_match_coverage: 1.0
providers_seen: aws, azure, gcp, kubernetes
```

See `docs/terraform_coverage.md` and `fixtures/terraform/README.md` for details.

## Community Terraform fixture packs

The `fixtures/terraform` directory contains executable fixture packs for common module-shaped plans:

| Fixture | Provider | Purpose |
|---|---|---|
| `aws-ecs-fargate-service` | AWS | ECS/Fargate service shape with task definition, ALB, security group, IAM, and secrets. |
| `azure-container-apps` | Azure | Container Apps shape with external ingress, managed identity, role assignment, and Key Vault. |
| `gcp-cloud-run` | GCP | Cloud Run shape with public invoker IAM, service account, domain mapping, and Secret Manager. |
| `kubernetes-ingress-workload` | Kubernetes | Deployment, Service, Ingress, ServiceAccount, and RBAC shape. |

Run the fixture harness locally:

```bash
PYTHONPATH=src python -m reachability_advisor fixtures list
PYTHONPATH=src python -m reachability_advisor fixtures validate
PYTHONPATH=src python -m reachability_advisor fixtures run \
  --out outputs/fixtures-report.json \
  --output-dir outputs/fixtures
```

The fixture packs assert `1.0` resource accounting, semantic classification, and artifact matching for their included resources. Unsupported resources and opaque rendered-manifest wrappers remain visibility gaps, not safe assumptions.


## Real-world Terraform validation

Use `hcl-audit` to check public Terraform source repositories when a `terraform show -json` plan is not available:

```bash
PYTHONPATH=src python -m reachability_advisor hcl-audit \
  --path infra \
  --out outputs/hcl-audit.json \
  --markdown-out outputs/hcl-audit.md
```

`hcl-audit` accounts for `.tf` resources and modules, classifies known AWS/Azure/GCP/Kubernetes resource types, resolves simple literal variable defaults and `.tfvars` assignments, extracts simple image/exposure/identity literals, and reports unresolved variables, modules, or opaque Helm/kubectl manifest wrappers as visibility gaps. For release gates, prefer `--terraform-plan`; for early PR/IDE or open-source repository validation, use `--terraform-source` or `hcl-audit`.

A curated external corpus is in `external_corpus/popular_terraform_projects.json`. In a network-enabled environment:

```bash
python scripts/run_external_hcl_audit.py
```

The current corpus validates 9 public repositories with `1.0` semantic classification coverage and writes aggregate reports to `outputs/external-hcl-audit/`. See `docs/real_world_validation.md`.

Existing real-world Grype handoff outputs can be replayed with:

```bash
python scripts/run_external_grype_validation.py
```

That summary currently covers Petclinic, the AWS ECS demo backend, and the Azure Chainlit app.

## GitHub Actions pipeline

See [docs/pipeline.md](docs/pipeline.md) for a complete GitHub Actions example using GitHub-hosted runners. The workflow generates CycloneDX SBOMs and Grype vulnerability JSON, runs Reachability Advisor, uploads SARIF, stores mapping and Terraform coverage artifacts, and publishes a Markdown summary to the job page.

For repositories that want to consume the published action directly:

```yaml
- uses: Devko/reachability-advisor@main
  with:
    sbom: sboms/app.cdx.json
    vulns: vulns/app.grype.json
    source-root: app=.
    fail-on-tier: high
```

## CI gate

```bash
reachability-advisor scan \
  --sbom app.cdx.json \
  --vulns vulnerabilities.json \
  --terraform-plan tfplan.json \
  --terraform-coverage-out terraform-coverage.json \
  --mapping-out mapping.json \
  --source-root app=. \
  --sarif-out reachability.sarif \
  --markdown-out reachability-pr-summary.md \
  --fail-on-tier high
```

## PR delta gate

Use this to block only new or regressed high-risk findings instead of failing on the existing backlog.

```bash
reachability-advisor compare \
  --base-findings main.findings.json \
  --head-findings pr.findings.json \
  --markdown-out reachability-delta.md \
  --fail-on-new-tier high
```

## IDE integration

The `ide/vscode` directory contains a minimal VS Code extension skeleton. It invokes the CLI, reads `--diagnostics-out`, and places diagnostics in the editor. The extension is intentionally small so the security-sensitive logic stays in the audited Python CLI.

## Supported evidence

| Evidence | Current support |
|---|---|
| SBOM | CycloneDX JSON |
| SBOM acquisition support | `sbom-plan` command with Syft, Trivy, Maven, npm, and Python suggestions |
| Vulnerability input | Grype JSON, local JSON, and small OSV-Scanner-style JSON |
| Source reachability | Java/Maven, Node/npm including Express, Python/PyPI including FastAPI/Chainlit/aiohttp, and basic Go import evidence |
| Custom source rules | `--reachability-rules` JSON |
| Terraform context | AWS, Azure, GCP, and Kubernetes provider plan/source hints with coverage reporting and linked workload exposure inference |
| Context JSON | Optional explicit context keyed by artifact name |
| Outputs | JSON with remediation groups and raw findings, SARIF, diagnostics JSON, Markdown, annotations, Terraform coverage JSON, mapping JSON |

## Run quality gates

```bash
make compile
make test
make coverage
make sample
make fixtures
make release-check
make package
```

Current validation snapshot:

```text
Ran 318 tests: OK
Coverage: 93%
Coverage gate: 93% passed
Fixture packs: 4 passed, 0 failed
Release validation: passed
Package build: sdist and wheel
```

## Repository structure

```text
src/reachability_advisor/  Python package and CLI
samples/                   Reproducible demo inputs, including multi-cloud Terraform plan
fixtures/terraform/        Community Terraform fixture packs and harness inputs
tests/                     Unit and workflow tests
ide/vscode/                Minimal VS Code extension skeleton
docs/                      User, maintainer, algorithm, and governance docs
schemas/                   Output and policy schema drafts
.github/workflows/         CI and sample pipeline workflows
action.yml                 Composite GitHub Action wrapper
```

## Safety boundary

Reachability Advisor is a prioritization aid. It does **not** prove exploitability, does **not** automatically mark findings as not affected, and does **not** replace secure engineering review. Its job is to reduce alert fatigue by putting the most actionable findings at the top of the developer workflow.
