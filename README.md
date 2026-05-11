# Reachability Advisor

Reachability Advisor ranks dependency vulnerabilities with deployment reachability evidence.

The normal input set is:

- one CycloneDX SBOM per deployable artifact;
- Grype JSON or normalized local vulnerability data from the same artifact;
- source roots for code reachability;
- Terraform plan JSON and/or rendered Kubernetes manifests for workload, network, and IAM context.

The scanner can run without Terraform or Kubernetes manifests, but that is a degraded mode. Without deployment context it cannot prove public exposure, lateral network paths, private isolation, workload IAM/RBAC, or artifact-to-infrastructure mapping.

Outputs:

- ranked findings JSON;
- remediation-grouped fix queue;
- SARIF 2.1.0 for code scanning;
- IDE diagnostics JSON;
- GitHub Actions annotations;
- PR summary Markdown;
- self-contained interactive HTML graph report;
- evidence graph JSON;
- PR delta comparison;
- single-finding explanations;
- source-analysis coverage reports;
- Terraform multi-cloud coverage reports;
- rendered Kubernetes manifest coverage reports;
- SBOM/source/Terraform mapping reports.

Package status: **stable v1.0.0**.
License: **GNU GPL v3.0 or later**.

## Operating Rules

1. The scanner is local. It does not upload SBOMs, source, Terraform plans, or vulnerability data.
2. Terraform plan analysis is the primary deployment-context path.
3. Rendered Kubernetes manifests add workload, Service, Ingress, and RBAC context for Kubernetes deployments.
4. Source-only or HCL-static analysis is for early feedback, not release confidence.
5. Weak evidence never suppresses a vulnerability or marks it `not_affected`.
6. Every score includes rationale and every artifact match is visible in `--mapping-out`.
7. Every Terraform resource in a valid plan is represented in `--terraform-coverage-out`; unsupported resources are reported as visibility gaps.
8. This project does not provide live cloud inventory, posture management, ticketing, dashboards, secrets scanning, malware scanning, or DSPM.

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

## SBOM Inputs

Reachability Advisor consumes CycloneDX JSON SBOMs; it does not generate them during the scan. Use `sbom-plan` to generate commands for a specific artifact:

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
It includes public, internal/lateral, and private/no-ingress workloads so the HTML graph shows different entry paths.

```bash
PYTHONPATH=src python -m reachability_advisor scan \
  --sbom samples/sboms/payments-api.cdx.json \
  --sbom samples/sboms/notifier.cdx.json \
  --sbom samples/sboms/orders-api.cdx.json \
  --sbom samples/sboms/audit-api.cdx.json \
  --sbom samples/sboms/inventory-api.cdx.json \
  --sbom samples/sboms/batch-worker.cdx.json \
  --sbom samples/sboms/reports-api.cdx.json \
  --vulns samples/vulnerabilities.json \
  --terraform-plan samples/tfplan-multicloud.json \
  --terraform-coverage-out outputs/terraform-coverage.json \
  --kubernetes-manifest samples/kubernetes-manifest.yaml \
  --kubernetes-coverage-out outputs/kubernetes-coverage.json \
  --source-coverage-out outputs/source-coverage.json \
  --mapping-out outputs/mapping.json \
  --source-root payments-api=samples/source/payments-api \
  --source-root notifier=samples/source/notifier \
  --source-root orders-api=samples/source/orders-api \
  --source-root audit-api=samples/source/audit-api \
  --source-root inventory-api=samples/source/inventory-api \
  --source-root batch-worker=samples/source/batch-worker \
  --source-root reports-api=samples/source/reports-api \
  --out outputs/findings.json \
  --evidence-graph-out outputs/evidence-graph.json \
  --sarif-out outputs/findings.sarif \
  --diagnostics-out outputs/diagnostics.json \
  --markdown-out outputs/pr-summary.md \
  --html-out outputs/reachability-graph.html \
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

inventory-api / requests: high
  AWS ECS + lateral path through the public API security group + attacker-controlled source path

batch-worker / lodash: medium
  AWS ECS private security group + no detected ingress path + function-level source use

batch-worker / left-pad: low
  AWS ECS private security group + package present, but no source rule/import evidence

reports-api / requests: medium
  AWS ECS internal-only security group + read-only IAM + function-level source use
```

The checked-in sample covers the main network, IAM, and code-exposure combinations:

| Case | Sample asset |
|---|---|
| Public internet entry | `payments-api`, `orders-api`, `audit-api`, `notifier` |
| Lateral movement path | `inventory-api` |
| Fully internal/private-network ingress | `reports-api` |
| Private/no detected ingress | `batch-worker` |
| Admin role | `orders-api` |
| No linked role | `batch-worker`, `notifier` |
| Critical data-access role | `payments-api`, `audit-api` |
| Read-only/limited role | `reports-api` |

| Code exposure case | Sample finding |
|---|---|
| Request-controlled path | `payments-api / log4j-core`, `orders-api / requests`, `audit-api / jackson-databind`, `inventory-api / requests` |
| Reachable vulnerable API, no attacker-controlled path proven | `batch-worker / lodash`, `reports-api / requests` |
| SBOM only, source usage not observed | `payments-api / guava`, `notifier / minimist` |
| No source rule/import evidence | `batch-worker / left-pad` |

## How mapping works

```text
SBOM artifact
  -> component / package URL
  -> vulnerability intelligence
  -> source reachability evidence
  -> artifact identity candidates
  -> Terraform workload match
  -> exposure / identity / data context
  -> score, tier, and outputs
```

The mapper uses three guardrails:

| Area | Improvement |
|---|---|
| SBOM identity | Reads metadata component properties and external references; supports artifact aliases. |
| Artifact matching | Uses explicit image/reference/digest/repository-tag scoring and records the selected candidate source and strength. |
| Source reachability | Uses vulnerability-aware rules and requires same-function input/sink evidence or a bounded handler-to-sink call path for `attacker_controlled`. |

Verify the logic with:

```bash
--mapping-out outputs/mapping.json
```

The mapping report shows artifact candidates, candidate source/strength, source roots, Terraform match methods/scores, and warnings. See `docs/reachability_mapping.md`.

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

Generate starter Semgrep rules from the same rule set:

```bash
reachability-advisor export-semgrep-rules \
  --reachability-rules reachability-rules.json \
  --out semgrep-reachability.yml
```

Import stronger analyzer output when available:

```bash
reachability-advisor scan \
  --sbom app.cdx.json \
  --vulns vulnerabilities.json \
  --source-root app=. \
  --source-evidence-in semgrep-results.json \
  --source-coverage-out source-coverage.json
```

## Terraform coverage model

Reachability Advisor supports AWS, Azure, GCP, and Kubernetes provider resources through a manifest-driven Terraform analyzer and executable community fixture packs.

Two coverage numbers are reported:

| Metric | Meaning |
|---|---|
| `resource_accounting_coverage` | Every Terraform resource observed in the plan is represented in the coverage report. Valid plans are expected to report `1.0`. |
| `semantic_classification_coverage` | Fraction of observed resources covered by the declared semantic manifest. Unsupported resources become `visibility_gaps`. |

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
| `aws-lambda-function-url` | AWS | Lambda container-image function exposed through a public function URL with secret-read IAM. |
| `azure-container-apps` | Azure | Container Apps shape with external ingress, managed identity, role assignment, and Key Vault. |
| `azure-app-service` | Azure | Linux App Service container with public web access, managed identity, and Key Vault access. |
| `gcp-cloud-run` | GCP | Cloud Run shape with public invoker IAM, service account, domain mapping, and Secret Manager. |
| `gcp-gke-workload` | GCP/Kubernetes | GKE cluster context plus Kubernetes Deployment, Service, and workload identity resources. |
| `kubernetes-ingress-workload` | Kubernetes | Deployment, Service, Ingress, ServiceAccount, and RBAC shape. |
| `helm-heavy-kubernetes` | Kubernetes | Helm wrapper plus rendered Deployment, Service, Ingress, and cluster RBAC. |
| `kubernetes-private-service-mesh` | Kubernetes | Internal ClusterIP workload with service-mesh wrappers and limited RoleBinding. |

Run the fixture harness locally:

```bash
PYTHONPATH=src python -m reachability_advisor fixtures list
PYTHONPATH=src python -m reachability_advisor fixtures validate
PYTHONPATH=src python -m reachability_advisor fixtures run \
  --out outputs/fixtures-report.json \
  --output-dir outputs/fixtures
```

The fixture packs assert `1.0` resource accounting, semantic classification, and artifact matching for their included resources. Unsupported resources and opaque rendered-manifest wrappers remain visibility gaps.


## Real-world Terraform validation

Use `hcl-audit` to check public Terraform source repositories when a `terraform show -json` plan is not available:

```bash
PYTHONPATH=src python -m reachability_advisor hcl-audit \
  --path infra \
  --out outputs/hcl-audit.json \
  --markdown-out outputs/hcl-audit.md
```

`hcl-audit` accounts for `.tf` resources and modules, classifies known AWS/Azure/GCP/Kubernetes resource types, resolves simple literal variable defaults and `.tfvars` assignments, extracts simple image/exposure/identity literals, and reports unresolved variables, modules, or opaque Helm/kubectl manifest wrappers as visibility gaps.

Use `--terraform-plan` for release gates. Use `--terraform-source` or `hcl-audit` only when a plan is not available.

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

For scale validation, run the complex app harness. It generates one SBOM and Grype report per service, merges vulnerability matches with artifact scope, runs source plus Terraform/Kubernetes context analysis, and emits the HTML graph. The corpus currently includes AWS Retail Store and Google Cloud Online Boutique:

```bash
python scripts/run_complex_app_validation.py \
  --no-clone \
  --strict
```

Outputs are written to `outputs/external-complex/`, including schema-validated `benchmark.json` and `benchmark.md` for release-to-release drift checks.
Current local snapshots:

- AWS Retail Store: 5 service SBOMs, 40 Grype matches, 40 findings, 24 remediation groups, 91 Terraform resources, and generated HTML graph.
- Google Cloud Online Boutique: 10 service SBOMs, 38 Grype matches, 38 findings, 23 remediation groups, Kubernetes context with public frontend ingress and internal service hops, and generated HTML graph.

## GitHub Actions pipeline

See [docs/pipeline.md](docs/pipeline.md) for a complete GitHub Actions example using GitHub-hosted runners. The workflow generates CycloneDX SBOMs and Grype vulnerability JSON, runs Reachability Advisor, uploads SARIF, stores mapping/source-coverage/Terraform/Kubernetes/HTML artifacts, and publishes a Markdown summary to the job page.
See [docs/policy_playbooks.md](docs/policy_playbooks.md) for strict release, advisory PR, and backlog migration policy examples.

For repositories that want to consume the published action directly:

```yaml
- uses: Devko/reachability-advisor@main
  with:
    sbom: sboms/app.cdx.json
    vulns: vulns/app.grype.json
    source-root: app=.
    kubernetes-manifest: k8s/rendered.yaml
    fail-on-tier: high
```

## CI gate

```bash
reachability-advisor scan \
  --sbom app.cdx.json \
  --vulns vulnerabilities.json \
  --terraform-plan tfplan.json \
  --terraform-coverage-out terraform-coverage.json \
  --kubernetes-manifest k8s/rendered.yaml \
  --kubernetes-coverage-out kubernetes-coverage.json \
  --source-coverage-out source-coverage.json \
  --mapping-out mapping.json \
  --source-root app=. \
  --sarif-out reachability.sarif \
  --baseline-out reachability-baseline.json \
  --markdown-out reachability-pr-summary.md \
  --fail-on-tier high
```

## PR delta gate

Use this to block only new or worsened high-risk findings instead of failing on the existing backlog.

```bash
reachability-advisor compare \
  --baseline reachability-baseline.json \
  --head-findings reachability-findings.json \
  --markdown-out reachability-delta.md \
  --fail-on-new-tier high
```

`--baseline` reads the stable artifact written by `scan --baseline-out`. The PR delta JSON and Markdown include only new and worsened findings.

## IDE integration

The `ide/vscode` directory contains a minimal VS Code extension skeleton. It invokes the CLI, reads `--diagnostics-out`, and places diagnostics in the editor. Security-sensitive logic stays in the audited Python CLI.

## Supported evidence

| Evidence | Current support |
|---|---|
| SBOM | CycloneDX JSON |
| SBOM acquisition support | `sbom-plan` command with Syft, Trivy, Maven, npm, and Python suggestions |
| Vulnerability input | Grype JSON, local JSON, and small OSV-Scanner-style JSON |
| Source reachability | JVM, Node, Python, and Go rules with same-function input/sink evidence, bounded handler-to-sink paths, CycloneDX dependency-graph evidence, and package-manager manifest evidence for Maven/Gradle, npm/pnpm/Yarn, Poetry/requirements, and Go modules |
| Custom source rules | `--reachability-rules` JSON and `export-semgrep-rules` starter YAML |
| External source evidence | `--source-evidence-in` for Reachability Advisor JSON, Semgrep JSON, SARIF, and govulncheck JSONL, with selector diagnostics and quality gates for artifact-only or unscoped evidence |
| Terraform context | Primary deployment context. AWS, Azure, GCP, and Kubernetes plan/source support with coverage reporting, artifact matching, network graphing, route/private-endpoint/firewall-tag hints, IAM capability records, AWS `sts:AssumeRole` propagation, and IAM impact classification |
| Kubernetes manifests | Rendered YAML/JSON workload, Service, Ingress, RBAC, and NetworkPolicy context with artifact matching and coverage reporting |
| Context JSON | Explicit override/enrichment keyed by artifact name |
| Outputs | JSON with remediation groups and raw findings, evidence graph JSON, baseline JSON, PR delta JSON/Markdown, SARIF, diagnostics JSON, Markdown, interactive HTML, annotations, Terraform coverage JSON, Kubernetes coverage JSON, source coverage JSON, mapping JSON |
| CI quality gates | Built-in scan gates for artifact match coverage, strong artifact identity coverage, mapping warnings, source rule coverage, external evidence presence, and external evidence selector usability |

## Import/export contract

The release check runs an executable contract for the public import/export claims:

```bash
python scripts/validate_release.py
```

It verifies:

- vulnerability imports: local JSON, Grype `matches[]`, and OSV-Scanner-style JSON;
- source-evidence imports: native Reachability Advisor JSON, Reachability Advisor findings JSON, Semgrep JSON/dataflow traces, SARIF/CodeQL code flows, and govulncheck JSONL;
- deployment/context inputs: Terraform plan JSON, a synthetic no-cloud Terraform plan E2E fixture, Terraform source paths through `hcl-audit`, rendered Kubernetes YAML/JSON, context JSON, and artifact aliases;
- configuration inputs: custom reachability rules and runtime policy JSON;
- exports: findings JSON, remediation groups, evidence graph JSON, baseline JSON, PR delta JSON/Markdown, SARIF, diagnostics JSON, PR summary Markdown, GitHub annotations, self-contained HTML graph, source coverage, Terraform coverage, Kubernetes coverage, mapping reports, HCL audit JSON/Markdown, SBOM plan JSON/Markdown, scoring benchmark JSON, complex benchmark JSON/Markdown, Semgrep starter rules, fixture validation, fixture run reports, and single-finding explanations.

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
Ran 420 tests: OK
Coverage: 93%
Coverage gate: 93% passed
Fixture packs: 9 passed, 0 failed
Release import/export contract: 49 checks passed
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

Reachability Advisor prioritizes vulnerability remediation. It does not prove exploitability, does not mark findings as not affected, and does not replace security review. It ranks work from SBOM, vulnerability, source, Terraform network, and IAM evidence.
