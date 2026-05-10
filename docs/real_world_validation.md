# Real-world Terraform validation

Reachability Advisor now supports two Terraform validation modes:

1. **Plan mode** using `terraform show -json`, which is the strongest evidence path for CI gates because variables, modules, `for_each`, `count`, and provider defaults have already been evaluated.
2. **HCL static mode** using `reachability-advisor hcl-audit`, which is useful for public open-source repositories and early IDE/PR checks where cloud credentials or Terraform initialization are unavailable.

HCL static mode is deliberately conservative. It accounts for `.tf` resource and module blocks, classifies known resource types, resolves simple literal `variable` defaults and `.tfvars` assignments, extracts simple image/exposure/identity literals, and reports unresolved variables, modules, and opaque manifest wrappers as visibility gaps. It does **not** claim full deployment reachability.

## Why add HCL static validation?

Many popular open-source cloud deployment repositories publish Terraform module source but not a generated plan. A verifier may not have provider credentials, backend access, or permission to initialize modules. Static HCL validation lets the project answer a narrower but important question:

> Do real public Terraform projects contain resource shapes that our analyzer recognizes, and where does a full plan remain necessary?

## New command

```bash
PYTHONPATH=src python -m reachability_advisor hcl-audit \
  --path path/to/terraform/source \
  --out outputs/project.hcl-audit.json \
  --markdown-out outputs/project.hcl-audit.md
```

The report includes:

- Terraform files scanned;
- resource blocks, module blocks, and data blocks;
- resource types seen;
- semantic classification coverage;
- image-like literals and unresolved image expressions;
- module expansion gaps;
- unsupported or unclassified resource types.

## Optional scan mode

`scan` can now accept Terraform source when a plan is not available:

```bash
PYTHONPATH=src python -m reachability_advisor scan \
  --sbom sboms/app.cdx.json \
  --vulns vulnerabilities.json \
  --terraform-source infra \
  --artifact-alias app=ghcr.io/example/app:1.2.3 \
  --terraform-coverage-out outputs/terraform-source-coverage.json \
  --mapping-out outputs/mapping.json
```

Use this as a weak/early signal. For release gates, prefer:

```bash
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
reachability-advisor scan --terraform-plan tfplan.json ...
```

## External corpus

`external_corpus/popular_terraform_projects.json` defines public repositories that exercise important provider shapes:

| Project | Provider | Purpose |
|---|---|---|
| `GoogleCloudPlatform/terraform-google-cloud-run` | GCP | Cloud Run service, domain mapping, invoker IAM, image variable patterns. |
| `Azure/terraform-azure-container-apps` | Azure | Container App, app environment, image, ingress, secrets, identity, dynamic blocks. |
| `aws-ia/terraform-aws-ecs-fargate` | AWS | ECS/Fargate module shape; demonstrates why module expansion needs a plan. |
| `GoogleCloudPlatform/terraform-ecommerce-microservices-on-gke` | GCP/Kubernetes context | GKE clusters, service account/IAM, multi-cluster ecommerce deployment context. |
| `aws-samples/amazon-ecs-fullstack-app-terraform` | AWS | ECS, ALB, CodePipeline, ECR, DynamoDB, and module/pipeline-driven image identity. |
| `aws-samples/aws-ecs-cicd-terraform` | AWS | Petclinic ECS deployment with HCL variable defaults that can be resolved statically. |
| `aws-containers/retail-store-sample-app` | AWS/Kubernetes | EKS-adjacent Terraform with Helm and kubectl manifest wrapper resources. |
| `Azure-Samples/container-apps-openai` | Azure | Azure Container Apps, private endpoints, Azure OpenAI, and source-only Chainlit app validation. |
| `Azure-Samples/container-apps-azapi-terraform` | Azure | Container Apps deployed through AzAPI ARM resource wrappers. |

In a network-enabled environment, run:

```bash
python scripts/run_external_hcl_audit.py
```

The script clones each repository into `external_corpus/worktrees/` and writes per-project reports plus an aggregate `summary.json` and `summary.md` under `outputs/external-hcl-audit/`. The Bash wrapper still exists for Unix-like environments:

```bash
./scripts/run_external_hcl_audit.sh
```

## Current validation snapshot

Snapshot date: 2026-05-10.

The current corpus run audits 9 public repositories. All 9 completed successfully on Windows using `scripts/run_external_hcl_audit.py`.

| Result | Count |
|---|---:|
| Projects cloned/audited | 9 |
| Projects with 100% semantic Terraform resource classification | 9 |
| Projects with explicit opaque Helm/Kubectl wrapper visibility gaps | 2 |
| Expected resource-type misses | 0 |

The two projects that contain `helm_release` or `kubectl_manifest` now classify those resources as Kubernetes supporting resources, so semantic coverage stays at `1.0`. They still emit `opaque_manifest_wrapper` visibility gaps because the HCL static analyzer cannot inspect rendered Kubernetes manifests. This preserves the important boundary: the Terraform wrapper is known, but child workloads, images, exposure, and RBAC still need rendered manifest or plan evidence.

Real Grype source scans were also run against app-code repositories in the corpus:

| Project | Grype matches | Reachability Advisor result |
|---|---:|---|
| `aws-samples/aws-ecs-cicd-terraform` Petclinic | 6 | SBOM artifact matched ECS task/service from resolved HCL variable defaults; Terraform artifact match coverage `1.0`; linked ECS security-group/load-balancer exposure plus limited IAM context raised the grouped Bootstrap remediation to `medium`. |
| `aws-samples/amazon-ecs-fullstack-app-terraform` Node backend | 51 | Grype JSON and CycloneDX output parsed; Express is now classified as `attacker_controlled` from same-file route/request evidence, raising the grouped Express remediation to `medium`; Terraform source was classified but artifact identity stayed unmatched because image identity is module/pipeline driven. |
| `Azure-Samples/container-apps-openai` Python app | 110 | Grype JSON and CycloneDX output parsed; Chainlit is now classified as `attacker_controlled` from same-file message-handler evidence, raising the grouped Chainlit remediation to `high`; Terraform Container App resource classified, but `for_each`/variable-driven image identity remained an explicit mapping warning. |

These handoff cases can be rerun without refreshing the Grype database when the existing Grype/CycloneDX files are present:

```bash
python scripts/run_external_grype_validation.py
```

The script writes `outputs/external-grype/summary.json` and `summary.md`. Current result: 3 cases passed, 0 failed. The two source-heavy app cases intentionally keep Terraform artifact match coverage at `0.0` because static HCL cannot resolve their module/pipeline-driven image identity without a plan or explicit artifact alias; their prioritization proof comes from Grype parsing and source reachability.

## Complex Application Validation

`external_corpus/complex_app_cases.json` defines end-to-end validation cases that combine:

- multiple deployable services;
- real source trees in different ecosystems;
- Grype-generated CycloneDX SBOMs;
- Grype vulnerability JSON;
- artifact-scoped vulnerability matching;
- Terraform source analysis and optional Kubernetes manifest context;
- source reachability;
- the interactive HTML graph.

The corpus currently contains two scale cases:

| Case | Why it is useful |
|---|---|
| `aws-retail-store-sample-app` | Java, Go, and Node/TypeScript services plus AWS Terraform for ECS/EKS/App Runner-style deployment paths. It stresses artifact matching, source reachability, IAM/network context, and dense graph rendering. |
| `google-online-boutique` | Ten Google Online Boutique microservices across Go, Python, Node.js, C#, and Java. It uses Kubernetes manifests to prove public frontend ingress and internal service hops, while Terraform source provides the GKE infrastructure surface. |

Run the full corpus locally with existing checkouts and Grype DB:

```bash
python scripts/run_complex_app_validation.py \
  --no-clone \
  --strict
```

Run a single case by adding `--case <case-id>`. If a checkout does not exist and network access is available, omit `--no-clone`. The runner writes:

- per-service SBOMs under `outputs/external-complex/<case>/sboms/`;
- per-service Grype JSON under `outputs/external-complex/<case>/vulns/`;
- a merged artifact-scoped Grype file at `outputs/external-complex/<case>/merged-grype.json`;
- Kubernetes manifest context at `outputs/external-complex/<case>/kubernetes-context.json` when the case defines a manifest;
- Reachability Advisor findings, mapping, Terraform coverage, and HTML graph under `outputs/external-complex/<case>/`;
- aggregate `summary.json` and `summary.md` under `outputs/external-complex/`.

Use `--refresh` to regenerate SBOM/vulnerability files. Use `--skip-grype` to reuse already generated SBOM/Grype files without invoking Grype.

Current complex snapshot, using the local Grype DB available on 2026-05-10:

| Case | Status | SBOMs | Grype matches | Findings | Services with findings | Terraform resources | Artifact match coverage |
|---|---|---:|---:|---:|---:|---:|---:|
| `aws-retail-store-sample-app` | passed | 5 | 40 | 40 | 2 | 91 | 0.4 |
| `google-online-boutique` | passed | 10 | 38 | 38 | 5 | 5 | 0.0 |

The low artifact match coverage is expected for source-only Terraform in this
repository set: many deployable image identities flow through modules, unresolved
locals, or Kubernetes manifests. The runner still produces a useful proof because
it makes that gap explicit while validating Grype parsing, source reachability,
Terraform resource classification, Kubernetes service exposure, IAM/network
context for matched services, and the HTML graph.

## Expected findings from manual source inspection

The public source inspection used to build the corpus showed these useful checks:

- the Google Cloud Run module contains `google_cloud_run_service`, `google_cloud_run_domain_mapping`, and `google_cloud_run_service_iam_member` resources;
- the Azure Container Apps module contains `azurerm_container_app` and related Container Apps environment resources, with nested `image` and `ingress` configuration;
- the AWS ECS/Fargate repository's deploy entrypoint calls a module and passes `image_url`, which is exactly the case where static HCL should report a module expansion gap;
- the GCP ecommerce/GKE solution contains `google_container_cluster`, service account, and project IAM resources, but application package reachability must be tied to microservice SBOMs separately.

## Acceptance criteria for external validation

For each external project, reviewers should record:

- whether resource accounting is complete for visible `.tf` resources;
- whether expected resource types are semantically classified;
- whether modules/unresolved variables are reported as gaps;
- whether generated plan mode improves artifact/exposure matching over source-only mode;
- whether any observed resource type should be added to the manifest or left as an explicit gap.

## Boundary statement

HCL static validation improves real-world verification, but it is not Terraform. It only resolves simple literal variables; it does not evaluate expressions, modules, locals, data sources, provider defaults, `count`, `for_each`, or rendered Helm/Kubectl child manifests. A static finding of `unknown` is not a safe state; it means a plan, explicit context file, or artifact alias is needed. Public exposure is now linked to matched workloads for supported patterns rather than inferred from unrelated public resources in the same provider plan.
