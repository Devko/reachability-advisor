# Real-world Terraform validation

Reachability Advisor now supports two Terraform validation modes:

1. **Plan mode** using `terraform show -json`, which is the strongest evidence path for CI gates because variables, modules, `for_each`, `count`, and provider defaults have already been evaluated.
2. **HCL static mode** using `reachability-advisor hcl-audit`, which is useful for public open-source repositories and early IDE/PR checks where cloud credentials or Terraform initialization are unavailable.

HCL static mode is deliberately conservative. It accounts for `.tf` resource and module blocks, classifies known resource types, extracts simple image/exposure/identity literals, and reports unresolved variables/modules as visibility gaps. It does **not** claim full deployment reachability.

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

In a network-enabled environment, run:

```bash
./scripts/run_external_hcl_audit.sh
```

The script clones each repository into `external_corpus/worktrees/` and writes reports under `outputs/external-hcl-audit/`.

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

HCL static validation improves real-world verification, but it is not Terraform. It does not evaluate expressions, modules, locals, data sources, provider defaults, `count`, or `for_each`. A static finding of `unknown` is not a safe state; it means a plan, explicit context file, or artifact alias is needed.
