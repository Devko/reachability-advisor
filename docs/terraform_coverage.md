# Terraform Multi-Cloud Coverage

Reachability Advisor adds a provider-neutral Terraform context layer for developer pipelines and IDE integrations.

The intent is not to become a CNAPP or live cloud inventory product. The tool reads a local `terraform show -json` plan and extracts enough context to help developers prioritize dependency findings:

- whether an SBOM artifact appears to be deployed;
- whether the deployment is likely public, external, internal, private, or unknown;
- whether provider IAM hints suggest limited, sensitive, or admin blast radius;
- whether tags or labels identify environment and owner;
- which Terraform resources were semantically classified and which became visibility gaps.

## What “100% Terraform coverage” means here

There are thousands of Terraform resource types and modules can create arbitrary provider shapes. A defensible pipeline/IDE tool should not pretend to understand all of them semantically.

This project therefore uses two coverage concepts:

1. **Resource accounting coverage:** every resource observed in the plan is parsed and represented in `--terraform-coverage-out`. This is expected to be `1.0` for every valid plan.
2. **Semantic classification coverage:** the fraction of observed resources whose type appears in the declared support manifest below. Unsupported resources are reported as `visibility_gaps`, not treated as safe.

The sample multi-cloud plan intentionally reaches `1.0` for both accounting and semantic coverage. Plans with unsupported resources still reach `1.0` accounting coverage and explicitly show gaps.

## Supported providers

- AWS: `aws_*`
- Azure: `azurerm_*` and selected `azuread_*`
- GCP: `google_*`
- Kubernetes provider: `kubernetes_*`

## Supported semantic classes

| Class | Meaning |
|---|---|
| `workload` | Resource can help match an SBOM artifact to a deployed container, function, batch job, app, VM, or Kubernetes workload. |
| `exposure` | Resource can indicate public/external/internal access. |
| `identity` | Resource can indicate IAM or role blast radius. |
| `sensitive_data` | Resource can indicate nearby secrets, storage, databases, or KMS assets. |
| `supporting` | Resource is common in module plans and should be semantically accounted for even when it does not directly score a finding. |

The exact support manifest is generated from `reachability_advisor.terraform.TERRAFORM_COVERAGE_MANIFEST` and included in every coverage report.

## CLI usage

```bash
reachability-advisor scan \
  --sbom app.cdx.json \
  --vulns vulnerabilities.json \
  --terraform-plan tfplan.json \
  --terraform-coverage-out terraform-coverage.json \
  --source-root app=. \
  --sarif-out reachability.sarif \
  --markdown-out reachability-pr-summary.md
```

To generate the Terraform input:

```bash
terraform init
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
```

## Example coverage summary

```json
{
  "total_resources": 14,
  "accounted_resources": 14,
  "resource_accounting_coverage": 1.0,
  "semantically_classified_resources": 14,
  "semantic_classification_coverage": 1.0,
  "artifacts_requested": 4,
  "artifacts_matched": 4,
  "artifact_match_coverage": 1.0,
  "providers_seen": {"aws": 5, "azure": 3, "gcp": 4, "kubernetes": 2}
}
```

## Conservative behavior

- Missing Terraform context is `unknown`, not safe.
- Unsupported resource types become visibility gaps.
- Public exposure is only raised when a supported resource provides a clear public signal.
- Privilege is coarse and explainable: `unknown`, `none`, `limited`, `sensitive`, `admin`.
- The tool never emits automatic `not_affected` claims.


## Community fixture packs

The fixture harness turns Terraform coverage into executable documentation. Each fixture pack includes:

- a reduced `terraform show -json` plan;
- one or more CycloneDX SBOMs;
- local vulnerability intelligence;
- optional source roots;
- expected coverage and finding assertions.

Run all packs:

```bash
PYTHONPATH=src python -m reachability_advisor fixtures run \
  --out outputs/fixtures-report.json \
  --output-dir outputs/fixtures
```

The current packs cover AWS ECS/Fargate service module shapes, Azure Container Apps, GCP Cloud Run, and Kubernetes ingress workloads. They are sanitized and module-shaped: they model common Terraform resource graphs without vendoring third-party module source code.

## Adding provider/module coverage

1. Add the resource type to `TERRAFORM_COVERAGE_MANIFEST` in the correct provider/category.
2. Add a fixture pack under `fixtures/terraform/packs/<id>`.
3. Include expected assertions for resource types, matched artifacts, and minimum finding tiers.
4. Run `make fixtures` and `make coverage`.
5. Document any unsupported resources as visibility gaps rather than treating them as safe.
