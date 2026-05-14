# Terraform Context and Coverage

Terraform plan JSON is the release-gate deployment-context input for Reachability Advisor. It links SBOM artifacts to workloads, builds network paths, classifies exposure, and evaluates workload IAM impact.

The scanner reads a local `terraform show -json` plan and extracts:

- whether an SBOM artifact appears to be deployed;
- whether the deployment is public, external, internal, private, or unknown;
- whether linked workload IAM permissions imply limited, sensitive, or admin blast radius;
- whether tags or labels identify environment and owner;
- which Terraform resources were classified and which remain visibility gaps.

This is not a live cloud inventory or CNAPP. It is plan-based context for CI and release review.

## What "100% Terraform coverage" means here

Terraform providers expose thousands of resource types, and modules can generate arbitrary resource graphs. Coverage reporting makes unsupported shapes explicit.

This project uses two coverage concepts:

1. **Resource accounting coverage:** every resource observed in the plan is parsed and represented in `--terraform-coverage-out`. This is expected to be `1.0` for every valid plan.
2. **Semantic classification coverage:** the fraction of observed resources whose type appears in the support manifest. Unsupported resources are reported as `visibility_gaps`.

The sample multi-cloud plan reaches `1.0` for both accounting and semantic coverage. Plans with unsupported resources still reach `1.0` accounting coverage and show gaps.

## Supported providers

- AWS: `aws_*`
- Azure: `azurerm_*` and selected `azuread_*`
- GCP: `google_*`
- Kubernetes provider: `kubernetes_*`

## Supported semantic classes

| Class | Meaning |
|---|---|
| `workload` | Resource can match an SBOM artifact to a deployed container, function, batch job, app, VM, or Kubernetes workload. |
| `exposure` | Resource can indicate public/external/internal access. |
| `identity` | Resource can indicate IAM or role blast radius. |
| `sensitive_data` | Resource can indicate nearby secrets, storage, databases, or KMS assets. |
| `supporting` | Resource is common in module plans and is counted even when it does not directly score a finding. |

The exact support manifest is generated from `reachability_advisor.terraform.TERRAFORM_COVERAGE_MANIFEST` and included in every coverage report.

## CLI usage

```bash
reachability-advisor scan \
  --sbom app.cdx.json \
  --vuln-in vulnerabilities.json \
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
  "total_resources": 15,
  "accounted_resources": 15,
  "resource_accounting_coverage": 1.0,
  "semantically_classified_resources": 15,
  "semantic_classification_coverage": 1.0,
  "artifacts_requested": 4,
  "artifacts_matched": 4,
  "artifact_match_coverage": 1.0,
  "providers_seen": {"aws": 5, "azure": 3, "gcp": 4, "kubernetes": 2}
}
```

## Scoring Behavior

- Missing Terraform context is `unknown`; it is not isolation evidence. Scoring treats unknown network/IAM as uncertainty that ranks above confirmed internal/no-role context, but below confirmed public or sensitive/admin context, and caps it below `urgent` until stronger evidence proves the effective path.
- Unsupported resource types become visibility gaps.
- Helm and kubectl manifest wrappers are semantically classified as Kubernetes support resources, but still emit `opaque_manifest_wrapper` gaps because Terraform does not expose the rendered child workload graph. Pass rendered YAML/JSON through `--kubernetes-manifest` to analyze workload, Service, Ingress, and RBAC context.
- Public exposure is only raised when a supported resource provides a clear public signal linked to the matched workload. A public resource elsewhere in the same provider plan does not create provider-wide public context.
- Restricted external exposure is represented separately from public exposure when ingress is limited to specific public CIDRs or equivalent external-source signals.
- Internal lateral exposure is raised from bounded graph paths such as security-group hops, private load balancer/application gateway forwarding, Kubernetes ClusterIP service matches, and provider bridge resources such as VPC/VNet peering, VPN, transit gateway, ExpressRoute, and Interconnect.
- Network-reachable workloads with linked `admin_control`, `network_control`, or `iam_escalation` IAM impacts create an internal provider-control-plane pivot to private same-provider workloads.
- IAM is evaluated per linked workload identity when Terraform exposes the relationship. The analyzer records impact classes for `data_access`, `network_control`, `iam_escalation`, `compute_control`, and `admin_control`; limited-looking permissions can still raise criticality when they expose secrets/data, network mutation, role escalation, or workload code execution.
- IAM criticality is mixed with network reachability: critical impacts on public, external, or internal workloads become `high`; the same impact on a private-only workload becomes `medium`.
- Private exposure means a workload is private-attached or public access is disabled without a detected bridge or ingress path.
- Supported linked public exposure currently includes AWS ECS security-group and load-balancer target-group links, AWS target-group attachments, Azure application gateway/load-balancer backend pool paths through network interfaces, GCP forwarding-rule/backend-service/NEG paths, AWS Lambda function URLs, GCP Cloud Run and Cloud Functions public invoker grants, Azure Container Apps external ingress, and Kubernetes Service/Ingress name or selector matches.
- Privilege is coarse and explainable: `unknown`, `none`, `limited`, `sensitive`, `admin`. Direct workload identity links and IAM impacts are recorded when visible; unrelated provider-level IAM no longer raises every workload in the same plan.
- The tool never emits automatic `not_affected` claims.


## Terraform Fixture Packs

The fixture harness turns Terraform coverage into executable documentation. Each fixture pack includes:

- a reduced `terraform show -json` plan;
- one or more CycloneDX SBOMs;
- local vulnerability intelligence;
- source roots;
- expected coverage and finding assertions.

Run all packs:

```bash
PYTHONPATH=src python -m reachability_advisor fixtures run \
  --out outputs/fixtures-report.json \
  --output-dir outputs/fixtures
```

The current packs cover AWS ECS/Fargate, AWS Lambda function URLs, Azure Container Apps, Azure App Service, GCP Cloud Run, GKE plus Kubernetes workloads, Kubernetes ingress workloads, Helm-heavy deployments, and private service-mesh workloads. They are sanitized, module-shaped plans. They model common Terraform resource graphs without vendoring third-party module source code.

## Adding provider/module coverage

1. Add the resource type to `TERRAFORM_COVERAGE_MANIFEST` in the correct provider/category.
2. Add a fixture pack under `fixtures/terraform/packs/<id>`.
3. Include expected assertions for resource types, matched artifacts, and minimum finding tiers.
4. Run `make fixtures` and `make coverage`.
5. Document unsupported resources as visibility gaps.
