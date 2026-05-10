# Community Terraform Fixture Packs

Reachability Advisor uses fixture packs to keep Terraform coverage reviewable and contributor-friendly. A fixture pack is a small, executable test case for a provider or module-shaped plan.

## Why fixture packs exist

The project is intended for CI and IDE workflows, not live cloud inventory. Terraform fixture packs let maintainers test common module outputs locally without cloud credentials. They also make coverage claims auditable: a pack either passes its expected assertions or it does not.

## Current packs

| Pack | Provider | Main resources exercised |
|---|---|---|
| `aws-ecs-fargate-service` | AWS | `aws_ecs_task_definition`, `aws_ecs_service`, `aws_lb`, `aws_security_group`, IAM role policies, Secrets Manager, supporting ECS resources. |
| `azure-container-apps` | Azure | `azurerm_container_app`, Container Apps environment, managed identity, role assignment, Key Vault, supporting resource group/log analytics resources. |
| `gcp-cloud-run` | GCP | `google_cloud_run_v2_service`, public invoker IAM, service account, project IAM, Secret Manager, domain mapping, supporting project service/artifact registry resources. |
| `kubernetes-ingress-workload` | Kubernetes | Deployment, Service, Ingress, ServiceAccount, ClusterRoleBinding, Namespace. |

## Commands

```bash
PYTHONPATH=src python -m reachability_advisor fixtures list
PYTHONPATH=src python -m reachability_advisor fixtures validate
PYTHONPATH=src python -m reachability_advisor fixtures run --out outputs/fixtures-report.json --output-dir outputs/fixtures
```

## Pack anatomy

```text
fixtures/terraform/packs/<id>/
  fixture.json
  tfplan.json
  sboms/<artifact>.cdx.json
  source/<artifact>/...
  README.md
```

`fixture.json` declares the plan, SBOMs, vulnerability file, source roots, and expected assertions.

## Contribution checklist

1. Use a sanitized `terraform show -json` plan or a reduced plan with the same resource shape.
2. Do not vendor third-party module source code.
3. Include enough SBOM and source data to demonstrate the scanner behavior.
4. Assert `resource_accounting_coverage`, `semantic_classification_coverage`, and `artifact_match_coverage`.
5. Add `required_resource_types` so future maintainers can see which resources the pack protects.
6. Add at least one `min_tier_by_finding` assertion.
7. Register the pack in `fixtures/terraform/index.json`.
8. Run `make fixtures` and `make coverage`.

Unsupported resources should remain visible as coverage gaps. Do not mark a fixture as passed by deleting realistic resources unless the README explains why the resource is intentionally out of scope.
