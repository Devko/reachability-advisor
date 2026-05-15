# Community Terraform fixture packs

These fixture packs are executable documentation for multi-cloud Terraform coverage. Each pack contains a reduced `terraform show -json` plan, SBOMs, vulnerability data, source roots, and expected outcomes.

The packs are sanitized and module-shaped. They model common resource graphs emitted by Terraform modules without copying or vendoring upstream module source code.

## Current packs

| Pack | Provider | Main behavior checked |
|---|---|---|
| `aws-ecs-fargate-service` | AWS | Public ALB/security-group path to ECS, task IAM, Secrets Manager context. |
| `aws-lambda-function-url` | AWS | Public Lambda function URL path to a container-image Lambda and secret-read IAM. |
| `azure-container-apps` | Azure | External Container Apps ingress, managed identity, role assignment, Key Vault context. |
| `azure-app-service` | Azure | Public App Service container, managed identity, Key Vault role assignment. |
| `gcp-cloud-run` | GCP | Public Cloud Run invoker IAM, domain mapping, service account, Secret Manager. |
| `gcp-gke-workload` | GCP/Kubernetes | GKE cluster context, Kubernetes workload matching, public Service, workload identity. |
| `kubernetes-ingress-workload` | Kubernetes | Public Ingress/Service path to Deployment with admin RBAC. |
| `helm-heavy-kubernetes` | Kubernetes | Opaque Helm wrapper plus rendered workload, Service, Ingress, and cluster RBAC. |
| `kubernetes-private-service-mesh` | Kubernetes | Internal ClusterIP workload, service-mesh wrappers, limited RoleBinding. |

## Run

```bash
PYTHONPATH=src python -m reachability_advisor fixtures list
PYTHONPATH=src python -m reachability_advisor fixtures validate
PYTHONPATH=src python -m reachability_advisor fixtures run --out outputs/fixtures-report.json --output-dir outputs/fixtures
```

## Add a fixture pack

1. Create `fixtures/terraform/packs/<id>/fixture.json`.
2. Add `tfplan.json`, one or more CycloneDX SBOMs, and source roots.
3. Add expectations for resource accounting, semantic classification, artifact matching, required resource types, and expected minimum finding tiers.
4. Register the pack in `fixtures/terraform/index.json`.
5. Run the fixture harness and tests.

Unsupported resources appear as visibility gaps in the Terraform coverage report.
