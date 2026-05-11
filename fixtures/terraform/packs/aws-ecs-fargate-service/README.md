# AWS ECS/Fargate service module fixture

Provider: `aws`

Upstream/module reference: `terraform-aws-modules/ecs/aws service submodule`

This reduced module-shaped fixture covers ECS task definitions, services, load balancer exposure, security groups, IAM, and Secrets Manager context.

Run this pack:

```bash
PYTHONPATH=src python -m reachability_advisor fixtures run --fixture aws-ecs-fargate-service --out outputs/aws-ecs-fargate-service-report.json
```
