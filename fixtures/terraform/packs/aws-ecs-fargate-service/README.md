# AWS ECS/Fargate service module fixture

Provider: `aws`

Upstream/module reference: `terraform-aws-modules/ecs/aws service submodule`

This is a reduced and sanitized module-shaped fixture. It is designed to exercise Reachability Advisor's Terraform coverage and artifact matching, not to reproduce the upstream module.

Run just this pack:

```bash
PYTHONPATH=src python -m reachability_advisor fixtures run --fixture aws-ecs-fargate-service --out outputs/aws-ecs-fargate-service-report.json
```
