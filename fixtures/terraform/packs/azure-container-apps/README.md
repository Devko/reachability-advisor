# Azure Container Apps module fixture

Provider: `azure`

Upstream/module reference: `Azure/container-apps/azure`

This is a reduced and sanitized module-shaped fixture. It is designed to exercise Reachability Advisor's Terraform coverage and artifact matching, not to reproduce the upstream module.

Run just this pack:

```bash
PYTHONPATH=src python -m reachability_advisor fixtures run --fixture azure-container-apps --out outputs/azure-container-apps-report.json
```
