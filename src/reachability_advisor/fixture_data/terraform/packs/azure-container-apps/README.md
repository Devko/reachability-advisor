# Azure Container Apps module fixture

Provider: `azure`

Upstream/module reference: `Azure/container-apps/azure`

This reduced module-shaped fixture covers Container Apps workload matching, external ingress, managed identity, role assignment, and Key Vault context.

Run this pack:

```bash
PYTHONPATH=src python -m reachability_advisor fixtures run --fixture azure-container-apps --out outputs/azure-container-apps-report.json
```
