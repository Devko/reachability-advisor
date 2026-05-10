# Google Cloud Run module fixture

Provider: `gcp`

Upstream/module reference: `GoogleCloudPlatform/cloud-run/google`

This is a reduced and sanitized module-shaped fixture. It is designed to exercise Reachability Advisor's Terraform coverage and artifact matching, not to reproduce the upstream module.

Run just this pack:

```bash
PYTHONPATH=src python -m reachability_advisor fixtures run --fixture gcp-cloud-run --out outputs/gcp-cloud-run-report.json
```
