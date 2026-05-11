# Google Cloud Run module fixture

Provider: `gcp`

Upstream/module reference: `GoogleCloudPlatform/cloud-run/google`

This reduced module-shaped fixture covers Cloud Run workload matching, public invoker IAM, service accounts, project IAM, Secret Manager, and domain mapping.

Run this pack:

```bash
PYTHONPATH=src python -m reachability_advisor fixtures run --fixture gcp-cloud-run --out outputs/gcp-cloud-run-report.json
```
