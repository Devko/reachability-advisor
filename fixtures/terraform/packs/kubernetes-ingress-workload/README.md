# Kubernetes ingress workload fixture

Provider: `kubernetes`

Upstream/module reference: `generic kubernetes provider ingress/workload pattern`

This is a reduced and sanitized module-shaped fixture. It is designed to exercise Reachability Advisor's Terraform coverage and artifact matching, not to reproduce the upstream module.

Run just this pack:

```bash
PYTHONPATH=src python -m reachability_advisor fixtures run --fixture kubernetes-ingress-workload --out outputs/kubernetes-ingress-workload-report.json
```
