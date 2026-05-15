# Kubernetes ingress workload fixture

Provider: `kubernetes`

Upstream/module reference: `generic kubernetes provider ingress/workload pattern`

This reduced fixture covers Kubernetes Deployment, Service, Ingress, ServiceAccount, ClusterRoleBinding, and namespace context.

Run this pack:

```bash
PYTHONPATH=src python -m reachability_advisor fixtures run --fixture kubernetes-ingress-workload --out outputs/kubernetes-ingress-workload-report.json
```
