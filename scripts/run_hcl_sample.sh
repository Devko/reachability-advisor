#!/usr/bin/env bash
set -euo pipefail
mkdir -p outputs
PYTHONPATH=src python -m reachability_advisor hcl-audit \
  --path samples/terraform-source \
  --out outputs/hcl-audit-sample.json \
  --markdown-out outputs/hcl-audit-sample.md
PYTHONPATH=src python -m reachability_advisor scan \
  --sbom samples/sboms/audit-api.cdx.json \
  --vuln-in samples/vulnerabilities.json \
  --terraform-source samples/terraform-source \
  --artifact-alias audit-api=gcr.io/acme/audit-api:1.0.0 \
  --terraform-coverage-out outputs/terraform-source-coverage.json \
  --mapping-out outputs/hcl-mapping.json \
  --out outputs/hcl-findings.json \
  --no-table
