#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p outputs
PYTHONPATH=src python -m reachability_advisor scan \
  --sbom samples/sboms/payments-api.cdx.json \
  --sbom samples/sboms/notifier.cdx.json \
  --sbom samples/sboms/orders-api.cdx.json \
  --sbom samples/sboms/audit-api.cdx.json \
  --vulns samples/vulnerabilities.json \
  --terraform-plan samples/tfplan-multicloud.json \
  --terraform-coverage-out outputs/terraform-coverage.json \
  --mapping-out outputs/mapping.json \
  --source-root payments-api=samples/source/payments-api \
  --source-root notifier=samples/source/notifier \
  --source-root orders-api=samples/source/orders-api \
  --source-root audit-api=samples/source/audit-api \
  --out outputs/findings.json \
  --sarif-out outputs/findings.sarif \
  --diagnostics-out outputs/diagnostics.json \
  --markdown-out outputs/pr-summary.md \
  --annotations-out outputs/annotations.txt
