#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p outputs
PYTHONPATH=src python -m reachability_advisor scan \
  --sbom samples/sboms/payments-api.cdx.json \
  --sbom samples/sboms/notifier.cdx.json \
  --sbom samples/sboms/orders-api.cdx.json \
  --sbom samples/sboms/audit-api.cdx.json \
  --sbom samples/sboms/inventory-api.cdx.json \
  --sbom samples/sboms/batch-worker.cdx.json \
  --sbom samples/sboms/reports-api.cdx.json \
  --vulns samples/vulnerabilities.json \
  --terraform-plan samples/tfplan-multicloud.json \
  --terraform-coverage-out outputs/terraform-coverage.json \
  --mapping-out outputs/mapping.json \
  --source-root payments-api=samples/source/payments-api \
  --source-root notifier=samples/source/notifier \
  --source-root orders-api=samples/source/orders-api \
  --source-root audit-api=samples/source/audit-api \
  --source-root inventory-api=samples/source/inventory-api \
  --source-root batch-worker=samples/source/batch-worker \
  --source-root reports-api=samples/source/reports-api \
  --out outputs/findings.json \
  --sarif-out outputs/findings.sarif \
  --diagnostics-out outputs/diagnostics.json \
  --markdown-out outputs/pr-summary.md \
  --html-out outputs/reachability-graph.html \
  --annotations-out outputs/annotations.txt
