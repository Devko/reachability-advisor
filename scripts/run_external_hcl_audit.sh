#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="${1:-$ROOT/external_corpus/popular_terraform_projects.json}"
WORKDIR="${2:-$ROOT/external_corpus/worktrees}"
OUTDIR="${3:-$ROOT/outputs/external-hcl-audit}"

python "$ROOT/scripts/run_external_hcl_audit.py" \
  --corpus "$CORPUS" \
  --workdir "$WORKDIR" \
  --outdir "$OUTDIR"
