#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p outputs/fixtures
PYTHONPATH=src python -m reachability_advisor fixtures validate --json-out outputs/fixtures-validate.json
PYTHONPATH=src python -m reachability_advisor fixtures run --out outputs/fixtures-report.json --output-dir outputs/fixtures
