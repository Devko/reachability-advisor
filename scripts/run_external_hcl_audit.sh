#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="${1:-$ROOT/external_corpus/popular_terraform_projects.json}"
WORKDIR="${2:-$ROOT/external_corpus/worktrees}"
OUTDIR="${3:-$ROOT/outputs/external-hcl-audit}"

mkdir -p "$WORKDIR" "$OUTDIR"

python - <<'PY' "$ROOT" "$CORPUS" "$WORKDIR" "$OUTDIR"
import json
import os
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
corpus = Path(sys.argv[2])
workdir = Path(sys.argv[3])
outdir = Path(sys.argv[4])
data = json.loads(corpus.read_text(encoding="utf-8"))
projects = data.get("projects", [])
for project in projects:
    pid = project["id"]
    repo = project["repo"]
    rel = project.get("path", ".")
    checkout = workdir / pid
    if not checkout.exists():
        print(f"[clone] {pid}: {repo}")
        subprocess.run(["git", "clone", "--depth", "1", repo, str(checkout)], check=True)
    else:
        print(f"[reuse] {pid}: {checkout}")
    audit_path = checkout / rel
    json_out = outdir / f"{pid}.hcl-audit.json"
    md_out = outdir / f"{pid}.hcl-audit.md"
    print(f"[audit] {pid}: {audit_path}")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    subprocess.run([
        sys.executable, "-m", "reachability_advisor", "hcl-audit",
        "--path", str(audit_path),
        "--out", str(json_out),
        "--markdown-out", str(md_out),
    ], check=True, env=env, cwd=str(root))
print(f"Reports written to {outdir}")
PY
