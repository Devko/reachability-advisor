# Policy Playbooks

Runtime policies control when CI fails and how temporary exceptions are recorded. They do not suppress findings and they never mark a dependency as not affected.

## Strict Release Gate

Use for protected release branches when the team is ready to block medium and higher active findings.

```bash
reachability-advisor scan \
  --policy configs/policy.strict-release.json \
  --fail-on-tier medium \
  --out reachability/findings.json
```

Expected behavior:

- active `medium`, `high`, and `urgent` findings fail the job;
- exceptions must be explicit and expiring;
- use image/runtime SBOMs and Terraform plan JSON for this mode.

## Advisory Pull Request Mode

Use while onboarding a repository or when a team wants visibility before hard blocking.

```bash
reachability-advisor scan \
  --policy configs/policy.advisory-pr.json \
  --out reachability/findings.json \
  --markdown-out reachability/summary.md
```

Expected behavior:

- only `urgent` findings fail by default;
- `high` and below still appear in SARIF, Markdown, JSON, and the HTML graph;
- publish `source-coverage.json`, `mapping.json`, and `evidence-graph.json` so teams can fix evidence gaps before enforcing stricter gates.

## Backlog Migration

Use when existing high findings should not block every pull request, but new or worsened findings should fail.

```bash
reachability-advisor scan \
  --baseline-out reachability-baseline.json \
  --policy configs/policy.backlog-migration.json \
  --out reachability/findings.json

reachability-advisor compare \
  --baseline main.reachability-baseline.json \
  --head-findings reachability/findings.json \
  --fail-on-new-tier high \
  --markdown-out reachability-delta.md
```

Expected behavior:

- the default branch publishes a baseline artifact;
- pull requests fail only for new or worsened findings at or above the configured delta tier;
- backlog exceptions must name artifact, component, vulnerability, reason, and expiry.

## Review Rules

- Do not use broad exceptions without artifact and component scope.
- Do not use exceptions to hide missing source, Terraform, or Kubernetes evidence.
- Review `scoring.gates[]` before deciding that a finding is low priority.
- Review `source_reachability.diagnostics[]` for rule gaps, missing source roots, and unlinked attacker-input evidence.
