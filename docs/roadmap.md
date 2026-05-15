# Roadmap

Reachability Advisor is at the `1.1.0` baseline: a local-first CLI and CI/IDE correlation layer for dependency, SAST, DAST, CSPM, Terraform, Kubernetes, source, and artifact identity evidence. The next phase is not feature sprawl. The priority is making the tool boring to run, review, and release.

## Stabilization Goal

Make every high-value workflow deterministic from checked-in or CI-produced artifacts:

- local demo and sample scans should run the same way on every supported Python version;
- CI gates should explain exactly which evidence is missing instead of hiding uncertainty;
- output formats should remain schema-validated and backwards-conscious;
- scoring changes should be benchmarked against real and synthetic fixtures before release;
- documentation should point users to one clear path for advisory scans, release gates, and maintainer work.

## Current Stable Baseline

- Package version: `1.1.0`.
- Python support target: 3.10, 3.11, 3.12, and 3.13.
- Active gate set: compile, lint, strict type-checking, unit/workflow tests, coverage, sample, demo, Terraform fixture packs, release validation, package build, and wheel smoke test.
- Coverage threshold: 93% branch-aware coverage.
- Test inventory: 610 unit and workflow tests.
- Local-first boundary: no live cloud API calls, telemetry, automatic suppression, or automatic `not_affected` claims.

## Near-Term Stabilization

### 1. Release Evidence Determinism

Acceptance criteria:

- The CI matrix and documented local gates produce deterministic JSON, SARIF, Markdown, HTML, baseline, mapping, readiness, and coverage artifacts.
- Generated artifacts are easy to diff across pull requests and releases.
- `scripts/validate_release.py` remains the single release-contract check for schemas, sample outputs, action metadata, fixture packs, and end-to-end no-cloud evidence.
- Release docs and changelog entries are updated before every tag.

Work items:

- Keep generated output ordering stable across Python versions.
- Add regression checks whenever a report adds, removes, or renames fields.
- Keep GitHub Action inputs and CLI gates in sync through release validation.
- Add signed release artifacts after the tag workflow is stable enough to make signatures useful.

### 2. CLI And Workflow Reliability

Acceptance criteria:

- First-run commands work from a clean checkout after `python -m pip install -e ".[dev]"`.
- Advisory workflows remain useful with partial evidence, while production profile failures identify missing release evidence directly.
- Windows, Linux, and GitHub Actions examples describe equivalent paths where shell behavior differs.
- CLI, report, and web messages name the missing evidence in plain language and include concrete next steps for release-gate blockers.

Work items:

- Add a Windows-native sample command path alongside Bash wrappers where needed.
- Keep `demo`, `sample`, `fixtures`, and `release-check` documented as the preferred local sanity checks.
- Keep user-facing errors sharp for malformed inputs, missing source roots, missing deployment evidence, weak artifact identity, and unusable external evidence selectors.
- Keep `analysis-profile=production` strict about external analyzer evidence and rendered deployment evidence.

### 3. Output Contract Stability

Acceptance criteria:

- Every persisted JSON report used by CI or downstream tooling has a schema or a documented reason for not having one.
- Schema changes are reflected in samples, tests, docs, and release validation in the same change.
- Additive fields preserve older consumer behavior unless the changelog documents a breaking change.

Work items:

- Keep `docs/data_formats.md` as the canonical report-format reference.
- Add schema-contract tests for any new report surface.
- Keep `findings.json`, readiness, mapping, coverage, baseline, evidence graph, and benchmark outputs stable enough for downstream automation.
- Document migration guidance when a report shape must change.

### 4. Scoring And Evidence Calibration

Acceptance criteria:

- Scoring changes are covered by focused unit tests, golden output tests, and benchmark snapshot checks.
- Unknown, weak, blocked, constrained, internal, public, and sensitive/admin paths remain distinguishable in findings and evidence graphs.
- Weak evidence never becomes proof of exploitability or proof of safety.

Work items:

- Expand benchmark cases for constrained networks, denied paths, low-confidence IAM, source-only evidence, and scanner-only evidence.
- Keep urgent/high inflation limits visible in benchmark snapshots.
- Add fixture cases before broadening provider semantics that affect score tiers.
- Keep rationale strings concise and tied to observable evidence fields.

### 5. Adapter And Fixture Hardening

Acceptance criteria:

- Scanner adapters tolerate partial real-world output without crashing and report skipped or unusable records as diagnostics.
- Terraform and Kubernetes fixture packs cover each supported provider/resource family with explicit expected assertions.
- Unsupported deployment shapes remain visibility gaps, not silent success.

Work items:

- Add adapter fixtures for additional Semgrep, CodeQL/SARIF, ZAP, Nuclei, Grype, OSV-style, and CSPM variants as they are observed.
- Expand rendered Helm/Kustomize validation cases beyond the current manifest parser coverage.
- Grow provider network and policy fixtures for route precedence, private endpoints, firewall/NSG decisions, service-mesh policy, IAM deny precedence, and scoped identity access.
- Add Docker Compose only when it can provide deployment evidence without weakening release-gate semantics.

### 6. Documentation And Contributor Onboarding

Acceptance criteria:

- The README links to one documentation index.
- New contributors can find the right doc for inputs, algorithms, scoring, CI, fixtures, release process, and maintainer rules without reading source first.
- Any behavior change updates the matching docs, schemas, samples, and tests in the same pull request.

Work items:

- Keep [Documentation Index](README.md) current when docs are added, removed, or renamed.
- Keep roadmap work here, domain target states in [Maturity Targets](maturity_targets.md), and current gates in [Code Quality](code_quality.md).
- Add focused troubleshooting notes only when they reflect common failures from real use.

## Later Stabilization Candidates

- npm wrapper for teams that want Node-native install ergonomics.
- pre-commit hook example for source-only advisory runs.
- Language-server wrapper after the VS Code extension contract is settled.
- Baseline cache format once PR-delta usage patterns are clear.
- Community registry for source-reachability rules.
- Call-graph plugin interface for projects that want deeper source reachability than built-in heuristics.

## Out Of Scope

- Live cloud inventory.
- Commercial CNAPP replacement features.
- Ticketing-system API integrations.
- Secrets scanning.
- Malware scanning.
- DSPM.
- Automatic `not_affected` claims.
