# Maintainer Guide

## Release criteria

A release must meet these gates:

- `make compile` passes.
- `make test` passes.
- `make coverage` passes at or above the configured threshold.
- `make sample` produces all expected outputs.
- `make fixtures` validates and runs all Terraform fixture packs.
- `make release-check` validates release metadata and generated outputs against repository schemas.
- `make package` builds the source distribution and wheel.
- Changelog entry is added.
- Any new output format has a schema update or documented rationale.
- Any new supported Terraform resource type is backed by at least one unit test or fixture-pack assertion.
- Documentation that describes changed behavior is updated in the same pull request.

## Adding a source reachability rule

1. Add a `ReachabilityRule` to `src/reachability_advisor/source.py`.
2. Add a sample source fixture.
3. Add tests for import-only, function-reachable, and attacker-controlled cases where applicable.
4. Verify same-function or bounded call-path evidence before expecting `attacker_controlled`.
5. Export Semgrep starter rules with `export-semgrep-rules` when the rule should be reusable outside the built-in analyzer.
6. Document the limitation in `docs/algorithms.md`.

## Adding a vulnerability adapter

1. Keep network calls out of the scanner.
2. Add a parser in `vulnerability.py`.
3. Add fixture-based tests.
4. Ensure malformed inputs produce user-facing errors.

## Project governance

The repository uses the Apache License 2.0 for code and documentation, plus DCO sign-off for contributions. Releases must be documented and reproducible through the local quality gates.

## Documentation maintenance

Use `docs/README.md` as the documentation map. Keep it current when files are added, renamed, or removed.

- Put user setup and common commands in `docs/quickstart.md`.
- Put report schemas, fields, and examples in `docs/data_formats.md`.
- Put algorithm and evidence semantics in `docs/algorithms.md`, `docs/evidence_model.md`, `docs/reachability_mapping.md`, and `docs/scoring.md`.
- Put CI, release gates, and action usage in `docs/pipeline.md`.
- Put strategic stabilization work in `docs/roadmap.md`.
- Put detailed domain target states and implemented controls in `docs/maturity_targets.md`.
- Keep current gates and test coverage in `docs/code_quality.md`.

When CLI options, generated reports, schemas, gates, scoring, or supported inputs change, update the relevant docs, samples, and tests in the same change.


## Adding a Terraform fixture pack

1. Create `fixtures/terraform/packs/<id>/fixture.json`.
2. Add a reduced `tfplan.json` generated from or shaped like `terraform show -json`.
3. Add CycloneDX SBOMs and source roots for the artifact being matched.
4. Declare expected coverage and finding assertions in `fixture.json`.
5. Register the pack in `fixtures/terraform/index.json`.
6. Run `make fixtures` and `make coverage`.
7. Add or update docs when the pack introduces a new provider, resource category, or scanner limitation.

Fixture packs must be sanitized and must not vendor third-party Terraform module source code.
