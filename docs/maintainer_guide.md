# Maintainer Guide

## Release criteria

A release should meet these gates:

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

## Adding a source reachability rule

1. Add a `ReachabilityRule` to `src/reachability_advisor/source.py`.
2. Add a sample source fixture.
3. Add tests for import-only, function-reachable, and attacker-controlled cases where applicable.
4. Document the limitation in `docs/algorithms.md`.

## Adding a vulnerability adapter

1. Keep network calls out of the scanner.
2. Add a parser in `vulnerability.py`.
3. Add fixture-based tests.
4. Ensure malformed inputs produce user-facing errors.

## Project governance

The repository uses GNU GPL v3.0 or later for code and DCO sign-off for contributions. Maintainers should keep releases small, documented, and reproducible through the local quality gates.


## Adding a Terraform fixture pack

1. Create `fixtures/terraform/packs/<id>/fixture.json`.
2. Add a reduced `tfplan.json` generated from or shaped like `terraform show -json`.
3. Add CycloneDX SBOMs and optional source roots for the artifact being matched.
4. Declare expected coverage and finding assertions in `fixture.json`.
5. Register the pack in `fixtures/terraform/index.json`.
6. Run `make fixtures` and `make coverage`.
7. Add or update docs when the pack introduces a new provider, resource category, or scanner limitation.

Fixture packs should be sanitized and should not vendor third-party Terraform module source code.
