# Documentation Index

Use this page as the entry point for project documentation. The README stays focused on what the tool does and the quickest path to a local run; this index keeps the deeper operating, design, and maintenance docs discoverable.

## Start Here

- [Quickstart](quickstart.md) - install, demo, sample scan, release gate, PR delta, and fixture commands.
- [Scope](scope.md) - what the tool does, what it intentionally does not do, and safety rules.
- [Input adapters](input_adapters.md) - scanner and context inputs accepted by the CLI.
- [Data formats](data_formats.md) - JSON, SARIF, diagnostics, coverage, baseline, fixture, and report formats.

## How It Works

- [Algorithms](algorithms.md) - pipeline, matching, source evidence, deployment context, scoring, and guardrails.
- [Evidence model](evidence_model.md) - dependency, source, runtime, deployment, posture, network, IAM, and correlation evidence.
- [Reachability mapping](reachability_mapping.md) - artifact, vulnerability, source, Terraform, and mapping-report flow.
- [Scoring](scoring.md) - finding categories, graph decisions, and scoring dimensions.
- [Security evidence](security_evidence.md) - SAST, DAST, posture, runtime, and correlation evidence.
- [Terraform coverage](terraform_coverage.md) - Terraform and rendered Kubernetes context coverage.
- [SBOM generation and artifact identity](sbom_generation.md) - SBOM planning, required metadata, and artifact aliases.

## CI And Developer Workflows

- [Pipeline integration](pipeline.md) - GitHub Actions, composite action, release gates, baselines, and quality gates.
- [Policy playbooks](policy_playbooks.md) - strict release, advisory PR, backlog migration, and review rule examples.
- [IDE integration](ide.md) - VS Code wrapper behavior, settings, diagnostics, and evidence explorer.
- [User-facing messages](user_facing_messages.md) - wording rules for CLI errors, readiness blockers, reports, and web labels.
- [Community Terraform fixture packs](community_fixtures.md) - fixture-pack purpose, commands, anatomy, and contribution checklist.

## Project Health

- [Roadmap](roadmap.md) - stabilization roadmap and release-readiness priorities.
- [Maturity targets](maturity_targets.md) - detailed target state and implemented controls by domain.
- [Production readiness review](production_readiness.md) - feature-by-feature readiness grades and next stabilization focus.
- [Code quality](code_quality.md) - active gates, commands, and behavior coverage.
- [Logic verification checklist](logic_verification.md) - manual review checklist for logic changes.
- [Real-world validation](real_world_validation.md) - HCL/static validation corpus and complex app benchmarks.
- [Threat model](threat_model.md) - assets, trust boundaries, controls, and project risks.
- [Privacy model](privacy.md) - local-first data handling.

## Maintainers

- [Maintainer guide](maintainer_guide.md) - release criteria and contribution patterns for rules, adapters, fixtures, and docs.
- [Release process](release_process.md) - tag-based release workflow and required local gates.

## Documentation Maintenance

- Update docs in the same change that changes CLI behavior, output schema, scoring, release gates, or supported evidence.
- Keep user-facing wording self-explanatory: name the missing evidence, explain the impact, and give a concrete next step.
- Keep command examples runnable from a fresh checkout. Prefer checked-in samples and local-only workflows.
- Keep release gates and matrix references aligned with `Makefile`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, and `pyproject.toml`.
- Put strategic work in [Roadmap](roadmap.md), detailed domain targets in [Maturity targets](maturity_targets.md), and implementation mechanics in the domain-specific docs above.
