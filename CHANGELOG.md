# Changelog

## Unreleased

### Notable: first runtime dependency

- **PyYAML is now a runtime dependency** — the first this project has had. It is used exclusively through `yaml.safe_load`, which does not construct arbitrary Python objects, and every YAML read is additionally bounded by a document size limit, a nesting-depth cap, a node budget that stops anchor/alias expansion, and a `RecursionError` guard. A security tool acquiring a dependency is worth stating plainly rather than leaving in a diff. It paid for deleting a hand-rolled YAML parser in `kubernetes.py` in which an audit had found a stack overflow, and for correctly resolving anchors and aliases that the old parser silently mis-parsed.

### Added

- `.reachability.yml` configuration, so options are declared once and shared between local runs and CI instead of being retyped as flags. Values resolve through layers: built-in defaults, an organization baseline via `extends:`, the repository file, then CLI flags. `extends:` resolves only from a relative path or an installed package, never over the network.
- `reachability-advisor init` — inspects the repository and writes a `.reachability.yml` declaring what is actually present, marking everything else with the exact command that produces it. Non-interactive, so a platform team can script it across many repositories. It never rewrites an existing config; `--refresh` writes `.reachability.detected.yml` alongside for manual merge.
- `reachability-advisor doctor` — reports what evidence is missing and the command that produces it, exits non-zero until the gate is satisfiable, and emits the same data as JSON for tracking onboarding across repositories.
- `reachability-advisor config explain` / `config validate` — prints each resolved value with the layer that set it, so "why did this gate fire" is answerable without archaeology.
- `compare --config`, and a `config` input on the composite GitHub Action.

### Changed

- Onboarding is three commands — `init`, `doctor`, `scan` — replacing the previous flow of running three `*-plan` commands, copying their printed output, and assembling roughly twenty flags by hand.
- `scan` accepts a configuration file, so `--sbom` and `--vuln-in` are no longer required as flags. With no configuration file present, behaviour is unchanged.
- Kubernetes manifests are parsed by the shared bounded loader instead of a hand-rolled parser. Manifests using YAML anchors and aliases now resolve correctly; they were previously mis-parsed without error.

### Fixed

- A malformed configuration now stops the run instead of being coerced into a weaker one. Unknown keys are rejected at every level, an out-of-range gate threshold is refused, and a configuration file that is not a readable regular file is an error rather than being silently treated as absent.
- Terraform plan loading now fails closed on deeply nested input instead of raising an uncaught `RecursionError`, matching the other input loaders.
- `scan` fails closed with exit code 2 on an unreadable input file instead of crashing with a traceback.

## 1.2.0 - 2026-05-15

- v1.2: replaced per-finding attack-path cards with a unified attack graph that starts from a shared Internet/attacker node and branches into route, workload, and finding nodes.
- v1.2: added draggable, clickable, expandable attack graph nodes with right-side context details for routes, assets, finding groups, individual findings, and graph edges.
- v1.2: moved visible risk scenarios into a dedicated left sidebar in the attack-path view so the right panel can stay focused on selected context.
- v1.2: added attack-surface grouping for outside entry, lateral movement, private/no-external-entry, and unresolved network paths.
- v1.2: improved graph layout behavior when finding groups are expanded so rows resize instead of overlapping.
- v1.2: refreshed the real-app benchmark snapshot expectations after the current validation corpus distribution changed.
- v1.2: kept the release gate at 612 unit and workflow tests, 93% coverage threshold, strict typing, linting, release validation, demo generation, fixture validation, scale validation, and package build.

## 1.1.0 - 2026-05-14

- v1.1: separated DAST runtime evidence from source reachability.
- v1.1: added canonical finding types for dependency, static SAST, dynamic DAST, CSPM, and correlated security findings.
- v1.1: added `--vuln-in`, `--sast-in`, `--dast-in`, and `--cspm-in` CLI aliases.
- v1.1: added non-destructive scanner correlation and DAST URL-to-workload mapping behavior.
- v1.1: added conservative ZAP JSON and Nuclei JSONL DAST adapters.
- v1.1: added CSPM/posture evidence import for normalized JSON, SARIF, Checkov, Trivy config, KICS, and tfsec.
- v1.1: added native local Terraform/Kubernetes posture checks for public ingress, broad IAM/RBAC, public data endpoints, disabled encryption, privileged workloads, and sensitive manifest values.
- v1.1: added per-finding attack-path stories and risk scenario views to the HTML report.
- v1.1: added `reachability-advisor demo` and `make demo` with checked-in multi-scanner samples.
- v1.1: simplified README positioning around dependency, SAST, DAST, and CSPM correlation.
- v1.1: added CodeQL, Scorecard, tag-based release workflow, issue templates, and a PR template.
- Hardened release validation so the documented import/export contract is exercised end to end.
- Fixed `explain --out` so nested output paths are created consistently with the other writers.
- Refreshed README support and validation claims.
- Added CI enforcement for lint, strict typing, and built-wheel entry point smoke testing.
- Added golden output regression coverage for sample findings, coverage summaries, and visual graph connectivity.
- Added hostile-input tests for malformed SBOM/vulnerability/source-evidence inputs and HTML report escaping.
- Added complex app benchmark JSON/Markdown output for scale validation drift tracking.
- Added a schema contract for complex benchmark output and direct schema regression tests for repository fixtures/config.
- Added CI artifact upload for generated reports and built packages.
- Refactored visual graph ranking and card layout constants into a shared module.

## 1.0.0 - 2026-05-10

Stable public v1 release.

- Promoted the package metadata to `Development Status :: 5 - Production/Stable`.
- Aligned the package and CLI version to `1.0.0`.
- Added `scripts/validate_release.py` and `make release-check` to validate release metadata and generated output schemas before tagging.
- Added release validation to CI.
- Includes the full local-first CLI, CycloneDX ingestion, Grype/local/OSV-style vulnerability adapters, source reachability heuristics, Terraform plan and HCL static context, mapping reports, remediation grouping, SARIF/diagnostics/Markdown/annotation outputs, fixture packs, and real-world replay scripts.
- Release validation snapshot: 269 tests, 93% coverage gate, clean sdist/wheel build, 4 fixture packs, 9 external HCL corpus projects, and 3 Grype replay cases.

## Pre-1.0 internal milestones

The entries below were local development milestones before the first stable public release.

### Internal milestone 5 - 2026-05-10

Real-world Terraform validation release.

- Added conservative Terraform HCL static auditing via `reachability-advisor hcl-audit`.
- Added `--terraform-source` scan input for weak early PR/IDE context when a plan is not available.
- Added HCL source-to-synthetic-plan conversion for resource accounting, semantic classification, literal image hints, public exposure hints, and identity hints.
- Added explicit module expansion and unresolved-variable visibility gaps.
- Added curated external corpus metadata for popular AWS, Azure, GCP, and Kubernetes/GKE Terraform projects.
- Added `scripts/run_external_hcl_audit.sh` for network-enabled real-world validation runs.
- Added `docs/real_world_validation.md`, HCL audit schema, sample Terraform source, and HCL sample workflow.
- Improved image discovery to handle list-shaped image values.
- Expanded tests from 224 to 242.

### Internal milestone 4 - 2026-05-10

Logic verification and mapping-hardening release.

- Added `sbom-plan` for developer-friendly SBOM acquisition guidance.
- Added `--mapping-out` to show SBOM artifact candidates, source roots, Terraform match evidence, and mapping warnings.
- Added `--artifact-alias` for explicit image/reference mapping when generated SBOMs lack metadata.
- Added `--reachability-rules` for custom package/vulnerability-specific source heuristics.
- Hardened artifact matching with normalized image references, digest/repository/tag scores, and reduced substring matching.
- Extended CycloneDX parsing for metadata component properties and external references.
- Improved source reachability so `attacker_controlled` requires same-file import, risky function usage, and input/entrypoint evidence.
- Added basic Go import evidence and expanded Java/Node/Python tests.
- Added documentation for SBOM generation, reachability mapping, and logic verification.
- Expanded tests from 174 to 224 and raised coverage threshold from 92% to 93%.
- Current measured coverage was 94%.

### Internal milestone 3 - 2026-05-10

Community Terraform fixture-pack release.

- Added `reachability-advisor fixtures list|validate|run`.
- Added executable fixture packs for AWS ECS/Fargate, Azure Container Apps, GCP Cloud Run, and Kubernetes ingress workloads.
- Added per-fixture expected assertions for resource accounting, semantic classification, artifact matching, required resource types, and minimum finding tiers.
- Added schema drafts for fixture packs and fixture run reports.
- Added `make fixtures` and CI execution for fixture-pack validation.
- Expanded Terraform semantic manifest with common supporting resources from module-shaped plans.
- Expanded tests from 134 to 174 and raised coverage threshold from 90% to 92%.
- Current measured coverage was 94%.

### Internal milestone 2 - 2026-05-10

Multi-cloud Terraform developer context release.

- Added manifest-driven Terraform analyzer for AWS, Azure, GCP, and Kubernetes provider resources.
- Added `--terraform-coverage-out` with 100% resource accounting for valid plans.
- Added semantic classification coverage and visibility-gap reporting.
- Added workload matching for common container, serverless, app-service, batch, VM, Cloud Run, and Kubernetes resources.
- Added exposure hints for security groups, NSGs, firewalls, API gateways, function URLs, public invoker IAM, load balancers, services, and ingresses.
- Added provider IAM blast-radius classification for AWS IAM, Azure role assignments/Key Vault policies, GCP IAM, and Kubernetes bindings.
- Added Azure and GCP sample artifacts and a multi-cloud Terraform sample plan.
- Expanded tests from 71 to 134 and raised coverage threshold from 88% to 90%.

### Internal milestone 1 - 2026-05-09

Focused developer edition.

- Added local-first CLI for SBOM + vulnerability + source/context prioritization.
- Added SARIF, diagnostics JSON, Markdown PR summary, and GitHub annotations.
- Added PR delta comparison and single-finding explanation.
- Added Java/Maven, Node/npm, and Python/PyPI lightweight source heuristics.
- Added context JSON and Terraform-lite context inference.
- Added VS Code extension skeleton.
- Added governance, security, privacy, and contribution docs.
- Added 71 tests with 88% coverage.
