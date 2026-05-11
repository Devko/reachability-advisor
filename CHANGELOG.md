# Changelog

## Unreleased

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
