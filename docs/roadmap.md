# Roadmap

## Stable v1.0 release baseline

- Local-first CLI.
- CycloneDX JSON ingestion.
- Grype, local vulnerability intelligence, and OSV-style parsers.
- Java, Node, Python, and Go source heuristics with same-function and bounded handler-to-sink evidence.
- CycloneDX dependency-graph source evidence and external evidence import for Semgrep, SARIF, and govulncheck-style output.
- Terraform plan context, context JSON enrichment, and conservative HCL static fallback.
- JSON, SARIF, diagnostics, Markdown, HTML graph, and annotation outputs.
- Mapping reports, source coverage reports, Terraform coverage reports, HCL audit reports, SBOM planning, and remediation groups.
- PR delta workflow.
- Release validation against repository JSON schemas.
- VS Code extension skeleton.
- Governance, contribution, and security docs.

## v1.1 roadmap: quality, evidence, and CI adoption

Goal: make the public repository easy to trust in CI. The scanner should stay local, deterministic, and explainable.

Priority 1: CI quality gates

- Done: install `.[dev]` in CI and run `make lint`, `make type-check`, `make coverage`, `make release-check`, and `make package`.
- Keep Python 3.10, 3.11, and 3.12 in the matrix.
- Keep strict `mypy` passing across all `src` modules.
- Done: smoke-test the built wheel entry point after packaging.
- Publish coverage, SARIF, diagnostics, HTML graph, mapping, source coverage, and Terraform coverage as workflow artifacts.
- Keep generated outputs deterministic so PR reviews can diff them.

Priority 2: Source reachability coverage

- Keep package-manager manifest coverage current for Gradle, Maven POMs, pnpm, Yarn, npm locks, Poetry, Python requirements, and Go modules.
- Add richer source diagnostics for package-manager roots, imported vulnerable packages, vulnerable call sites, and handler-to-sink paths.
- Done: native adapters import Semgrep `dataflow_trace` taint paths and CodeQL SARIF `codeFlows` when package, purl, or vulnerability selectors are available.
- Add native adapters for more language-specific analyzer output when selectors are available.
- Track unknown source states as rule gaps, package-manager gaps, or missing source roots instead of one generic unknown bucket.

Priority 3: Terraform and IaC coverage

- Done: rendered Kubernetes YAML/JSON manifests are first-class `scan` inputs with workload, service, ingress, RBAC, context, and coverage output.
- Done: fixture packs now cover AWS Lambda function URLs, Azure App Service, GKE plus Kubernetes workloads, Helm-heavy Kubernetes deployments, and private service meshes.
- Expand rendered Helm/Kustomize validation cases beyond the current Kubernetes manifest parser.
- Expand lateral movement evidence for route tables, peering, VPN, transit gateways, private endpoints, service endpoints, and Kubernetes network policies.
- Keep unsupported IaC resources visible in coverage reports.

Priority 4: Policy and baseline workflow

- Publish a schema for runtime policy files.
- Validate the example policy during release checks.
- Done: stable default-branch baseline artifacts are generated with `scan --baseline-out`.
- Done: `compare --baseline` emits PR deltas with only new and worsened findings.
- Add policy examples for strict release gates, advisory PR mode, exception expiration, and backlog migration.

Priority 5: Validation corpus

- Keep AWS Retail Store and Google Online Boutique as scale tests.
- Add compact fixtures for each important exposure class: public, restricted external, lateral, internal-only, IAM admin, critical limited role, read-only role, no role, code reachable, and code not observed.
- Done: add golden sample-output regressions for finding counts, tier spread, top remediation order, coverage summaries, and graph connectivity.
- Done: complex validation now emits `benchmark.json` and `benchmark.md` for release-to-release metric drift tracking.
- Publish expected outputs for fixtures so downstream contributors can verify behavior without reading implementation details.
- Done: visual graph regression tests cover connected network-path rendering and dense multi-asset layouts.

## Completed milestone: Multi-cloud Terraform context

- AWS, Azure, GCP, and Kubernetes Terraform plan support.
- Manifest-driven resource coverage.
- 100% resource accounting coverage for valid plans.
- Semantic classification coverage report with visibility gaps.
- Workload matching for containers, serverless, batch, app services, VMs, Cloud Run, and Kubernetes workloads.
- Exposure hints for public networks, APIs, load balancers, function URLs, public invoker IAM, services, and ingresses.
- Coarse IAM blast-radius classification across providers.
- Expanded sample data, 134 tests, and 90%+ coverage gate.

## Completed milestone: Community Terraform fixture packs

- Fixture harness with `fixtures list`, `fixtures validate`, and `fixtures run`.
- Sanitized module-shaped fixture packs for AWS ECS/Fargate, AWS Lambda function URLs, Azure Container Apps, Azure App Service, GCP Cloud Run, GKE workloads, Kubernetes ingress, Helm-heavy Kubernetes, and private service-mesh workloads.
- Per-fixture expected assertions for resource accounting, semantic classification, artifact matching, required resource types, and minimum finding tiers.
- CI target `make fixtures`.
- Fixture pack and fixture report schemas.
- Expanded test suite to 174 tests and raised the coverage gate to 92%.

## Completed milestone: Logic verification and mapping hardening

- `sbom-plan` command for SBOM acquisition guidance.
- Stronger CycloneDX metadata parsing, including metadata component properties and external references.
- Explicit artifact alias support for generated SBOMs without image metadata.
- Conservative artifact identity matching with digest/repository/tag scores and reduced substring matching.
- `--mapping-out` to inspect SBOM candidates, source roots, Terraform match scores, and warnings.
- Vulnerability-aware source reachability rules.
- Same-function and bounded handler-to-sink requirement for `attacker_controlled` evidence.
- Custom reachability rule JSON.
- Go import evidence plus common JWT/YAML sink hints.
- Expanded test suite to 224 tests and raised the coverage gate to 93%.

## Completed milestone: Grype handoff and real-world validation

- Grype JSON parser for using Grype as the vulnerability scanner and database handoff.
- Package-level remediation grouping with fixed-version recommendations when scanner data includes them.
- HCL static audit mode for public Terraform repositories and early PR/IDE checks.
- Real-world replay scripts for external HCL corpus validation and existing Grype/CycloneDX outputs.
- Expanded source rules for Express, NestJS/Express, Spring Web, FastAPI, Chainlit, aiohttp, common SSRF/template/JWT/XML/deserialization/archive families, and direct call-path evidence.
- Linked IaC exposure inference instead of provider-wide public fallback for supported workload patterns.
- Expanded test suite to 269 tests while keeping the coverage gate at 93%.

## Post-v1 Candidates

- npm package wrapper for projects that want Node-native install ergonomics.
- pre-commit hook example for source-only advisory runs.
- Small public corpus for action-level workflow validation.

## Longer-term candidates

- language-server wrapper.
- Baseline cache format.
- Community registry for source-reachability rules.
- call-graph plugin interface for projects that want deeper source reachability.

## Out of scope for now

- Live cloud inventory.
- Commercial CNAPP replacement features.
- Ticketing-system API integrations.
- Secrets scanning.
- Malware scanning.
- DSPM.
- Automatic `not_affected` claims.
