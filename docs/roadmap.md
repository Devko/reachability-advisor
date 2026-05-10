# Roadmap

## Stable v1.0 release baseline

- Local-first CLI.
- CycloneDX JSON ingestion.
- Grype, local vulnerability intelligence, and OSV-style parsers.
- Java, Node, Python, and Go source heuristics with direct handler-to-sink evidence.
- Context JSON, Terraform plan context, and conservative HCL static context.
- JSON, SARIF, diagnostics, Markdown, HTML graph, and annotation outputs.
- Mapping reports, Terraform coverage reports, HCL audit reports, SBOM planning, and remediation groups.
- PR delta workflow.
- Release validation against repository JSON schemas.
- VS Code extension skeleton.
- Governance, contribution, and security docs.

## v1.1 roadmap: CI adoption and policy hardening

Goal: make the published GitHub repository easy to consume from production CI while keeping the scanner local-first and auditable.

Priority 1: GitHub Actions consumption

- Harden the composite action so external repositories can use the published action without checking out this repository as their application source.
- Support multiple SBOMs, source-root mappings, artifact aliases, runtime policy, custom reachability rules, Terraform plan/source context, SARIF, diagnostics, HTML graph, mapping, and Terraform coverage outputs through action inputs.
- Expose stable action output paths so downstream workflow steps can upload SARIF and artifacts without duplicating path conventions.
- Add an action usage example to the pipeline documentation.

Priority 2: Policy packs

- Publish a schema for runtime policy files.
- Validate the example policy during release checks.
- Expand policy examples for exceptions, fail thresholds, and expiration hygiene.
- Later: add named policy pack examples for strict release gates, PR-only advisory mode, and legacy backlog migration.

Priority 3: Evidence coverage

- Improve package-manager manifest coverage for Gradle, pnpm, yarn, Poetry, and Go modules.
- Add more precise source diagnostics for package manager files and vulnerable call sites.
- Add fixture packs for AWS Lambda, Azure App Service, GCP GKE, and Helm-heavy Kubernetes shapes.

Priority 4: Baseline and developer workflow

- Add a stable baseline artifact format for default-branch findings.
- Provide a first-class workflow for comparing PR findings against a downloaded baseline artifact.
- Keep the CLI output deterministic so teams can diff findings in code review.

## Completed milestone: Multi-cloud Terraform developer context

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
- Sanitized module-shaped fixture packs for AWS ECS/Fargate, Azure Container Apps, GCP Cloud Run, and Kubernetes ingress workloads.
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
- Same-file and direct handler-to-sink requirement for `attacker_controlled` evidence.
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

## Post-v1 candidates

- Optional npm package wrapper for projects that want Node-native install ergonomics.
- Optional pre-commit hook example for source-only advisory runs.
- Small public corpus for action-level workflow validation.

## Longer-term candidates

- Optional language-server wrapper.
- Baseline cache format.
- Community registry for source-reachability rules.
- Optional call-graph plugin interface for projects that want deeper source reachability.

## Out of scope for now

- Live cloud inventory.
- Commercial CNAPP replacement features.
- Ticketing-system API integrations.
- Secrets scanning.
- Malware scanning.
- DSPM.
- Automatic `not_affected` claims.
