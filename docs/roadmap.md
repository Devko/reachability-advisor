# Roadmap

## Stable v1.0 release baseline

- Local-first CLI.
- CycloneDX JSON ingestion.
- Grype, local vulnerability intelligence, and OSV-style parsers.
- Java, Node, Python, and basic Go source heuristics.
- Context JSON, Terraform plan context, and conservative HCL static context.
- JSON, SARIF, diagnostics, Markdown, and annotation outputs.
- Mapping reports, Terraform coverage reports, HCL audit reports, SBOM planning, and remediation groups.
- PR delta workflow.
- Release validation against repository JSON schemas.
- VS Code extension skeleton.
- Governance, contribution, and security docs.

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
- Same-file requirement for `attacker_controlled` evidence.
- Custom reachability rule JSON.
- Basic Go import evidence.
- Expanded test suite to 224 tests and raised the coverage gate to 93%.

## Completed milestone: Grype handoff and real-world validation

- Grype JSON parser for using Grype as the vulnerability scanner and database handoff.
- Package-level remediation grouping with fixed-version recommendations when scanner data includes them.
- HCL static audit mode for public Terraform repositories and early PR/IDE checks.
- Real-world replay scripts for external HCL corpus validation and existing Grype/CycloneDX outputs.
- Expanded source rules for Express, NestJS/Express, Spring Web, FastAPI, Chainlit, and aiohttp.
- Linked IaC exposure inference instead of provider-wide public fallback for supported workload patterns.
- Expanded test suite to 269 tests while keeping the coverage gate at 93%.

## Post-v1 candidates

- Better package-manager manifest support for Gradle, pnpm, yarn, Poetry, and Go modules.
- More precise diagnostics-to-source mapping.
- Additional community Terraform fixtures for common AWS Lambda, Azure App Service, GCP GKE, and Kubernetes Helm module shapes.
- Example policy packs.

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
