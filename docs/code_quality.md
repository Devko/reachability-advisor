# Code Quality

## Current gates

- Unit and workflow tests: 413.
- Coverage threshold: 93%.
- Current measured coverage: passes the 93% line/branch-aware coverage gate.
- Test runner: `scripts/run_tests.py`.
- Compile check: `python -m compileall -q src scripts tests`.
- Static lint configuration: `ruff` with `E`, `F`, `I`, `UP`, `B`, `C4`, and `SIM` rules across `src`, `tests`, and `scripts`.
- Static type configuration: strict `mypy` across `src`.
- Sample workflow: `make sample`.
- Terraform fixture workflow: `make fixtures`.
- Release validation: `make release-check` currently covers 49 import/export and release-contract checks.
- Complex real-world app validation: `make external-complex` (AWS Retail Store and Google Online Boutique).
- Package build: `make package` (`python -m build --no-isolation`).
- CI matrix: Python 3.10, 3.11, 3.12.
- CI runs compile, lint, strict type-checking, tests, coverage, sample output generation, fixture packs, release validation, package build, and a built-wheel CLI smoke test.
- CI uploads generated JSON/Markdown/SARIF/HTML/text reports and built distribution files as workflow artifacts.

## Local quality commands

Install the development tools before running lint, type checks, or package validation:

```bash
python -m pip install -e ".[dev]"
```

Common gates:

```bash
make test
make coverage
make compile
make release-check
make package
make lint
make type-check
```

Full local gate:

```bash
make quality
```

Windows shells without `make` can run the same gates directly:

```powershell
python scripts/run_tests.py
python -m coverage run --source=src/reachability_advisor scripts/run_tests.py
python -m coverage report -m --fail-under=93
python -m compileall -q src scripts tests
python scripts/validate_release.py
python -m ruff check src tests scripts
python -m mypy src
python -m build --no-isolation
```

`make package` uses `--no-isolation` so the bundled local Python can validate packaging even when `venv` is not available. The development extra supplies the required build backend and quality tools.

## Engineering choices

- Standard library only in the Python scanner.
- Dataclass model for reviewability.
- Explicit parser errors for malformed inputs.
- Output renderers separated from scoring.
- Thin IDE wrapper that delegates logic to the CLI.
- Multi-cloud Terraform coverage is manifest-driven and auditable.
- SBOM/source/Terraform mapping is exposed through `--mapping-out`.
- Source analysis coverage is exposed through `--source-coverage-out`.
- The HTML graph is backed by `--evidence-graph-out`, a structured graph of assets, network paths, IAM capability edges, code evidence, components, vulnerabilities, and findings.
- Unsupported Terraform resources are reported as visibility gaps instead of being silently ignored.

## Logic quality bar

The logic layer has tests for:

- CycloneDX metadata component properties and external references.
- Explicit artifact aliases from `--artifact-alias`.
- Artifact identity proof chains, OCI-ish image reference normalization, digest matching, repository/tag matching, and conservative rejection of substring false positives.
- SBOM-to-source-root mapping reports.
- Vulnerability-specific source reachability rules.
- Custom reachability rule loading.
- Same-function and bounded handler-to-sink gating for `attacker_controlled` evidence.
- CycloneDX dependency-graph evidence for imported parent dependencies.
- Package-manager manifest evidence for Gradle, Maven POMs, pnpm, Yarn, npm locks, Poetry, Python requirements, and Go modules.
- External source evidence import from native JSON, Semgrep JSON including `dataflow_trace`, CodeQL/SARIF `codeFlows`, plain SARIF, and govulncheck-style JSONL.
- External evidence selector diagnostics for artifact-only or unscoped records.
- Source coverage metrics for package-specific rule coverage, rule gaps, weak-source evidence, and usable external evidence ratio.
- Semgrep starter rule export from built-in and custom reachability rules.
- Weaker rationale when input/entrypoint evidence appears in a different file.
- Java/Spring, Node/Express/NestJS, Python/FastAPI/Chainlit/aiohttp, common SSRF/template/JWT/XML/deserialization/archive package families, and Go source evidence.
- CLI generation of mapping, source coverage, Terraform coverage, SARIF, diagnostics, Markdown, HTML, and annotations.
- Account-free Terraform plan E2E coverage with source reachability, artifact identity proof, network context, IAM capability extraction, evidence graph, and HTML output.
- Stable baseline artifact generation and PR delta comparison for only new or worsened findings.
- Visual graph generation for public, internal, lateral, private, and Kubernetes public-ingress-to-internal-hop paths.
- Visual graph regression coverage for connected entry/path/asset/vulnerability edges and dense multi-asset layouts.
- Rendered Kubernetes manifest analysis for workload, Service, Ingress, RBAC, artifact matching, and coverage output.
- Generated output validation against repository JSON schemas through `scripts/validate_release.py`.
- Direct schema-contract tests for checked-in sample vulnerability data, context data, runtime policy config, fixture packs, and complex benchmark output.
- Golden regression tests for the main sample lock finding counts, tier spread, top remediation order, coverage summaries, and visual graph connectivity.
- Hostile-input tests cover malformed SBOM/vulnerability/source-evidence files and HTML report escaping.

## Terraform quality bar

The Terraform layer has tests for:

- AWS, Azure, GCP, and Kubernetes provider detection.
- Manifest uniqueness and manifest accounting.
- Plan parsing from `planned_values` and `resource_changes`.
- Container image extraction across ECS/Lambda/App Runner, Azure Container Apps/App Service, GCP Cloud Run, and Kubernetes resources.
- Public, restricted external, internal lateral, private-only, and unknown exposure detection across AWS, Azure, GCP, and Kubernetes resources.
- Bounded graph pathfinding for AWS ECS security groups/target groups, AWS target attachments, AWS Lambda URLs, Azure application gateway/load-balancer backend paths, GCP forwarding-rule/backend-service/NEG paths, GCP Cloud Run/Cloud Functions public invokers, Azure Container Apps ingress, Kubernetes Service/Ingress names or selectors, security-group hops, route table associations, firewall target tags, firewall priorities, private endpoints, NSG allow/deny rules, and lateral bridge resources such as peering, VPN, transit, ExpressRoute, and Interconnect.
- IAM blast-radius classification, provider role catalogs, per-workload identity linkage, per-resource IAM capability records with resource scope, condition keys, effective risk, risk multiplier, targeted sensitive-resource evidence, and network-aware criticality across AWS IAM, Azure role assignments and Key Vault policies, GCP IAM, and Kubernetes role bindings.
- CLI generation of `--terraform-coverage-out`.

## Fixture-pack quality bar

Every Terraform fixture pack must validate and run through the fixture harness. The current packs assert:

- `resource_accounting_coverage == 1.0`;
- `semantic_classification_coverage == 1.0`;
- `artifact_match_coverage == 1.0`;
- no unsupported or unclassified resources in the pack;
- required resource types are present;
- at least one expected finding reaches the documented minimum tier.

The active pack set covers AWS ECS/Fargate, AWS Lambda function URLs, Azure Container Apps, Azure App Service, GCP Cloud Run, GKE plus Kubernetes workloads, Kubernetes ingress, Helm-heavy Kubernetes, and private service-mesh workloads.

## Future hardening

- Add signed release artifacts.
- Add property-based parser tests with a dedicated generator once the project accepts a test-only dependency.
- Expand fuzz-style malformed-input tests for SBOM, vulnerability, source, Kubernetes, and Terraform inputs.
- Expand community-maintained Terraform fixture packs for additional edge cases inside the supported providers.
