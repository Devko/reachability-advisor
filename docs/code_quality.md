# Code Quality

## Current gates

- Unit and workflow tests: 332.
- Coverage threshold: 93%.
- Current measured coverage: 94% line/branch-aware coverage report.
- Compile check: `python -m compileall`.
- Sample workflow: `make sample`.
- Terraform fixture workflow: `make fixtures`.
- Release validation: `make release-check`.
- Package build: `make package`.
- CI matrix: Python 3.10, 3.11, 3.12.

## Engineering choices

- Standard library only in the Python scanner.
- Dataclass model for reviewability.
- Explicit parser errors for malformed inputs.
- Output renderers separated from scoring.
- Thin IDE wrapper that delegates logic to the CLI.
- Multi-cloud Terraform coverage is manifest-driven and auditable.
- SBOM/source/Terraform mapping is exposed through `--mapping-out`.
- Unsupported Terraform resources are reported as visibility gaps instead of being silently ignored.

## Logic quality bar

The logic layer has tests for:

- CycloneDX metadata component properties and external references.
- Explicit artifact aliases from `--artifact-alias`.
- OCI-ish image reference normalization, digest matching, repository/tag matching, and conservative rejection of substring false positives.
- SBOM-to-source-root mapping reports.
- Vulnerability-specific source reachability rules.
- Custom reachability rule loading.
- Same-file and direct handler-to-sink gating for `attacker_controlled` evidence.
- Weaker rationale when input/entrypoint evidence appears in a different file.
- Java/Spring, Node/Express/NestJS, Python/FastAPI/Chainlit/aiohttp, common SSRF/template/JWT/XML/deserialization/archive package families, and Go source evidence.
- CLI generation of mapping, coverage, SARIF, diagnostics, Markdown, HTML, and annotations.
- Generated output validation against repository JSON schemas through `scripts/validate_release.py`.

## Terraform quality bar

The Terraform layer has tests for:

- AWS, Azure, GCP, and Kubernetes provider detection.
- Manifest uniqueness and manifest accounting.
- Plan parsing from `planned_values` and `resource_changes`.
- Container image extraction across ECS/Lambda/App Runner, Azure Container Apps/App Service, GCP Cloud Run, and Kubernetes resources.
- Public, restricted external, internal lateral, private-only, and unknown exposure detection across AWS, Azure, GCP, and Kubernetes resources.
- Bounded graph pathfinding for AWS ECS security groups/target groups, AWS target attachments, AWS Lambda URLs, Azure application gateway/load-balancer backend paths, GCP forwarding-rule/backend-service/NEG paths, GCP Cloud Run/Cloud Functions public invokers, Azure Container Apps ingress, Kubernetes Service/Ingress names or selectors, security-group hops, and lateral bridge resources such as peering, VPN, transit, ExpressRoute, and Interconnect.
- IAM blast-radius classification, per-workload identity linkage, IAM impact classes, targeted sensitive-resource evidence, and network-aware criticality across AWS IAM, Azure role assignments and Key Vault policies, GCP IAM, and Kubernetes role bindings.
- CLI generation of `--terraform-coverage-out`.

## Fixture-pack quality bar

Every Terraform fixture pack should validate and run through the fixture harness. The current packs assert:

- `resource_accounting_coverage == 1.0`;
- `semantic_classification_coverage == 1.0`;
- `artifact_match_coverage == 1.0`;
- no unsupported or unclassified resources in the pack;
- required resource types are present;
- at least one expected finding reaches the documented minimum tier.

## Future hardening

- Add JSON schema validation in tests.
- Add signed release artifacts.
- Add property-based parser tests.
- Add fuzz tests for SBOM, vulnerability, source, and Terraform inputs.
- Expand community-maintained Terraform fixture packs for additional common modules and provider edge cases.
