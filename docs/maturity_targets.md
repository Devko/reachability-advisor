# Maturity Targets

This page defines the target state for the areas that decide whether Reachability Advisor can be used as a release gate instead of an advisory triage tool.

## Source reachability

Target state:

- Production scans import external analyzer evidence by default: Semgrep JSON, CodeQL/SARIF code flows, govulncheck JSONL, or native Reachability Advisor evidence.
- Built-in source rules remain available, but they are fallback evidence.
- Critical findings cannot pass a release gate on package-manager or dependency-graph evidence alone.
- Critical findings cannot pass a release gate when external evidence exists but does not cover the risky package set.
- Critical findings cannot pass a release gate when the package does not map to a maintained proven query family.
- Every imported record must carry a package, package URL, or vulnerability selector. Artifact-only records are diagnostics, not upgrades.
- Maintained Semgrep/CodeQL/govulncheck profiles exist per ecosystem and are measured in `source-coverage.json`.

Implemented controls:

- `source-evidence-plan` emits concrete Semgrep, CodeQL, and govulncheck commands for CI.
- `source-evidence-pack` writes versioned npm, Maven/Gradle, Python, and Go Semgrep/CodeQL/govulncheck assets, package-family query packs, expected sample coverage metadata, and the release-gate selector contract.
- `fixtures/source-vulnerable-apps/coverage-expectations.json` defines checked-in vulnerable sample apps and pinned public repository commits used to measure package-family true-positive coverage. Unit tests require the maintained family rules to cover every expected local sample.
- The plan JSON includes ecosystem profiles for npm/pnpm/Yarn, Maven/Gradle, PyPI/Poetry/pip, and Go modules.
- `--analysis-profile production` requires external source evidence and usable selectors.
- Production gates require `critical_external_evidence_coverage=1.0`, `critical_query_family_coverage=1.0`, and `critical_proven_query_family_coverage=1.0` unless a stricter user threshold is supplied.
- `--require-strong-source-for-critical` fails when critical findings only have `absent`, `unknown_due_to_no_rule`, `package_present`, or `dependency_reachable` evidence. Production profile enables the same gate.
- `source-coverage.json` reports critical package rows, external evidence coverage per critical package, selected external evidence coverage, proven query-family coverage, rule gaps, and weak-source counts.
- `--min-critical-query-family-coverage` and `--min-critical-proven-query-family-coverage` expose the production gates explicitly for CI.

## SAST and DAST evidence

Target state:

- First-party code weakness evidence is imported separately from dependency reachability.
- High and critical SAST/DAST records carry CWE, scanner type, source location or tested URL, confidence, and artifact mapping.
- Release gates fail when high or critical SAST/DAST records do not map to a maintained profile.
- Maintained profiles are tested against local vulnerable examples and public reference applications.

Implemented controls:

- `security-evidence-pack` writes maintained SAST/DAST profiles, Semgrep profile files, DAST profile metadata, and a release-gate contract.
- `fixtures/security-vulnerable-apps/coverage-expectations.json` defines local vulnerable examples for XSS, command injection, SQL injection, unsafe deserialization, missing authorization, and dynamic web probes.
- `source-coverage.json.security_evidence.summary.critical_profile_coverage` reports profile coverage for imported high and critical code weaknesses.
- `--min-critical-security-profile-coverage` fails CI when imported high or critical SAST/DAST records lack a maintained profile.

## IAM effective access

Target state:

- Model identities, resources, actions, allow edges, deny edges, trust edges, conditions, scope, blockers, and confidence as graph records.
- Explicit deny has precedence in the evidence model and must not raise privilege.
- Scoped or conditional permissions remain visible and score lower than broad unconditioned access.
- Cross-account and role-assumption paths must show the identity, target role/resource, action, decision, and inherited visible capability.
- Provider policy decisions must come from structured policy documents when available, not only from Terraform resource labels or pre-classified allow/deny summaries.

Implemented controls:

- Terraform IAM policies emit per-action capability records with `effect`, `policy_layer`, `resource_scope`, `condition_keys`, `access`, `impact`, `effective_risk`, and `risk_multiplier`.
- Effective access records include `identity`, `resource`, `action`, `decision`, `decision_basis`, `policy_layer`, `confidence`, `blockers`, and target resource evidence.
- Explicit deny statements are preserved as `decision=denied` and matching allow records are marked `decision=denied_by_explicit_deny`.
- `sts:AssumeRole` expands visible target-role blast radius when both roles are present in the plan.
- Provider evaluators add provider decision bases and normalize scoped resources, conditions, explicit denies, permissions boundaries, SCPs, Azure deny assignments, GCP deny policies, Workload Identity, and Kubernetes RBAC scope before scoring.
- AWS, Azure, GCP, and Kubernetes evaluators now run a structured policy engine before effective-access selection when records include policy documents. The engine parses provider policy ASTs and evaluates principal, action, resource, and condition matches. It models explicit deny precedence, conditions, boundaries, inherited scope, trust, resource policies, and cross-account or workload identity constraints from AWS IAM statements, Azure RBAC/deny assignments, GCP IAM/deny/PAB/org policies, and Kubernetes RBAC rules.
- `fixtures/policies/provider-policy-examples.json` exercises boundary, SCP, session-policy, resource-policy, source-VPC-endpoint condition, cross-account, deny-assignment, inherited Azure scope, principal-access-boundary, GCP organization policy, Workload Identity, and Kubernetes service-account escalation cases without requiring a cloud account.
- Selected identity results emit `evaluation_order`, `policy_evaluation`, and `effective_access_model` for the chosen identity/resource/action decision. Azure, GCP, and Kubernetes expose provider-layer states comparable to AWS: deny controls, allow basis, resource policy or role/binding scope, conditions, inherited scope, provider-specific boundaries, and high-risk identity transitions.

## Network exposure

Target state:

- Replace broad exposure labels with typed ingress, egress, lateral, and control-plane path evidence.
- Record provider-specific blockers such as authorizers, API keys, WAF/firewall policy, private endpoints, service-mesh policy, route precedence, and deny rules.
- Infer public/internal/private state only from linked paths or explicit workload settings. Unrelated public resources must not expose unrelated workloads.

Implemented controls:

- Terraform and Kubernetes contexts emit typed `network_paths` with `path_type`, `entry`, `steps`, `confidence`, `blockers`, and `unknowns`.
- Provider evaluators build provider-specific resource graphs from structured resources before using explicit `network_graph`, `network_edges`, or inferred `steps`. Built edges carry `type`, `precedence`, `precedence_reason`, and the provider rule that selected them. Disconnected graphs block the path instead of trusting the exposure label.
- Inferred exposure records are emitted for directly classified workloads when no full hop sequence exists.
- Provider blockers include auth settings, API Gateway authorizers, API keys, WAF/firewall policies, public network disabled flags, internal-only endpoints, private endpoints, route/firewall adapter signals, NSG denies, and NetworkPolicy deny-all ingress.
- Network blockers carry an effect: `blocks`, `constrains`, or unknown. Scoring treats blockers as uncertainty instead of equivalent confirmed exposure.
- Lateral inference is bounded to linked security groups, target attachments, selectors, route/private-network bridges, and IAM network-control pivots.
- The effective exposure engine delegates network and IAM decisions to AWS, Azure, GCP, Kubernetes, and fallback provider evaluators before scoring.
- Provider evaluators emit `reachable`, `constrained`, `blocked`, `isolated`, or `unknown` decisions and carry blocker/unknown semantics from the provider layer into scoring.
- Provider network evaluators add decision bases for AWS source security groups/CIDRs, source VPC endpoint conditions, WAF/API authorizers, Azure access restrictions/NSG/WAF/private endpoints, GCP IAP/Cloud Armor/Private Service Connect/internal ingress, and Kubernetes NetworkPolicy/service-mesh/internal-ingress evidence. Golden resource-graph fixtures cover route precedence, deny-before-allow rule selection, private endpoint direction, and Kubernetes service-mesh authorization decisions.

## Terraform and artifact matching

Target state:

- Terraform plan JSON and rendered Kubernetes manifests are the release-gate inputs.
- Static Terraform source/HCL mode is advisory only.
- Artifact matching prefers image digests and exact image references, then repository/tag, then weaker names.
- CI, Helm, Kustomize, Docker, OCI, and registry metadata should feed artifact identity.
- Pipelines can pass one structured CI artifact manifest that maps SBOM path, image reference, image digest, registry reference, Git SHA, Helm value image, Kustomize image, and Terraform image output. Strict release gates can require digest-level identity, SBOM path, Git SHA, and a signature or attestation marker.
- A readiness report explains missing release evidence in direct terms.

Implemented controls:

- `--analysis-profile production` rejects Terraform source mode without `--terraform-plan` and requires Terraform plan JSON or rendered Kubernetes manifests.
- Artifact candidates include OCI image refs, Docker repo digests, GitHub Actions image hints, build metadata, Helm/Kustomize/Skaffold/Tilt/ko/Jib hints, Compose images, and scan-time aliases.
- `--artifact-manifest` imports CI artifact identity when SBOM tooling drops image or digest metadata.
- `artifact-manifest init` and `artifact-manifest validate` let CI create and check that manifest before scanning.
- `rendered-iac-plan` writes the Terraform, Helm, and Kustomize render commands expected before a release scan.
- `--mapping-out` records candidate source, strength, match method, match score, and mapping warnings.
- `--readiness-out` and `evidence-profile` report missing release identity, missing SBOM paths, missing or weak workload matches, missing network paths, missing identity paths, low-confidence network or identity evidence, external source coverage, query-family coverage, proven query-family coverage, and unrendered IaC gaps.
- Quality gates can enforce artifact match coverage, strong artifact identity coverage, mapping warning failures, readiness blockers, and readiness warnings.

## IDE integration

Target state:

- The extension should discover common local outputs, show whether the scan is advisory or release-gate, filter by baseline, and expose finding details without hiding the CLI contract.
- Extension helpers must have tests outside VS Code so the wrapper does not regress silently.
- Release-gate mode should pass the same source and deployment gates used in CI.
- It should generate plan files from the editor instead of requiring users to remember CLI options.

Implemented controls:

- `reachabilityAdvisor.profilePreset` exposes `advisory` and `release-gate` presets.
- Release-gate preset maps to `analysis-profile=production` and adds `--require-strong-source-for-critical`.
- The extension discovers common `reachability/` and `.reachability/` SBOM and Grype paths, filters diagnostics by tier and baseline, and opens selected finding evidence as JSON.
- The extension validates missing profile inputs before a scan, passes artifact manifests, and provides commands to generate SBOM and source-evidence plans.
- The evidence explorer webview shows finding cards, baseline state, source evidence, network paths, IAM context, effective path, scoring rationale, and raw evidence JSON from the last scan.
- Helper tests cover profile resolution, profile validation, plan command generation, path discovery, repeated path handling, tier filtering, and evidence explorer rendering.

## Scoring calibration

Target state:

- Benchmark snapshots cover expected tier distributions for public, internal, private, constrained, blocked, low-confidence, admin, sensitive, read-only, and no-role cases.
- Low-confidence IAM/network evidence remains visible, but it is not scored the same as confirmed exposure.
- Unknown network/IAM context ranks above confirmed internal/no-role context, below confirmed public or sensitive/admin context, and stays below urgent until stronger evidence resolves the uncertainty.
- Network blockers can reduce exposure points or cap priority until the effective path is proven.

Implemented controls:

- The scoring benchmark includes constrained network, blocked network, and low-confidence IAM cases.
- `scoring.dimensions[]` shows when exposure points were reduced by auth/WAF/firewall evidence or removed by a blocker.
- `scoring.gates[]` records caps for confirmed blockers, low-confidence network paths, low-confidence IAM effective access, weak source evidence, and the urgent gate.
