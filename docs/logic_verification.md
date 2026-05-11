# Logic Verification Checklist

Use this checklist when reviewing a new repository, fixture pack, or release candidate.

## SBOM acquisition

- [ ] One SBOM exists per deployable artifact.
- [ ] Release gates use image/runtime SBOMs when a container image is deployed.
- [ ] IDE/PR workflows may use source/filesystem SBOMs for early feedback.
- [ ] SBOM metadata includes artifact name, version, and preferably image reference or digest.
- [ ] CI, Dockerfile, Helm, Kustomize, or Terraform module image hints are preserved as SBOM properties when image metadata is not otherwise available.
- [ ] `sbom-plan` was run for projects without a documented SBOM generation command.

## SBOM-to-vulnerability matching

- [ ] Components have package URLs where possible.
- [ ] Vulnerability data includes package name, ecosystem or PURL, severity, and fixed versions when known.
- [ ] Version-matching behavior is tested for affected and unaffected versions.

## Source reachability

- [ ] Source roots are supplied by artifact name.
- [ ] Built-in rules or custom rules cover the package family under test.
- [ ] `attacker_controlled` findings include same-function input/sink evidence or a bounded handler-to-sink call path.
- [ ] `dependency_reachable` findings include a CycloneDX dependency path from an imported parent dependency or a package-manager manifest declaration.
- [ ] `--source-coverage-out` is reviewed for source files, package-manager manifests, skipped files, evidence states, dependency-graph evidence, manifest evidence, and external evidence counts.
- [ ] `source_rule_coverage`, `findings_with_rule_gap`, `findings_with_weak_source_evidence`, and `external_evidence_usable_ratio` are reviewed before treating the source result as strong.
- [ ] CI uses `--require-external-source-evidence` and `--min-external-evidence-usable-ratio` when Semgrep, CodeQL, or govulncheck output is required for release confidence.
- [ ] `source_reachability.diagnostics[]` and `source_diagnostic_counts` are reviewed before trusting weak or unknown source states.
- [ ] Semgrep, CodeQL/SARIF, or govulncheck evidence imported through `--source-evidence-in` has component, package URL, or vulnerability selectors. Artifact can narrow a match, but is not enough by itself.
- [ ] When several external source records match, the selected record is explainable by reachability state, confidence, selector specificity, then provider trust.
- [ ] `external_evidence_selector_diagnostics` has no unexpected artifact-only or unscoped records.
- [ ] Semgrep `dataflow_trace` and CodeQL `codeFlows` evidence is reviewed as external analyzer evidence, not as a claim made by the built-in source heuristic.
- [ ] `unknown_due_to_no_rule` findings are reviewed as rule coverage gaps.
- [ ] Different-file input evidence is reported as weaker rationale, not overclaimed.

## Terraform reachability

- [ ] Terraform plan is generated with `terraform show -json` and handled as sensitive material.
- [ ] `--terraform-coverage-out` reports all resources.
- [ ] `visibility_gaps` are reviewed.
- [ ] Artifact match methods and scores are inspected for important findings.
- [ ] Artifact match proof includes candidate source and strength for important findings, especially when no image digest is present.
- [ ] CI uses `--min-artifact-match-coverage`, `--min-strong-artifact-identity-coverage`, and `--fail-on-mapping-warnings` after artifact identity metadata is stable.
- [ ] Fixture/sample coverage includes public, internal/lateral, private, and unknown exposure states when those states are in scope.
- [ ] Fixture/sample coverage includes admin, sensitive/critical, limited/read-only, and no linked IAM role states when those states are in scope.
- [ ] `context.iam_capabilities` shows the concrete action and impact behind important IAM labels, especially secret reads, role passing, network mutation, and workload mutation.
- [ ] Critical IAM capabilities include resource scope, condition keys, effective risk, and risk multiplier when the provider policy exposes them.
- [ ] Synthetic no-cloud plan fixtures are used only for scanner E2E coverage; real release gates still use repository-generated `terraform show -json` output.

## Kubernetes manifests

- [ ] Rendered YAML/JSON is supplied through `--kubernetes-manifest` when workloads are deployed through Kubernetes, Helm, or Kustomize.
- [ ] `--kubernetes-coverage-out` is reviewed for workload, Service, Ingress, RBAC, and artifact-match coverage.
- [ ] `--kubernetes-infer-lateral` is enabled only when public-to-internal cluster lateral movement is a valid assumption for the environment.
- [ ] RBAC-derived `admin`, `sensitive`, and `limited` privilege states are checked against the rendered Role/ClusterRole bindings.
- [ ] Rendered NetworkPolicy resources are reviewed when Service or Ingress exposure appears inconsistent with expected isolation.

## Outputs

- [ ] SARIF and diagnostics point to source files when available.
- [ ] PR summaries explain why a finding is high priority.
- [ ] The HTML graph shows high-priority findings linked to asset, code exposure, source, network, and IAM evidence.
- [ ] Large HTML reports are reviewed first with the default top-risk/top-per-asset view, then expanded when investigating full backlog.
- [ ] `evidence-graph.json` is retained when generated and its asset, network, IAM, and code edges support the HTML graph.
- [ ] `evidence-graph.json` includes typed `network_nodes` and `network_edges` for important ingress and lateral paths.
- [ ] `source-coverage.json`, `terraform-coverage.json`, `kubernetes-coverage.json`, and `mapping.json` are retained as audit artifacts when generated.
- [ ] `scan --baseline-out` is produced on the default branch and `compare --baseline` gates only new or worsened findings in pull requests.

## Scoring sanity

- [ ] SBOM-only and no-source-rule findings do not become high without known exploitation or high EPSS.
- [ ] Dependency-graph-only findings stay below high unless public/external critical context or exploit intelligence exists.
- [ ] Import-only findings stay below high unless they are public/external and have critical context.
- [ ] Internal/lateral request-controlled findings can become high when vulnerability severity is high enough.
- [ ] Private/no-ingress findings stay below high unless there is an exploit signal or critical context.
- [ ] Context scoring uses the strongest privilege/IAM/criticality impact rather than stacking overlapping labels.
- [ ] Each high or urgent finding has `scoring.dimensions[]` and `scoring.gates[]` that explain the final score without relying on prose rationale.
- [ ] `scripts/validate_scoring_benchmark.py` passes after scoring-weight or gate changes.

## Safety

- [ ] The tool does not call external services during scan.
- [ ] The tool does not emit `not_affected` for weak evidence.
- [ ] Policy exceptions are explicit and expiring.
