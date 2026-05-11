# Logic Verification Checklist

Use this checklist when reviewing a new repository, fixture pack, or release candidate.

## SBOM acquisition

- [ ] One SBOM exists per deployable artifact.
- [ ] Release gates use image/runtime SBOMs when a container image is deployed.
- [ ] IDE/PR workflows may use source/filesystem SBOMs for early feedback.
- [ ] SBOM metadata includes artifact name, version, and preferably image reference or digest.
- [ ] `sbom-plan` was run for projects without a documented SBOM generation command.

## SBOM-to-vulnerability matching

- [ ] Components have package URLs where possible.
- [ ] Vulnerability data includes package name, ecosystem or PURL, severity, and fixed versions when known.
- [ ] Version-matching behavior is tested for affected and unaffected versions.

## Source reachability

- [ ] Source roots are supplied by artifact name.
- [ ] Built-in rules or custom rules cover the package family under test.
- [ ] `attacker_controlled` findings include same-function input/sink evidence or a bounded handler-to-sink call path.
- [ ] `dependency_reachable` findings include a CycloneDX dependency path and an imported parent dependency.
- [ ] `--source-coverage-out` is reviewed for files scanned, skipped files, evidence states, and external evidence counts.
- [ ] Semgrep, SARIF, or govulncheck evidence imported through `--source-evidence-in` has component, package URL, or vulnerability selectors. Artifact can narrow a match, but is not enough by itself.
- [ ] `unknown_due_to_no_rule` findings are reviewed as rule coverage gaps.
- [ ] Different-file input evidence is reported as weaker rationale, not overclaimed.

## Terraform reachability

- [ ] Terraform plan is generated with `terraform show -json` and handled as sensitive material.
- [ ] `--terraform-coverage-out` reports all resources.
- [ ] `visibility_gaps` are reviewed.
- [ ] Artifact match methods and scores are inspected for important findings.
- [ ] Fixture/sample coverage includes public, internal/lateral, private, and unknown exposure states when those states are in scope.
- [ ] Fixture/sample coverage includes admin, sensitive/critical, limited/read-only, and no linked IAM role states when those states are in scope.

## Outputs

- [ ] SARIF and diagnostics point to source files when available.
- [ ] PR summaries explain why a finding is high priority.
- [ ] The HTML graph shows high-priority findings linked to asset, code exposure, source, network, and IAM evidence.
- [ ] `source-coverage.json`, `terraform-coverage.json`, and `mapping.json` are retained as audit artifacts.
- [ ] `compare` gates only new or regressed findings when historical backlog exists.

## Scoring sanity

- [ ] SBOM-only and no-source-rule findings do not become high without known exploitation or high EPSS.
- [ ] Dependency-graph-only findings stay below high unless public/external critical context or exploit intelligence exists.
- [ ] Import-only findings stay below high unless they are public/external and have critical context.
- [ ] Internal/lateral request-controlled findings can become high when vulnerability severity is high enough.
- [ ] Private/no-ingress findings stay below high unless there is an exploit signal or critical context.
- [ ] Context scoring uses the strongest privilege/IAM/criticality impact rather than stacking overlapping labels.

## Safety

- [ ] The tool does not call external services during scan.
- [ ] The tool does not emit `not_affected` for weak evidence.
- [ ] Policy exceptions are explicit and expiring.
