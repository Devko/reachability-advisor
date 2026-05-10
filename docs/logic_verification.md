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
- [ ] `attacker_controlled` findings include same-file input/entrypoint evidence or a direct handler-to-sink call path.
- [ ] `unknown_due_to_no_rule` findings are reviewed as rule coverage gaps, not safe states.
- [ ] Different-file input evidence is reported as weaker rationale, not overclaimed.

## Terraform reachability

- [ ] Terraform plan is generated with `terraform show -json` and handled as sensitive material.
- [ ] `--terraform-coverage-out` reports all resources.
- [ ] `visibility_gaps` are reviewed rather than treated as safe.
- [ ] Artifact match methods and scores are inspected for important findings.
- [ ] Fixture/sample coverage includes public, internal/lateral, private, and unknown exposure states when those states are in scope.
- [ ] Fixture/sample coverage includes admin, sensitive/critical, limited/read-only, and no linked IAM role states when those states are in scope.

## Developer output

- [ ] SARIF and diagnostics point to source files when available.
- [ ] PR summaries explain why a finding is high priority.
- [ ] The HTML graph shows high-priority findings linked to asset, code exposure, source, network, and IAM evidence.
- [ ] `compare` gates only new or regressed findings when historical backlog exists.

## Safety

- [ ] The tool does not call external services during scan.
- [ ] The tool does not emit `not_affected` for weak evidence.
- [ ] Policy exceptions are explicit and expiring.
