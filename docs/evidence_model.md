# Evidence Model

Reachability Advisor separates evidence by what it can actually prove.

## Dependency Evidence

Dependency evidence comes from an SBOM plus vulnerability intelligence. It proves that a package and version were reported for an artifact. It does not prove the vulnerable code path is used.

Example: `express@4.17.1` in `demo-api` with `GHSA-demo-express`.

## Source Evidence

Source evidence comes from built-in source analysis or external analyzers such as Semgrep, CodeQL/SARIF, and govulncheck. It can show import evidence, dependency graph evidence, reachable functions, or handler-to-sink paths.

Example: a Semgrep trace showing `req.query.q -> res.send`.

## Runtime Evidence

Runtime evidence comes from DAST-style scanner output. States are:

- `not_observed`
- `endpoint_observed`
- `vulnerability_observed`
- `authenticated_observed`
- `unauthenticated_observed`

Runtime evidence is not source evidence. A DAST URL finding with no source mapping keeps source reachability weak and records `source mapping unavailable`.

## Deployment Evidence

Deployment evidence comes from Terraform plan/source and rendered Kubernetes manifests. Terraform plan and rendered manifests are the release-gate path. Static Terraform source mode is advisory because modules, dynamic expressions, provider defaults, and rendered Helm/Kustomize output may be missing.

## Posture Evidence

Posture evidence comes from imported CSPM/configuration scanner output or native checks over local Terraform plan and rendered Kubernetes evidence. It records scanner/tool, rule, provider, affected resource, expected state, actual state, IaC location when present, blockers, unknowns, and remediation.

Posture evidence is configuration context. It does not prove source reachability, runtime exploitability, or causality with a dependency/SAST/DAST finding. It can raise confidence in deployment exposure or blast radius when it maps to the same workload, identity, ingress, or data resource.

Example: `CKV_AWS_20` on `aws_s3_bucket.public` with expected `private bucket ACL` and actual `public-read ACL`.

## Network And IAM Evidence

Network evidence describes typed ingress, internal, lateral, private, and unknown paths. IAM evidence describes effective access signals, deny/allow decisions, identity scope, conditions, blockers, and confidence.

Unknowns and blockers are first-class. Missing evidence is never treated as safe.

## Correlation Evidence

Correlation links existing findings without merging them.

Examples:

- SAST XSS on `/search` plus DAST XSS at `/search?q=` creates `sast_dast_route_match`.
- A DAST finding and a dependency finding on the same artifact creates weak `sca_dast_same_artifact`.
- Same-artifact-only correlation is context, not causation.

## Examples

1. Dependency vulnerability with no source usage: package present, weak source, capped priority unless exploit intelligence or critical context exists.
2. Dependency vulnerability with source usage and public deployment: source and network evidence can raise priority.
3. SAST finding with data flow but no deployment context: static evidence is strong, deployment exposure remains unknown.
4. DAST finding with runtime evidence but unknown source: runtime can be high priority, source remains unknown.
5. SAST+DAST correlated route: confidence rises because static and runtime evidence point at the same route/CWE.
6. DAST unmapped to artifact: finding stays visible with an artifact-mapping visibility gap.
7. CSPM public ingress on the same workload as a dependency finding: deployment confidence rises, but the CSPM finding remains independently fixable.
