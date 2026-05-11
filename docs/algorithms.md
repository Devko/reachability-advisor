# Algorithms

Reachability Advisor ranks dependency vulnerabilities from four evidence streams: SBOM, vulnerability data, source reachability, and Terraform deployment context.

## Pipeline

```text
CycloneDX SBOMs
  + vulnerability intelligence (Grype JSON or normalized local JSON)
  + source roots
  + Terraform plan JSON
  + context JSON overrides, when needed
  + custom source rules, when needed
  -> SBOM artifact identity
  -> vulnerability/component matches
  -> source reachability evidence
  -> artifact-to-Terraform workload matches
  -> exposure / identity / data context
  -> score and tier
  -> remediation groups by artifact/component/version
  -> JSON/SARIF/diagnostics/Markdown/HTML/annotations/coverage/mapping
```

## SBOM acquisition model

The scanner consumes SBOMs; it does not generate them during scan. Use the `sbom-plan` command to generate reproducible command suggestions.

```bash
reachability-advisor sbom-plan \
  --artifact payments-api \
  --image ghcr.io/example/payments-api:1.8.2 \
  --source-root . \
  --ecosystem maven
```

SBOM requirements:

1. Generate one CycloneDX JSON SBOM per deployable artifact.
2. Prefer image/runtime SBOMs for release gates.
3. Use source/filesystem SBOMs for early PR and IDE feedback.
4. Preserve artifact identity metadata: image reference, digest, owner, and environment when available.

## Artifact identity extraction

For each SBOM, the loader builds artifact candidates from:

- `metadata.component.name`;
- `metadata.component.version`;
- `metadata.component.purl` or reference when present;
- metadata properties such as `container:image`, `oci:image:ref`, `artifact:reference`, and `reachability:artifact_ref`;
- external references such as `distribution`, `container-image`, and `vcs`;
- scan-time aliases from `--artifact-alias`.

All candidates appear in `--mapping-out` so reviewers can verify the mapping.

## Dependency matching

When `--vulns` points to Grype JSON, Reachability Advisor treats Grype's
`matches[]` as the scanner/database handoff. Each match is normalized to the
same vulnerability record shape used by local fixtures, with the Grype artifact
version recorded as the affected version. The advisor then verifies that record
against the supplied SBOM component before scoring it.

A vulnerability matches a component when one of these conditions is true:

1. exact package URL match;
2. package URL ecosystem and package name match, with namespace respected when supplied;
3. normalized component name equals normalized vulnerability package name.

Version filtering is conservative. If a vulnerability record provides `affected_versions`, the component version must be listed. If version data is missing, the finding remains visible with lower confidence.

## Source evidence

Source reachability states:

| State | Meaning |
|---|---|
| `absent` | Reserved for explicit evidence that a package is not present in analyzed source or runtime scope. |
| `unknown_due_to_no_rule` | Component appears in the SBOM, but no package-specific source rule exists; generic import evidence was also not observed. |
| `package_present` | Component appears in the SBOM, but no stronger source evidence was found. |
| `dependency_reachable` | CycloneDX dependency graph links the component to an imported parent dependency, or a package-manager manifest declares the component. This is indirect dependency evidence, not import or vulnerable API evidence. |
| `imported` | Source imports/requires/uses the package. |
| `function_reachable` | Source imports the package and contains usage patterns associated with vulnerable APIs or high-risk library functions. |
| `attacker_controlled` | The same function contains risky usage and input/entrypoint evidence, or a bounded static handler-to-sink call path links entrypoint code to the vulnerable sink. |

The default analyzer builds one source index per artifact for Python, JavaScript/TypeScript, Java, and Go. Python functions are extracted with the standard-library `ast` module; other languages use conservative syntax patterns. The analyzer can promote same-function input/sink evidence and bounded handler-to-sink call paths to `attacker_controlled`. It does not model full interprocedural dataflow, dependency injection, async framework lifecycles, reflection, or framework-specific sanitizers.

Rules are visible in `src/reachability_advisor/source.py`. Additional project-specific rules can be supplied with `--reachability-rules`. Use `export-semgrep-rules` to generate starter Semgrep YAML from built-in and custom rules. Use `--source-evidence-in` to import higher-confidence evidence from Reachability Advisor JSON, Semgrep JSON including native `dataflow_trace`, CodeQL/SARIF data-flow paths, plain SARIF, or govulncheck JSONL.

Built-in high-risk source rules currently cover common Java, Node, Python, and Go evidence:

- Java/Maven import and sink patterns, including Log4j, Jackson, SnakeYAML, Commons Text, JJWT, XML parsing, archive extraction, and Spring Web entrypoints;
- Node/npm import and route/request patterns, including lodash, axios, jsonwebtoken, EJS, Handlebars, js-yaml, xml2js, archive extraction, Express, and NestJS on Express;
- Python/PyPI import and handler patterns, including requests, PyYAML, Jinja2, PyJWT, lxml, Django, FastAPI, Chainlit, and aiohttp;
- Go import and sink evidence for common JWT/YAML packages plus generic import evidence.

The JSON output includes both the machine state and a human label. The HTML report uses the labels `request-controlled path`, `reachable vulnerable API`, `dependency evidence`, `import observed`, `SBOM only`, and `no source rule`.

`--source-coverage-out` writes source coverage metrics: source files and package-manager manifests scanned, skipped files, evidence states by artifact, external evidence records consumed, and the fraction of findings with dependency-graph, manifest, import, vulnerable API, or request-controlled evidence.

## Remediation grouping

Individual scanner findings are preserved. JSON and Markdown outputs also include a package-level remediation queue. Findings are grouped by artifact, component name, component version, and package URL. The group keeps the highest reachability, highest score, advisory IDs, and the highest fixed version reported by vulnerability intelligence.

## Artifact-to-Terraform matching

Terraform evidence is derived from a local `terraform show -json` plan. Plan mode is the expected mode for release gates. The analyzer is manifest-driven:

1. Parse every planned resource from `planned_values` and `resource_changes`.
2. Classify the resource provider: AWS, Azure, GCP, Kubernetes, or unknown.
3. Classify the resource category if it appears in `TERRAFORM_COVERAGE_MANIFEST`: `workload`, `exposure`, `identity`, `sensitive_data`, or supporting context.
4. Extract likely container image or artifact references from provider-specific and generic fields.
5. Match those references against SBOM artifact candidates.
6. Build a bounded network graph from ingress, load balancer, target attachment, gateway backend, service, security-group, private-network, and provider bridge edges.
7. Infer exposure from graph paths linked to the matched workload.
8. Infer direct workload identity privilege and IAM impact classes from IAM/role/policy resources, including targeted sensitive resources where visible. Unrelated provider-level IAM is not applied to every workload.
9. Emit coverage and mapping reports.

Helm and kubectl wrapper resources are classified as Kubernetes supporting
resources, but they still emit `opaque_manifest_wrapper` visibility gaps because
the rendered child manifests are where workload images, exposure, and RBAC live.

## Rendered Kubernetes manifests

`--kubernetes-manifest` accepts rendered YAML or JSON files, or directories that contain them. This input is for manifests after Helm, Kustomize, or another renderer has expanded templates. It is static and local; the scanner does not query a live cluster.

The analyzer extracts:

- workloads: Deployment, StatefulSet, DaemonSet, ReplicaSet, Pod, Job, and CronJob;
- network entrypoints: Service and Ingress objects linked to workloads by selectors;
- RBAC: Role, ClusterRole, RoleBinding, and ClusterRoleBinding objects linked to workload service accounts.

`LoadBalancer`, `NodePort`, and public Ingress objects produce `public` exposure. `ExternalName` services produce `external` exposure. `ClusterIP` services produce `internal` exposure. Workloads without a Service or Ingress stay `private`. `--kubernetes-infer-lateral` can add an internal path from a public Kubernetes entrypoint to internal services; keep it disabled unless that lateral assumption matches the cluster trust model.

Kubernetes RBAC uses the same context fields as Terraform IAM: `privilege`, `iam_impacts`, and `criticality`. `cluster-admin` maps to `admin_control`; secret reads map to `data_access`; workload mutation maps to `compute_control`; service, ingress, and network-policy mutation maps to `network_control`; role and binding mutation maps to `iam_escalation`.

Match scoring:

| Method | Score | Confidence | Meaning |
|---|---:|---|---|
| `exact-reference` | 100 | high | SBOM candidate exactly equals Terraform reference. |
| `digest` | 96 | high | Image digests match. |
| `repository-tag` | 90 | high | Repository and tag match. |
| `repository` | 72 | medium | Repository matches without exact tag/digest evidence. |
| `repository-leaf` | 58 | low/medium | Last repository segment matches. |
| `name` / `artifact-name` | 45-52 | low | Weak name-only match. |

Exposure inference is deliberately linked instead of provider-wide. A public load balancer, API gateway, or ingress in the same Terraform plan does not automatically make every matched artifact public.

Exposure tiers:

| Tier | Meaning | Examples |
|---|---|---|
| `public` | Direct internet entrypoint. | Public IP assignment, public security group, internet-facing load balancer or application gateway, API gateway, CDN, unauthenticated Lambda function URL, public Cloud Run/Cloud Functions invoker, Kubernetes LoadBalancer/Ingress. |
| `external` | Internet-routable or external-source access, but not open to the whole internet. | Security group or firewall restricted to a specific public CIDR, Cloud Run ingress that allows external traffic without public invoker evidence. |
| `internal` | Private-network or lateral-movement path is visible. | Private CIDR/security-group ingress linked to the workload, internal load balancer or application gateway, Kubernetes ClusterIP linked by name or selector, VPC/VNet peering, VPN, transit gateway, ExpressRoute, or Interconnect. |
| `private` | Workload has private network attachment or public access is disabled, but no bridge or ingress path is visible. | Private subnet-only VM, VPC-attached Lambda, Azure App Service with public network access disabled and no detected VNet bridge. |
| `unknown` | The plan does not contain enough linked evidence. | Opaque module output, rendered Helm child resources unavailable, unsupported resource type. |

The graph walks directed paths such as internet -> public security group -> workload, public load balancer -> target group -> target attachment -> workload, Azure application gateway -> backend pool -> network interface -> VM, GCP forwarding rule -> backend service -> network endpoint group -> Cloud Run service, Kubernetes Service/Ingress selector -> workload, and security group -> security group -> workload. Edges can cap exposure: a direct internet edge remains `public`, while a path that requires compromising one reachable workload before reaching another is capped at `internal`.

IAM is combined with network reachability in three ways. First, workload identity references such as task roles, instance profiles, service accounts, managed identities, and role bindings add `limited`, `sensitive`, or `admin` privilege evidence to the matched artifact. Second, policies are classified into impact classes: `data_access`, `network_control`, `iam_escalation`, `compute_control`, and `admin_control`. Limited-looking permissions such as `secretsmanager:GetSecretValue`, `ec2:AuthorizeSecurityGroupIngress`, `iam:PassRole`, or workload update permissions can raise context criticality when the workload is reachable. Third, a network-reachable workload with `admin_control`, `network_control`, or `iam_escalation` can create an internal provider-control-plane pivot, raising private same-provider workloads to `internal` when the compromised identity can alter routes, security groups, policies, or attachments.

IAM criticality is network-aware. Critical IAM impacts on public, external, or internal workloads raise context `criticality` to `high`; the same impact on a private-only workload raises it to `medium` because the blast radius is serious but the entry path is weaker. Targeted sensitive resources are recorded as evidence when Terraform exposes both the policy resource ARN/name and the sensitive resource. Identity resource names alone are not treated as permission evidence.

Supported public links include AWS ECS services through public security groups or public load balancer target groups and target attachments, AWS Lambda function URLs, Azure application gateway or load balancer backend pool paths, GCP forwarding rule/backend service/NEG paths, GCP Cloud Run and Cloud Functions public invoker grants, Azure Container Apps external ingress, and Kubernetes Service/Ingress names or selectors. Provider-bridge lateral inference is limited to bridge resources such as peering, VPN, transit, ExpressRoute, and Interconnect; unrelated private resources do not make every workload internal.

This is deployment context, not exploit confirmation. Unsupported resources and opaque rendered-manifest wrappers are reported as gaps.

## Context evidence

Terraform is the primary source for deployment context. Context JSON can override or enrich Terraform-derived fields such as owner, environment, or criticality.

```json
{
  "artifacts": {
    "payments-api": {
      "environment": "prod",
      "exposure": "public",
      "privilege": "sensitive",
      "criticality": "high",
      "iam_impacts": ["data_access"],
      "owner": "@team-payments",
      "confidence": "high"
    }
  }
}
```

Missing context is `unknown`; it is not isolation evidence.

## Scoring

The score is explainable and capped at 100. It starts from vulnerability severity, then adds exploit likelihood, source evidence, dependency scope, network exposure, environment, and the strongest context impact:

```text
score = severity
      + known exploited bonus
      + EPSS likelihood bonus
      + source reachability points
      + scope adjustment
      + exposure points
      + environment points
      + max(privilege impact, IAM impact, asset criticality)
```

Context impact is not fully additive. `admin`, `sensitive`, `data_access`, `network_control`, `iam_escalation`, and high asset criticality can describe the same blast radius, so the scorer takes the strongest one instead of stacking all of them.

Priority gates prevent weakly actionable findings from crossing high-severity thresholds only because several small signals add up:

- dev/test dependencies without source usage are capped below `medium`;
- weak source evidence (`SBOM only`, `no source rule`, or `absent`) is capped below `high` unless the vulnerability is known exploited or has high EPSS; even then it stays below `urgent` until source usage is proven;
- dependency-graph evidence is capped below `high` unless it is public/external with critical context, and below `urgent` until direct vulnerable API usage or stronger exploit intelligence exists;
- import-only evidence is capped below `high` unless it is public/external and has critical context;
- private/no-ingress findings without exploit signal or critical context are capped below `high`;
- `urgent` requires known exploitation, high EPSS, a request-controlled public/external path, or critical reachable context.

The default model is meant to separate these common cases:

| Example | Expected priority |
|---|---|
| Public request-controlled vulnerable code path plus sensitive/admin context | `urgent` |
| Public request-controlled vulnerable code path without critical context | `high` |
| Internal/lateral request-controlled vulnerable code path | `high` when severity is high enough |
| Function/API usage with no proven attacker-controlled path | usually `medium` |
| Import-only, SBOM-only, or no-rule evidence | usually `low` or `medium`, depending on severity and context |
| Private/no-ingress workload without exploit signal or critical context | below `high` |

Default tiers:

| Tier | Threshold |
|---|---:|
| urgent | 85 |
| high | 65 |
| medium | 40 |
| low | 20 |
| informational | 0 |

## Mapping report

`--mapping-out` is the primary logic-verification artifact. It shows:

- every SBOM artifact;
- artifact candidates used for matching;
- source root status;
- Terraform match method/score;
- mapping warnings;
- Terraform coverage summary.

## Terraform coverage metrics

| Metric | Meaning |
|---|---|
| `resource_accounting_coverage` | Every resource observed in the plan appears in the coverage report. |
| `semantic_classification_coverage` | Fraction of observed resources whose type is in the declared semantic manifest. |
| `artifact_match_coverage` | Fraction of SBOM artifacts matched to at least one Terraform workload resource. |
| `visibility_gaps` | Unsupported or unclassified resources that require human review or future rule work. |

## Guardrails

- The tool does not emit `not_affected` status.
- Weak source or Terraform evidence never causes automatic suppression.
- Test/dev scope demotion is reduced if attacker-controlled usage is observed.
- Exceptions must be explicit, can expire, and are visible in the finding rationale.
- Unsupported Terraform resources are never treated as safe.
