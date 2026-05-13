# Algorithms

Reachability Advisor scores dependency vulnerabilities from SBOM, vulnerability, source-reachability, and deployment-context evidence.

## Pipeline

```text
CycloneDX SBOMs
  + vulnerability intelligence (Grype JSON, OSV-style JSON, or normalized local JSON)
  + source roots
  + Terraform plan JSON
  + CI artifact manifest, when SBOM metadata lacks image identity
  + context JSON overrides, when needed
  + custom source rules, when needed
  -> SBOM artifact identity
  -> vulnerability/component matches
  -> source reachability evidence
  -> artifact-to-Terraform workload matches
  -> exposure / identity / data context
  -> effective exposure graph
  -> score and tier
  -> remediation groups by artifact/component/version
  -> JSON/SARIF/diagnostics/Markdown/HTML/annotations/coverage/mapping
  -> optional real-app benchmark snapshot regression checks
```

## Effective exposure graph

Every finding is normalized into one path:

```text
asset -> network path -> identity -> reachable code/package -> vulnerability -> score
```

This path is the per-finding evidence model. The separate network, IAM, code, and vulnerability arrays remain for reporting and debugging.

Each effective edge records:

- `evidence_layer`: `sbom`, `source`, `external_analyzer`, `terraform`, `kubernetes`, `iam`, `context`, or `scoring`;
- `origin_layer`: where the edge came from when it differs from the semantic layer, for example IAM derived from Terraform;
- `evidence_source`: the concrete rule, record, analyzer, path, or scoring model that produced the edge;
- `confidence`: `high`, `medium`, or `low`;
- `provider` and `language`, when known;
- `blockers`: concrete constraints such as IAM conditions, private endpoints, network policy denies, or auth gates;
- `unknowns`: missing evidence that prevents stronger conclusions.

The graph is evidence-first. A high score must be traceable from the score node back through the vulnerable package, source evidence, identity, and network path to the asset. Missing network, identity, or source evidence is recorded as `unknowns`; it is not proof of safety.

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
- CI, Dockerfile, Helm, Kustomize, and Terraform-module output hints when they are preserved as SBOM properties such as `github:workflow:image`, `dockerfile:image`, `helm:values:image`, `kustomize:image`, or `terraform:module_output:image`;
- CI artifact manifest entries supplied with `--artifact-manifest`, including image references, digests, registry refs, Git SHA, Helm values image, Kustomize image, Terraform image output, and SBOM path;
- scan-time aliases from `--artifact-alias`.

All candidates appear in `--mapping-out` with their source and strength. Strong candidates are image digests, exact image references, and repository/tag references. Weak candidates such as artifact names and repository leaf names remain usable, but the selected Terraform match records the proof chain in `match_proof`.

## Dependency matching

When `--vulns` points to Grype JSON, Reachability Advisor treats Grype's
`matches[]` as the scanner/database handoff. Each match is normalized to the
same vulnerability record shape used by local fixtures, with the Grype artifact
version recorded as the affected version. The advisor then verifies that record
against the supplied SBOM component before scoring it.

The normalized vulnerability record preserves source attribution. Grype, OSV-style input, and local JSON can carry severity, CVSS, EPSS, CISA KEV, VEX status, fix state/versions, references, source records, and timestamps. The scanner uses the top-level compatibility fields for scoring (`epss`, `known_exploited`, `fixed_versions`) and writes the complete source-attributed record under `vulnerability.intelligence`.

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

The default analyzer builds one source index per artifact for Python, JavaScript/TypeScript, Java, and Go. Python functions are extracted with the standard-library `ast` module; other languages use conservative syntax patterns. The analyzer can promote same-function input/sink evidence and bounded handler-to-sink call paths to `attacker_controlled`. It does not model full interprocedural dataflow, dependency injection, async framework lifecycles, reflection, or framework-specific sanitizers. Treat this as advisory fallback evidence.

Rules are visible in `src/reachability_advisor/source.py`. Additional project-specific rules can be supplied with `--reachability-rules`. Use `export-semgrep-rules` to generate starter Semgrep YAML from built-in and custom rules. Use `--source-evidence-in` to import evidence from Reachability Advisor JSON, Semgrep JSON including native `dataflow_trace`, CodeQL/SARIF data-flow paths, plain SARIF, or govulncheck JSONL.

When multiple source evidence providers match the same finding, the scanner picks the strongest record by reachability state, confidence, selector specificity, then provider precedence. Exact package URL or vulnerability selectors beat package-name-only selectors. CodeQL, Semgrep, govulncheck, and native Reachability Advisor evidence are preserved as provider names in `source_reachability.evidence_source`, `source-coverage.json`, and the evidence graph.

External source evidence must include a component/package, package URL, or vulnerability selector. Artifact-only records are retained for diagnostics but do not upgrade findings, because artifact names can only narrow a dependency match. `source-coverage.json` reports unmatchable external records under `external_evidence_selector_diagnostics`.

Use `--analysis-profile production` for release gates. It requires external source evidence, usable selectors, rendered deployment evidence from `--terraform-plan` or `--kubernetes-manifest`, and external analyzer coverage for critical findings. For maintained package families, the evidence must also include the relevant `query_family` or `query_families` metadata, for example `http-client`, `logging`, or `deserialization`. A generic Semgrep or CodeQL record is not enough for a critical finding when the package maps to a maintained query family. The gate also fails when critical findings only have dependency-level or weaker source evidence. The default `advisory` profile keeps built-in source rules available for local development and early pull requests.

Use `source-evidence-pack` to write the maintained rules and query packs. The pack includes Semgrep rules per package family plus CodeQL suites for the upstream query ids used by each family. Checked-in vulnerable sample apps and pinned public repository commits under `fixtures/source-vulnerable-apps/` define the coverage target; tests require the maintained family rules to match every expected local true-positive sample. Production gates require the imported evidence to name the relevant query family and that family must be in the proven query-family list. Use `source-evidence-plan` to generate the analyzer handoff. Pass `--language` for CodeQL command generation. Supported language profiles are JavaScript/TypeScript, Java/Kotlin, Python, and Go; Go plans also include `govulncheck`. Without a supported language or package-manager hint, the command emits only the generic Semgrep starter workflow.

```bash
reachability-advisor source-evidence-plan \
  --source-root . \
  --language python \
  --out-md reachability/source-evidence-plan.md \
  --out-json reachability/source-evidence-plan.json
```

Built-in high-risk source rules currently cover common Java, Node, Python, and Go evidence:

- Java/Maven import and sink patterns, including Log4j, Jackson, SnakeYAML, Commons Text, JJWT, XML parsing, archive extraction, and Spring Web entrypoints;
- Node/npm import and route/request patterns, including lodash, axios, jsonwebtoken, EJS, Handlebars, js-yaml, xml2js, archive extraction, Express, and NestJS on Express;
- Python/PyPI import and handler patterns, including requests, PyYAML, Jinja2, PyJWT, lxml, Django, FastAPI, Chainlit, and aiohttp;
- Go import and sink evidence for common JWT/YAML packages plus generic import evidence.

The JSON output includes both the machine state and a human label. The HTML report uses the labels `request-controlled path`, `reachable vulnerable API`, `dependency evidence`, `import observed`, `SBOM only`, and `no source rule`.

`--source-coverage-out` writes source coverage metrics: source files and package-manager manifests scanned, skipped files, evidence states by artifact, source diagnostic counts, external evidence records consumed, external evidence provider counts, package-specific rule coverage, rule gaps, weak-source evidence counts, critical package coverage, critical query-family coverage, critical proven query-family coverage, and the fraction of findings with dependency-graph, manifest, import, vulnerable API, or request-controlled evidence.

## Remediation grouping

Individual scanner findings are preserved. JSON and Markdown outputs also include a package-level remediation queue. Findings are grouped by artifact, component name, component version, and package URL. The group keeps the highest reachability, highest score, advisory IDs, and the highest fixed version reported by vulnerability intelligence.

## Artifact-to-Terraform matching

Terraform evidence is derived from a local `terraform show -json` plan. Use plan mode for release gates. The analyzer is manifest-driven:

1. Parse every planned resource from `planned_values` and `resource_changes`.
2. Classify the resource provider: AWS, Azure, GCP, Kubernetes, or unknown.
3. Classify the resource category if it appears in `TERRAFORM_COVERAGE_MANIFEST`: `workload`, `exposure`, `identity`, `sensitive_data`, or supporting context.
4. Extract likely container image or artifact references from provider-specific and generic fields.
5. Match those references against SBOM artifact candidates and preserve candidate source/strength in the match proof.
6. Build a bounded network graph from ingress, load balancer, target attachment, gateway backend, service, security-group, private-network, and provider bridge edges.
7. Infer exposure from graph paths linked to the matched workload. The emitted context includes typed `network_paths` with path type, entry class, provider, confidence, steps, blocker/constraint evidence, and unknowns where visible. Provider evaluators can also consume `network_graph` or `network_edges` records and solve the path from entry to workload before applying blockers.
8. Build effective-access records per matched workload identity, resource/action, policy layer, allow-or-deny effect, decision, decision basis, impact, scope, condition keys, target resources, confidence, and blockers. When structured policy documents are attached to a record, the provider policy engine evaluates those documents before provider selection. Matching explicit denies mark allow records as `denied_by_explicit_deny`. Provider evaluators then select the effective identity/resource/action record with provider-specific deny precedence and emit a normalized authorization model for scoring.
9. Infer direct workload identity privilege and IAM impact classes from IAM/role/policy resources, including targeted sensitive resources where visible. Unrelated provider-level IAM is not applied to every workload.
10. Emit coverage and mapping reports.

Helm and kubectl wrapper resources are classified as Kubernetes supporting
resources, but they still emit `opaque_manifest_wrapper` visibility gaps because
the rendered child manifests are where workload images, exposure, and RBAC live.

## Rendered Kubernetes manifests

`--kubernetes-manifest` accepts rendered YAML or JSON files, or directories that contain them. This input is for manifests after Helm, Kustomize, or another renderer has expanded templates. It is static and local; the scanner does not query a live cluster.

The analyzer extracts:

- workloads: Deployment, StatefulSet, DaemonSet, ReplicaSet, Pod, Job, and CronJob;
- network entrypoints: Service and Ingress objects linked to workloads by selectors;
- RBAC: Role, ClusterRole, RoleBinding, and ClusterRoleBinding objects linked to workload service accounts.

`LoadBalancer`, `NodePort`, and public Ingress objects produce `public` exposure. `ExternalName` services produce `external` exposure. `ClusterIP` services produce `internal` exposure. Workloads without a Service or Ingress stay `private`. If selected rendered `NetworkPolicy` resources control ingress and none of them contains an allow rule, Service/Ingress exposure is overridden to `private`. `--kubernetes-infer-lateral` can add an internal path from a public Kubernetes entrypoint to internal services; keep it disabled unless that lateral assumption matches the cluster trust model.

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

The graph walks directed paths such as internet -> public security group -> workload, public load balancer -> target group -> target attachment -> workload, Azure application gateway -> backend pool -> network interface -> VM, GCP forwarding rule -> backend service -> network endpoint group -> Cloud Run service, Kubernetes Service/Ingress selector -> workload, and security group -> security group -> workload. Edges can cap exposure: a direct internet edge remains `public`, while a path that requires compromising one reachable workload before reaching another is capped at `internal`. The evidence graph also emits typed `network_nodes` and `network_edges` so downstream tools can inspect load balancers, gateways, security boundaries, private-network hops, Kubernetes network objects, workloads, and asset endpoints without parsing path strings.

Route tables, AWS/Azure/GCP route resources, private endpoints, VPC access connectors, subnet associations, firewall priorities, firewall target tags, and Azure NSG allow/deny rules are handled by provider network adapters. Adapter signals can prove internal reachability or lateral/provider-network bridges when linked to a workload. They do not turn an unrelated private workload public.

Network blockers carry semantics. `blocks` means the observed path should not contribute exposure points unless stronger evidence proves reachability. `constrains` means the path still exists, but auth, WAF, firewall, or API-key evidence reduces exposure weight and keeps non-exploited findings below `urgent`. Missing blocker semantics are treated as uncertainty.

The effective exposure engine normalizes provider signals into one asset-level decision before scoring. It selects the strongest linked network path, routes the record through the AWS, Azure, GCP, Kubernetes, or fallback evaluator, joins the strongest effective-access or IAM capability record, and emits:

- `decision`: `reachable`, `constrained`, `blocked`, `isolated`, `unknown`, or `reachable_without_effective_identity`;
- `decision_basis`: the network or identity reason that drove the combined decision;
- `evaluator`: the provider evaluator that produced the decision, for example `aws.effective_exposure`;
- `network`: provider, entry, path type, exposure, confidence, decision basis, blockers, unknowns, and evidence layer;
- `identity`: identity/action/impact, policy layer, source decision basis, provider decision basis, confidence, blockers, unknowns, evaluation order, and `effective_access_model`;
- `edges`: asset -> effective network path -> effective identity -> runtime, with provider, source, confidence, blocker, and unknown state.

The provider evaluators live under `src/reachability_advisor/provider_evaluators/`. `network_engine.py` builds provider resource graphs before falling back to explicit `network_graph.edges`, `network_edges`, or inferred `steps`. Builders select typed edges from provider resources such as AWS routes/NACLs/security groups, Azure routes and NSG rules, GCP routes and firewall rules, and Kubernetes NetworkPolicy or service-mesh policy. Route selectors use matching longest prefix first and provider priority as the tie breaker. NSG/firewall/NACL selectors choose the effective matching inbound rule before path evaluation, so a lower-priority deny can block a later allow. Private endpoint edges preserve direction; outbound/dependency endpoints constrain but do not block public ingress. Service-mesh authz evaluates DENY before ALLOW and blocks when an ALLOW policy does not match the observed source. Each selected edge carries `type`, `precedence`, and `precedence_reason`; the graph output records the provider rule used to select it. A disconnected graph blocks the path; a linked graph emits per-edge state under `network.network_graph`.

`policy_engine.py` is the structured IAM policy layer. It parses provider documents into policy AST records for principal, action, resource, and condition evaluation before selecting an effective-access record. It accepts AWS policy statements, Azure role/deny assignments, GCP IAM/deny/PAB/org policies, and Kubernetes RBAC rules when those documents are present on an effective-access record. The engine emits `policy_evaluation` with matched statements, principal/action/resource match state, condition keys, blockers, unknowns, resource scope, confidence, and per-layer evaluation order. Each provider evaluator then owns the blocker taxonomy, provider decision basis, and unresolved-precedence notes for its platform:

- AWS evaluates structured route, security-group, and NACL evidence before falling back to text hints. Route evaluation checks the selected default route, blackhole state, egress-only gateways, and private transit targets. Security-group evaluation distinguishes public ingress, source-security-group-only ingress, source-CIDR restrictions, and missing inbound allows. NACL evaluation follows AWS rule order and lets the first matching allow or deny decide the path. AWS policy evaluation models identity/resource allows, explicit denies, permissions boundaries, SCPs, session policies, trust policies, resource policies, condition keys, scoped resources, and `sts:AssumeRole` trust constraints.
- Azure interprets Private Endpoint, App Service auth and access restrictions, NSG deny evidence, Front Door/Application Gateway WAF evidence, NSG ordering, and route-table uncertainty. Azure policy evaluation models deny assignments, role assignments, role definitions, common built-in role names, resource policies, assignable scopes, inherited management-group/subscription/resource-group scope, PIM activation hints, and role-assignment conditions.
- GCP interprets IAP, Cloud Armor, Private Service Connect, internal serverless ingress, VPC connector evidence, hierarchical firewall uncertainty, and route uncertainty. GCP policy evaluation models IAM bindings, common predefined role names, deny policies, principal access boundaries, organization-policy constraints, resource policies, organization/folder/project/resource scope, conditional bindings, Workload Identity mappings, and service-account impersonation.
- Kubernetes interprets NetworkPolicy deny-all or allow-list evidence, internal ingress class, service-mesh AuthorizationPolicy and mTLS evidence. Kubernetes policy evaluation models RBAC denies, RoleBinding/ClusterRoleBinding allows, cluster/namespace/service-account scope, `resourceNames`, non-resource URLs, aggregated ClusterRoles, and high-risk verbs such as `impersonate`, `bind`, `escalate`, and pod exec.

The fallback evaluator keeps unknown-provider evidence visible without pretending provider precedence was evaluated.

This is the provider-specific layer used by scoring gates and by the evidence graph. It does not replace raw network paths or IAM records; it makes their effective meaning explicit.

IAM is combined with network reachability in three ways. First, workload identity references such as task roles, instance profiles, service accounts, managed identities, and role bindings add `limited`, `sensitive`, or `admin` privilege evidence to the matched artifact. Second, policies are expanded into capability records with action, effect, policy layer, decision, decision basis, impact, access class, resource scope, condition keys, resource references, `effective_risk`, and `risk_multiplier` where known. Effective-access records may also carry the structured source policy documents used to make that decision. Impact classes are `data_access`, `network_control`, `iam_escalation`, `compute_control`, `admin_control`, and `limited_access`. Provider role catalogs cover common AWS managed policies, Azure built-in roles, GCP predefined roles, and Kubernetes role names before falling back to string impact detection. Limited-looking permissions such as `secretsmanager:GetSecretValue`, `ec2:AuthorizeSecurityGroupIngress`, `iam:PassRole`, `sts:AssumeRole`, secret reads, role binding writes, or workload update permissions can raise context criticality when the workload is reachable. Scoped or conditional permissions still count, but score lower than broad unconditioned permissions for the same impact. Explicit deny records take precedence over matching or equally critical allow records in AWS, Azure, GCP, and Kubernetes evaluators; unrelated low-impact denies do not hide a separate admin or escalation capability. Each selected identity result includes `evaluation_order`, `effective_access_model`, and `policy_evaluation` when structured policy documents were evaluated. Explicit `sts:AssumeRole` edges inherit the target role's visible capabilities when the target role is present in the plan; `iam:PassRole` remains escalation evidence but is not expanded without a compatible compute mutation path. Third, a network-reachable workload with `admin_control`, `network_control`, or `iam_escalation` can create an internal provider-control-plane pivot, raising private same-provider workloads to `internal` when the compromised identity can alter routes, security groups, policies, or attachments.

IAM criticality is network-aware. Critical IAM impacts on public, external, or internal workloads raise context `criticality` to `high`; the same impact on a private-only workload raises it to `medium` because the blast radius is serious but the entry path is weaker. Targeted sensitive resources are recorded as evidence when Terraform exposes both the policy resource ARN/name and the sensitive resource. Identity resource names alone are not treated as permission evidence.

Supported public links include AWS ECS services through public security groups or public load balancer target groups and target attachments, AWS Lambda function URLs, Azure application gateway or load balancer backend pool paths, GCP forwarding rule/backend service/NEG paths, GCP Cloud Run and Cloud Functions public invoker grants, Azure Container Apps external ingress, and Kubernetes Service/Ingress names or selectors. Provider-bridge lateral inference is limited to bridge resources such as peering, VPN, transit, ExpressRoute, and Interconnect; unrelated private resources do not make every workload internal.

This is deployment context, not exploit confirmation. Unsupported resources and opaque rendered-manifest wrappers are reported as gaps.

## Context evidence

Terraform plan JSON is the deployment-context source for release gates. Context JSON can override or enrich Terraform-derived fields such as owner, environment, or criticality.

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

Missing context is `unknown`; it is not isolation evidence. Unknown network or IAM context gets an uncertainty premium so it ranks above confirmed internal/no-role context, but below confirmed public or sensitive/admin context. It is still capped below `urgent` until stronger deployment, network, IAM, or exploit evidence proves the effective path.

## Scoring

The score is derived from the effective exposure path and capped at 100. It starts from vulnerability severity, then adds exploit likelihood, source evidence, dependency scope, network exposure, environment, and the strongest context impact:

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

Context impact is not fully additive. `admin`, `sensitive`, `data_access`, `network_control`, `iam_escalation`, and high asset criticality can describe the same blast radius, so the scorer takes the strongest one instead of stacking all of them. IAM capability records are normalized before scoring, and the strongest capability contributes through the same impact table as aggregate `iam_impacts` after applying its `risk_multiplier`. The provider-specific `effective_exposure` decision drives blocker and low-confidence gates. Low-confidence IAM and network paths remain evidence, but caps prevent them from behaving like confirmed exposure. The JSON finding includes `scoring.dimensions[]` for each point contribution and `scoring.gates[]` for caps such as weak source evidence, private/no-ingress context, low-confidence IAM/network evidence, network blockers, and the urgent gate.

Default exposure weights are deliberately ordered as public, external, unknown, internal, private/no ingress. Default privilege weights are admin, sensitive, unknown, limited, none. This means missing evidence is treated as a risk to close, not as a safe state. The model does not use absolute worst case for unknowns because that would make missing Terraform/Kubernetes/IAM evidence indistinguishable from confirmed internet exposure with admin rights.

Priority gates prevent weakly actionable findings from crossing high-severity thresholds only because several small signals add up:

- dev/test dependencies without source usage are capped below `medium`;
- weak source evidence (`SBOM only`, `no source rule`, or `absent`) is capped below `high` unless the vulnerability is known exploited or has high EPSS; even then it stays below `urgent` until source usage is proven;
- dependency-graph evidence is capped below `high` unless it is public/external with critical context, and below `urgent` until direct vulnerable API usage or stronger exploit intelligence exists;
- import-only evidence is capped below `high` unless it is public/external and has critical context;
- private/no-ingress findings without exploit signal or critical context are capped below `high`;
- confirmed network blockers cap non-exploited findings below `high`;
- constrained or unknown network semantics keep non-exploited findings below `urgent`;
- low-confidence IAM or network evidence keeps non-exploited findings below `urgent`;
- `urgent` requires known exploitation, high EPSS, a request-controlled public/external path, or critical reachable context.

Each JSON finding includes `scoring.effective_exposure_path`, a compact reference to the path used for the score. The full node and edge details are in `evidence_graph.effective_exposure_graph`.

The default model is meant to separate these common cases:

| Example | Expected priority |
|---|---|
| Public request-controlled vulnerable code path plus sensitive/admin context | `urgent` |
| Public request-controlled vulnerable code path without critical context | `high` |
| Internal/lateral request-controlled vulnerable code path | `high` when severity is high enough |
| Unknown deployment or IAM context with request-controlled code | `high` when severity is high enough, but below `urgent` until the path is proven |
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

`--mapping-out` is the logic-verification artifact for artifact matching. It shows:

- every SBOM artifact;
- artifact candidates used for matching;
- source root status;
- Terraform match method/score;
- mapping warnings;
- Terraform coverage summary.

CI can enforce mapping quality with `--min-artifact-match-coverage`, `--min-strong-artifact-identity-coverage`, and `--fail-on-mapping-warnings`.

## Benchmark gates

The synthetic scoring benchmark protects individual scoring decisions. Each case in `configs/scoring-benchmark.json` has an expected tier, score band, plain-English reason, and required evidence labels such as `source:attacker_controlled`, `network:public`, `iam_impact:data_access`, or `gate:network_blocker:capped`. The benchmark fails when either the tier or the reason labels drift.

Real-app benchmark snapshots protect distribution drift. `scripts/run_complex_app_validation.py` writes `benchmark.json` with aggregate and per-case tier counts for AWS Retail Store, Google Online Boutique, Bank of Anthos, Azure AKS Store, and Instana Robot Shop. `reachability-advisor benchmark-snapshots` compares that file with `fixtures/benchmarks/real-app-tier-snapshots.json`.

The snapshot gate checks:

- expected aggregate and per-case tier distributions;
- explicit high and urgent count limits;
- high-or-urgent ratio limits;
- total finding drift limits;
- expected case status.

This gate is specifically aimed at over-prioritization. If a scoring change turns internal or weak-evidence findings into broad high/urgent output, the real-app snapshot fails before the change is published.

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
