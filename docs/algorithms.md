# Algorithms

Reachability Advisor uses transparent, conservative algorithms. The goal is to help developers decide what to fix first, not to prove exploitability.

## Pipeline

```text
CycloneDX SBOMs
  + vulnerability intelligence (Grype JSON or normalized local JSON)
  + optional source roots
  + optional context JSON
  + optional Terraform plan JSON
  + optional custom source rules
  -> SBOM artifact identity
  -> vulnerability/component matches
  -> source reachability evidence
  -> artifact-to-Terraform workload matches
  -> exposure / identity / data context
  -> explainable score
  -> remediation groups by artifact/component/version
  -> JSON/SARIF/diagnostics/Markdown/annotations/coverage/mapping
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

Recommended practice:

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

Version filtering is conservative: if a vulnerability record provides `affected_versions`, the component version must be in that list. If data is incomplete, the finding is not suppressed; it receives lower confidence.

## Source evidence

Source reachability states:

| State | Meaning |
|---|---|
| `package_present` | Component appears in the SBOM, but no stronger source evidence was found. |
| `imported` | Source imports/requires/uses the package. |
| `function_reachable` | Source imports the package and contains usage patterns associated with vulnerable APIs or high-risk library functions. |
| `attacker_controlled` | The same source file contains package import, risky usage, and input/entrypoint evidence. |

The same-file requirement prevents overclaiming. If an HTTP handler appears in one file and a risky library call appears in another file, the tool reports weaker `function_reachable` evidence unless a future call-graph plugin proves the path.

Rules are visible in `src/reachability_advisor/source.py`. Additional project-specific rules can be supplied with `--reachability-rules`.

Built-in high-risk source rules currently cover common Java, Node, Python, and Go evidence:

- Java/Maven import and sink patterns, including Log4j and Spring Web entrypoints;
- Node/npm import and route/request patterns, including Express and NestJS on Express;
- Python/PyPI import and handler patterns, including FastAPI, Chainlit, and aiohttp;
- basic Go import evidence, with stronger evidence available through custom rules.

## Remediation grouping

Individual scanner findings are preserved, but JSON and Markdown outputs also
include a package-level remediation queue. Findings are grouped by artifact,
component name, component version, and package URL. The group inherits the
highest reachability and highest score among its findings, keeps all advisory
IDs underneath, and proposes one package upgrade from the highest fixed version
reported by vulnerability intelligence.

## Artifact-to-Terraform matching

Terraform evidence is derived from a local `terraform show -json` plan. The analyzer is manifest-driven:

1. Parse every planned resource from `planned_values` and `resource_changes`.
2. Classify the resource provider: AWS, Azure, GCP, Kubernetes, or unknown.
3. Classify the resource category if it appears in `TERRAFORM_COVERAGE_MANIFEST`: `workload`, `exposure`, `identity`, `sensitive_data`, or supporting context.
4. Extract likely container image or artifact references from provider-specific and generic fields.
5. Match those references against SBOM artifact candidates.
6. Infer exposure from public network/API resources linked to the matched workload.
7. Infer coarse privilege from IAM/role/policy resources.
8. Emit coverage and mapping reports.

Helm and kubectl wrapper resources are classified as Kubernetes supporting
resources, but they still emit `opaque_manifest_wrapper` visibility gaps because
the rendered child manifests are where workload images, exposure, and RBAC live.

Match scoring:

| Method | Score | Confidence | Meaning |
|---|---:|---|---|
| `exact-reference` | 100 | high | SBOM candidate exactly equals Terraform reference. |
| `digest` | 96 | high | Image digests match. |
| `repository-tag` | 90 | high | Repository and tag match. |
| `repository` | 72 | medium | Repository matches without exact tag/digest evidence. |
| `repository-leaf` | 58 | low/medium | Last repository segment matches. |
| `name` / `artifact-name` | 45-52 | low | Weak name-only match. |

Exposure inference is deliberately linked instead of provider-wide. A public load balancer, API gateway, or ingress in the same Terraform plan does not automatically make every matched artifact public. Supported public links include AWS ECS services through public security groups or public load balancer target groups, AWS Lambda function URLs, GCP Cloud Run and Cloud Functions public invoker grants, Azure Container Apps external ingress, and Kubernetes Service/Ingress names or selectors.

This is deployment context, not exploit proof. Unsupported resources and opaque rendered-manifest wrappers do not lower risk; they are reported as gaps.

## Context evidence

Context may come from a small JSON file or from Terraform inference. The JSON format is useful when teams want to override or enrich Terraform with known service ownership and criticality.

```json
{
  "artifacts": {
    "payments-api": {
      "environment": "prod",
      "exposure": "public",
      "privilege": "sensitive",
      "criticality": "high",
      "owner": "@team-payments",
      "confidence": "high"
    }
  }
}
```

Missing context is `unknown`, not safe.

## Scoring

The score is additive and capped at 100:

```text
score = severity
      + known exploited bonus
      + EPSS likelihood bonus
      + source reachability points
      + scope adjustment
      + exposure points
      + environment points
      + privilege points
      + criticality points
      - weak-evidence penalty
```

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
