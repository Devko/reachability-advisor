# Reachability Mapping

This document describes how Reachability Advisor maps an SBOM vulnerability to source evidence and deployment context from Terraform plans, Terraform source fallback, rendered Kubernetes manifests, or explicit context JSON.

The short version:

```text
SBOM artifact
  -> SBOM component / package URL
  -> vulnerability intelligence
  -> source reachability evidence
  -> artifact identity candidates
  -> Terraform/Kubernetes workload match
  -> exposure / identity / data context
  -> score, tier, and outputs
```

## Step 1: SBOM artifact identity

The SBOM loader extracts artifact identity from:

1. `metadata.component.name` and `metadata.component.version`;
2. `metadata.component.purl` or BOM reference when available;
3. `metadata.component.properties` such as `container:image`, `oci:image:ref`, `artifact:reference`, and `reachability:artifact_ref`;
4. `metadata.component.externalReferences`, especially `distribution`, `container-image`, `vcs`, and source references.

The mapping report exposes every candidate used by the scanner.

## Step 2: vulnerability-to-component matching

For Grype input, the vulnerability file is already a scanner result: Grype has
matched the SBOM package to a vulnerability database entry. Reachability Advisor
normalizes each Grype `matches[]` item, then still verifies the package
name/package URL and version against the SBOM component before source and
deployment scoring.

A vulnerability matches an SBOM component when one of the following holds:

| Evidence | Confidence |
|---|---|
| Exact package URL match | high |
| Same ecosystem and package name, with namespace respected | medium/high |
| Normalized package name match | medium |

Version matching is conservative. If a vulnerability record provides `affected_versions`, the component version must be listed. If version data is missing, the finding is still reported with lower confidence instead of being suppressed.

## Step 3: source reachability

Source reachability is vulnerability-aware. The analyzer receives the component and matched vulnerability, then selects a rule by ecosystem, package, and vulnerability ID when available.

States:

| State | Meaning |
|---|---|
| `absent` | Reserved for explicit evidence that a package is not present in analyzed source or runtime scope. |
| `unknown_due_to_no_rule` | Package is in the SBOM, but no package-specific source rule exists and generic import usage was not observed. |
| `package_present` | Package is in the SBOM; no stronger source evidence was observed. |
| `dependency_reachable` | CycloneDX dependency graph links the package to an imported parent dependency, or a package-manager manifest declares the package. |
| `imported` | A matching import/require/use statement was observed. |
| `function_reachable` | Import plus risky function/class usage was observed. |
| `attacker_controlled` | Risky usage and input/entrypoint evidence appear in the same function, or a bounded static call path links an attacker-controlled handler to a sink function. |

Reports show these as human labels: `absent from scanned source`, `no source rule`, `SBOM only`, `dependency evidence`, `import observed`, `reachable vulnerable API`, and `request-controlled path`.

Same-function attacker control is the baseline. The analyzer also builds one source index per artifact and can promote bounded handler-to-sink call paths, including cross-file calls such as a route handler calling a service function that calls a vulnerable sink wrapper. Unlinked handlers remain `function_reachable` with explicit rationale.

Use `--source-coverage-out` to review source files and package-manager manifests scanned, skipped files, state counts, dependency-graph evidence, manifest evidence, and imported external evidence. Use `--source-evidence-in` to import stronger Semgrep, SARIF, govulncheck, or native evidence.

Supported built-in rule families:

| Ecosystem | Examples |
|---|---|
| Maven/Java | Log4j, Jackson Databind, SnakeYAML, Commons Text, JJWT, XML parsing, Commons Compress, Guava |
| npm/Node | lodash, axios, jsonwebtoken, EJS, Handlebars, js-yaml, xml2js, adm-zip, minimist, Express, NestJS |
| PyPI/Python | requests, PyYAML, Jinja2, PyJWT, lxml, Django, FastAPI, Chainlit, aiohttp |
| Go | Generic import/package evidence plus common JWT/YAML sink hints |

## Step 4: custom reachability rules

Teams can add rules without patching the scanner:

```json
{
  "rules": [
    {
      "ecosystem": "npm",
      "package": "example-lib",
      "vulnerabilities": ["GHSA-example-1234"],
      "import_patterns": ["require\\(['\"]example-lib['\"]\\)"],
      "function_patterns": ["exampleLib\\.dangerous"],
      "attacker_patterns": ["req\\.", "event\\.body"]
    }
  ]
}
```

Use it with:

```bash
reachability-advisor scan \
  --sbom app.cdx.json \
  --vulns vulnerabilities.json \
  --source-root app=. \
  --reachability-rules reachability-rules.json
```

## Step 5: Terraform Deployment Matching

Terraform plan JSON is the primary deployment-context input. The analyzer reads the plan, accounts for every resource, and semantically classifies resources whose provider/type appears in the support manifest.

Artifact-to-workload matching uses conservative evidence scores:

| Match method | Score | Meaning |
|---|---:|---|
| `exact-reference` | 100 | SBOM artifact candidate exactly equals Terraform image/reference. |
| `digest` | 96 | Image digests match. |
| `repository-tag` | 90 | Repository and tag match. |
| `repository` | 72 | Repository matches; tag/digest missing or different. |
| `repository-leaf` | 58 | Last path segment matches. |
| `name` / `artifact-name` | 45-52 | Weak name-only match. |

Low-confidence matches remain visible and do not become high-confidence evidence.

Terraform context also combines network reachability and IAM. The analyzer links workload identities to IAM policies where the plan exposes task roles, instance profiles, service accounts, managed identities, or role assignments. It records impact classes such as `data_access`, `network_control`, `iam_escalation`, and `compute_control`. Those impacts raise context criticality only after considering whether the workload is public, external, internal, or private.

Rendered Kubernetes manifests supplied through `--kubernetes-manifest` add direct workload, Service, Ingress, and RBAC evidence. They are useful when Terraform contains only a Helm release or kubectl wrapper and cannot expose the rendered child resources. The Kubernetes analyzer emits a separate `--kubernetes-coverage-out` report.

## Step 6: mapping report

Use `--mapping-out` to verify the full logic:

```bash
reachability-advisor scan \
  --sbom sboms/payments-api.cdx.json \
  --vulns vulnerabilities.json \
  --terraform-plan tfplan.json \
  --source-root payments-api=. \
  --mapping-out mapping.json
```

The report includes:

- artifact candidates from SBOM metadata and aliases;
- whether a source root exists;
- Terraform matches with method and score;
- warnings for missing source roots, weak artifact identity, or no Terraform match;
- Terraform coverage summary.

## Non-goals

Reachability Advisor does not prove exploitability, does not build a complete interprocedural call graph, and does not mark vulnerabilities as `not_affected`. It ranks remediation work and reports uncertainty.
