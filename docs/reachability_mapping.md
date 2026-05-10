# Reachability Mapping Logic

This document explains how Reachability Advisor maps from an SBOM vulnerability to source-code evidence and optional Terraform deployment context.

The short version:

```text
SBOM artifact
  -> SBOM component / package URL
  -> vulnerability intelligence
  -> source reachability evidence
  -> artifact identity candidates
  -> Terraform workload match
  -> exposure / identity / data context
  -> explainable score and developer output
```

## Step 1: SBOM artifact identity

The SBOM loader extracts artifact identity from:

1. `metadata.component.name` and `metadata.component.version`;
2. `metadata.component.purl` or BOM reference when available;
3. `metadata.component.properties` such as `container:image`, `oci:image:ref`, `artifact:reference`, and `reachability:artifact_ref`;
4. `metadata.component.externalReferences`, especially `distribution`, `container-image`, `vcs`, and source references.

The mapping report exposes all candidates so a developer can see exactly what the scanner used.

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

Source reachability is vulnerability-aware. The analyzer receives the component and matched vulnerability, then selects a rule by ecosystem, package, and optional vulnerability ID.

States:

| State | Meaning |
|---|---|
| `package_present` | Package is in the SBOM; no stronger source evidence was observed. |
| `imported` | A matching import/require/use statement was observed. |
| `function_reachable` | Import plus risky function/class usage was observed. |
| `attacker_controlled` | Import, risky usage, and input/entrypoint evidence appear in the same file. |

Same-file attacker control is deliberate. A web handler in one file and a risky library call in another file is useful evidence, but it is not enough to claim attacker-controlled reachability without a call graph. That case becomes `function_reachable` with explicit rationale.

Supported built-in rule families:

| Ecosystem | Examples |
|---|---|
| Maven/Java | Log4j, Jackson Databind, Guava |
| npm/Node | lodash, minimist, Express |
| PyPI/Python | requests, FastAPI, Chainlit, aiohttp |
| Go | Generic import/package evidence |

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

## Step 5: Terraform deployment matching

Terraform context is optional. When supplied, the analyzer reads Terraform plan JSON and accounts for every resource. It then semantically classifies resources whose provider/type appears in the supported manifest.

Artifact-to-workload matching uses conservative evidence scores:

| Match method | Score | Meaning |
|---|---:|---|
| `exact-reference` | 100 | SBOM artifact candidate exactly equals Terraform image/reference. |
| `digest` | 96 | Image digests match. |
| `repository-tag` | 90 | Repository and tag match. |
| `repository` | 72 | Repository matches; tag/digest missing or different. |
| `repository-leaf` | 58 | Last path segment matches. |
| `name` / `artifact-name` | 45-52 | Weak name-only match. |

Low-confidence matches are still visible. They do not silently become proof.

Terraform context also combines network reachability and IAM. The analyzer links workload identities to IAM policies where the plan exposes task roles, instance profiles, service accounts, managed identities, or role assignments. It records impact classes such as `data_access`, `network_control`, `iam_escalation`, and `compute_control`; those impacts raise context criticality only after considering whether the workload is public, external, internal, or private.

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

Reachability Advisor does not prove exploitability, does not build a complete interprocedural call graph, and does not mark vulnerabilities as `not_affected`. It ranks developer work using transparent evidence and clearly reports uncertainty.
