# Data Formats

Reachability Advisor is local-first. Inputs are files supplied by the developer pipeline; outputs are JSON, Markdown, SARIF, and self-contained HTML artifacts suitable for CI and IDE integrations.

## CycloneDX SBOM JSON

The scanner reads CycloneDX JSON and uses:

- `metadata.component` as the deployable artifact identity;
- `components[]` as dependency inventory;
- component package URLs (`purl`) when present;
- `properties[]` and `externalReferences[]` for artifact/image/source metadata.

Recommended artifact metadata:

```json
{
  "metadata": {
    "component": {
      "type": "application",
      "name": "payments-api",
      "version": "1.8.2",
      "properties": [
        {"name": "container:image", "value": "ghcr.io/example/payments-api:1.8.2"},
        {"name": "owner", "value": "team-payments"}
      ],
      "externalReferences": [
        {"type": "distribution", "url": "ghcr.io/example/payments-api:1.8.2"},
        {"type": "vcs", "url": "https://example.invalid/repo/payments-api"}
      ]
    }
  }
}
```

Use `--artifact-alias artifact=image-or-reference` when generated SBOMs lack artifact/image metadata.

For source-only validation, Grype's CycloneDX output is acceptable SBOM input when it includes the package inventory:

```bash
grype dir:path/to/app -o cyclonedx-json --name app --file app.cdx.json
```

## Vulnerability intelligence

Preferred production input is Grype JSON generated from the same SBOM that
Reachability Advisor scans:

```bash
grype sbom:sboms/payments-api.cdx.json -o json > vulns/payments-api.grype.json

reachability-advisor scan \
  --sbom sboms/payments-api.cdx.json \
  --vulns vulns/payments-api.grype.json \
  --source-root payments-api=. \
  --terraform-plan tfplan.json
```

The Grype adapter reads `matches[]`, normalizes the matched artifact package,
matched vulnerable version, severity, CVSS, EPSS when present, fixed versions,
aliases, and references, then the normal source/deployment scoring pipeline runs.

Recommended local format:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "package": {"name": "log4j-core", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core"},
      "affected_versions": ["2.14.1"],
      "severity": "critical",
      "cvss": 10.0,
      "epss": 0.94,
      "known_exploited": true,
      "fixed_versions": ["2.17.1"],
      "summary": "Short description"
    }
  ]
}
```

Small OSV-Scanner-style inputs are also supported by the vulnerability loader.

## Custom source reachability rules

Use `--reachability-rules` to add package/vulnerability-specific source heuristics.

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

Schema draft: `schemas/reachability-rules.schema.json`.

## Runtime policy JSON

Runtime policy files control CI fail thresholds and temporary exceptions. The scanner never treats an exception as proof that a vulnerability is not affected; it marks matching findings as `policy_status: excepted` and preserves the rationale in the finding.

```json
{
  "$schema": "../schemas/runtime-policy.schema.json",
  "schema_version": "1.0",
  "fail_on_tier": "high",
  "exceptions": [
    {
      "vulnerability": "CVE-EXAMPLE-0001",
      "artifact": "example-service",
      "component": "example-lib",
      "expires": "2026-12-31",
      "reason": "Accepted by service owner while upgrade is validated."
    }
  ]
}
```

Recommended practice:

- set `fail_on_tier` to `high` for release gates and `urgent` while onboarding an existing backlog;
- require a human-readable `reason`;
- set an `expires` date for every exception;
- scope exceptions as narrowly as possible with vulnerability, artifact, and component.

Schema draft: `schemas/runtime-policy.schema.json`.

## Context JSON

```json
{
  "artifacts": {
    "service-name": {
      "environment": "prod",
      "exposure": "public",
      "privilege": "sensitive",
      "criticality": "high",
      "iam_impacts": ["data_access"],
      "owner": "@team-name",
      "confidence": "high",
      "evidence": ["public API", "secrets access"]
    }
  }
}
```

## Terraform coverage JSON

Generated with `--terraform-coverage-out`.

```json
{
  "schema_version": "2.0",
  "summary": {
    "total_resources": 15,
    "accounted_resources": 15,
    "resource_accounting_coverage": 1.0,
    "semantically_classified_resources": 15,
    "semantic_classification_coverage": 1.0,
    "unsupported_or_unclassified_resources": 0,
    "artifacts_requested": 4,
    "artifacts_matched": 4,
    "artifact_match_coverage": 1.0
  },
  "artifact_matches": [
    {
      "artifact": "payments-api",
      "resource": "aws_ecs_task_definition.payments",
      "image": "ghcr.io/example/payments-api:1.8.2",
      "match_method": "repository-tag",
      "match_score": 90
    }
  ],
  "visibility_gaps": []
}
```

`visibility_gaps` is intentionally part of the format. A gap means the resource was seen and accounted for, but the tool does not yet have semantic rules for that resource type.

Schema draft: `schemas/terraform-coverage.schema.json`.

## Mapping report JSON

Generated with `--mapping-out`.

```json
{
  "schema_version": "4.0",
  "summary": {
    "artifact_count": 1,
    "artifacts_with_source_roots": 1,
    "artifacts_with_terraform_matches": 1
  },
  "artifacts": [
    {
      "name": "payments-api",
      "artifact_candidates": ["payments-api", "ghcr.io/example/payments-api:1.8.2"],
      "source_root": "services/payments-api",
      "source_root_exists": true,
      "terraform_matched": true,
      "terraform_matches": [],
      "mapping_warnings": []
    }
  ]
}
```

Schema draft: `schemas/mapping-report.schema.json`.

## SBOM plan JSON

Generated with `sbom-plan --out-json`.

```json
{
  "schema_version": "4.0",
  "artifact": "payments-api",
  "commands": [
    {
      "tool": "syft",
      "purpose": "container image SBOM",
      "command": "syft ghcr.io/example/payments-api:1.8.2 -o cyclonedx-json=sboms/payments-api.cdx.json",
      "output": "sboms/payments-api.cdx.json",
      "notes": []
    }
  ]
}
```

Schema draft: `schemas/sbom-plan.schema.json`.

## Findings JSON

The canonical output is:

```json
{
  "metadata": {"remediation_groups": 1},
  "remediations": [
    {
      "artifact": {"name": "audit-api"},
      "component": {"name": "jackson-databind", "version": "2.9.9"},
      "vulnerability_count": 52,
      "max_score": 100.0,
      "tier": "urgent",
      "reachability": "attacker_controlled",
      "suggested_version": "2.12.7.1",
      "suggested_fix": "Set Maven dependency com.fasterxml.jackson.core:jackson-databind to version 2.12.7.1",
      "top_vulnerabilities": []
    }
  ],
  "findings": []
}
```

`remediations[]` groups findings by artifact and dependency so developers see a
package-level fix queue before individual advisory rows. Each finding still
includes artifact, component, vulnerability, source reachability, context,
score, tier, confidence, rationale, fix commands, and policy status.

Schema draft: `schemas/findings.schema.json`.

## Visual HTML report

Generated with `--html-out`.

The report is a single HTML file with embedded JSON, CSS, and JavaScript. It does not load external scripts, fonts, or network assets.

It visualizes:

- attacker entry and ingress/path cards derived from Terraform network-path evidence, such as Internet -> public security group/load balancer/application gateway -> workload;
- deployable asset cards with network, IAM, source, environment, owner, and criticality context;
- vulnerability cards linked to the affected asset;
- colors that emphasize the highest tier/criticality on each asset and vulnerability;
- a searchable, filterable findings list with click-through details.

The graph supports mouse-wheel zoom, drag-to-pan, tier filtering, exposure filtering, active-only filtering, and text search. It is an audit artifact, not a separate source of truth; the canonical machine-readable data remains `--out` findings JSON.

## Terraform fixture pack JSON

Fixture packs live under `fixtures/terraform/packs/<id>/fixture.json`.

```json
{
  "schema_version": "3.0",
  "id": "aws-ecs-fargate-service",
  "name": "AWS ECS/Fargate service module fixture",
  "provider": "aws",
  "terraform_plan": "tfplan.json",
  "sboms": ["sboms/payments-api.cdx.json"],
  "vulnerabilities": "../../common/vulnerabilities.json",
  "source_roots": {"payments-api": "source/payments-api"},
  "expected": {
    "resource_accounting_coverage": 1.0,
    "semantic_classification_coverage": 1.0,
    "artifact_match_coverage": 1.0,
    "min_findings": 1
  }
}
```

Schema draft: `schemas/fixture-pack.schema.json`.

## Fixture run report JSON

Generated with:

```bash
reachability-advisor fixtures run --out outputs/fixtures-report.json
```

The report includes aggregate pass/fail status, per-fixture coverage summaries, top findings, and assertion results. Schema draft: `schemas/fixture-run-report.schema.json`.
