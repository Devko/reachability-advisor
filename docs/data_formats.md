# Data Formats

Reachability Advisor is local-first. Inputs are files supplied by the developer pipeline; outputs are JSON/Markdown/SARIF artifacts suitable for CI and IDE integrations.

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

## Vulnerability intelligence

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

## Context JSON

```json
{
  "artifacts": {
    "service-name": {
      "environment": "prod",
      "exposure": "public",
      "privilege": "sensitive",
      "criticality": "high",
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
    "total_resources": 14,
    "accounted_resources": 14,
    "resource_accounting_coverage": 1.0,
    "semantically_classified_resources": 14,
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
  "metadata": {},
  "findings": []
}
```

Each finding includes artifact, component, vulnerability, source reachability, context, score, tier, confidence, rationale, fix commands, and policy status.

Schema draft: `schemas/findings.schema.json`.

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
