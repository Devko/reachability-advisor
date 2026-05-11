# Data Formats

Reachability Advisor reads local files and writes local artifacts. The scanner does not fetch vulnerability databases, cloud inventory, SBOMs, or source code.

Primary scan inputs:

- CycloneDX SBOM JSON;
- Grype JSON or normalized vulnerability JSON;
- source-root mappings;
- Terraform plan JSON.

Context JSON, Terraform source mode, and custom source rules are enrichment or fallback inputs.

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

For early source-only validation, Grype's CycloneDX output is acceptable SBOM input when it includes the package inventory:

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

When several per-service Grype reports are merged into one input, stamp each
match with `reachability_advisor.artifact` to keep matches scoped to the SBOM
artifact that produced them:

```json
{
  "matches": [
    {
      "reachability_advisor": {"artifact": "checkout"},
      "vulnerability": {"id": "GHSA-example", "severity": "High"},
      "artifact": {"name": "request", "version": "2.88.2", "purl": "pkg:npm/request@2.88.2"}
    }
  ]
}
```

The complex validation runner does this automatically.

Recommended local format:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "artifact": "payments-api",
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

Use `artifact` when one vulnerability file is shared across multiple SBOMs and a record applies to only one artifact.

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

Generate starter Semgrep rules from the same rule set:

```bash
reachability-advisor export-semgrep-rules \
  --reachability-rules reachability-rules.json \
  --out semgrep-reachability.yml
```

## External source evidence

Use `--source-evidence-in` to import source evidence from another analyzer. The native JSON format is:

```json
{
  "evidence": [
    {
      "artifact": "payments-api",
      "component": "requests",
      "vulnerability": "GHSA-example",
      "state": "attacker_controlled",
      "confidence": "high",
      "reason": "Semgrep taint trace links request query to requests.get",
      "tool": "semgrep",
      "locations": [{"path": "src/api.py", "line": 42, "column": 12}]
    }
  ]
}
```

`component`, `purl`, and `vulnerability` are matching selectors. `artifact` narrows a selector match to one SBOM artifact. Provide at least one `component`, `purl`, or `vulnerability` selector besides the evidence state. Imported evidence can upgrade the built-in result; it does not downgrade stronger built-in evidence.

Supported imported formats:

- native Reachability Advisor evidence JSON;
- Reachability Advisor findings JSON;
- Semgrep JSON with `extra.metadata.reachability_advisor`, plain selector metadata such as `package` or `purl`, and native `extra.dataflow_trace` taint paths;
- SARIF with matching selectors in `result.properties`;
- CodeQL SARIF path-problem output with `codeFlows` and selectors in `result.properties`, `driver.rules[].properties`, or nested `reachability_advisor` metadata;
- govulncheck JSONL for Go call-stack evidence.

For CodeQL, generic query ids such as `js/request-forgery` are kept as matched symbols, not treated as vulnerability selectors. Rule ids are used as vulnerability selectors only when they look like vulnerability ids such as `CVE-*`, `GHSA-*`, `GO-*`, `OSV-*`, or `PYSEC-*`.

## Source coverage JSON

Generated with `--source-coverage-out`.

```json
{
  "schema_version": "1.0",
  "summary": {
    "artifact_count": 1,
    "artifacts_with_source_root": 1,
    "files_scanned": 42,
    "manifest_files_scanned": 6,
    "findings_analyzed": 12,
    "findings_with_external_evidence": 7,
    "findings_with_builtin_only_evidence": 5,
    "findings_with_dependency_graph_path": 3,
    "findings_with_manifest_evidence": 2,
    "findings_with_package_specific_rule": 8,
    "findings_with_rule_gap": 1,
    "findings_with_weak_source_evidence": 2,
    "source_rule_coverage": 0.9167,
    "external_evidence_usable_ratio": 0.6667,
    "external_evidence_selected_ratio": 0.5833,
    "analysis_profile": "production",
    "source_diagnostic_counts": {"missing_package_rule": 2},
    "source_evidence_coverage": 0.75,
    "external_evidence_records": 3,
    "external_evidence_providers": {"CodeQL": 1, "semgrep": 2},
    "external_evidence_selector_diagnostics": {
      "records": 3,
      "matchable_records": 2,
      "artifact_only_records": 1,
      "unscoped_records": 0
    },
    "states": {
      "attacker_controlled": 2,
      "function_reachable": 4,
      "dependency_reachable": 3,
      "package_present": 3
    }
  },
  "production_readiness": {
    "status": "ready",
    "blockers": [],
    "source_mode": "external-first",
    "deployment_evidence": {
      "terraform_plan": true,
      "terraform_source": false,
      "kubernetes_manifest": true
    }
  },
  "artifacts": []
}
```

Schema draft: `schemas/source-coverage.schema.json`.

## Runtime policy JSON

Runtime policy files control CI fail thresholds and temporary exceptions. The scanner never treats an exception as evidence that a vulnerability is not affected; it marks matching findings as `policy_status: excepted` and preserves the rationale in the finding.

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
      "iam_capabilities": [
        {
          "action": "secretsmanager:GetSecretValue",
          "impact": "data_access",
          "resource_refs": ["arn:aws:secretsmanager:eu-central-1:123456789012:secret:payments"]
        }
      ],
      "effective_access": [
        {
          "identity": "aws_iam_role.payments",
          "resource": "aws_ecs_service.payments",
          "action": "secretsmanager:GetSecretValue",
          "impact": "data_access",
          "decision": "allowed",
          "confidence": "medium",
          "blockers": [{"kind": "scoped_resource", "evidence": "policy resource scope is constrained"}]
        }
      ],
      "network_paths": [
        {
          "exposure": "public",
          "path_type": "public_load_balancer",
          "steps": ["aws_lb.edge public load balancer", "aws_lb_target_group.payments", "aws_ecs_service.payments"],
          "confidence": "medium",
          "blockers": []
        }
      ],
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
    "artifact_match_coverage": 1.0,
    "network_paths_observed": 4,
    "effective_access_records": 3
  },
  "artifact_matches": [
    {
      "artifact": "payments-api",
      "resource": "aws_ecs_task_definition.payments",
      "image": "ghcr.io/example/payments-api:1.8.2",
      "match_method": "repository-tag",
      "match_score": 90,
      "match_confidence": "high",
      "match_proof": {
        "candidate_source": "metadata.properties.container:image",
        "candidate_strength": "tagged_image"
      }
    }
  ],
  "resources": [
    {
      "address": "aws_route.private",
      "type": "aws_route",
      "category": "supporting",
      "network_adapter_signals": [
        {"kind": "private_route_bridge", "label": "transit gateway route"}
      ]
    }
  ],
  "visibility_gaps": []
}
```

`visibility_gaps` is part of the format. A gap means the resource was parsed and counted, but no semantic rule currently maps it to workload, exposure, identity, data, or supporting context.

`network_adapter_signals` are provider-specific hints used by the graph builder. They explain route-table, private-endpoint, VPC connector, firewall target, and security-rule evidence without making unrelated workloads public.

Schema draft: `schemas/terraform-coverage.schema.json`.

## Kubernetes coverage JSON

Generated with `--kubernetes-coverage-out` when `--kubernetes-manifest` is supplied.

```json
{
  "schema_version": "1.0",
  "summary": {
    "manifest_files_scanned": 1,
    "total_resources": 7,
    "workload_resources": 2,
    "service_resources": 2,
    "ingress_resources": 0,
    "network_policy_resources": 0,
    "rbac_resources": 3,
    "artifacts_requested": 2,
    "artifacts_matched": 2,
    "artifact_match_coverage": 1.0,
    "contexts_generated": 2,
    "exposure_counts": {
      "internal": 1,
      "public": 1
    },
    "privilege_counts": {
      "admin": 1,
      "limited": 1
    }
  },
  "resources": [],
  "unmatched_artifacts": []
}
```

Schema draft: `schemas/kubernetes-coverage.schema.json`.

## Mapping report JSON

Generated with `--mapping-out`.

```json
{
  "schema_version": "4.0",
  "summary": {
    "artifact_count": 1,
    "artifacts_with_source_roots": 1,
    "source_root_coverage": 1.0,
    "artifacts_with_terraform_matches": 1,
    "artifact_match_coverage": 1.0,
    "artifacts_with_strong_terraform_matches": 1,
    "strong_terraform_match_coverage": 1.0,
    "artifacts_with_strong_identity": 1,
    "strong_artifact_identity_coverage": 1.0,
    "artifacts_with_mapping_warnings": 0,
    "mapping_warnings_count": 0
  },
  "artifacts": [
    {
      "name": "payments-api",
      "artifact_candidates": ["payments-api", "ghcr.io/example/payments-api:1.8.2"],
      "artifact_identity": {
        "candidates": [
          {
            "value": "ghcr.io/example/payments-api:1.8.2",
            "source": "metadata.properties.container:image",
            "strength": "image_reference"
          }
        ],
        "warnings": []
      },
      "strong_artifact_identity": true,
      "source_root": "services/payments-api",
      "source_root_exists": true,
      "terraform_matched": true,
      "strong_terraform_match": true,
      "terraform_matches": [],
      "mapping_warnings": []
    }
  ]
}
```

Schema draft: `schemas/mapping-report.schema.json`. The coverage ratios are designed for CI gates: artifact deployment mapping, strong image/digest identity, source-root presence, and mapping warning count.

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

`remediations[]` groups findings by artifact and dependency. Each finding still includes artifact, component, vulnerability, source reachability, context, score, tier, confidence, rationale, fix commands, and policy status. `scoring` contains the scoring model version, per-dimension point contributions, gates/caps that applied, final score, final tier, and a compact `effective_exposure_path` reference.

`source_reachability.state` is one of `absent`, `unknown_due_to_no_rule`, `package_present`, `dependency_reachable`, `imported`, `function_reachable`, or `attacker_controlled`. `source_reachability.label` is the human-facing version used by reports: `absent from scanned source`, `no source rule`, `SBOM only`, `dependency evidence`, `import observed`, `reachable vulnerable API`, or `request-controlled path`. The `unknown_due_to_no_rule` state is a coverage warning: the vulnerable package is present, but no package-specific source rule exists and generic import evidence was not observed.

`source_reachability.diagnostics[]` explains evidence gaps such as missing source roots, missing package-specific rules, unobserved imports, dependency-graph-only evidence, and unlinked attacker-input hints.

`context.iam_capabilities[]` is the per-resource IAM view behind `privilege` and `iam_impacts`. Each capability records an action, impact class, access class, resource references when known, resource scope (`scoped`, `wildcard`, or `unknown`), IAM condition keys when present, provider, source resource, and evidence string. This is useful when a role is not admin but still grants critical rights such as secret reads, network mutation, workload mutation, or role passing.

Schema draft: `schemas/findings.schema.json`.

## Evidence graph JSON

Generated with `--evidence-graph-out`. The findings JSON also embeds the same structure under `evidence_graph`.

The evidence graph is the stable machine contract used by the HTML report. Its canonical model is `effective_exposure_graph`, where each finding is represented as:

```text
asset -> network path -> identity -> reachable code/package -> vulnerability -> score
```

Every effective edge carries `evidence_layer`, `origin_layer`, `evidence_source`, `confidence`, `provider`, `language`, `blockers`, `unknowns`, and `blocker_state`. This is the preferred contract for integrations that need to explain why a finding was prioritized.

The older arrays still exist as compatibility views so consumers can inspect assets, components, vulnerabilities, findings, network paths, IAM capability edges, and code reachability edges without parsing rationale text.

Top-level arrays:

- `assets`: deployable artifacts with strongest exposure, privilege, criticality, IAM impacts, max score, and linked finding keys;
- `components`: SBOM components scoped to an asset;
- `vulnerabilities`: normalized vulnerability records;
- `findings`: score/tier nodes that link asset, component, and vulnerability;
- `network_paths`: attacker or internal entry paths with exposure, entry kind, steps, and raw evidence;
- `network_nodes` and `network_edges`: typed network graph nodes and path edges derived from network-path evidence;
- `iam_edges`: per-asset IAM capability edges or summary IAM edges when only aggregate context exists;
- `code_edges`: source reachability state, provider, locations, symbols, and dependency path;
- `effective_exposure_graph`: unified path graph with provenance on every edge;
- `edges`: generic asset-finding-component-vulnerability links.

Schema draft: `schemas/evidence-graph.schema.json`.

## Baseline artifact JSON

Generated with `--baseline-out`.

The baseline artifact is the stable default-branch input for pull-request gates. It keeps only comparison fields and removes volatile evidence such as file paths, source snippets, rationale text, and raw network evidence.

```json
{
  "schema_version": "1.0",
  "kind": "reachability-advisor-baseline",
  "metadata": {
    "finding_count": 12,
    "active_finding_count": 10,
    "tier_counts": {"urgent": 1, "high": 3, "medium": 6, "low": 2, "informational": 0},
    "policy_status_counts": {"active": 10, "excepted": 2}
  },
  "findings": []
}
```

Use it in pull requests:

```bash
reachability-advisor compare \
  --baseline reachability-baseline.json \
  --head-findings reachability-findings.json \
  --markdown-out reachability-delta.md \
  --fail-on-new-tier high
```

When `--baseline` is used, `compare` emits only new and worsened findings. Schema draft: `schemas/baseline.schema.json`.

## Visual HTML report

Generated with `--html-out`.

The report is a single HTML file with embedded JSON, CSS, and JavaScript. It does not load external scripts, fonts, or network assets.

It visualizes:

- attacker entry and ingress/path cards derived from Terraform network-path evidence, such as Internet -> public security group/load balancer/application gateway -> workload;
- deployable asset cards with network, IAM, code exposure, source, environment, owner, and criticality context;
- vulnerability cards linked to the affected asset, including a plain code-exposure label such as `request-controlled path`, `reachable vulnerable API`, `dependency evidence`, `SBOM only`, or `no source rule`;
- colors that emphasize the highest tier/criticality on each asset and vulnerability;
- a searchable, filterable findings list with click-through details.

The graph supports mouse-wheel zoom, drag-to-pan, tier filtering, exposure filtering, active-only filtering, and text search. The canonical machine-readable result remains `--out` findings JSON.

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
