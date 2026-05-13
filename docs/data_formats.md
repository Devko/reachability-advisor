# Data Formats

Reachability Advisor reads local files and writes local artifacts. The scanner does not fetch vulnerability databases, cloud inventory, SBOMs, or source code.

Release-gate inputs:

- CycloneDX SBOM JSON;
- Grype JSON, OSV-style JSON, or normalized vulnerability JSON;
- normalized SAST/DAST evidence, Semgrep JSON, or SARIF for first-party code weaknesses;
- source-root mappings;
- external source evidence from Semgrep, CodeQL/SARIF, govulncheck, or native JSON;
- Terraform plan JSON and/or rendered Kubernetes manifests;
- CI artifact manifest when SBOM metadata lacks image digest or registry reference.

Context JSON, Terraform source mode, and custom source rules are enrichment or fallback inputs.

## CycloneDX SBOM JSON

The scanner reads CycloneDX JSON and uses:

- `metadata.component` as the deployable artifact identity;
- `components[]` as dependency inventory;
- component package URLs (`purl`) when present;
- `properties[]` and `externalReferences[]` for artifact/image/source metadata.

Useful artifact metadata:

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

For release gates, use Grype JSON generated from the same SBOM that Reachability Advisor scans:

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
Each finding also carries `vulnerability.intelligence`, a normalized record with source attribution and timestamps. The scanner does not fetch those feeds. It preserves what the supplied Grype, OSV, VEX, KEV, EPSS, or local metadata already contains.

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

The complex validation runner writes this field when it merges per-service Grype reports.

Local vulnerability format:

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

Source-attributed intelligence can be supplied directly in the local format:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-0001",
      "package": {"name": "demo-lib", "purl": "pkg:npm/demo-lib"},
      "severity": "high",
      "cvss": 8.8,
      "epss": {"score": 0.73, "percentile": 0.98, "date": "2026-05-12", "source": "first-epss"},
      "kev": {"known_exploited": true, "date_added": "2026-05-01", "source": "cisa-kev"},
      "vex": {"status": "affected", "justification": "reachable_code", "source": "vendor-vex"},
      "fix": {"state": "fixed", "versions": ["1.2.3"], "source": "vendor-advisory"},
      "sources": [
        {"name": "internal-vuln-feed", "type": "normalized", "retrieved_at": "2026-05-13T00:00:00Z"}
      ]
    }
  ]
}
```

Normalized finding output uses this shape:

```json
{
  "vulnerability": {
    "id": "CVE-2024-0001",
    "epss": 0.73,
    "known_exploited": true,
    "fixed_versions": ["1.2.3"],
    "intelligence": {
      "schema_version": "1.0",
      "id": "CVE-2024-0001",
      "package": {"name": "demo-lib", "purl": "pkg:npm/demo-lib"},
      "epss": {"score": 0.73, "percentile": 0.98, "date": "2026-05-12", "source": "first-epss"},
      "kev": {"known_exploited": true, "date_added": "2026-05-01", "source": "cisa-kev"},
      "vex": {"status": "affected", "justification": "reachable_code", "source": "vendor-vex"},
      "fix": {"available": true, "state": "fixed", "versions": ["1.2.3"], "source": "vendor-advisory"},
      "timestamps": {"observed_at": "2026-05-13T00:00:00Z", "kev_date_added": "2026-05-01"},
      "sources": [{"name": "internal-vuln-feed", "type": "normalized", "retrieved_at": "2026-05-13T00:00:00Z"}]
    }
  }
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
      "query_family": "http-client",
      "reason": "Semgrep taint trace links request query to requests.get",
      "tool": "semgrep",
      "locations": [{"path": "src/api.py", "line": 42, "column": 12}]
    }
  ]
}
```

`component`, `purl`, and `vulnerability` are matching selectors. `artifact` narrows a selector match to one SBOM artifact. Provide at least one `component`, `purl`, or `vulnerability` selector besides the evidence state. For production critical findings, include `query_family` or `query_families` when the package maps to a maintained query pack such as `http-client`, `logging`, `deserialization`, `template-engine`, `archive-file-io`, `auth-token-crypto`, or `web-handler`. Imported evidence can upgrade the built-in result; it does not downgrade stronger built-in evidence.

Supported imported formats:

- native Reachability Advisor evidence JSON;
- Reachability Advisor findings JSON;
- Semgrep JSON with `extra.metadata.reachability_advisor`, plain selector metadata such as `package` or `purl`, and native `extra.dataflow_trace` taint paths;
- SARIF with matching selectors in `result.properties`;
- CodeQL SARIF path-problem output with `codeFlows` and selectors in `result.properties`, `driver.rules[].properties`, or nested `reachability_advisor` metadata;
- govulncheck JSONL for Go call-stack evidence.

For CodeQL, generic query ids such as `js/request-forgery` are kept as matched symbols, not treated as vulnerability selectors. Rule ids are used as vulnerability selectors only when they look like vulnerability ids such as `CVE-*`, `GHSA-*`, `GO-*`, `OSV-*`, or `PYSEC-*`.

## Security evidence for SAST and DAST

Use `--security-evidence-in` for first-party code weaknesses. This is separate from dependency reachability evidence. The scanner imports these records as `finding_type: code_weakness` and scores them with the same network, IAM, criticality, baseline, policy, SARIF, Markdown, JSON, and HTML paths used by dependency findings.

Prefer SARIF 2.1.0 when a scanner can emit it. SARIF is the broad static-analysis interchange format, so one adapter can cover Semgrep, CodeQL, and other tools that preserve rule metadata, source locations, and code-flow records. Native scanner JSON remains useful when a tool emits richer fields than SARIF or does not support SARIF.

Native JSON:

```json
{
  "security_evidence": [
    {
      "scanner_type": "sast",
      "tool": "semgrep",
      "artifact": "web-api",
      "rule_id": "js.express.xss",
      "weakness": "cross-site scripting",
      "cwe": "CWE-79",
      "severity": "high",
      "confidence": "high",
      "source": {"path": "src/routes/search.js", "line": 12, "column": 5},
      "sink": {"function": "res.send"},
      "evidence": {"dataflow": "req.query.q reaches res.send"},
      "remediation": "Encode untrusted output before writing HTML responses."
    },
    {
      "scanner_type": "dast",
      "tool": "zap",
      "artifact": "web-api",
      "rule_id": "dast.xss.reflected",
      "weakness": "reflected xss",
      "cwe": "CWE-79",
      "severity": "medium",
      "confidence": "high",
      "method": "GET",
      "url": "https://web-api.example/search?q=%3Cscript%3E"
    }
  ]
}
```

Supported imported formats:

- native `security_evidence[]` JSON;
- simple `findings[]` JSON with the same fields;
- Semgrep JSON (`results[]`) with `extra.metadata.artifact`, `cwe`, confidence, and remediation metadata when available;
- SARIF (`runs[]`) with scanner metadata in `result.properties` or `driver.rules[].properties`; code-flow records promote the weakness to attacker-controlled source evidence.

Artifact matching is explicit. Prefer `artifact`, image reference, registry reference, or digest metadata that matches a supplied SBOM artifact. Unmatched SAST/DAST records are reported under `source-coverage.json.security_evidence.unmapped_records`.

High and critical SAST/DAST records should carry a CWE that maps to a maintained security profile. The scanner reports this as `source-coverage.json.security_evidence.summary.critical_profile_coverage`. Use `--min-critical-security-profile-coverage 1.0` to fail when imported critical code weaknesses are outside the maintained profile catalog.

Checked-in examples:

- `samples/security-evidence/semgrep-ce-xss.sarif` is a compact Semgrep SARIF example for an Express XSS finding.
- `samples/security-evidence/semgrep-nodejs-goof-command-injection.sarif` is based on the open-source `snyk-labs/nodejs-goof` vulnerable demo application and exercises command-injection evidence with a SARIF code-flow path.

## Security evidence pack JSON

Generated with `security-evidence-pack --output-dir`.

```json
{
  "schema_version": "1.0",
  "kind": "reachability-advisor-security-evidence-pack",
  "version": "2026-05-13",
  "profiles": [
    {
      "id": "sast-web-injection",
      "scanner_type": "sast",
      "cwes": ["CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-918"],
      "tools": ["semgrep", "codeql", "sarif"]
    },
    {
      "id": "dast-web-app",
      "scanner_type": "dast",
      "cwes": ["CWE-22", "CWE-79", "CWE-89", "CWE-352", "CWE-601", "CWE-918"],
      "tools": ["sarif", "generic-json", "dast-json"]
    }
  ],
  "release_gate": {
    "critical_profile_coverage": 1.0,
    "requires_cwe": true,
    "requires_maintained_profile": true,
    "selector_contract": "artifact plus scanner rule, source location, tested URL, CWE, or route"
  }
}
```

The pack writes Semgrep profile files for static findings and DAST profile metadata for dynamic findings. The fixtures under `fixtures/security-vulnerable-apps/` provide local vulnerable examples and normalized evidence for the maintained profiles. Tests require 100% expected profile/CWE coverage for those examples.

## Source evidence pack JSON

Generated with `source-evidence-pack --output-dir`.

```json
{
  "schema_version": "1.0",
  "kind": "reachability-advisor-source-evidence-pack",
  "version": "2026-05-13",
  "profile": {
    "name": "javascript-typescript",
    "ecosystems": ["npm", "pnpm", "yarn"],
    "tools": ["semgrep", "codeql"],
    "critical_package_families": ["http clients", "template engines"]
  },
  "profiles": [
    {"name": "npm", "ecosystems": ["npm", "pnpm", "yarn"]},
    {"name": "maven-gradle", "ecosystems": ["maven", "gradle"]},
    {"name": "python", "ecosystems": ["pypi", "poetry", "pip"]},
    {"name": "go", "ecosystems": ["go", "golang"]}
  ],
  "query_packs": [
    {"id": "http-client", "ecosystems": ["npm", "pypi", "maven", "go"]},
    {"id": "logging", "ecosystems": ["maven", "npm"]},
    {"id": "deserialization", "ecosystems": ["npm", "pypi", "maven", "go"]}
  ],
  "files": [
    "reachability/source-evidence-pack/semgrep-reachability.yml",
    "reachability/source-evidence-pack/semgrep/profiles/npm.yml",
    "reachability/source-evidence-pack/semgrep/profiles/maven-gradle.yml",
    "reachability/source-evidence-pack/semgrep/profiles/python.yml",
    "reachability/source-evidence-pack/semgrep/profiles/go.yml",
    "reachability/source-evidence-pack/query-packs/http-client.json",
    "reachability/source-evidence-pack/semgrep/query-packs/http-client.yml",
    "reachability/source-evidence-pack/codeql/query-packs/http-client/reachability-suite.qls",
    "reachability/source-evidence-pack/codeql/query-packs/http-client/metadata.json",
    "reachability/source-evidence-pack/codeql/reachability-suite.qls",
    "reachability/source-evidence-pack/codeql/profiles/npm/qlpack.yml",
    "reachability/source-evidence-pack/govulncheck/reachability-govulncheck.json"
  ],
  "release_gate": {
    "requires_external_evidence": true,
    "critical_external_evidence_coverage": 1.0,
    "critical_query_family_coverage": 1.0,
    "critical_proven_query_family_coverage": 1.0,
    "requires_relevant_query_family": true,
    "requires_proven_query_family": true,
    "rejects_dependency_only_critical_source": true,
    "selector_contract": "artifact plus package URL, component, or vulnerability selector"
  }
}
```

The pack is local project scaffolding. It writes maintained Semgrep metadata rules per package family, ecosystem-specific Semgrep profiles, package-family query pack metadata, CodeQL suite/profile files that run upstream security queries and preserve SARIF path evidence, govulncheck profile metadata, and a manifest that states the release-gate evidence contract. The repository also carries checked-in vulnerable sample apps and pinned public repository commits under `fixtures/source-vulnerable-apps/`; tests measure whether maintained family assets cover the expected local samples.

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
    "critical_findings_requiring_query_family": 4,
    "critical_findings_with_required_query_family": 3,
    "critical_findings_missing_query_family": 1,
    "critical_findings_without_maintained_query_family": 0,
    "source_rule_coverage": 0.9167,
    "critical_query_family_coverage": 0.75,
    "critical_proven_query_family_coverage": 0.75,
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

Policy file rules:

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
          "identity_policy": {
            "Statement": [
              {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "arn:aws:secretsmanager:*:*:secret:payments-*"}
            ]
          },
          "permissions_boundary": {
            "Statement": [
              {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "arn:aws:secretsmanager:*:*:secret:payments-prod-*"}
            ]
          },
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

Generated findings and evidence graphs include `effective_exposure`. Terraform plan and rendered Kubernetes inputs generate this record during analysis. External context files may also provide it directly.

`network_paths[]` may carry provider resources or an explicit provider network graph instead of only a label and hop list. When structured resources are present, provider evaluators build typed graph edges first and attach precedence evidence. Examples include AWS route/NACL/security-group records, Azure route/NSG rules, GCP route/firewall rules, and Kubernetes NetworkPolicy or service-mesh policy records. If the upstream renderer already has explicit links, use `network_graph.edges` or `network_edges`. Each edge uses `from`, `to`, and `type` or `kind`; provider evaluators solve a path from `entry` to `target` and evaluate each edge by type. Supported edge types include AWS `route`, `security_group`, `network_acl`, `load_balancer`, `api_gateway`, `serverless_url`, `waf`, and `private_endpoint`; Azure `network_security_group`, `route`, `gateway`, `access_restriction`, `auth`, `waf`, and `private_endpoint`; GCP `firewall`, `route`, `iap`, `cloud_armor`, `private_endpoint`, `serverless_ingress`, and `vpc_connector`; and Kubernetes `ingress`, `network_policy`, `service_mesh`, and `pod_security`. Route records should include destination prefixes such as `destination_cidr_block`, `address_prefix`, or `dest_range`; optional `source_cidr`/`source_ip` on the path lets the selector choose a more-specific return route. Private endpoint records should include `direction` or `target_role` when they describe outbound dependency access rather than inbound service exposure. Service-mesh policy records should include `action` and source principal fields when authz matching is known. The solved path is emitted as `network.network_graph` with per-edge state, blockers, unknowns, `precedence`, `precedence_reason`, and `resource_graph.precedence_rules`.

```json
{
  "network_paths": [
    {
      "provider": "aws",
      "exposure": "public",
      "entry": "internet",
      "target": "aws_ecs_service.api",
      "network_graph": {
        "edges": [
          {"from": "internet", "to": "aws_route.public", "type": "route", "destination_cidr_block": "0.0.0.0/0", "gateway_id": "igw-123"},
          {"from": "aws_route.public", "to": "aws_security_group.api", "type": "security_group", "cidr_blocks": ["10.0.0.0/8"]},
          {"from": "aws_security_group.api", "to": "aws_ecs_service.api", "type": "load_balancer"}
        ]
      },
      "network_acls": {
        "ingress": [
          {"id": "acl-deny", "rule_number": 90, "rule_action": "deny", "cidr_block": "0.0.0.0/0"},
          {"id": "acl-allow", "rule_number": 100, "rule_action": "allow", "cidr_block": "0.0.0.0/0"}
        ]
      }
    }
  ]
}
```

`effective_access[]` can include structured provider policy documents. Supported keys are AWS `identity_policy`, `resource_policy`, `permissions_boundary`, `service_control_policy`, `session_policy`, and `trust_policy`; Azure `role_assignment`, `role_definition`, `deny_assignment`, and `resource_policy`; GCP `iam_policy`, `deny_policy`, `principal_access_boundary`, `organization_policy`, and `resource_policy`; and Kubernetes `rules`, `role`, `cluster_role`, `role_binding`, and `cluster_role_binding`. Azure and GCP also expand a small catalog of common built-in role names when the document has a role name but no expanded permission list. The provider policy engine parses those documents into statement ASTs and evaluates principal, action, resource, and condition matches before selecting the effective identity decision. Runtime values for conditional policies can be supplied under `condition_context` or `request_context`. Conditional allows remain `constrained_allow`; unsatisfied conditions do not match; unknown conditions are reported as blockers and unknowns. The selected result is written under `identity.policy_evaluation` and mirrored in `identity.effective_access_model`.

```json
{
  "id": "effective-exposure:payments-api:abc123",
  "artifact": "payments-api",
  "provider": "aws",
  "decision": "constrained",
  "decision_basis": "network:constrained_by:auth_required; identity:constrained_by:scoped_resource",
  "exposure": "public",
  "entry": "internet",
  "path_type": "public_load_balancer",
  "confidence": "medium",
  "evaluator": "aws.effective_exposure",
  "network": {
    "decision": "constrained",
    "decision_basis": "constrained_by:auth_required",
    "blockers": [{"kind": "auth_required", "effect": "constrains"}]
  },
  "identity": {
    "decision": "constrained_allow",
    "action": "secretsmanager:GetSecretValue",
    "impact": "data_access",
    "policy_layer": "identity_policy",
    "decision_basis": "allowed",
    "provider_decision_basis": "constrained_by:scoped_resource",
    "evaluation_order": [
      {"step": "explicit_deny", "state": "not_observed"},
      {"step": "identity_and_resource_policy_allow", "state": "matched"},
      {"step": "conditions_and_scope", "state": "matched"},
      {"step": "effective_decision", "state": "constrained_allow"}
    ],
    "effective_access_model": {
      "authorization_model": "aws_iam",
      "identity": "aws_iam_role.payments",
      "action": "secretsmanager:GetSecretValue",
      "policy_layer": "identity_policy",
      "decision": "constrained_allow",
      "policy_engine": "aws.structured_policy",
      "policy_evaluation": {
        "decision": "constrained_allow",
        "policy_layer": "permissions_boundary",
        "matched_statements": [],
        "condition_keys": []
      },
      "resource_scope": "scoped",
      "blocking_reasons": [],
      "constraints": ["scoped_resource"],
      "conditions": []
    }
  },
  "edges": []
}
```

Decision values:

| Decision | Meaning |
|---|---|
| `reachable` | A provider-specific network path is linked and no blocker is visible. |
| `constrained` | The path exists, but auth, WAF/firewall, scoped IAM, or conditions reduce confidence. |
| `blocked` | The selected provider evidence contains a blocking condition for the path. |
| `isolated` | No direct or lateral ingress path is visible for a private asset. |
| `unknown` | The supplied evidence is not enough to decide the path. |
| `reachable_without_effective_identity` | Network path is reachable, but effective IAM evidence is denied or absent for blast-radius scoring. |

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
  "artifact_matches": [
    {
      "artifact": "payments-api",
      "resource": "kubernetes_deployment.payments-api",
      "type": "kubernetes_deployment",
      "provider": "kubernetes",
      "image": "ghcr.io/example/payments-api:1.8.2",
      "match_method": "exact-reference",
      "match_score": 100,
      "match_confidence": "high"
    }
  ],
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
    "artifacts_with_deployment_matches": 1,
    "deployment_match_coverage": 1.0,
    "artifacts_with_terraform_matches": 1,
    "terraform_match_coverage": 1.0,
    "artifacts_with_kubernetes_matches": 0,
    "kubernetes_match_coverage": 0.0,
    "artifact_match_coverage": 1.0,
    "artifacts_with_strong_deployment_matches": 1,
    "strong_deployment_match_coverage": 1.0,
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
      "deployment_matched": true,
      "strong_deployment_match": true,
      "deployment_matches": [],
      "terraform_matched": true,
      "strong_terraform_match": true,
      "terraform_matches": [],
      "kubernetes_matched": false,
      "strong_kubernetes_match": false,
      "kubernetes_matches": [],
      "mapping_warnings": []
    }
  ]
}
```

`artifact_match_coverage` is deployment coverage: an artifact can be matched through Terraform plan/source evidence or rendered Kubernetes manifest evidence. Provider-specific ratios stay available as `terraform_match_coverage` and `kubernetes_match_coverage`.

Schema draft: `schemas/mapping-report.schema.json`. The coverage ratios are designed for CI gates: artifact deployment mapping, strong image/digest identity, source-root presence, and mapping warning count.

## CI artifact manifest JSON

Passed with `--artifact-manifest`. Use it when the build knows the image digest or registry reference but the SBOM does not preserve it.

```json
{
  "artifacts": [
    {
      "name": "payments-api",
      "sbom": "sboms/payments-api.cdx.json",
      "image": "ghcr.io/example/payments-api:1.8.2",
      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "registry_ref": "ghcr.io/example/payments-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "git_sha": "abc123",
      "helm_values_image": "ghcr.io/example/payments-api:1.8.2",
      "kustomize_image": "ghcr.io/example/payments-api:1.8.2",
      "terraform_image": "ghcr.io/example/payments-api:1.8.2"
    }
  ],
  "signature": {}
}
```

`signature`, `attestation`, `slsa`, or `sigstore_bundle` are recorded as provenance markers only. Reachability Advisor does not cryptographically verify them.

Schema draft: `schemas/artifact-manifest.schema.json`.

Generate and validate a manifest in CI:

```bash
reachability-advisor artifact-manifest init \
  --artifact payments-api \
  --sbom sboms/payments-api.cdx.json \
  --image ghcr.io/example/payments-api:1.8.2 \
  --digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --registry-ref ghcr.io/example/payments-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --git-sha "$GITHUB_SHA" \
  --out reachability/artifacts.json

reachability-advisor artifact-manifest validate \
  --manifest reachability/artifacts.json \
  --out reachability/artifact-manifest-validation.json \
  --strict-provenance \
  --fail-on-warning
```

Validation reports whether each artifact has a strong image reference or digest, an SBOM path, Git identity, and a signature marker. `--strict-provenance` blocks release use unless each artifact has digest-level identity, an SBOM path, a valid Git SHA, no unresolved image expression, and a signature or attestation marker. `scan --require-artifact-provenance` applies the same gate to all `--artifact-manifest` inputs.

## Rendered IaC plan JSON

Generated with `rendered-iac-plan --out-json`.

```json
{
  "schema_version": "1.0",
  "kind": "reachability-advisor-rendered-iac-plan",
  "commands": [
    {
      "tool": "shell",
      "purpose": "create the local directory used for rendered evidence",
      "command": "mkdir -p reachability",
      "output": "reachability"
    },
    {
      "tool": "terraform",
      "purpose": "create a Terraform plan from the deployable module",
      "command": "terraform -chdir=infra plan -out=tfplan.binary",
      "output": "infra/tfplan.binary"
    },
    {
      "tool": "terraform",
      "purpose": "render Terraform plan JSON for release-gate context",
      "command": "terraform -chdir=infra show -json tfplan.binary > reachability/tfplan.json",
      "output": "reachability/tfplan.json"
    }
  ]
}
```

This is a helper artifact, not scan evidence. It records the exact Terraform, Helm, and Kustomize render commands a pipeline should run before `scan`.

## Readiness report JSON

Generated with `--readiness-out` or `evidence-profile`.

```json
{
  "schema_version": "1.0",
  "status": "blocked",
  "summary": {
    "blockers": 3,
    "warnings": 0,
    "artifacts": 1,
    "critical_external_evidence_coverage": 0.0,
    "critical_query_family_coverage": 0.0,
    "critical_proven_query_family_coverage": 0.0,
    "artifacts_missing_release_identity": 1,
    "artifacts_missing_workload_match": 0,
    "artifacts_missing_network_path": 0,
    "artifacts_missing_identity_path": 0
  },
  "blockers": [
    {
      "kind": "critical_source_coverage",
      "message": "critical external source evidence coverage is 0.0000; expected 1.0"
    },
    {
      "kind": "critical_source_query_family_coverage",
      "message": "critical source query-family coverage is 0.0000; expected 1.0"
    },
    {
      "kind": "critical_source_proven_query_family_coverage",
      "message": "critical proven query-family coverage is 0.0000; expected 1.0"
    }
  ],
  "warnings": [],
  "artifacts": [
    {
      "artifact": "payments-api",
      "terraform_matched": true,
      "strong_terraform_match": true,
      "kubernetes_matched": false,
      "artifact_identity_strength": "image_reference",
      "missing": [],
      "warnings": []
    }
  ]
}
```

The report lists missing image digest or exact image reference, missing SBOM path, missing or weak deployment workload match, missing network path evidence, missing identity/effective-access evidence, low-confidence network or identity evidence, critical source coverage gaps, critical query-family coverage gaps, critical proven query-family coverage gaps, and unrendered Terraform or Kubernetes evidence.

Schema draft: `schemas/readiness.schema.json`.

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

The main scan output is:

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

`context.iam_capabilities[]` is the per-resource IAM view behind `privilege` and `iam_impacts`. Each capability records an action, effect, policy layer, impact class, access class, resource references when known, resource scope (`scoped`, `wildcard`, or `unknown`), IAM condition keys when present, provider, source resource, and evidence string. This is useful when a role is not admin but still grants critical rights such as secret reads, network mutation, workload mutation, or role passing.

`context.effective_access[]` records the workload identity/resource/action decision used by scoring. It includes `decision`, `decision_basis`, `policy_layer`, `confidence`, blockers, target resources, and the underlying Terraform or rendered manifest evidence. When structured provider policy documents are present, provider engines evaluate deny precedence, boundaries, trust, inherited scope, conditions, resource policies, and workload identity constraints before record selection. Matching explicit denies mark allow records as `denied_by_explicit_deny`. The provider evaluator selects the effective record and writes `identity.evaluation_order`, `identity.policy_evaluation`, and `identity.effective_access_model` in each `effective_exposure[]` result.

Schema draft: `schemas/findings.schema.json`.

## Real-app benchmark snapshot JSON

`scripts/run_complex_app_validation.py` writes `benchmark.json` for the scale corpus. Snapshot expectations live in `fixtures/benchmarks/real-app-tier-snapshots.json`.

```json
{
  "schema_version": "1.0",
  "snapshots": [
    {
      "id": "external-complex-aggregate",
      "expected_tier_counts": {
        "urgent": 0,
        "high": 1,
        "medium": 105,
        "low": 69,
        "informational": 12
      },
      "regression_limits": {
        "max_count_by_tier": {"urgent": 0, "high": 2, "high_or_urgent": 2},
        "max_ratio_by_tier": {"high_or_urgent": 0.02}
      }
    }
  ]
}
```

Validate a new scale run:

```bash
reachability-advisor benchmark-snapshots \
  --benchmark outputs/external-complex/benchmark.json \
  --expectations fixtures/benchmarks/real-app-tier-snapshots.json \
  --out outputs/external-complex/benchmark-regression.json
```

The validator checks aggregate and per-case tier distributions, total finding drift, expected case status, and configured high/urgent limits. It is intentionally a regression guard against over-prioritization, not a replacement for reviewing the underlying findings.

Schema draft: `schemas/benchmark-snapshots.schema.json`.

## Scoring benchmark JSON

`configs/scoring-benchmark.json` is the unit-level scoring contract. It is separate from the real-app snapshot because it checks specific decisions, not only tier counts.

```json
{
  "schema_version": "1.0",
  "require_expected_decisions": true,
  "cases": [
    {
      "id": "public-request-controlled-sensitive",
      "component": {"name": "log4j-core", "scope": "runtime"},
      "vulnerability": {"id": "CVE-2021-44228", "package_name": "log4j-core", "cvss": 10.0, "known_exploited": true},
      "source": {"reachability": "attacker_controlled", "confidence": "high"},
      "context": {"exposure": "public", "environment": "prod", "privilege": "sensitive", "iam_impacts": ["data_access"]},
      "expected_tier": "urgent",
      "expected_decision": {
        "why": "Known exploited critical vulnerability in request-controlled public code with sensitive IAM.",
        "required_reason_labels": ["tier:urgent", "severity:critical", "source:attacker_controlled", "network:public", "iam_impact:data_access"]
      },
      "min_score": 85,
      "max_score": 100
    }
  ]
}
```

`required_reason_labels` are stable machine labels emitted by `scripts/validate_scoring_benchmark.py`. They cover severity, exploit intelligence, source evidence, network state, IAM, asset criticality, confidence, and score gates. A case fails when the expected tier is correct but the expected rationale labels are missing.

Schema draft: `schemas/scoring-benchmark.schema.json`.

## Evidence graph JSON

Generated with `--evidence-graph-out`. The findings JSON also embeds the same structure under `evidence_graph`.

The evidence graph is the machine-readable graph used by the HTML report. Its per-finding model is `effective_exposure_graph`:

```text
asset -> network path -> identity -> reachable code/package -> vulnerability or weakness -> score
```

Every effective edge carries `evidence_layer`, `origin_layer`, `evidence_source`, `confidence`, `provider`, `language`, `blockers`, `unknowns`, and `blocker_state`. Integrations that need the full prioritization chain should read this graph.

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

The baseline artifact is the default-branch input for pull-request gates. It keeps comparison fields and removes volatile evidence such as file paths, source snippets, rationale text, and raw network evidence.

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
- finding cards linked to the affected asset, including dependency vulnerabilities and imported code weaknesses with a plain code-exposure label such as `request-controlled path`, `reachable vulnerable API`, `dependency evidence`, `SBOM only`, or `no source rule`;
- colors that emphasize the highest tier/criticality on each asset and finding;
- a searchable, filterable findings list with click-through details.

The graph supports mouse-wheel zoom, drag-to-pan, tier filtering, exposure filtering, active-only filtering, and text search. Use `--out` findings JSON for automation.

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
