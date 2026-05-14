# Security Evidence

Security evidence is first-party scanner output for application weaknesses and cloud posture. It is separate from dependency vulnerability evidence.

## Finding Types

- `dependency_vulnerability`: package vulnerability from SBOM plus vulnerability intelligence.
- `static_code_weakness`: SAST finding from SARIF, Semgrep JSON, or normalized JSON.
- `dynamic_runtime_observation`: DAST finding from normalized JSON, ZAP JSON, or Nuclei JSONL.
- `cloud_posture_finding`: CSPM/configuration finding from normalized JSON, SARIF, Checkov, Trivy config, KICS, tfsec, or native local IaC checks.
- `correlated_security_finding`: reserved for non-destructive correlation views.

## Runtime Evidence

DAST writes `runtime_evidence`. It never automatically upgrades source reachability to request-controlled. If no source mapping exists, reports include `source mapping unavailable`.

## Posture Evidence

CSPM writes `posture_evidence`. It records the scanner/tool, provider, resource, expected state, actual state, IaC location when present, unknowns, blockers, and remediation. CSPM does not create runtime evidence or source reachability by itself.

## Correlation

Correlation adds `correlated_evidence[]` to findings. It does not hide, merge, suppress, or mark findings as not affected.

Supported correlation types:

- `sca_source_usage`
- `sast_dast_route_match`
- `dast_deployment_match`
- `sast_deployment_match`
- `sca_dast_same_artifact`
- `sca_sast_same_sink_or_package_family`
- `multi_tool_same_cwe`
- `weak_possible_relation`

Only strong evidence such as shared route and CWE should materially raise confidence.
