# Scope

Reachability Advisor is a local-first CI/IDE prioritization and correlation layer for security findings.

## In Scope

- dependency vulnerability evidence from SBOM plus Grype, OSV-style, or local JSON;
- source reachability evidence from built-in rules, Semgrep, CodeQL/SARIF, and govulncheck-style data;
- SAST evidence from SARIF, Semgrep JSON, and normalized JSON;
- DAST evidence from normalized JSON, ZAP JSON, and Nuclei JSONL;
- Terraform plan/source and rendered Kubernetes manifest context;
- artifact identity manifests;
- prioritized findings, evidence paths, SARIF, diagnostics, Markdown, HTML graph, mapping, readiness, coverage, and PR deltas.

## Out Of Scope

- live cloud API calls;
- telemetry;
- secrets scanning;
- malware scanning;
- ticketing automation;
- broad CNAPP inventory;
- automatic suppression;
- automatic "not affected" conclusions.

## Safety Rules

Missing evidence remains unknown. Weak evidence can add context but must not be treated as proof of exploitability or proof of safety.
