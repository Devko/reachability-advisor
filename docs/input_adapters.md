# Input Adapters

Reachability Advisor accepts scanner outputs that can be reviewed locally in CI. It does not call scanner APIs or cloud APIs.

## Vulnerability/SCA Inputs

Use `--vuln-in` for vulnerability scanner output.

Supported formats:

- Grype JSON with `matches[]`;
- OSV-style JSON with `results[]`;
- local JSON with `vulnerabilities[]` or `findings[]`.

Required fields for local JSON:

```json
{
  "vulnerabilities": [
    {
      "id": "GHSA-example",
      "package": {"name": "example-lib", "purl": "pkg:npm/example-lib@1.0.0"},
      "severity": "high"
    }
  ]
}
```

Useful optional fields: `cvss`, `epss`, `known_exploited`, `affected_versions`, `fixed_versions`, `aliases`, `references`, and artifact scope.

## Source Reachability Inputs

Use `--source-evidence-in`.

Supported formats:

- native Reachability Advisor source evidence JSON;
- Semgrep JSON with package or sink evidence;
- SARIF 2.1.0, including CodeQL `codeFlows`;
- govulncheck-style JSONL.

Source evidence can strengthen dependency findings. Built-in source analysis remains a fallback when external evidence is absent.

## SAST Inputs

Use `--sast-in` for explicit SAST files or `--security-evidence-in` for generic security evidence.

Supported formats:

- SARIF 2.1.0;
- Semgrep JSON;
- normalized JSON with `security_evidence[]`.

Minimal normalized SAST record:

```json
{
  "security_evidence": [
    {
      "scanner_type": "sast",
      "tool": "semgrep",
      "rule_id": "js.xss",
      "weakness": "Reflected XSS",
      "severity": "high",
      "cwe": "CWE-79",
      "artifact": "web-api",
      "route": "/search",
      "source": {"path": "src/app.js", "line": 12, "column": 5},
      "evidence": {"dataflow": "req.query.q -> res.send"}
    }
  ]
}
```

Semgrep `dataflow_trace` and SARIF `codeFlows` are stronger than location-only findings. Location-only SAST remains static evidence and does not prove runtime exposure.

## DAST Inputs

Use `--dast-in` for explicit DAST files or `--security-evidence-in` for generic security evidence.

Supported formats:

- normalized JSON with `security_evidence[]`;
- ZAP JSON;
- Nuclei JSONL.

Minimal normalized DAST record:

```json
{
  "security_evidence": [
    {
      "scanner_type": "dast",
      "tool": "zap",
      "rule_id": "40012",
      "weakness": "Reflected XSS",
      "severity": "high",
      "cwe": "CWE-79",
      "method": "GET",
      "url": "https://app.example.test/search?q=test",
      "parameter": "q",
      "response_evidence": "reflected payload"
    }
  ]
}
```

DAST creates runtime evidence. It does not set source reachability to request-controlled unless a source location or source data-flow record is also present.

## Limitations

- Scanner-controlled text is preserved only as bounded report evidence.
- Unmapped DAST URLs stay visible as visibility gaps.
- One-SBOM fallback is marked weak; it is not proof that the runtime route belongs to the artifact.
- Correlation links findings but does not prove causality.
