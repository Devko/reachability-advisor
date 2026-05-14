# Security Policy

## Supported Versions

The maintained release line is `1.x`.

## Private Reporting

Report suspected vulnerabilities through GitHub Private Vulnerability Reporting for this repository. If the button is not available, open a public issue that asks maintainers to enable private reporting, but do not include exploitable details in that issue.

Please include:

- affected version or commit;
- reproduction steps;
- impact;
- suggested fix, if known.

Targets:

- acknowledge within 7 days;
- triage within 14 days.

These are response targets, not a guarantee that every report will be fixed within that window.

## Scope

In scope:

- unsafe parsing of untrusted SBOM, vulnerability, source, SAST, DAST, context, Terraform, Kubernetes, or policy inputs;
- command injection or unsafe file paths in generated outputs;
- HTML, Markdown, SARIF, or diagnostics escaping bugs;
- unintended network calls or privacy leaks;
- incorrect policy exception handling.

Out of scope:

- inaccurate results caused by deliberately wrong user-supplied intelligence files;
- malicious repositories exploiting unrelated tools in a user's pipeline;
- findings in third-party scanners that Reachability Advisor only imports.
