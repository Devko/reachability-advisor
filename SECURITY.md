# Security Policy

## Supported versions

The current maintained version is `1.x`.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers listed in `GOVERNANCE.md`. Do not open a public issue containing exploitable details until maintainers have assessed the report.

A report must include enough detail to reproduce and assess the issue:

- affected version or commit;
- reproduction steps;
- impact;
- suggested fix, if known.

## Scope

In scope:

- command injection in generated outputs;
- unsafe parsing of untrusted SBOM/vulnerability/context inputs;
- privacy leaks or unintended network calls;
- incorrect policy exception handling.

Out of scope:

- vulnerability results caused by deliberately wrong user-supplied intelligence files;
- malicious source repositories that exploit unrelated tools in the user's pipeline.
