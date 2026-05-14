# Governance

Reachability Advisor uses maintainer review for code, documentation, tests, scope, and releases.

## Maintainers

- Devko organization maintainers for `Devko/reachability-advisor`.

GitHub Private Vulnerability Reporting is the private security contact path for this project.

## Responsibilities

- Review changes for evidence semantics, scoring behavior, output safety, and backwards compatibility.
- Require tests for parser, mapping, correlation, scoring, and output changes.
- Keep the project local-first. Do not add live cloud API calls, telemetry, ticketing automation, secrets scanning, malware scanning, or CNAPP-style inventory.
- For security-sensitive changes, require an explicit review of escaping, untrusted input handling, path handling, and evidence claims.

## Decision Process

- Routine changes: maintainer approval through pull request review.
- Security-sensitive changes: at least two maintainer approvals when project staffing allows it.
- Releases: tag-based release workflow plus maintainer approval.
- Scope changes: document them in `docs/roadmap.md` or `docs/maturity_targets.md`.

## Vendor Neutrality

The project can parse outputs from commercial or open-source scanners, but it must not endorse a vendor.
