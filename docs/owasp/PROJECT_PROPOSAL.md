# OWASP Project Proposal Draft

## Proposed project name

OWASP Reachability Advisor

## Project type

Tool project.

## Current status

Candidate package prepared for submission. This repository is not an accepted OWASP project until OWASP Foundation approval is granted.

## One-sentence description

Reachability Advisor helps developers prioritize dependency vulnerability alerts by combining SBOM presence, source-code reachability hints, optional Terraform deployment context, and developer-friendly CI/IDE outputs.

## Problem statement

Software composition analysis and SBOM workflows can produce large alert queues. Developers need a local-first way to understand which findings are most likely to matter in the code and deployment context they are working on, without depending on a hosted commercial platform.

## Goals

- Provide a free, open-source, vendor-neutral developer tool.
- Run locally in CI and IDE workflows.
- Produce actionable outputs: SARIF, diagnostics, Markdown summaries, annotations, JSON, and Terraform coverage reports.
- Use transparent algorithms that are easy for the community to review.
- Avoid unsafe automatic suppression.

## Non-goals

- Live cloud inventory.
- Commercial CNAPP/ASPM replacement.
- Secrets scanning.
- Malware scanning.
- DSPM.
- Automatic `not_affected` claims.

## Users

- Application developers.
- Security champions.
- AppSec teams.
- Open-source maintainers.
- Educators teaching secure software supply-chain workflows.

## Initial deliverables

- Python CLI.
- VS Code extension skeleton.
- GitHub Action wrapper.
- Multi-cloud sample dataset.
- Documentation, algorithms guide, and Terraform coverage guide.
- Security, governance, privacy, and contribution process.

## Project health commitments

- At least one public release per year.
- Public roadmap.
- Public issue tracker and pull request workflow.
- DCO sign-off.
- Apache-2.0 license for code.
- Community-accessible meetings if meetings are held.

## OWASP policy alignment checklist

| Requirement or expectation | Prepared status |
|---|---|
| Open-source tool/code project | Apache-2.0 repository prepared. |
| Defined roadmap and tasks | `docs/roadmap.md`. |
| Coverage transparency | `docs/terraform_coverage.md` and `schemas/terraform-coverage.schema.json`. |
| Project leaders | 2-5 leaders to be named before submission. |
| OWASP source platform | Ready to migrate into OWASP GitHub if approved. |
| Project page | Draft included in `PROJECT_PAGE_DRAFT.md`. |
| License | `LICENSE` and `NOTICE` included. |
| DCO | `DCO.md` and `CONTRIBUTING.md` included. |
| Activity/release cadence | Release process and annual release commitment documented. |
| Vendor neutrality | Explicit governance rule. |
| Community participation | Contributions open to the public. |

## References

- OWASP Projects page: https://owasp.org/projects/
- OWASP Project Policy: https://policy.owasp.org/operational/projects
- OWASP Project Handbook: https://www.owasp.community/project-handbook
