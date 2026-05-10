# OWASP Reachability Advisor Project Page Draft

> This is a draft for the future owasp.org project page. Do not publish it as an OWASP project page until the project is accepted.

## Description

OWASP Reachability Advisor is a developer-first tool that helps prioritize dependency vulnerability alerts using SBOM data, source reachability hints, and optional AWS/Azure/GCP/Kubernetes Terraform deployment context. It produces SARIF, IDE diagnostics, Markdown PR summaries, GitHub Actions annotations, and Terraform coverage reports.

## Project information

- Project type: Tool
- Project stage requested: Incubator
- License: Apache-2.0
- Repository: TBD after OWASP acceptance
- Leaders: TBD, minimum 2 and maximum 5
- Contact: TBD, preferably owasp.org leader addresses after acceptance

## Why this matters

Dependency scanning often reports many vulnerabilities without enough developer context. Reachability Advisor helps answer: is the package merely present, imported, function-used, or likely touched by attacker-controlled input? It then combines that source evidence with optional local context such as public exposure, production environment, or sensitive privilege, including Terraform-derived context when available.

## Getting started

```bash
python -m pip install reachability-advisor
reachability-advisor scan --sbom app.cdx.json --vulns vulnerabilities.json --terraform-plan tfplan.json --terraform-coverage-out terraform-coverage.json --source-root app=. --sarif-out reachability.sarif
```

## Roadmap

- v1.0: focused CI/IDE edition.
- v2.0: multi-cloud Terraform coverage for AWS, Azure, GCP, and Kubernetes.
- v2.1: more package-manager, language, and Terraform module fixture coverage.
- v2.2: optional language-server wrapper and better baseline support.

## How to contribute

- Submit issues and pull requests.
- Add source reachability and Terraform resource rules with tests.
- Improve documentation and examples.
- Sign commits using DCO.
