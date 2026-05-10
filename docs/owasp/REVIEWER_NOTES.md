# Reviewer Notes

## Why this should be a tool project

The project creates software that helps users detect and prioritize application security dependency risk in developer workflows. It does not provide offensive tooling and does not scan third-party targets.

## Why the scope is intentionally narrow

The project includes Terraform plan context, but keeps it local-first and developer-focused. It does not use live cloud credentials, runtime inventory, or posture-management workflows.

## Safety posture

- No network calls.
- No exploit generation.
- No automatic suppression.
- No live cloud credential use.
- Terraform resources are accounted for and unsupported types are visible as gaps.
- Community fixture packs exercise AWS, Azure, GCP, and Kubernetes module-shaped plans without cloud credentials.
- Conservative scoring and visible rationale.

## Community contribution opportunities

- Add language-specific reachability rules.
- Improve SARIF/diagnostic locations.
- Add scanner-output adapters.
- Add education labs for supply-chain prioritization.
- Add more sample projects.
- Add more community-maintained Terraform fixtures for common AWS, Azure, GCP, and Kubernetes modules.
- Add fixture packs for popular serverless, Kubernetes, and platform-as-a-service module families.
