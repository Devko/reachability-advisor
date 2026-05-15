# User-Facing Messages

Reachability Advisor is often used in CI by people who did not build the evidence pipeline. Every CLI error, readiness blocker, Markdown line, SARIF message, and HTML label should explain the evidence in direct terms.

## Message Rules

- Say what happened before saying how to fix it.
- Name the missing evidence directly: SBOM path, image digest, exact image reference, source analyzer evidence, rendered Terraform plan, rendered Kubernetes manifest, network path evidence, or IAM/RBAC evidence.
- Do not treat missing evidence as safe. Use `unknown`, `visibility gap`, or `advisory` when the tool cannot prove a path.
- Prefer `priority` over `severity` when talking about Reachability Advisor output. Scanner severity is an input; priority is the tool's scored result.
- Prefer `network exposure` over plain `exposure`.
- Prefer `IAM/RBAC privilege` or `effective access` over plain `privilege` when the message is about identity.
- Prefer `source evidence` over plain `source` when explaining reachability.
- Avoid internal shorthand in user-visible surfaces. Expand SAST, DAST, CSPM, SBOM, IAM, and RBAC when there is room, or pair the acronym with plain language.
- Every release-gate blocker should include impact and a next step.

## Standard Terms

| Term | Use it for |
|---|---|
| `advisory` | A result that is useful for triage but is not complete enough to block a release. |
| `release gate` | A strict CI decision based on complete artifact identity, source evidence, and deployment evidence. |
| `artifact identity` | Evidence that ties a finding to the exact built artifact, preferably an image digest or exact image reference. |
| `source analyzer evidence` | External Semgrep, CodeQL/SARIF, govulncheck, or equivalent evidence that proves source usage or reachability. |
| `rendered deployment evidence` | Terraform plan JSON from `terraform show -json` or rendered Kubernetes YAML/JSON. |
| `network path evidence` | Ingress, route, firewall, security group, NetworkPolicy, service mesh, or private endpoint evidence linked to a workload. |
| `effective access` | IAM/RBAC evidence showing what the workload identity can do, including deny rules and scope. |
| `visibility gap` | Evidence that is missing or opaque. It is not proof that the asset is safe. |

## Good Message Shape

Use this structure for CLI failures and readiness blockers:

```text
<artifact or gate>: <plain problem>. <why it matters>. Next step: <specific evidence or command family to provide>.
```

Examples:

- `payments-api: artifact identity is too weak for a release gate. Add an exact deployed image reference or image digest.`
- `Production profile requires rendered deployment evidence. Provide --terraform-plan from terraform show -json or --kubernetes-manifest with rendered YAML/JSON.`
- `No external source analyzer evidence was imported. Run Semgrep, CodeQL/SARIF, govulncheck, or an equivalent analyzer and pass the output with --source-evidence-in, --sast-in, or --security-evidence-in.`

## Surface Checklist

When changing behavior, review these user-facing surfaces in the same change:

- CLI help in `src/reachability_advisor/cli.py`;
- validation messages in `src/reachability_advisor/validators.py`;
- readiness blockers and warnings in `src/reachability_advisor/readiness.py`;
- JSON/SARIF/Markdown summaries in `src/reachability_advisor/outputs.py`;
- HTML report labels and empty states in `src/reachability_advisor/visual.py`;
- docs that teach the affected workflow.
