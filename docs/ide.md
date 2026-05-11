# IDE Integration

The `ide/vscode` directory contains a VS Code extension wrapper that invokes the CLI and loads diagnostics from `--diagnostics-out`.

## Why a thin extension?

Security logic stays in the Python CLI so it can be tested, audited, and reused across CI and IDEs. The extension only handles editor integration.

## Extension behavior

1. Read workspace settings and discover common local SBOM/vulnerability file names.
2. Run `reachability-advisor scan` with the configured profile and evidence paths.
3. Read diagnostics JSON.
4. Filter diagnostics by minimum tier.
5. If a baseline is configured, run `reachability-advisor compare` and keep only new or worsened findings.
6. Publish diagnostics with related source and network evidence.
7. Open the selected finding evidence with `Reachability Advisor: Explain Finding`.

## Settings

```json
{
  "reachabilityAdvisor.executable": "reachability-advisor",
  "reachabilityAdvisor.sbom": "app.cdx.json",
  "reachabilityAdvisor.vulns": "vulnerabilities.json",
  "reachabilityAdvisor.analysisProfile": "advisory",
  "reachabilityAdvisor.sourceEvidence": ["reachability/semgrep.json"],
  "reachabilityAdvisor.terraformPlan": "tfplan.json",
  "reachabilityAdvisor.kubernetesManifest": ["k8s/rendered.yaml"],
  "reachabilityAdvisor.context": "reachability-context.json",
  "reachabilityAdvisor.sourceRootArtifact": "app",
  "reachabilityAdvisor.baseline": "reachability-baseline.json",
  "reachabilityAdvisor.diagnosticMinimumTier": "medium"
}
```

Use `analysisProfile: advisory` for local development. Use `production` only when the workspace has external source evidence and rendered deployment evidence available locally.

## Diagnostic severity mapping

| Finding tier | IDE severity |
|---|---|
| urgent/high | error |
| medium | warning |
| low | information |
| informational | hint |
