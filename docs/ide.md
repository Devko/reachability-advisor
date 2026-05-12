# IDE Integration

The `ide/vscode` directory contains a VS Code extension that invokes the CLI, loads diagnostics from `--diagnostics-out`, and opens a finding evidence explorer.

## Design

Scan logic stays in the Python CLI so CI and IDE runs use the same code path. The extension handles editor integration, profile validation, diagnostics, baseline filtering, and local evidence browsing.

## Extension behavior

1. Read workspace settings and discover common local SBOM/vulnerability file names.
2. Validate the selected profile before scanning.
3. Run `reachability-advisor scan` with the configured profile and evidence paths.
4. Read diagnostics JSON.
5. Filter diagnostics by minimum tier.
6. If a baseline is configured, run `reachability-advisor compare` and keep only new or worsened findings.
7. Publish diagnostics with related source and network evidence.
8. Open the selected finding as JSON with `Reachability Advisor: Explain Finding`.
9. Open `Reachability Advisor: Open Evidence Explorer` for searchable finding cards, baseline state, source evidence, network paths, IAM context, and score rationale.
10. Generate SBOM and source-evidence plans from VS Code commands.
11. Show the active profile in the status bar: advisory or release gate.

## Settings

```json
{
  "reachabilityAdvisor.executable": "reachability-advisor",
  "reachabilityAdvisor.sbom": "app.cdx.json",
  "reachabilityAdvisor.vulns": "vulnerabilities.json",
  "reachabilityAdvisor.profilePreset": "advisory",
  "reachabilityAdvisor.analysisProfile": "advisory",
  "reachabilityAdvisor.sourceEvidence": ["reachability/semgrep.json"],
  "reachabilityAdvisor.artifactManifest": ["reachability/artifacts.json"],
  "reachabilityAdvisor.terraformPlan": "tfplan.json",
  "reachabilityAdvisor.kubernetesManifest": ["k8s/rendered.yaml"],
  "reachabilityAdvisor.context": "reachability-context.json",
  "reachabilityAdvisor.sourceRootArtifact": "app",
  "reachabilityAdvisor.baseline": "reachability-baseline.json",
  "reachabilityAdvisor.diagnosticMinimumTier": "medium",
  "reachabilityAdvisor.openExplorerAfterScan": true
}
```

Use `profilePreset: advisory` for local development. Use `profilePreset: release-gate` only when the workspace has external source evidence and rendered deployment evidence available locally. Release-gate mode maps to `analysisProfile: production` and fails critical findings that only have dependency-level or uncovered external source evidence.

Commands:

- `Reachability Advisor: Validate Profile` reports missing SBOM, vulnerability JSON, external source evidence, rendered deployment evidence, and artifact manifest warnings.
- `Reachability Advisor: Generate SBOM Plan` writes `.reachability/sbom-plan.md` and `.reachability/sbom-plan.json`.
- `Reachability Advisor: Generate Source Evidence Plan` writes `.reachability/source-evidence-plan.md` and `.reachability/source-evidence-plan.json`.
- `Reachability Advisor: Open Evidence Explorer` opens the last scan result in a webview. It does not rescan.

## Evidence Explorer

The explorer is a local webview backed by the last diagnostics payload. It shows:

- profile state and active minimum tier;
- one row per finding with tier, score, artifact, component, vulnerability, baseline status, and source state;
- selected-finding details for source exposure, network exposure, IAM impact, effective path, and score rationale;
- raw evidence JSON for audit and issue handoff.

Use it for triage. Use CI artifacts from the same CLI run as the release record.

## Diagnostic severity mapping

| Finding tier | IDE severity |
|---|---|
| urgent/high | error |
| medium | warning |
| low | information |
| informational | hint |
