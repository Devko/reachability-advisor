# Reachability Advisor VS Code Extension

This extension is a local wrapper around the Python CLI. It does not implement scoring or security logic in JavaScript.

What it does:

- discovers common SBOM and vulnerability file names when settings are empty;
- runs `reachability-advisor scan` with the configured profile;
- supports Terraform plan, Terraform source, rendered Kubernetes manifests, source evidence, policy, and baseline settings;
- filters diagnostics by minimum tier;
- filters to new or worsened findings when a baseline is configured;
- opens a JSON evidence view for a selected finding.

## Development

1. Install the Python CLI in the workspace.
2. Open `ide/vscode` in VS Code.
3. Press `F5` to launch an extension host.
4. Configure the workspace settings below as needed.
5. Run `Reachability Advisor: Scan Workspace`.

## Settings

- `reachabilityAdvisor.executable`: CLI path. Default: `reachability-advisor`.
- `reachabilityAdvisor.sbom`: CycloneDX SBOM path. If empty or missing, the extension tries common local names.
- `reachabilityAdvisor.vulnIn`: Grype or normalized vulnerability JSON path. If empty or missing, the extension tries common local names.
- `reachabilityAdvisor.sourceRootArtifact`: artifact name used for `artifact=workspace`.
- `reachabilityAdvisor.analysisProfile`: `advisory` for local feedback, `production` for strict evidence gates.
- `reachabilityAdvisor.sourceEvidence`: Semgrep, CodeQL/SARIF, govulncheck, or native evidence paths.
- `reachabilityAdvisor.terraformPlan`: `terraform show -json` plan path.
- `reachabilityAdvisor.terraformSource`: Terraform source path for advisory scans.
- `reachabilityAdvisor.kubernetesManifest`: rendered Kubernetes YAML/JSON paths or directories.
- `reachabilityAdvisor.baseline`: baseline artifact used to show only new or worsened findings.
- `reachabilityAdvisor.diagnosticMinimumTier`: minimum tier shown in the editor.
