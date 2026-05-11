# Reachability Advisor VS Code Extension Skeleton

This extension skeleton runs the `reachability-advisor` CLI and displays diagnostics in VS Code.

The extension is a thin wrapper:

- no security logic in JavaScript;
- no network calls;
- no telemetry;
- diagnostics are read from the CLI's `--diagnostics-out` JSON.

## Manual development

1. Install the Python CLI in the workspace.
2. Open `ide/vscode` in VS Code.
3. Press `F5` to launch an extension host.
4. Configure `reachabilityAdvisor.sbom`, `reachabilityAdvisor.vulns`, `reachabilityAdvisor.sourceRootArtifact`, and Terraform settings.
5. Run `Reachability Advisor: Scan Workspace`.
