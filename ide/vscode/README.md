# Reachability Advisor VS Code Extension Skeleton

This minimal extension runs the `reachability-advisor` CLI and displays diagnostics in VS Code.

It is intentionally a thin wrapper:

- no security logic in JavaScript;
- no network calls;
- no telemetry;
- diagnostics are read from the CLI's `--diagnostics-out` JSON.

## Manual development

1. Install the Python CLI in the workspace.
2. Open `ide/vscode` in VS Code.
3. Press `F5` to launch an extension host.
4. Configure `reachabilityAdvisor.sbom`, `reachabilityAdvisor.vulns`, and `reachabilityAdvisor.sourceRootArtifact`.
5. Run `Reachability Advisor: Scan Workspace`.
