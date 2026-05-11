# IDE Integration

The `ide/vscode` directory contains a minimal VS Code extension skeleton that invokes the CLI and loads diagnostics from `--diagnostics-out`.

## Why a thin extension?

Security logic stays in the Python CLI so it can be tested, audited, and reused across CI and IDEs. The extension only handles editor integration.

## Extension behavior

1. Read workspace settings.
2. Run `reachability-advisor scan` with configured SBOM, vulnerability, source-root, and Terraform paths.
3. Read diagnostics JSON.
4. Publish diagnostics to VS Code.

## Settings

```json
{
  "reachabilityAdvisor.executable": "reachability-advisor",
  "reachabilityAdvisor.sbom": "app.cdx.json",
  "reachabilityAdvisor.vulns": "vulnerabilities.json",
  "reachabilityAdvisor.terraformPlan": "tfplan.json",
  "reachabilityAdvisor.context": "reachability-context.json",
  "reachabilityAdvisor.sourceRootArtifact": "app"
}
```

## Diagnostic severity mapping

| Finding tier | IDE severity |
|---|---|
| urgent/high | error |
| medium | warning |
| low | information |
| informational | hint |
