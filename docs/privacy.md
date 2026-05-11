# Privacy Model

Reachability Advisor runs locally.

- No telemetry.
- No external API calls.
- No upload of SBOMs, source, Terraform plans, or vulnerability files.
- External source evidence is read from local files supplied with `--source-evidence-in`; the scanner does not invoke Semgrep, CodeQL, govulncheck, or other tools by itself.
- IDE diagnostics are generated locally.
- CI outputs stay in the pipeline workspace unless the user uploads them.

Use pipeline artifact rules to control which generated reports are retained.
