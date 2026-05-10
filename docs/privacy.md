# Privacy Model

Reachability Advisor is local-first.

- No telemetry.
- No external API calls.
- No upload of SBOMs, source, Terraform plans, or vulnerability files.
- IDE diagnostics are generated locally.
- CI outputs stay in the pipeline workspace unless the user uploads them.

This makes the tool suitable for organizations that want developer feedback without sending source or SBOM data to a hosted service.
