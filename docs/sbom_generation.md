# SBOM Generation and Artifact Identity

Reachability Advisor consumes CycloneDX JSON SBOMs. The scanner does not generate SBOMs during `scan`; SBOM generation belongs in the build or image pipeline. The `sbom-plan` command prints tool-specific commands for that pipeline.

## One SBOM Per Deployable Artifact

Create one SBOM for each deployable unit that can appear in Terraform, Kubernetes, or runtime context.

Examples:

| Deployable unit | Recommended SBOM |
|---|---|
| Container image | SBOM generated from the built image, preferably including image digest. |
| Lambda zip package | SBOM generated from the packaged build output or source tree. |
| Java service | Maven/Gradle SBOM for dependency graph, plus image SBOM when deployed as a container. |
| Node service | npm or image SBOM. |
| Python service | environment/package SBOM, plus image SBOM when deployed as a container. |

Use runtime or image SBOMs for release gates. Use source or filesystem SBOMs for early PR and IDE feedback. Preserve CycloneDX `dependencies` entries when the SBOM tool emits them; Reachability Advisor uses that graph to identify transitive packages reached through imported parent dependencies.

## Generate an SBOM plan

```bash
PYTHONPATH=src python -m reachability_advisor sbom-plan \
  --artifact payments-api \
  --image ghcr.io/example/payments-api:1.8.2 \
  --source-root . \
  --ecosystem maven \
  --out-md outputs/payments-api-sbom-plan.md \
  --out-json outputs/payments-api-sbom-plan.json
```

The command prints or writes suggested commands for Syft, Trivy, and ecosystem-specific tools.

## Common SBOM commands

Container image with Syft:

```bash
syft ghcr.io/example/payments-api:1.8.2 -o cyclonedx-json=sboms/payments-api.cdx.json
```

Container image with Trivy:

```bash
trivy image --format cyclonedx --output sboms/payments-api.cdx.json ghcr.io/example/payments-api:1.8.2
```

Filesystem/source tree with Trivy:

```bash
trivy fs --format cyclonedx --output sboms/payments-api.cdx.json .
```

Maven aggregate BOM:

```bash
mvn -q org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -DoutputFormat=json
```

Node/npm BOM:

```bash
npm sbom --sbom-format cyclonedx > sboms/notifier.cdx.json
```

Python environment BOM:

```bash
cyclonedx-py environment --of JSON -o sboms/worker.cdx.json
```

## Required metadata for reliable mapping

The scanner can parse minimal SBOMs, but Terraform mapping depends on artifact identity. Include the deployed image reference or digest whenever possible.

Recommended CycloneDX metadata component shape:

```json
{
  "metadata": {
    "component": {
      "type": "application",
      "name": "payments-api",
      "version": "1.8.2",
      "properties": [
        {"name": "container:image", "value": "ghcr.io/example/payments-api:1.8.2"},
        {"name": "oci:image:ref", "value": "ghcr.io/example/payments-api@sha256:..."},
        {"name": "owner", "value": "team-payments"},
        {"name": "environment", "value": "prod"}
      ],
      "externalReferences": [
        {"type": "distribution", "url": "ghcr.io/example/payments-api:1.8.2"},
        {"type": "vcs", "url": "https://example.invalid/repo/payments-api"}
      ]
    }
  }
}
```

Artifact metadata property names:

| Property | Purpose |
|---|---|
| `container:image` | Preferred image reference for artifact-to-Terraform matching. |
| `oci:image:ref` | Preferred digest reference when available. |
| `reachability:artifact_ref` | Explicit override inserted by `--artifact-alias`. |
| `owner` or `team` | Developer routing. |
| `environment` | Scoring context when Terraform/context JSON is absent. |

## Artifact aliases

When a generated SBOM lacks image metadata, add an alias at scan time instead of editing the SBOM:

```bash
reachability-advisor scan \
  --sbom sboms/payments-api.cdx.json \
  --artifact-alias payments-api=ghcr.io/example/payments-api:1.8.2 \
  --vuln-in vulnerabilities.json
```

Aliases are visible in the mapping report and are treated as evidence, not hidden assumptions.
