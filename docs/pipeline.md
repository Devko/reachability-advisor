# CI Pipeline Integration

Reachability Advisor runs after SBOM, vulnerability, source-evidence, and deployment-evidence generation. A production gate requires these inputs for each deployable artifact:

1. CycloneDX SBOM.
2. Grype JSON generated from that SBOM.
3. Source root for local mapping and advisory fallback checks.
4. External source reachability evidence from Semgrep, CodeQL/SARIF, govulncheck, or native Reachability Advisor evidence.
5. Terraform plan JSON and/or rendered Kubernetes manifests for workload, network, and IAM context.
6. CI artifact manifest when the SBOM does not carry the built image digest or registry reference.

The scanner itself does not call external services. Keep Syft, Grype, Terraform, and artifact upload steps in the pipeline so teams can pin versions, cache databases, and control credentials.

## GitHub Actions Workflow

This example targets GitHub-hosted Linux runners. It uses source-mode SBOM generation for pull requests because no image exists yet. The release variant below uses an image SBOM.

```yaml
name: reachability-advisor

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  reachability:
    runs-on: ubuntu-latest

    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Reachability Advisor
        run: |
          python -m pip install --upgrade pip
          python -m pip install git+https://github.com/Devko/reachability-advisor.git@main
          python -m pip install semgrep

      - name: Install Syft and Grype
        run: |
          mkdir -p "$HOME/.local/bin"
          curl -sSfL https://get.anchore.io/syft | sh -s -- -b "$HOME/.local/bin"
          curl -sSfL https://get.anchore.io/grype | sh -s -- -b "$HOME/.local/bin"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      - name: Generate SBOM and vulnerability matches
        run: |
          mkdir -p sboms vulns reachability
          syft dir:. -o cyclonedx-json=sboms/app.cdx.json
          grype sbom:sboms/app.cdx.json -o json --file vulns/app.grype.json

      - name: Set up Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_wrapper: false

      - name: Write rendered IaC command plan
        run: |
          reachability-advisor rendered-iac-plan \
            --terraform-dir infra \
            --helm-chart charts/app \
            --helm-release app \
            --helm-namespace default \
            --kustomize-dir k8s/overlays/prod \
            --out-md reachability/rendered-iac-plan.md \
            --out-json reachability/rendered-iac-plan.json

      - name: Generate Terraform plan context
        run: |
          terraform -chdir=infra init -backend=false
          terraform -chdir=infra plan -refresh=false -out=tfplan.binary
          terraform -chdir=infra show -json tfplan.binary > reachability/tfplan.json

      - name: Render Kubernetes manifests
        run: |
          # Replace this with `helm template`, `kustomize build`, or the checked-in rendered YAML path used by your repository.
          test ! -d k8s || cp k8s/*.yaml reachability/ || true

      - name: Generate source reachability evidence
        run: |
          reachability-advisor source-evidence-pack \
            --language javascript \
            --output-dir reachability/source-evidence-pack
          reachability-advisor source-evidence-plan \
            --source-root . \
            --language javascript \
            --out-md reachability/source-evidence-plan.md \
            --out-json reachability/source-evidence-plan.json
          semgrep scan --config reachability/source-evidence-pack/semgrep-reachability.yml --json --output reachability/semgrep.json

      - name: Run reachability prioritization
        run: |
          k8s_args=()
          if compgen -G "reachability/*.yaml" > /dev/null; then
            k8s_args+=(--kubernetes-manifest reachability --kubernetes-coverage-out reachability/kubernetes-coverage.json)
          fi
          reachability-advisor scan \
            --sbom sboms/app.cdx.json \
            --vulns vulns/app.grype.json \
            --source-root app=. \
            --source-evidence-in reachability/semgrep.json \
            --terraform-plan reachability/tfplan.json \
            --terraform-coverage-out reachability/terraform-coverage.json \
            "${k8s_args[@]}" \
            --analysis-profile production \
            --require-strong-source-for-critical \
            --source-coverage-out reachability/source-coverage.json \
            --mapping-out reachability/mapping.json \
            --readiness-out reachability/readiness.json \
            --require-release-ready \
            --min-critical-external-source-coverage 1.0 \
            --out reachability/findings.json \
            --evidence-graph-out reachability/evidence-graph.json \
            --sarif-out reachability/reachability.sarif \
            --markdown-out reachability/summary.md \
            --html-out reachability/reachability-graph.html \
            --annotations-out reachability/annotations.txt \
            --fail-on-tier high

      - name: Publish annotations and job summary
        if: always()
        run: |
          test ! -f reachability/annotations.txt || cat reachability/annotations.txt
          test ! -f reachability/summary.md || cat reachability/summary.md >> "$GITHUB_STEP_SUMMARY"

      - name: Upload SARIF
        if: always() && hashFiles('reachability/reachability.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reachability/reachability.sarif

      - name: Upload reachability artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: reachability-advisor
          path: |
            sboms/*.json
            vulns/*.json
            reachability/*.json
            reachability/*.sarif
            reachability/*.md
            reachability/*.html
            reachability/*.txt
```

For repositories that vendor Reachability Advisor as a development dependency, replace the install command with:

```bash
python -m pip install -e .
```

## Composite Action Variant

The composite action installs the scanner from this repository. It accepts newline-separated SBOMs, source roots, artifact aliases, artifact manifests, rendered Kubernetes manifests, and an optional default-branch baseline, then exposes fixed output paths for SARIF/artifact upload steps.

```yaml
      - name: Run Reachability Advisor
        id: reachability
        uses: Devko/reachability-advisor@main
        with:
          sbom: |
            sboms/app.cdx.json
          vulns: vulns/app.grype.json
          source-root: |
            app=.
          source-evidence-in: |
            reachability/semgrep.json
          artifact-manifest: |
            reachability/artifacts.json
          require-artifact-provenance: "true"
          terraform-plan: reachability/tfplan.json
          kubernetes-manifest: |
            k8s/rendered.yaml
          analysis-profile: production
          policy: configs/policy.example.json
          baseline: reachability-baseline.json
          min-artifact-match-coverage: "0.9"
          min-strong-artifact-identity-coverage: "0.9"
          min-source-rule-coverage: "0.8"
          require-strong-source-for-critical: "true"
          min-external-evidence-usable-ratio: "0.8"
          min-critical-external-source-coverage: "1.0"
          require-release-ready: "true"
          fail-on-mapping-warnings: "true"
          fail-on-new-tier: high

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.reachability.outputs.sarif }}

      - name: Upload reachability artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: reachability-advisor
          path: |
            ${{ steps.reachability.outputs.findings }}
            ${{ steps.reachability.outputs.mapping }}
            ${{ steps.reachability.outputs.terraform_coverage }}
            ${{ steps.reachability.outputs.kubernetes_coverage }}
            ${{ steps.reachability.outputs.source_coverage }}
            ${{ steps.reachability.outputs.readiness }}
            ${{ steps.reachability.outputs.baseline }}
            ${{ steps.reachability.outputs.delta }}
            ${{ steps.reachability.outputs.delta_markdown }}
            ${{ steps.reachability.outputs.markdown }}
            ${{ steps.reachability.outputs.html }}
```

Pin this to a release tag when one is available.

## Release Gate Variant

For release branches and deployment gates, scan the built artifact instead of the source checkout. The source checkout is still passed to Reachability Advisor so source reachability evidence can be collected.

```yaml
      - name: Build image
        run: |
          IMAGE_REF="ghcr.io/${{ github.repository }}/app:${{ github.sha }}"
          docker build -t "$IMAGE_REF" .
          IMAGE_DIGEST="$(docker image inspect "$IMAGE_REF" --format '{{.Id}}')"
          echo "IMAGE_REF=$IMAGE_REF" >> "$GITHUB_ENV"
          echo "IMAGE_DIGEST=$IMAGE_DIGEST" >> "$GITHUB_ENV"
          echo "REGISTRY_REF=$IMAGE_REF@$IMAGE_DIGEST" >> "$GITHUB_ENV"

      - name: Generate image SBOM and vulnerability matches
        run: |
          mkdir -p sboms vulns reachability
          syft "$IMAGE_REF" -o cyclonedx-json=sboms/app.cdx.json
          grype sbom:sboms/app.cdx.json -o json --file vulns/app.grype.json

      - name: Write CI artifact manifest
        run: |
          reachability-advisor artifact-manifest init \
            --artifact app \
            --sbom sboms/app.cdx.json \
            --image "$IMAGE_REF" \
            --digest "$IMAGE_DIGEST" \
            --registry-ref "$REGISTRY_REF" \
            --git-sha "${{ github.sha }}" \
            --signed \
            --out reachability/artifacts.json
          reachability-advisor artifact-manifest validate \
            --manifest reachability/artifacts.json \
            --strict-provenance \
            --out reachability/artifact-manifest-validation.json \
            --fail-on-warning

      - name: Generate Terraform plan context
        run: |
          terraform -chdir=infra init -backend=false
          terraform -chdir=infra plan -refresh=false -out=tfplan.binary
          terraform -chdir=infra show -json tfplan.binary > reachability/tfplan.json

      - name: Generate source reachability evidence
        run: |
          reachability-advisor source-evidence-pack \
            --language javascript \
            --output-dir reachability/source-evidence-pack
          reachability-advisor source-evidence-plan \
            --source-root . \
            --language javascript \
            --out-md reachability/source-evidence-plan.md \
            --out-json reachability/source-evidence-plan.json
          semgrep scan --config reachability/source-evidence-pack/semgrep-reachability.yml --json --output reachability/semgrep.json

      - name: Run release gate
        run: |
          reachability-advisor scan \
            --sbom sboms/app.cdx.json \
            --vulns vulns/app.grype.json \
            --source-root app=. \
            --source-evidence-in reachability/semgrep.json \
            --artifact-manifest reachability/artifacts.json \
            --require-artifact-provenance \
            --terraform-plan reachability/tfplan.json \
            --terraform-coverage-out reachability/terraform-coverage.json \
            --kubernetes-manifest k8s/rendered.yaml \
            --kubernetes-coverage-out reachability/kubernetes-coverage.json \
            --analysis-profile production \
            --require-strong-source-for-critical \
            --source-coverage-out reachability/source-coverage.json \
            --mapping-out reachability/mapping.json \
            --readiness-out reachability/readiness.json \
            --require-release-ready \
            --min-critical-external-source-coverage 1.0 \
            --out reachability/findings.json \
            --evidence-graph-out reachability/evidence-graph.json \
            --sarif-out reachability/reachability.sarif \
            --markdown-out reachability/summary.md \
            --html-out reachability/reachability-graph.html \
            --annotations-out reachability/annotations.txt \
            --fail-on-tier high
```

Use `--terraform-source infra` only for advisory feedback when a plan cannot be generated in the job. Source mode cannot evaluate modules, `count`, `for_each`, data sources, provider defaults, rendered Helm output, or generated Kubernetes child resources. It is rejected by `--analysis-profile production`.

## Baseline Pipeline Pattern

1. Generate one CycloneDX SBOM per deployable artifact.
2. Generate Grype JSON from the same SBOM.
3. Pass the matching source checkout with `--source-root name=path`.
4. Import source evidence with `--source-evidence-in`; use built-in rules only as fallback.
5. Pass Terraform plan JSON for release gates.
6. Pass rendered Kubernetes YAML/JSON when workloads are deployed through Kubernetes, Helm, or Kustomize.
7. Pass `--artifact-manifest` when the SBOM does not preserve image digest or registry reference.
8. Use `rendered-iac-plan` and `artifact-manifest validate --strict-provenance` to make missing release inputs explicit before the scan.
9. Use `--analysis-profile production` for release gates.
10. Fail critical findings that only have dependency-level source evidence or no matching external analyzer evidence.
11. Write `--mapping-out`, `--source-coverage-out`, `--terraform-coverage-out`, `--kubernetes-coverage-out`, `--readiness-out`, and `--evidence-graph-out` when the related inputs are present.
12. Upload SARIF to GitHub code scanning and upload JSON/Markdown/HTML artifacts for audit.
13. Fail on `--fail-on-tier high` only when the team is ready to enforce the prioritized queue.

Terraform plan JSON can include sensitive values. Prefer not to upload it. Upload `terraform-coverage.json`, `kubernetes-coverage.json`, `source-coverage.json`, `mapping.json`, and `evidence-graph.json` instead.

## Account-Free Terraform E2E Test

Reachability Advisor analyzes `terraform show -json` output. It does not call Terraform providers or cloud APIs during `scan`, so an end-to-end test can use a reduced plan JSON shaped like Terraform output.

The repository includes `samples/e2e-no-cloud/` for this path:

```bash
reachability-advisor scan \
  --sbom samples/e2e-no-cloud/app.cdx.json \
  --vulns samples/e2e-no-cloud/vulnerabilities.json \
  --source-root no-cloud-app=samples/e2e-no-cloud/source \
  --terraform-plan samples/e2e-no-cloud/tfplan.json \
  --terraform-coverage-out outputs/no-cloud/terraform-coverage.json \
  --source-coverage-out outputs/no-cloud/source-coverage.json \
  --mapping-out outputs/no-cloud/mapping.json \
  --evidence-graph-out outputs/no-cloud/evidence-graph.json \
  --html-out outputs/no-cloud/reachability-graph.html \
  --out outputs/no-cloud/findings.json
```

This exercises the scanner path, artifact matching, public network context, IAM capability extraction, source reachability, evidence graph, and HTML output without a cloud account. It does not prove that a real environment matches the fixture.

## Fallback Without a Plan

Use this only for early feedback when the repository cannot generate a plan in CI:

```bash
reachability-advisor scan \
  --sbom sboms/app.cdx.json \
  --vulns vulns/app.grype.json \
  --source-root app=. \
  --terraform-source infra \
  --terraform-coverage-out reachability/terraform-coverage.json \
  --source-coverage-out reachability/source-coverage.json \
  --mapping-out reachability/mapping.json \
  --evidence-graph-out reachability/evidence-graph.json \
  --out reachability/findings.json
```

Treat source-mode Terraform gaps as work to resolve before release gating.

## External Source Evidence

The built-in source analyzer is fast and local. For release gates, run a dedicated analyzer and import its result:

```bash
reachability-advisor source-evidence-pack \
  --language javascript \
  --output-dir reachability/source-evidence-pack

reachability-advisor security-evidence-pack \
  --output-dir reachability/security-evidence-pack

semgrep scan \
  --config reachability/source-evidence-pack/semgrep-reachability.yml \
  --json \
  --output reachability/semgrep.json

semgrep scan \
  --config reachability/security-evidence-pack/semgrep/security.yml \
  --sarif \
  --output reachability/security-semgrep.sarif

reachability-advisor scan \
  --sbom sboms/app.cdx.json \
  --vulns vulns/app.grype.json \
  --source-root app=. \
  --source-evidence-in reachability/semgrep.json \
  --security-evidence-in reachability/security-semgrep.sarif \
  --terraform-plan reachability/tfplan.json \
  --analysis-profile production \
  --source-coverage-out reachability/source-coverage.json \
  --out reachability/findings.json
```

To generate the analyzer handoff without memorizing tool-specific commands:

```bash
reachability-advisor source-evidence-plan \
  --source-root . \
  --language go \
  --out-json reachability/source-evidence-plan.json \
  --out-md reachability/source-evidence-plan.md
```

`source-evidence-pack` writes maintained Semgrep rules, per-ecosystem Semgrep profiles, package-family query packs, CodeQL suite/profile files, govulncheck metadata, and the release-gate selector contract. The maintained family rules are tested against checked-in vulnerable samples; pinned public repositories in `fixtures/source-vulnerable-apps/coverage-expectations.json` give maintainers reproducible larger targets. Use `semgrep-reachability.yml` for all maintained rules, `semgrep/profiles/npm.yml`, `semgrep/profiles/maven-gradle.yml`, `semgrep/profiles/python.yml`, and `semgrep/profiles/go.yml` when a pipeline scans one ecosystem at a time, or `semgrep/query-packs/<family>.yml` when it runs family-specific jobs. `source-evidence-plan` emits CodeQL commands for JavaScript/TypeScript, Java/Kotlin, Python, and Go. It emits `govulncheck` only for Go. If no supported language or package-manager hint is supplied, it emits the generic Semgrep workflow and no CodeQL command.

`security-evidence-pack` is for first-party weaknesses, not dependency reachability. It writes SAST Semgrep profiles and DAST profile metadata keyed by CWE. Import SAST/DAST SARIF or normalized JSON with `--security-evidence-in`; high and critical imported records should reach `critical_profile_coverage` of `1.0`.

For CodeQL, pass SARIF output as `--source-evidence-in`. CodeQL `codeFlows` are imported as high-confidence data-flow evidence when the result or rule metadata includes a package, package URL, or vulnerability selector. Generic CodeQL query ids are retained as symbols and are not treated as vulnerability ids unless they look like CVE/GHSA/OSV-style ids.

For Go services, pass `govulncheck -json` output as `--source-evidence-in`. Imported evidence must match a component/package, package URL, or vulnerability before it can upgrade a finding. Artifact is a narrowing selector, not a match by itself.

## Mapping Quality Gate

Use these gates once the pipeline emits image/runtime SBOMs and Terraform or rendered Kubernetes context:

```bash
reachability-advisor scan \
  --sbom sboms/app.cdx.json \
  --vulns vulns/app.grype.json \
  --source-root app=. \
  --source-evidence-in reachability/semgrep.json \
  --terraform-plan tfplan.json \
  --analysis-profile production \
  --require-strong-source-for-critical \
  --mapping-out reachability/mapping.json \
  --source-coverage-out reachability/source-coverage.json \
  --min-artifact-match-coverage 1.0 \
  --min-strong-artifact-identity-coverage 1.0 \
  --min-source-rule-coverage 0.8 \
  --min-critical-external-source-coverage 1.0 \
  --min-critical-query-family-coverage 1.0 \
  --min-critical-proven-query-family-coverage 1.0 \
  --min-critical-security-profile-coverage 1.0 \
  --fail-on-mapping-warnings \
  --out reachability/findings.json
```

Start with advisory thresholds on existing repositories. Raise thresholds after SBOM metadata and artifact aliases are consistent in CI.

## Release Evidence Readiness

Write a readiness report in the scan, or evaluate saved reports after the scan:

```bash
reachability-advisor evidence-profile \
  --mapping reachability/mapping.json \
  --source-coverage reachability/source-coverage.json \
  --terraform-coverage reachability/terraform-coverage.json \
  --kubernetes-coverage reachability/kubernetes-coverage.json \
  --findings reachability/findings.json \
  --out reachability/readiness.json \
  --fail-on-blockers
```

The report names the missing release evidence: weak artifact identity, missing workload match, no network path, no identity path, external source coverage gaps, query-family coverage gaps, or unrendered Terraform/Kubernetes wrappers.

To enforce the same report during `scan`, add:

```bash
--require-release-ready
```

Use `--fail-on-readiness-warnings` only after the pipeline has stable image digests, workload matches, and rendered IaC coverage.

## PR Delta Gate

To avoid blocking on old backlog, publish `reachability-baseline.json` from the default branch and compare pull requests against that artifact. The PR report contains only new and worsened findings:

```bash
reachability-advisor scan \
  --sbom sboms/app.cdx.json \
  --vulns vulns/app.grype.json \
  --source-root app=. \
  --out reachability/findings.json \
  --baseline-out reachability/reachability-baseline.json

reachability-advisor compare \
  --baseline main.reachability-baseline.json \
  --head-findings reachability/findings.json \
  --markdown-out reachability-delta.md \
  --fail-on-new-tier high
```

See `docs/policy_playbooks.md` for strict release, advisory pull request, and backlog migration policy files.

## Terraform Coverage Gate

This check fails if a valid Terraform plan is not fully accounted for. Visibility gaps indicate unsupported resources, unresolved modules, or opaque rendered manifests.

```bash
python - <<'PY'
import json
from pathlib import Path

coverage = json.loads(Path("reachability/terraform-coverage.json").read_text())
summary = coverage["summary"]
assert summary["resource_accounting_coverage"] == 1.0

if coverage["visibility_gaps"]:
    print("Terraform visibility gaps require review:")
    for gap in coverage["visibility_gaps"]:
        print("-", gap["type"], gap["address"])
    raise SystemExit(1)
PY
```
