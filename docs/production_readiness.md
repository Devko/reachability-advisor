# Production Readiness Review

Review date: 2026-05-15.

This review grades the current feature surface for production use after the latest stabilization pass. Production use here means a local-first CI, release-gate, or developer-triage workflow that is driven by checked-in or CI-produced artifacts and can be reviewed from generated reports. It does not mean live cloud inventory, automatic suppression, or replacement of the underlying scanners.

## Grade Scale

| Grade | Meaning |
|---|---|
| A | Ready for production release-gate use when documented inputs are supplied. |
| B | Ready for production advisory or CI use, but release-gate use needs prerequisites or careful review. |
| C | Useful and tested, but should be treated as advisory or beta until hardened with more real-world fixtures or integration coverage. |
| D | Not production-ready. Keep out of blocking workflows. |

## Current Assessment

The app is ready for controlled production CI usage when teams provide strong artifact identity, external source evidence, SBOM or scanner evidence, and rendered deployment evidence. The safest production boundary is a strict release gate for well-instrumented services, plus advisory mode for services with partial evidence.

Recent stabilization work materially improved scanner adapter tolerance, provider fixture coverage, weak-module coverage, and release-gate wording. The remaining risk is not a missing headline feature. It is confidence at the edges: more real scanner dialects, larger rendered infrastructure corpora, browser-level visual checks, and clearer onboarding for teams with incomplete evidence.

## Feature Grades

| Feature | Grade | Production Usage | Evidence | Main Weak Spot |
|---|---:|---|---|---|
| CLI package, command routing, and demo | A | Ready for local and CI use. | Versioned package, `demo`, `scan`, `validate`, `explain`, `compare`, fixture workflows, and release validation are covered by the local gate. | Keep Windows examples, first-run paths, and CLI help wording current. |
| SBOM and SCA vulnerability ingestion | A- | Ready when CycloneDX SBOMs and Grype, OSV, or local vulnerability JSON are generated in the same pipeline. | SBOM parsing, dependency graph evidence, artifact scoping, malformed input handling, Grype variants, OSV variants, and focused coverage now have regression tests. | SPDX and additional vendor-specific SCA formats are still outside the primary path. |
| Vulnerability intelligence normalization | A- | Ready for prioritization and reporting. | CVSS, EPSS, KEV, VEX-like fields, aliases, fixes, scanner attribution, partial records, and skipped-record diagnostics are covered. | Continue adding real scanner examples as observed. |
| Built-in source reachability | B | Ready for advisory triage and fallback evidence. | Tests cover common JavaScript/TypeScript, Java, Python, Go, route, manifest, and package-family patterns. | Built-in heuristics are not enough for strict production gates; critical findings still need external analyzer evidence. |
| External source evidence import | A- | Ready for production release gates when records carry package, purl, vulnerability, and query-family selectors. | Semgrep, CodeQL/SARIF code flows, govulncheck JSONL, native evidence, selector diagnostics, and coverage gates are implemented. | Needs more pinned public analyzer examples and query-family drift tests. |
| Source evidence packs and plans | B+ | Ready to generate CI handoff assets, strongest when analyzer versions are pinned. | Maintained npm, Maven/Gradle, Python, and Go profiles plus coverage expectations are tested. | More ecosystem-specific examples are needed before calling coverage complete. |
| SAST evidence import | B+ | Ready for advisory and production context when profile coverage is enforced. | SARIF, Semgrep JSON, CodeQL/SARIF variants, normalized security evidence, static finding type, CWE/profile coverage, and partial-record handling are covered. | Needs broader real scanner dialect fixtures and profile drift checks. |
| DAST evidence import | B+ | Ready for runtime context and production gates when mapped to artifacts and maintained profiles. | ZAP, Nuclei JSONL, normalized DAST, runtime evidence, route correlation, and conservative no-source-upgrade behavior are covered. | URL-to-artifact mapping and authenticated scan metadata need more real-world fixtures. |
| CSPM/posture import | B | Ready as posture evidence in advisory and CI reports. | Checkov, Trivy config, KICS, tfsec, SARIF, normalized posture inputs, partial records, and unmapped-resource diagnostics are covered. | Provider-specific posture semantics need broader fixture coverage before hard blocking. |
| Artifact identity and CI manifest | A- | Ready for production gates when image digest, SBOM path, Git SHA, and signature or attestation markers are supplied. | Manifest init/validate, strict provenance, mapping reports, artifact aliases, digest/reference matching, weak identity blockers, and readiness messages are covered. | Adoption still depends on pipeline quality. Teams without digest or exact image references should stay in advisory mode. |
| Terraform plan analysis | A- | Ready for production release gates with `terraform show -json` output. | Resource accounting, semantic coverage, image extraction, network paths, IAM, multi-cloud samples, provider policy fixtures, and provider network fixtures are tested. | Add more provider and module fixtures before broadening semantics. |
| Terraform HCL static audit/source mode | B- | Ready for early PR feedback and corpus checks only. | HCL audit, source-mode scan fallback, external HCL corpus, and explicit module/opaque-wrapper gaps exist. | Not release-gate evidence; it cannot fully evaluate modules, provider defaults, `for_each`, `count`, Helm, or kubectl children. |
| Rendered Kubernetes manifest analysis | B+ | Ready for release-gate context when manifests are rendered from the release pipeline. | Workload, Service, Ingress, RBAC, NetworkPolicy, service-mesh, artifact matching, and coverage output are tested. | Needs larger Helm/Kustomize rendered corpora and more private-cluster examples. |
| Network exposure modeling | B+ | Ready when driven by Terraform plan or rendered Kubernetes evidence. | Typed network paths, route precedence, private endpoints, WAF/auth/firewall blockers, constrained/blocked decisions, deny-before-allow cases, service mesh, and golden network fixtures exist. | Needs more real topology corpora, especially cross-account, hybrid, and private endpoint edge cases. |
| IAM effective access modeling | B+ | Ready for reviewable blast-radius context, not a full cloud IAM simulator. | Structured policy evaluation, deny precedence, boundaries, cross-account/assume-role, resource policies, provider policy fixtures, scoped access, confidence fields, and blocker wording are covered. | Add more real sanitized policy samples with nested conditions and identity-provider edge cases. |
| Effective exposure and graph-first scoring | A- | Ready for production prioritization with benchmark gates. | Effective exposure records, provider blockers, low-confidence caps, scoring dimensions, golden outputs, benchmark snapshots, and inflation checks are covered. | Keep adding benchmark cases before changing weights or provider semantics. |
| JSON report contracts | A | Ready for downstream automation. | Findings, mapping, readiness, coverage, baseline, evidence graph, benchmark, and fixture schemas are validated by release checks. | Keep schema migration notes strict when fields change. |
| SARIF, diagnostics, annotations, and Markdown outputs | A- | Ready for CI and developer workflows. | Output generation and schema/contract checks are in the suite, including clearer user-facing wording for release blockers. | Add more consumer-focused golden tests for GitHub code scanning and IDE diagnostics. |
| Interactive HTML attack-path report | B+ | Ready for local review artifacts and demos. | HTML escaping, graph construction, dense layout, unified attack graph, shared Internet entry, risk sidebar, expandable finding nodes, attack path, architecture, evidence paths, risk views, and clearer labels have regression tests. | Needs browser-render smoke tests with screenshots and pixel checks before treating visual UX as release-gate critical. |
| Baseline and PR delta comparison | B+ | Ready for CI advisory and review workflows. | Baseline generation, compare command, new/resolved/regressed/improved categories, and diagnostics filtering are covered. | Establish a long-lived baseline compatibility policy before heavy downstream adoption. |
| Release readiness and evidence-profile gates | A- | Ready for strict production pipelines with complete evidence. | Production profile, readiness report, missing external evidence, weak artifact identity, unrendered IaC wrappers, low-confidence paths, missing identity evidence, coverage gates, and release validation are tested. | Add a failure playbook based on real onboarding mistakes. |
| Fixture packs and benchmark snapshots | A- | Ready as executable documentation and regression gates. | Terraform fixture packs, provider policy/network fixtures, scanner adapter fixture families, real-app benchmark snapshots, and complex app validation exist. | Add more community fixture packs and keep cached external corpora reproducible. |
| GitHub Actions/composite action workflow | B+ | Ready as a documented CI integration pattern. | Action metadata is checked by release validation and docs include advisory, release-gate, and baseline examples. | Exercise the composite action itself in CI beyond metadata and local scripts. |
| VS Code extension | C+ | Useful for local advisory workflows; not yet a production gate surface. | Helper tests cover profile resolution, path discovery, validation, tier filtering, baseline filtering, and evidence explorer rendering. | Needs extension-host integration tests, packaging checks, and UX hardening before calling it production-ready. |
| Packaging and release process | A- | Ready for normal package releases. | Stable classifier, build gate, wheel smoke test, release validation, and release docs exist. | Add signed release artifacts and artifact verification once tag workflow is settled. |
| Documentation and onboarding | B+ | Ready for maintainers and motivated users. | README, docs index, quickstart, data formats, pipeline, roadmap, maturity targets, production readiness, threat/privacy models, and release process are organized. | Add troubleshooting from real failures and reduce duplicated command variants over time. |

## Focus Next

1. Add browser-level smoke coverage for the HTML report. The model tests are solid, but production confidence needs rendered screenshot checks for the risk table, attack path, dense graphs, issue drawer, and escaping behavior.
2. Keep growing scanner adapter fixtures from real outputs. The current adapter hardening covers the important families; the next step is versioned corpora for Grype, OSV, Semgrep, CodeQL/SARIF, ZAP, Nuclei, Checkov, Trivy, KICS, and tfsec as formats drift.
3. Expand provider fixtures before changing semantics. Network and IAM logic should grow only after fixtures prove route precedence, blockers, deny rules, scoped identity, private endpoints, service mesh, and cross-account behavior.
4. Turn release-gate onboarding failures into a playbook. Document exact fixes for missing external evidence, weak artifact identity, unrendered IaC wrappers, low-confidence network paths, and missing identity evidence.
5. Strengthen VS Code extension maturity. Add extension-host tests, packaging validation, and a clear separation between advisory diagnostics and release-gate expectations.
6. Build long-lived compatibility rules for baselines and report schemas. Downstream automation needs clear migration expectations before the tool is embedded broadly.
7. Keep coverage pressure on stability modules. Effective exposure now has focused blocker-edge tests for competing reachable, constrained, and blocked paths; future changes to `effective_exposure.py`, `sbom.py`, `terraform_manifest.py`, `scenario_view.py`, and `source_manifests.py` should include the same kind of regression coverage.

## Recommended Production Boundary

Use Reachability Advisor as a production release gate only when the pipeline supplies:

- artifact-scoped CycloneDX SBOMs and vulnerability matches;
- external source evidence with usable package, purl, vulnerability, and query-family selectors;
- Terraform plan JSON or rendered Kubernetes manifests from the release pipeline;
- artifact identity or CI manifest data with image digest or exact image reference;
- readiness, mapping, source coverage, deployment coverage, evidence graph, and findings artifacts retained for review.

Use advisory mode when any of those inputs are missing. Advisory output is still valuable, but missing evidence should remain a visibility gap rather than a pass/fail safety claim.
