# Config file and onboarding workflow — design

Status: approved in brainstorming, not yet implemented
Date: 2026-07-27
Scope: the adoption journey — zero to first useful scan
Primary user: platform / DevSecOps teams rolling the tool out across many repositories

## Problem

The tool works, but nothing gets a new team to a first useful run.

Measured on the current codebase:

| Surface | Count |
|---|---|
| CLI subcommands | 17, flat, ungrouped |
| Flags on `scan` | 49 |
| GitHub Action inputs | 48 |
| Config-file support | none |

Three consequences:

1. **No configuration can be declared.** Every option is a flag, so the same ~20 flags are
   retyped in the Makefile, in CI YAML, and by hand. A local run cannot reproduce what CI runs,
   and the two drift silently.
2. **Setup is a copy-paste loop run three times.** `sbom-plan`, `source-evidence-plan` and
   `rendered-iac-plan` print commands for the user to run, whose outputs the user then manually
   assembles into a `scan` invocation. `init-policy` exists; nothing scaffolds a working setup.
3. **Gate vocabulary is implementation vocabulary.** `--min-critical-proven-query-family-coverage`
   describes the code, not the user's intent.

## Target flow

Three commands, in order, each stating what to do next:

```
reachability-advisor init      # writes .reachability.yml from what is in the repo
reachability-advisor doctor    # what is missing, and the exact command that produces it
reachability-advisor scan      # no flags; reads the config
```

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Format | YAML, `.reachability.yml` | Platform teams live in YAML; it takes comments, which matter for justifying a gate; JSON is valid YAML so existing `configs/policy.*.json` still parse |
| Precedence | defaults → org baseline → repo file → CLI flags | CI can override one value without restating the rest |
| Parsing | PyYAML, `safe_load` only | Correctness over a hand-owned parser; accepted cost is the first runtime dependency |
| Org rollout | layered via `extends:` | Standardize centrally without an N-repo pull request per change |
| `init` | detect and scaffold, non-interactive | A team onboarding 50 repos scripts it; a wizard cannot be scripted |
| Scope | config + `init` + `doctor` | Fixes the adoption loop without churning every existing invocation |

### Accepted consequence: repos can weaken org gates

Layered precedence means `gate.fail_on: low` in a repo file beats the org baseline's `high`.
That is correct if the baseline is a *default*. If it must be a *floor*, that is a locking
mechanism, deliberately deferred rather than half-built here.

## Architecture

New modules, following the existing convention of small focused files:

| Module | Responsibility |
|---|---|
| `config.py` | `load_config(path) -> ResolvedConfig`; layer merging and precedence |
| `config_schema.py` | Typed schema, defaults, validation errors |
| `config_detect.py` | Repo inspection for `init` |
| `doctor.py` | Readiness diagnosis and next-action generation |

CLI wiring lives in `cli_parser.py` / `cli.py` as today.

### Resolution

```
built-in defaults  ->  org baseline (extends:)  ->  repo .reachability.yml  ->  CLI flags
```

`extends:` resolves **offline only**, two ways:
- a relative path — `extends: ./shared/base.yml`
- an installed Python package via `importlib.util.find_spec` — `extends: acme_baseline`
  (never `importlib.resources`/`import_module`, which execute the module's top-level
  code before anything about its contents is checked; `find_spec` locates it without
  executing it, and only single-segment package names are accepted)

The platform team distributes the baseline through the pip channel they already operate.
Nothing is fetched at scan time, preserving the local-first guarantee. Chains are followed
with cycle detection and a depth cap.

**Merge semantics**: maps deep-merge; scalars override; **lists replace, never append**.
Appending would make it impossible for a repo to remove an entry the org baseline set.

**Discovery**: explicit `--config` wins; else `.reachability.yml` in the working directory;
else walk up to the git root and no further — a config outside the repo is not reviewable in
that repo's pull requests.

### `config explain`

Prints every resolved value and the layer that set it, so "why did this gate fire" needs no
archaeology:

```
gate.fail_on          high            <- .reachability.yml:14
gate.profile          production      <- acme_baseline (org)
evidence.sast         [semgrep.json]  <- --sast-in (flag)
```

## Schema

```yaml
version: 1
extends: acme_baseline          # optional: path or installed package

artifacts:
  payments-api:
    sbom: sboms/payments-api.cdx.json
    source: src/payments-api
    image: ghcr.io/acme/payments-api

evidence:
  vulnerabilities: [grype.json]
  sast: [semgrep.json]
  dast: [zap.json]
  cspm: []

iac:
  terraform: tf-plan.json
  kubernetes: k8s/

gate:
  profile: production           # the existing --analysis-profile {advisory,production}
  fail_on: high                 # the existing --fail-on-tier
  thresholds:                   # optional per-gate overrides, same names as today's min-* flags
    min_critical_external_source_coverage: 0.8

output:
  dir: outputs
  formats: [json, sarif, markdown, html]
```

## `init` — detect and scaffold

Detects, and declares only what it finds:

- existing SBOMs (`*.cdx.json`, `*.spdx.json`)
- lockfiles per ecosystem, which imply the SBOM command to run
- artifacts from Dockerfiles and image references in `*.tf` and Kubernetes manifests
- source roots inferred from lockfile locations
- IaC: `*.tf`, Terraform plan JSON, Kubernetes manifests

Anything not found becomes a `# TODO:` carrying the exact command that produces it.
`init` never invents a path that does not exist.

### `init` does not rewrite in place

PyYAML does not round-trip comments — `safe_load` discards them. A naive idempotent merge
would therefore silently strip every comment justifying a gate. So:

- if `.reachability.yml` exists, `init` refuses and exits non-zero
- `--refresh` writes newly-detected items to `.reachability.detected.yml` for manual merge

Less magical, and it cannot eat the user's work.

## `doctor` — the adoption loop

Absorbs `validate`, `evidence-profile`, and the three `*-plan` commands into one re-runnable
status command.

```
payments-api    SBOM ok   vulns ok   source ok   IaC missing
  -> no Terraform plan. Produce one with:
       terraform show -json plan.tfout > tf-plan.json

gate: not ready - production profile needs source evidence for 2 critical findings
```

- exit code 0 when gate-ready, non-zero otherwise, so it is scriptable
- `--json` emits the same data: a platform team runs this across 50 repos to build an
  onboarding dashboard, not to read 50 terminals

The existing commands remain for compatibility.

## Error handling and security

The threat model already treats scanner inputs as untrusted; the config file is now part of
that surface.

- `yaml.safe_load` exclusively. `yaml.load` is arbitrary object construction, i.e. RCE.
- Config reads go through the existing `input_limits` size cap.
- A nesting-depth guard against YAML alias-expansion bombs: `safe_load` blocks object
  construction but not entity expansion.
- **Unknown keys are rejected, not ignored** — as the `policy.py` audit fix now does. A typo'd
  `gate.fial_on` must fail loudly. Silently falling back to a default is how a release gate
  stops gating.
- Validation errors carry `file:line`.
- A config parser that silently misreads a gate threshold is a security defect, not a bug.
  Fail closed.

## PyYAML: consequences to handle

Adding the first runtime dependency is a real change for a supply-chain security tool.

- `pyproject.toml` gains `dependencies = ["PyYAML>=6"]`; Dockerfile, action and packaging follow.
- README and docs claiming zero dependencies must be corrected. Honesty here is the point of
  the product.
- **Cleanup worth taking**: delete the hand-rolled YAML parser in `kubernetes.py` (~100 lines of
  security-sensitive code, in which this month's audit found a stack-overflow) in favour of
  `safe_load`. Keep the depth and size guards — manifests remain untrusted.

## Testing

- Unit: precedence across all four layers; `extends` cycles and depth cap; unknown-key
  rejection; list-replace semantics; alias-bomb and oversize inputs.
- Golden: `init` detection against fixture repos (node, python, go, terraform, k8s, and a
  monorepo with several artifacts).
- Behavioural: `doctor` exit codes for ready / not-ready; `--json` shape.
- Compatibility: every existing flag continues to work with no config file present.
- The full suite (905 tests), `ruff`, `mypy --strict`, coverage and release-check stay green,
  verified on Python 3.10 through 3.13.

## Out of scope

- Renaming the ~10 gate flags to intent vocabulary, and regrouping the 17 subcommands. Easier
  to get right once the config layer shows which options are set in config versus overridden
  at the command line.
- Gate locking (org baseline as a floor rather than a default).
- The CI/PR and triage journeys.
