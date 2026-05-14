# Scoring

Scores are priority signals, not exploitability claims.

The scorer is graph-first. It evaluates the strongest credible evidence path:

`asset -> network path -> identity/effective access -> source/runtime/package evidence -> finding`

The graph decision chooses the tier. The numeric `score` is then projected into
that tier's 0-100 band for sorting and CI thresholds. Additive point math is
not part of the output contract.

## Dependency Vulnerabilities

Dependency graph decisions use:

- severity/CVSS;
- KEV and EPSS when supplied;
- package scope;
- source reachability;
- deployment exposure;
- IAM and data blast radius;
- environment criticality;
- confidence gates.

SBOM-only dependency findings stay below high unless exploit intelligence or
critical deployment context justifies escalation. A blocked network edge caps the
confirmed tier; unresolved network or IAM evidence becomes a visibility gap and
may raise `potential_tier`, but it does not count as confirmed exposure.

## Static Code Weaknesses

SAST graph decisions use:

- scanner severity;
- CWE/category impact;
- source confidence;
- data-flow strength versus location-only evidence;
- route or handler evidence;
- mapped deployment exposure;
- IAM and data blast radius;
- DAST corroboration when present.

Location-only SAST without data flow or deployment context stays below high.
Data-flow plus deployment evidence can raise priority. SAST never proves runtime
observation by itself.

## Dynamic Runtime Observations

DAST graph decisions use:

- scanner severity;
- runtime evidence state and confidence;
- public or external URL context;
- authentication requirement when known;
- mapped deployment context;
- SAST/source corroboration when present.

DAST informational observations stay low unless corroborated. Runtime-observed high/critical findings can rank high even when source mapping is unknown, but the unknown is shown explicitly.

## Graph Decision Fields

Each finding includes `scoring.graph_decision`:

- `tier`: confirmed priority from the evaluated path;
- `potential_tier`: credible worst-case priority when important edges are unknown;
- `matched_rule`: the rule that selected the confirmed tier;
- `drivers`: evidence that raised the priority;
- `blockers`: evidence that constrained the path;
- `unknowns` and `visibility_gaps`: missing evidence that must not be treated as safe;
- `band_adjustments`: small ordering adjustments inside the selected tier band.

## Dimensions

Scoring output includes dimensions for `vulnerability_impact`, `source_reachability`, `runtime_evidence`, `deployment_exposure`, `identity_blast_radius`, `data_sensitivity`, `corroboration`, `confidence_penalty`, and `uncertainty_premium`. Their `points` value is `0.0` because dimensions explain the graph decision; they are not an additive ledger.

Weak same-artifact correlation has low score impact. Strong route/CWE SAST+DAST correlation can raise confidence.
