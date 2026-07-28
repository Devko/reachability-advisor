"""Report what evidence is present, what is missing, and the command that produces it.

`doctor` exists to make one promise concrete: if it reports `ready`, `scan` will actually
run against the declared configuration instead of failing on a missing file or a
combination of inputs `scan` itself refuses. Every existence/type/size/extension check
here calls the exact same functions `scan`'s own pre-flight `validate_paths` (validators.py)
calls -- `_validate_file`, `_validate_kubernetes_manifest`, `_validate_terraform_source`,
`_validate_source_root` -- rather than reimplementing `Path.exists()`/`Path.is_file()`
checks that could silently drift from what `scan` actually enforces. The remaining checks
(a required flag, an input combination `scan` explicitly rejects) mirror a real requirement
inside `run_scan` / `apply_config_defaults` (cli.py) directly, for the same reason.

Doctor starts at the same layer `validate_paths` does: does the declared path exist, is it
the right kind of thing (a file, not a directory; a directory, not a file; YAML/JSON for a
Kubernetes manifest), and is it non-empty. A bare `Path.exists()`/`is_file()` check stops
there -- but a file that exists, is the right kind, and is non-empty can still contain
garbage a report saying "ready" should not paper over: a `scan` run against it fails anyway,
just two steps later than doctor could have caught it. So once a declared input clears the
`validate_paths`-level check, doctor takes one more step for every input that has a cheap
one: it calls the *exact same loader* `scan` itself calls on that input -- `sbom.load_sbom`,
`vulnerability.load_vulnerabilities`, `terraform.load_terraform_plan`,
`kubernetes.load_kubernetes_resources` (via `_manifest_files`, for a single file or a
directory), `security_evidence_adapters.load_security_evidence` -- and reports whatever error
that loader raises as a blocker, in the loader's own words. This is reuse, not
reimplementation: doctor never parses JSON or YAML itself, it only calls the function that
already does, so a parse failure doctor misses is a parse failure `scan` would not have hit
either, by construction. `_check_content` (below) is the one place this happens, and it is
deliberately narrow -- it calls the loader and catches what the loader raises, nothing more.

One input is deliberately left unchecked past the `validate_paths` layer:
`iac.terraform_source`. Unlike every JSON/YAML loader above, `scan`'s HCL "loader"
(`hcl_static.audit_hcl_project`) is regex extraction, not a parser with a fail state -- it
never raises on malformed `.tf` syntax, a garbage body just yields zero extracted blocks, and
`scan` still exits 0. There is no "invalid HCL" error to reuse the way `load_sbom` raises on
invalid JSON, so calling it from doctor would add a real parsing cost (a full regex pass plus
tfvars resolution over every `.tf` file) to catch nothing `_validate_terraform_source` does
not already catch. See the inline comment at that check.

A file the process cannot open because of filesystem permissions is not a separate case to
handle: it surfaces as the same `OSError` `_check_content` already catches when the loader
tries to read it, so it becomes a blocker the same way malformed content does, with no
extra code.

Two independent kinds of problem are reported. `blockers` are what stop `scan` from
running at all, or from producing a trustworthy result: a required path that is missing,
the wrong kind, or empty (an `error`-severity issue in `validate_paths`); a required path
whose *content* fails to parse (an error `_check_content` catches from `scan`'s own loader);
at least one artifact must declare an `sbom` (`run_scan` raises without one); at least one vulnerability
input must be declared; and `iac.terraform` / `iac.terraform_source` must never both be set
(`scan` rejects that combination outright). `warnings` are gaps `validate_paths` itself
only rates `warning` severity: `scan` still runs and still exits 0, just against weaker
evidence -- a missing declared `source` root is the standing example, since `scan` falls
back to SBOM/package-level evidence rather than failing. Doctor does not escalate a warning
to a blocker just because `gate.profile` is `production`: `scan`'s own quality-gate
thresholds under that profile (external evidence coverage, source-rule coverage, and so on)
are computed from evidence content doctor cannot see without actually running `scan`, and
inventing a static approximation of them here would be exactly the kind of guess this
module exists to avoid making. The exit code reflects blockers only, so a repository that
`scan` runs cleanly against is never reported "not ready" merely because its evidence is
thin.

No config file at all is reported as its own, first blocker rather than folded into
"no artifacts declared": that is the first thing a new user hits running `doctor` before
ever running `init`, and it deserves a message that names the actual next step instead of
a generic "nothing is declared".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, TypeVar

from .config import LoadedConfig
from .kubernetes import _manifest_files, load_kubernetes_resources
from .sbom import load_sbom
from .security_evidence_adapters import load_security_evidence
from .terraform import load_terraform_plan
from .validators import (
    ValidationIssue,
    _validate_file,
    _validate_kubernetes_manifest,
    _validate_source_root,
    _validate_terraform_source,
    has_errors,
)
from .vulnerability import load_vulnerabilities

GRYPE_COMMAND = "grype sbom:{sbom} -o json > {out}"
SYFT_COMMAND = "syft dir:{path} -o cyclonedx-json > {out}"
TERRAFORM_COMMAND = "terraform show -json plan.tfout > {out}"


@dataclass(frozen=True)
class ArtifactReadiness:
    name: str
    present: dict[str, bool] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)


@dataclass
class Readiness:
    ready: bool = False
    artifacts: list[ArtifactReadiness] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)


def _record(readiness: Readiness, issues: list[ValidationIssue], *, context: str | None = None) -> None:
    """File each issue `validate_paths`'s helpers raised as a doctor blocker or warning.

    `error` severity means `validate_paths` would fail the scan (`has_errors` is true) --
    that is a blocker. `warning` severity means `scan` runs anyway, just against weaker
    evidence -- that stays a warning, never promoted to a blocker.
    """
    for issue in issues:
        message = f"{context}: {issue.message}" if context else issue.message
        bucket = readiness.blockers if issue.severity == "error" else readiness.warnings
        bucket.append(message)


_T = TypeVar("_T")


def _load_content(issues: list[ValidationIssue], label: str, loader: Callable[[], _T]) -> _T | None:
    """Parse a file exactly the way `scan`'s own loader will, once the file-level check
    above already found nothing wrong -- turning a parse failure `scan` would hit into the
    same kind of blocker a missing or empty file already gets, with the loader's own
    message. Returns the loaded value on success (so a caller that needs more than a
    pass/fail check -- see `diagnose`'s SBOM handling, which needs each SBOM's own
    artifact name to check declared `image` aliases -- does not have to parse the file a
    second time), or `None` once the failure has already been filed as an issue.

    Reuses `scan`'s loader instead of re-implementing "is this valid JSON/YAML" here, so the
    two checks cannot silently drift apart the way `Path.exists()` once did (see the module
    docstring, and the fix that closed that gap). `ValueError` catches every loader's own
    error type -- `SbomError`, `VulnerabilityError`, `TerraformContextError`,
    `KubernetesManifestError`, and `SecurityEvidenceError` all subclass it -- plus stdlib
    `json.JSONDecodeError` and `UnicodeDecodeError`, which are also `ValueError`. `OSError`
    catches a permission or other filesystem failure a loader does not itself convert to its
    own error type (an unreadable file that slipped past the file-level existence/type/size
    check above). `RecursionError` guards deeply nested input for the one loader
    (`load_terraform_plan`) that does not already convert it to a controlled error the way
    its siblings do. None of these can reach the caller as an unhandled traceback -- exactly
    doctor's "never crash" requirement.
    """
    try:
        return loader()
    except (ValueError, OSError, RecursionError) as exc:
        issues.append(ValidationIssue("error", label, str(exc)))
        return None


def _check_content(issues: list[ValidationIssue], label: str, loader: Callable[[], object]) -> None:
    """`_load_content`, for the common case where the caller only needs pass/fail and has
    no use for the loaded value itself.
    """
    _load_content(issues, label, loader)


def _load_kubernetes_content(path: Path) -> None:
    """Parse every manifest file `scan` would find under `path` -- a single file or a
    directory -- using the exact file-discovery (`_manifest_files`) and per-file parser
    (`load_kubernetes_resources`) `analyze_kubernetes_manifests` uses internally.
    Deliberately stops there: the context-matching and coverage-report computation
    `analyze_kubernetes_manifests` also does needs a real artifact list and belongs to
    `scan`, not to a content-parses check.
    """
    for manifest_file in _manifest_files([path]):
        load_kubernetes_resources(manifest_file)


def diagnose(loaded: LoadedConfig, root: Path) -> Readiness:
    """Check every declared input the same way `scan` will, and that `scan` can run at all.

    See the module docstring for how blockers and warnings are told apart, how content
    validity is checked by calling `scan`'s own loaders via `_check_content`, and why
    `iac.terraform_source` is the one input left at the existence/type/size layer only.
    """
    readiness = Readiness()
    root = root.resolve()

    if loaded.path is None:
        readiness.blockers.append(
            "No .reachability.yml found. Run `reachability-advisor init` to create one "
            "from what is already in this repository."
        )
        readiness.next_actions.append("reachability-advisor init")
        readiness.ready = False
        return readiness

    config = loaded.config

    if not config.artifacts:
        readiness.blockers.append("No artifacts declared. Run `reachability-advisor init`.")

    # Populated below as each artifact's own SBOM is loaded, then consulted once every
    # artifact has been processed -- see the alias-resolution pass right after this loop.
    loaded_sbom_artifact_names: set[str] = set()

    for name, artifact in sorted(config.artifacts.items()):
        present: dict[str, bool] = {}
        missing: list[str] = []

        if artifact.sbom is None:
            present["sbom"] = False
            missing.append("sbom")
        else:
            sbom_issues: list[ValidationIssue] = []
            _validate_file(str(root / artifact.sbom), "sbom", sbom_issues)
            sbom_document = None
            if not has_errors(sbom_issues):
                sbom_document = _load_content(
                    sbom_issues, "sbom", partial(load_sbom, root / artifact.sbom)
                )
            if sbom_document is not None:
                loaded_sbom_artifact_names.add(sbom_document.artifact.name)
            present["sbom"] = not sbom_issues
            if sbom_issues:
                missing.append("sbom")
            _record(readiness, sbom_issues, context=f"{name}: sbom")

        if artifact.source is None:
            present["source"] = False
            missing.append("source")
        else:
            source_issues: list[ValidationIssue] = []
            _validate_source_root(str(root / artifact.source), f"{name}: source", source_issues)
            present["source"] = not source_issues
            if source_issues:
                missing.append("source")
            _record(readiness, source_issues, context=f"{name}: source")

        if artifact.sbom is None:
            readiness.next_actions.append(
                f"{name}: "
                + SYFT_COMMAND.format(path=artifact.source or ".", out=f"sboms/{name}.cdx.json")
            )
        readiness.artifacts.append(ArtifactReadiness(name=name, present=present, missing=missing))

    # `apply_config_defaults` (cli.py) turns every artifact's `image` into a `scan
    # --artifact-alias {name}={image}` flag, and `_apply_artifact_aliases` (cli.py) then
    # matches `{name}` against each *loaded SBOM's own* `artifact.name` (its CycloneDX
    # `metadata.component.name`, not the config's artifact key) across every SBOM `scan`
    # loaded -- not just this artifact's own. If nothing matches, `scan` fails outright
    # ("Artifact alias refers to an SBOM artifact that was not loaded"). Before this
    # check, doctor never looked past "does the sbom file parse" -- a config where the
    # artifact key and the SBOM's own component name disagree (the common case for a
    # detected artifact named after its directory, e.g. `init` on this project's own
    # tree: an SBOM component named "sbom" but a config key derived from the containing
    # directory) reported `ready` while `scan` hard-failed on the very next input. This
    # is deliberately a second pass over every artifact, not folded into the loop above:
    # `loaded_sbom_artifact_names` must be fully populated (a match can come from *any*
    # artifact's SBOM, exactly as `_apply_artifact_aliases` checks against the full,
    # flattened `sboms` list) before any artifact's `image` can be checked against it.
    for name, artifact in sorted(config.artifacts.items()):
        if artifact.image and name not in loaded_sbom_artifact_names:
            readiness.blockers.append(
                f"{name}: image is declared ({artifact.image!r}) but no loaded SBOM's own "
                f"component name matches the artifact key {name!r}. `scan` maps "
                f"`--artifact-alias {name}={artifact.image}` (derived from `image`) against "
                "each SBOM's own `metadata.component.name`, not the config key, and fails "
                f"outright when nothing matches. Rename this artifact block's key to match "
                f"the SBOM's own component name, or change the SBOM's component name to "
                f"match {name!r}."
            )

    # A source-only artifact (no `sbom` key at all) is exactly what `init` scaffolds for a
    # repository that has a lockfile but no SBOM yet -- the loop above does not flag it,
    # because an *undeclared* field is not a broken reference the way a declared-but-
    # missing one is. But if not a single artifact anywhere declares an sbom, `run_scan`
    # fails immediately with "At least one --sbom is required": doctor must catch that
    # before scan does, not report `ready` on a config `scan` cannot actually run against.
    if config.artifacts and not any(item.sbom for item in config.artifacts.values()):
        readiness.blockers.append(
            "No artifact declares an sbom. `scan` requires --sbom for at least one "
            "artifact (artifacts.<name>.sbom in .reachability.yml)."
        )

    vulnerabilities = config.evidence.get("vulnerabilities", ())
    if not vulnerabilities:
        readiness.blockers.append("No vulnerability report declared under evidence.vulnerabilities")
        first = next(iter(sorted(config.artifacts)), None)
        sbom = config.artifacts[first].sbom if first else "sboms/<artifact>.cdx.json"
        readiness.next_actions.append(
            GRYPE_COMMAND.format(sbom=sbom or "sboms/<artifact>.cdx.json", out="grype.json")
        )
    for item in vulnerabilities:
        vuln_issues: list[ValidationIssue] = []
        _validate_file(str(root / item), "vuln-in", vuln_issues)
        if not has_errors(vuln_issues):
            _check_content(vuln_issues, "vuln-in", partial(load_vulnerabilities, root / item))
        if vuln_issues:
            readiness.next_actions.append(
                GRYPE_COMMAND.format(sbom="sboms/<artifact>.cdx.json", out=item)
            )
        _record(readiness, vuln_issues, context="vulnerability report")

    # sast/dast/cspm are optional evidence -- scan runs fine with none of them declared --
    # but a *declared* path that fails `_validate_file` is a hard failure in `validate_paths`
    # ("error" severity), the same as a missing sbom. `evidence.posture` and
    # `evidence.source` are accepted by the schema but not yet wired into
    # `apply_config_defaults`/`run_scan` at all, so checking their existence here would
    # claim a relevance they do not currently have; they are deliberately left unchecked.
    for category in ("sast", "dast", "cspm"):
        for item in config.evidence.get(category, ()):
            category_issues: list[ValidationIssue] = []
            _validate_file(str(root / item), category, category_issues)
            if not has_errors(category_issues):
                _check_content(
                    category_issues,
                    category,
                    partial(load_security_evidence, [root / item], default_scanner_type=category),
                )
            _record(readiness, category_issues, context=f"{category} evidence")

    terraform = config.iac.get("terraform")
    terraform_source = config.iac.get("terraform_source")
    if terraform and terraform_source:
        readiness.blockers.append(
            "iac.terraform and iac.terraform_source are both set; `scan` accepts only one "
            "Terraform input at a time. Keep iac.terraform (a rendered plan is stronger "
            "evidence) and remove iac.terraform_source, or the reverse."
        )
    if terraform:
        terraform_issues: list[ValidationIssue] = []
        _validate_file(str(root / terraform), "terraform-plan", terraform_issues)
        if not has_errors(terraform_issues):
            _check_content(
                terraform_issues, "terraform-plan", partial(load_terraform_plan, root / terraform)
            )
        if terraform_issues:
            readiness.next_actions.append(TERRAFORM_COMMAND.format(out=terraform))
        _record(readiness, terraform_issues, context="Terraform plan")
    if terraform_source:
        terraform_source_issues: list[ValidationIssue] = []
        _validate_terraform_source(str(root / terraform_source), terraform_source_issues)
        # No content-loader call here, unlike every other input above: see the module
        # docstring for why `iac.terraform_source` has no analogous "invalid content" error
        # to reuse -- `scan`'s HCL extraction never fails closed on malformed `.tf` syntax,
        # it just extracts fewer blocks, so there is nothing `_check_content` could catch
        # that `_validate_terraform_source` above does not already catch.
        _record(readiness, terraform_source_issues)

    kubernetes = config.iac.get("kubernetes")
    if kubernetes:
        kubernetes_issues: list[ValidationIssue] = []
        _validate_kubernetes_manifest(str(root / kubernetes), kubernetes_issues)
        if not has_errors(kubernetes_issues):
            _check_content(
                kubernetes_issues,
                "kubernetes-manifest",
                partial(_load_kubernetes_content, root / kubernetes),
            )
        _record(readiness, kubernetes_issues)

    if config.gate.profile == "production" and readiness.blockers:
        # This does not change `ready` -- it was already going to be False, since every
        # blocker above is about evidence `scan` needs regardless of profile, and
        # switching to `advisory` would not make a missing or conflicting declared path
        # any less missing or conflicting. It is purely context: under `production`, the
        # blockers above are exactly what stands between this repository and a trustworthy
        # release gate, not just an incomplete triage run.
        readiness.blockers.append(
            "gate.profile is `production`: a release gate needs every blocker above "
            "resolved before this scan's output can be trusted for a release decision."
        )

    readiness.ready = not readiness.blockers
    return readiness


def render_text(readiness: Readiness) -> str:
    lines: list[str] = []
    for artifact in readiness.artifacts:
        marks = "  ".join(
            f"{label} {'ok' if ok else 'missing'}" for label, ok in sorted(artifact.present.items())
        )
        lines.append(f"{artifact.name}    {marks}")
    if readiness.blockers:
        lines.append("")
        lines.append("Blockers:")
        lines.extend(f"  - {item}" for item in readiness.blockers)
    if readiness.warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  - {item}" for item in readiness.warnings)
    if readiness.next_actions:
        lines.append("")
        lines.append("Next:")
        lines.extend(f"  {item}" for item in readiness.next_actions)
    lines.append("")
    lines.append("gate: ready" if readiness.ready else "gate: not ready")
    return "\n".join(lines)


def readiness_to_dict(readiness: Readiness) -> dict[str, Any]:
    return {
        "ready": readiness.ready,
        "artifacts": [
            {"name": item.name, "present": item.present, "missing": item.missing}
            for item in readiness.artifacts
        ],
        "blockers": list(readiness.blockers),
        "warnings": list(readiness.warnings),
        "next_actions": list(readiness.next_actions),
    }
