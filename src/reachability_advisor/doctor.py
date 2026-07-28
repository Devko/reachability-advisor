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

Doctor stops at the same layer `validate_paths` does: does the declared path exist, is it
the right kind of thing (a file, not a directory; a directory, not a file; YAML/JSON for a
Kubernetes manifest), and is it non-empty. Neither doctor nor `validate_paths` opens a file
to check whether its *content* parses (valid JSON/YAML, valid CycloneDX) or whether the
process can actually read it (file permissions). That gap is intentional and shared: a file
that exists, is the right kind, and is non-empty but contains garbage, or one `scan` cannot
open because of filesystem permissions, passes both `doctor` and `validate_paths` and is
only caught once `scan`'s own loaders try to parse or open it -- which fails closed with a
clear, specific error (e.g. "invalid JSON", or a permission error), never a silent success
and never an unhandled traceback. Doing that check here too would require doctor to
duplicate every loader's parsing logic, which is exactly the kind of drift-prone
reimplementation this module exists to avoid; "does it exist and is it usable as a file"
is doctor's remit, "is it valid" stays `scan`'s.

Two independent kinds of problem are reported. `blockers` are what stop `scan` from
running at all, or from producing a trustworthy result: a required path that is missing,
the wrong kind, or empty (an `error`-severity issue in `validate_paths`); at least one
artifact must declare an `sbom` (`run_scan` raises without one); at least one vulnerability
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

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import LoadedConfig
from .validators import (
    ValidationIssue,
    _validate_file,
    _validate_kubernetes_manifest,
    _validate_source_root,
    _validate_terraform_source,
)

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


def diagnose(loaded: LoadedConfig, root: Path) -> Readiness:
    """Check every declared input the same way `scan` will, and that `scan` can run at all.

    See the module docstring for how blockers and warnings are told apart, and why content
    validity and file readability are out of scope for both doctor and `validate_paths`.
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

    for name, artifact in sorted(config.artifacts.items()):
        present: dict[str, bool] = {}
        missing: list[str] = []

        if artifact.sbom is None:
            present["sbom"] = False
            missing.append("sbom")
        else:
            sbom_issues: list[ValidationIssue] = []
            _validate_file(str(root / artifact.sbom), "sbom", sbom_issues)
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
        if terraform_issues:
            readiness.next_actions.append(TERRAFORM_COMMAND.format(out=terraform))
        _record(readiness, terraform_issues, context="Terraform plan")
    if terraform_source:
        terraform_source_issues: list[ValidationIssue] = []
        _validate_terraform_source(str(root / terraform_source), terraform_source_issues)
        _record(readiness, terraform_source_issues)

    kubernetes = config.iac.get("kubernetes")
    if kubernetes:
        kubernetes_issues: list[ValidationIssue] = []
        _validate_kubernetes_manifest(str(root / kubernetes), kubernetes_issues)
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
