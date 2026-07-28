"""Report what evidence is present, what is missing, and the command that produces it.

`doctor` exists to make one promise concrete: if it reports `ready`, `scan` will actually
run against the declared configuration instead of failing on a missing file or a
combination of inputs `scan` itself refuses. Every check here mirrors a real requirement
inside `run_scan` / `apply_config_defaults` (cli.py) or `validate_paths` (validators.py) --
a required flag, a file `scan` will try to open, or an input combination `scan` explicitly
rejects -- rather than a heuristic about what "looks" complete. Anything doctor cannot
verify, it says so; it never reports `ready` on evidence it has not actually checked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import LoadedConfig

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
    next_actions: list[str] = field(default_factory=list)


def diagnose(loaded: LoadedConfig, root: Path) -> Readiness:
    """Check every declared input actually exists, and that `scan` can run at all.

    Two independent kinds of problem are reported, both as `blockers`, because both stop
    `scan` from producing a trustworthy result:

    - A path *declared* in `.reachability.yml` does not exist on disk. `scan` would either
      fail to load it outright (an sbom or an evidence file) or silently degrade to weaker
      evidence (a missing source root only warns in `validate_paths`) -- doctor treats both
      the same way, because onboarding should surface every gap up front rather than lean
      on `scan`'s own, more forgiving, per-input fault tolerance.
    - The declared configuration cannot satisfy `scan`'s own structural requirements, even
      if every path it names exists: at least one artifact must declare an `sbom`
      (`run_scan` raises without one), at least one vulnerability input must be declared,
      and `iac.terraform` and `iac.terraform_source` must never both be set (`scan` rejects
      that combination outright -- and `config_detect.detect_repo` can produce exactly that
      combination for a repository that has both a `.tf` source tree and a rendered plan
      checked in, so this is reachable straight out of `init`, not just from a hand-edited
      config).

    No config file at all is reported as its own, first blocker rather than folded into
    "no artifacts declared": that is the first thing a new user hits running `doctor`
    before ever running `init`, and it deserves a message that names the actual next step
    instead of a generic "nothing is declared".
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
        for label, value in (("sbom", artifact.sbom), ("source", artifact.source)):
            if value is None:
                present[label] = False
                missing.append(label)
                continue
            exists = (root / value).exists()
            present[label] = exists
            if not exists:
                missing.append(label)
                readiness.blockers.append(f"{name}: declared {label} {value!r} does not exist")
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
        if not (root / item).exists():
            readiness.blockers.append(f"declared vulnerability report {item!r} does not exist")
            readiness.next_actions.append(
                GRYPE_COMMAND.format(sbom="sboms/<artifact>.cdx.json", out=item)
            )

    # sast/dast/cspm are optional evidence -- scan runs fine with none of them declared --
    # but a *declared* path that does not exist is a hard failure in `validate_paths`
    # ("error" severity), the same as a missing sbom. `evidence.posture` and
    # `evidence.source` are accepted by the schema but not yet wired into
    # `apply_config_defaults`/`run_scan` at all, so checking their existence here would
    # claim a relevance they do not currently have; they are deliberately left unchecked.
    for category in ("sast", "dast", "cspm"):
        for item in config.evidence.get(category, ()):
            if not (root / item).exists():
                readiness.blockers.append(f"declared {category} evidence {item!r} does not exist")

    terraform = config.iac.get("terraform")
    terraform_source = config.iac.get("terraform_source")
    if terraform and terraform_source:
        readiness.blockers.append(
            "iac.terraform and iac.terraform_source are both set; `scan` accepts only one "
            "Terraform input at a time. Keep iac.terraform (a rendered plan is stronger "
            "evidence) and remove iac.terraform_source, or the reverse."
        )
    if terraform and not (root / terraform).exists():
        readiness.blockers.append(f"declared Terraform plan {terraform!r} does not exist")
        readiness.next_actions.append(TERRAFORM_COMMAND.format(out=terraform))
    if terraform_source and not (root / terraform_source).exists():
        readiness.blockers.append(f"declared Terraform source {terraform_source!r} does not exist")

    kubernetes = config.iac.get("kubernetes")
    if kubernetes and not (root / kubernetes).exists():
        readiness.blockers.append(f"declared Kubernetes manifest {kubernetes!r} does not exist")

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
        "next_actions": list(readiness.next_actions),
    }
