# src/reachability_advisor/config_render.py
"""Render a detected repository into a commented .reachability.yml.

This module writes YAML by hand rather than dumping the whole document, so it
controls exactly which comments (headers, `# TODO`s) appear and where. That
means every value it interpolates into a line is this module's own
responsibility to quote safely -- a path or artifact name comes straight off
a filesystem this tool does not control, and a directory can legally be named
`%weird`, `true`, `a: b`, or contain a literal newline. `_scalar`, `_flow_list`
and `_comment` below are the three points where untrusted text is turned into
YAML; every other line in `render_config` is a fixed, known-safe string.

Governing principle (matches config_detect.py): declare only what was
actually found. Missing evidence becomes a `# TODO` naming the exact command
that would produce it, never a guessed path.
"""

from __future__ import annotations

from pathlib import PurePosixPath

import yaml

from .config_detect import SBOM_SUFFIXES, DetectedArtifact, Detection

HEADER = """# Reachability Advisor configuration.
# Written by `reachability-advisor init` from what was found in this repository.
# Values here are defaults; any CLI flag overrides them.
# Run `reachability-advisor doctor` to see what is still missing.
"""


def _scalar(value: str) -> str:
    """Render `value` as a YAML scalar that loads back to exactly `value`.

    Quoting is delegated to PyYAML's own emitter -- which already knows every
    plain-scalar ambiguity (leading `%`/`#`/`-`, `true`/`null`/numeric-looking
    strings, embedded `: `/` #`, leading/trailing space, flow indicators, ...)
    -- instead of a hand-rolled set of quoting rules, which is exactly the
    kind of thing that is easy to get subtly wrong for input this module does
    not control.

    A value containing a raw control character (most importantly an embedded
    newline, which is legal in a Unix filename) is forced into double-quoted
    style. Left to its default, PyYAML represents an embedded newline with a
    *multi-line* single-quoted scalar; when that value is an artifact's own
    name -- rendered as a bare mapping key, `  {name}:` -- a multi-line key
    breaks the surrounding block mapping ("mapping values are not allowed
    here"), because this hand-written renderer does not track the additional
    indentation multi-line quoted scalars require. Double-quoted style keeps
    the whole scalar on one physical line, which this renderer's plain
    line-by-line assembly always supports.

    `width` is set far past anything this ever produces for the same reason:
    PyYAML wraps a long scalar at its default 80-column width even without
    any control character present, by inserting a line-fold at an existing
    space -- confirmed to break exactly the same way ("mapping values are not
    allowed here") when the wrapped value is an artifact name used as a
    mapping key, e.g. a long, space-containing name detected from an unusual
    directory. Folding back on load happens to reconstitute the *value* of a
    plain scalar correctly (the fold lands where a real space already was),
    but it does not save the surrounding document's structure when that value
    is a key, so this is not treated as a narrower, value-only fix.
    """
    style = '"' if any(ord(char) < 0x20 for char in value) else None
    dumped = yaml.safe_dump(
        value, default_flow_style=True, allow_unicode=True, default_style=style, width=1_000_000
    ).rstrip("\n")
    # A plain scalar dumped as a standalone document gets a trailing `...` end-of-
    # document marker (PyYAML disambiguates it from a second document); strip it,
    # since here it is embedded mid-line in a larger, hand-written document.
    if dumped.endswith("..."):
        dumped = dumped[:-3].rstrip()
    return dumped


def _flow_list(items: list[str]) -> str:
    """Render `items` as a YAML flow sequence (`[a, b]`), quoting elements safely.

    Dumping the whole list at once -- rather than joining `_scalar`-quoted
    items with ", " by hand -- is what keeps an item containing a literal
    comma from being split into two list entries on load: a plain scalar is
    safe as a lone document but not as an element of a flow sequence, where a
    comma is a structural separator.

    `width` is set far past anything this ever produces to suppress PyYAML's
    default 80-column line wrapping. A wrapped flow sequence still parses back
    correctly (YAML does not care about a flow collection's internal line
    breaks), so this is a readability fix, not a correctness one -- confirmed
    against this project's own real `evidence.vulnerabilities` list, which is
    long enough to wrap at the default width and, unwrapped, is far easier for
    a human to read and hand-edit, which this file is explicitly meant for.
    """
    return yaml.safe_dump(
        list(items), default_flow_style=True, allow_unicode=True, width=1_000_000
    ).rstrip("\n")


def _comment(text: str) -> str:
    """Sanitize free text for use as a single-line `# ...` comment.

    A YAML comment runs to the end of its physical line, with no way to escape
    a literal newline inside one. Note text can be built from a detected path
    (e.g. "no SBOM found for <name>"), so any embedded newline is flattened to
    a space rather than trusted to stay out of the comment this renders --
    otherwise the note's tail would land on its own, un-commented line and
    could break the document, or at best silently vanish as a stray scalar.
    """
    return text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def _natural_key(artifact: DetectedArtifact) -> str | None:
    """The bare candidate name `config_detect._unique_name` would try first.

    `detect_repo` already guarantees every `DetectedArtifact.name` is unique:
    a second artifact that collided on the same bare candidate (e.g. two
    directories both named "api") was given a path-derived fallback name
    instead. That means two artifacts can end up with different `.name`s while
    still having come from the same obvious name -- an SBOM `sboms/api.cdx.json`
    and a lockfile directory `services/api/` both naturally called "api". This
    recomputes that candidate independently, from only the public `sbom`/
    `source` fields (mirroring, not reusing, `config_detect`'s own private
    logic), so `render_config` can find those pairs again and flag them for a
    human to reconcile -- without merging them itself.

    Returns None when no candidate can be derived (no sbom and no source, or a
    source path that *is* the repository root, `"."`, whose PurePosixPath name
    is empty) -- rare shapes where under-flagging a possible duplicate is the
    safe failure mode, not over-flagging one.
    """
    if artifact.sbom:
        stem = PurePosixPath(artifact.sbom).name
        for suffix in SBOM_SUFFIXES:
            if stem.endswith(suffix):
                return stem[: -len(suffix)]
        return stem
    if artifact.source:
        name = PurePosixPath(artifact.source).name
        return name or None
    return None


def _duplicate_groups(
    artifacts: list[DetectedArtifact],
) -> list[tuple[str, list[DetectedArtifact]]]:
    """Group artifacts that share a natural key, keeping only groups of 2+.

    Sorted by key for deterministic output -- `detect_repo` already returns
    `artifacts` in a deterministic order, but grouping by a dict key would
    otherwise depend on Python's dict-ordering-by-first-insertion, which is
    deterministic in practice but not the property this function should rely
    on to justify it.
    """
    groups: dict[str, list[DetectedArtifact]] = {}
    for artifact in artifacts:
        key = _natural_key(artifact)
        if key is None:
            continue
        groups.setdefault(key, []).append(artifact)
    return sorted((item for item in groups.items() if len(item[1]) > 1), key=lambda item: item[0])


def render_config(detection: Detection) -> str:
    """Render a detected repository into a `.reachability.yml` document.

    Declares only what `detection` actually reports. Missing evidence and
    possible name-collision duplicates both become `# TODO` comments -- never
    a guessed path and never a silent merge -- so the emitted config always
    loads and validates, even when detection found nothing at all.
    """
    lines = [HEADER, "version: 1", ""]

    duplicate_groups = _duplicate_groups(detection.artifacts)
    # Map each artifact's own name to the *other* names in its duplicate group,
    # so the per-artifact TODO below can name them directly.
    duplicate_siblings: dict[str, list[str]] = {
        artifact.name: [other.name for other in group if other.name != artifact.name]
        for _, group in duplicate_groups
        for artifact in group
    }
    duplicate_notes = [
        f"possible duplicate: {', '.join(a.name for a in group)} were all matched to the "
        f"name {key!r}. They were kept as separate artifacts on purpose -- merging on a "
        "name match risks attaching the wrong SBOM to the wrong source, which is exactly "
        "the silent-error class this tool exists to catch. Reconcile by hand if they are "
        "really the same artifact."
        for key, group in duplicate_groups
    ]

    all_notes = [*detection.notes, *duplicate_notes]
    if all_notes:
        lines.append("# TODO: read these before trusting this config.")
        lines.extend(f"# TODO: {_comment(note)}" for note in all_notes)
        lines.append("")

    lines.append("artifacts:")
    if not detection.artifacts:
        lines.append("  # TODO: no artifacts detected. Add one, for example:")
        lines.append("  #   my-service:")
        lines.append("  #     sbom: sboms/my-service.cdx.json")
        lines.append("  #     source: src/my-service")
    for artifact in detection.artifacts:
        lines.append(f"  {_scalar(artifact.name)}:")
        if artifact.sbom:
            lines.append(f"    sbom: {_scalar(artifact.sbom)}")
        else:
            lines.append(f"    # TODO: no SBOM found for {_comment(artifact.name)}")
        if artifact.source:
            lines.append(f"    source: {_scalar(artifact.source)}")
        if artifact.image:
            lines.append(f"    image: {_scalar(artifact.image)}")
        siblings = duplicate_siblings.get(artifact.name)
        if siblings:
            lines.append(
                f"    # TODO: possible duplicate of {_comment(', '.join(siblings))} "
                "-- not merged automatically; reconcile by hand if this is the same artifact."
            )
    lines.append("")

    lines.append("evidence:")
    if detection.vulnerabilities:
        lines.append(f"  vulnerabilities: {_flow_list(list(detection.vulnerabilities))}")
    else:
        lines.append("  # TODO: no vulnerability report found.")
        lines.append("  vulnerabilities: []")
    lines.append("")

    if detection.terraform or detection.terraform_source or detection.kubernetes:
        lines.append("iac:")
        if detection.terraform:
            lines.append(f"  terraform: {_scalar(detection.terraform)}")
        if detection.terraform_source:
            lines.append(f"  terraform_source: {_scalar(detection.terraform_source)}")
        if detection.kubernetes:
            lines.append(f"  kubernetes: {_scalar(detection.kubernetes)}")
        lines.append("")

    lines.append("gate:")
    lines.append("  profile: advisory   # switch to `production` once doctor reports ready")
    lines.append("  fail_on: high")
    lines.append("")
    return "\n".join(lines)


__all__ = ["HEADER", "render_config"]
