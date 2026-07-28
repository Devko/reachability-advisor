"""Detect what evidence a repository already has, for `init` and `doctor`.

This module is pure inspection: it walks a filesystem tree and reports
dataclasses describing what it found. It never parses YAML config, never
loads a `.reachability.yml`, and never talks to the CLI. Tasks that scaffold
a config (`init`) or diagnose a repo (`doctor`) consume `Detection`.

Governing principle: detect and declare only what is actually there. A path
is only ever reported if a file or directory with that exact relative path
exists on disk. Missing evidence is reported as a note (with the command
that would produce it), never papered over and never guessed at.

The repository being walked is untrusted: it may be a hostile or unusual
tree with broken symlinks, symlink cycles, permission-denied files, huge
files, non-UTF8 names, or a pathological number of entries. Detection must
degrade -- skip what it cannot read -- rather than raise or hang.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

# Directories that are never descended into. This mirrors source_index.py's
# ignored_dirs, plus a few extras relevant to what a repo *ships* (build
# output, package caches) rather than what it wrote. "outputs" specifically
# is this project's own gitignored scratch directory for generated
# artifacts -- detection must not mistake a previous local run's leftovers
# for checked-in evidence.
SKIP_DIRECTORIES = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
    "__pycache__", "dist", "build", ".mypy_cache", ".ruff_cache", ".tox",
    "target", "outputs",
})

LOCKFILE_ECOSYSTEMS: dict[str, str] = {
    "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "poetry.lock": "python", "requirements.txt": "python", "Pipfile.lock": "python",
    "go.sum": "go", "Cargo.lock": "rust", "Gemfile.lock": "ruby", "pom.xml": "java",
    "build.gradle": "java", "composer.lock": "php",
}

SBOM_COMMANDS: dict[str, str] = {
    "npm": "syft dir:{path} -o cyclonedx-json > {out}",
    "python": "syft dir:{path} -o cyclonedx-json > {out}",
    "go": "syft dir:{path} -o cyclonedx-json > {out}",
    "rust": "syft dir:{path} -o cyclonedx-json > {out}",
    "ruby": "syft dir:{path} -o cyclonedx-json > {out}",
    "java": "syft dir:{path} -o cyclonedx-json > {out}",
    "php": "syft dir:{path} -o cyclonedx-json > {out}",
}

SBOM_SUFFIXES = (".cdx.json", ".spdx.json")
VULNERABILITY_REPORT_NAMES = frozenset({
    "grype.json", "trivy.json", "osv.json", "vulnerabilities.json",
})
SBOM_IMAGE_PROPERTIES = ("container:image", "oci:image:ref")

# Bounded prefix read for content sniffing (Kubernetes YAML, Terraform plan
# JSON). Never read a whole untrusted file just to look at its first few
# keys -- a hostile or merely huge file must not turn a filesystem walk into
# an unbounded read.
HEAD_SNIFF_BYTES = 4096

# SBOMs are read in full (not sniffed) to extract an embedded image
# reference, but only up to this size. Detection is a cheap, frequent,
# best-effort pass -- unlike the real SBOM loader (input_limits.py, 50MB
# cap) it should never spend real memory/time on a multi-megabyte document
# just to check one optional property.
MAX_SBOM_IMAGE_SNIFF_BYTES = 2_000_000

# Circuit breaker for pathological trees (a monorepo with hundreds of
# thousands of files, or a directory bomb). Measured against a synthetic
# 250k-file tree: detect_repo completes in ~3s once this trips (see _walk's
# docstring for where that time goes) -- well within what is acceptable for
# a one-time, non-interactive `init`/`doctor` pass, so this is not a
# normal-case limit. It exists so a hostile input cannot turn `detect_repo`
# into an unbounded operation. When it trips, that fact is reported in
# `notes` rather than silently under-reporting.
MAX_FILES_SCANNED = 200_000


@dataclass(frozen=True)
class DetectedArtifact:
    name: str
    sbom: str | None = None
    source: str | None = None
    image: str | None = None
    ecosystem: str | None = None


@dataclass
class Detection:
    artifacts: list[DetectedArtifact] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    terraform: str | None = None
    terraform_source: str | None = None
    kubernetes: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _WalkResult:
    files: list[Path]
    truncated: bool


def _walk(root: Path) -> _WalkResult:
    """List every file under root, skipping SKIP_DIRECTORIES, sorted by path.

    Uses os.walk with followlinks=False (the default): a symlinked
    directory is listed but never descended into, so a symlink cycle
    (including a directory symlinked to one of its own ancestors) cannot
    cause unbounded recursion.

    Directory and file names are also sorted at each level during the walk
    itself. That is what keeps a truncated walk (MAX_FILES_SCANNED tripped on
    a pathological tree) deterministic: which subset of files gets collected
    before the cap trips depends on traversal order, so traversal order must
    not depend on filesystem readdir order either.

    The returned list is additionally fully sorted by path: os.walk's own
    traversal order (a directory's own files, then each subdirectory in
    turn) is deterministic but is not the same thing as a flat sort of full
    paths, and every caller downstream wants a single, globally sorted list
    to pick "the first" match from. Sorting once here -- instead of five
    separate call sites each doing their own sorted(files) -- is mainly
    about having one place that owns the invariant; it is a smaller
    performance win than it looks like, because Timsort is adaptive and a
    second sort of an already-sorted list is close to free. The dominant
    cost at scale is Path's own comparison overhead, not the number of sort
    calls: on a 250k-file synthetic tree, sorting 200k Path objects alone
    took ~1.6-2.2s (vs. ~0.01s to sort the equivalent plain strings), and
    detect_repo end to end took ~2.9s -- both before and after moving the
    sort here. That is an intentionally-pathological input that already
    trips MAX_FILES_SCANNED; a few seconds for a one-time `init`/`doctor`
    pass on a monorepo of that size was judged acceptable rather than worth
    a deeper rewrite to sort by string key.
    """
    files: list[Path] = []
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIRECTORIES)
        current_path = Path(current)
        for filename in sorted(filenames):
            files.append(current_path / filename)
        if len(files) >= MAX_FILES_SCANNED:
            files.sort()
            return _WalkResult(files=files, truncated=True)
    files.sort()
    return _WalkResult(files=files, truncated=False)


def _relative(path: Path, root: Path) -> str:
    # Every path passed here comes from _walk(root), so it is always root or a
    # descendant of root -- relative_to cannot raise. No fallback: an
    # untested "can't happen" branch is worse than none.
    return path.relative_to(root).as_posix()


def _is_regular_file(path: Path) -> bool:
    """True only for a real, readable-in-principle regular file.

    Both symlink targets and ordinary files pass stat(); what must be
    rejected is anything that is not a regular file -- a broken symlink
    (stat raises), a FIFO or socket (would block forever on open), or a
    character device (reports misleading sizes). This mirrors the same
    check in source_index.py.
    """
    try:
        info = path.stat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode)


def _read_head(path: Path, max_bytes: int) -> str | None:
    """Read up to max_bytes from path, or None if it cannot be read safely."""
    if not _is_regular_file(path):
        return None
    try:
        with path.open("rb") as handle:
            raw = handle.read(max_bytes)
    except OSError:
        return None
    return raw.decode("utf-8", errors="ignore")


def _unique_name(candidate: str, identity: str, claimed: set[str]) -> str:
    """Return a name not already in claimed, and reserve it.

    Two artifacts detected under the same candidate name (e.g. two
    directories both called "api") must not collide: reporting evidence
    only for the first and silently dropping the second would misrepresent
    what is actually in the repository. When the bare candidate is taken,
    fall back to a name derived from the full relative path -- guaranteed
    unique per artifact, since two artifacts never share the same source
    path -- and if even that somehow collides, append a deterministic
    numeric suffix rather than raise or drop the artifact.
    """
    if candidate and candidate not in claimed:
        claimed.add(candidate)
        return candidate
    fallback = identity.replace("/", "-") or candidate or "artifact"
    if fallback not in claimed:
        claimed.add(fallback)
        return fallback
    index = 2
    while f"{fallback}-{index}" in claimed:
        index += 1
    unique = f"{fallback}-{index}"
    claimed.add(unique)
    return unique


def _sbom_suffix(name: str) -> str | None:
    for suffix in SBOM_SUFFIXES:
        if name.endswith(suffix):
            return suffix
    return None


def _sbom_image(path: Path) -> str | None:
    """Best-effort extraction of an image reference already embedded in an SBOM.

    Reports only a property that is actually present in the document --
    this is reading a fact out of existing evidence, not inventing one.
    Any failure (oversized file, invalid JSON, unexpected shape) degrades
    to None; a malformed SBOM is still evidence that a file exists at that
    path, so it must not affect whether the SBOM itself is reported.
    """
    if not _is_regular_file(path):
        return None
    try:
        if path.stat().st_size > MAX_SBOM_IMAGE_SNIFF_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    metadata = data.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    properties = component.get("properties") if isinstance(component, dict) else None
    if not isinstance(properties, list):
        return None
    for item in properties:
        if not isinstance(item, dict):
            continue
        if item.get("name") in SBOM_IMAGE_PROPERTIES:
            value = item.get("value")
            if isinstance(value, str) and value:
                return value
    return None


def _looks_like_terraform_plan(path: Path) -> bool:
    """Sniff a *.json file for the shape of `terraform show -json` output.

    Every real plan begins with `{"format_version": ...` -- format_version
    is Terraform's own stable schema marker and is always emitted first.
    Reading a bounded prefix (rather than the whole, possibly huge, plan)
    and checking for that marker is enough to tell a rendered plan apart
    from an SBOM (which uses "bomFormat"/"specVersion") or unrelated JSON,
    without a full parse.
    """
    head = _read_head(path, HEAD_SNIFF_BYTES)
    if head is None:
        return False
    text = head.lstrip()
    return text.startswith("{") and '"format_version"' in text


def _looks_like_kubernetes_manifest(path: Path) -> bool:
    head = _read_head(path, HEAD_SNIFF_BYTES)
    if head is None:
        return False
    return "kind:" in head and "apiVersion:" in head


def detect_repo(root: Path) -> Detection:
    """Inspect a repository and report only what is actually present."""
    root = Path(root)
    detection = Detection()
    with contextlib.suppress(OSError):
        root = root.resolve()
    if not root.is_dir():
        detection.notes.append(f"{root}: not a directory; nothing to detect.")
        return detection

    walked = _walk(root)
    files = walked.files  # already sorted by path; see _walk's docstring
    if walked.truncated:
        detection.notes.append(
            f"This repository has more than {MAX_FILES_SCANNED} files under scan; "
            "detection stopped early and may have missed evidence. Narrow the scan "
            "to a subdirectory or exclude vendor/build directories."
        )

    claimed: set[str] = set()

    sbom_entries = [
        (path, suffix)
        for path in files
        if (suffix := _sbom_suffix(path.name)) is not None
    ]
    for path, suffix in sbom_entries:
        rel = _relative(path, root)
        stem = path.name[: -len(suffix)]
        identity = rel[: -len(suffix)] if rel.endswith(suffix) else rel
        name = _unique_name(stem, identity, claimed)
        detection.artifacts.append(
            DetectedArtifact(name=name, sbom=rel, image=_sbom_image(path))
        )

    seen_source_dirs: set[str] = set()
    for path in files:
        ecosystem = LOCKFILE_ECOSYSTEMS.get(path.name)
        if ecosystem is None:
            continue
        source_dir = path.parent
        source_rel = _relative(source_dir, root)
        if source_rel in seen_source_dirs:
            # Another lockfile already recorded this exact directory (e.g. a
            # Python project with both poetry.lock and requirements.txt).
            # Same source, so one artifact -- not a second, near-duplicate
            # record for the identical path.
            continue
        seen_source_dirs.add(source_rel)
        candidate = source_dir.name if source_dir != root else root.name
        name = _unique_name(candidate, source_rel, claimed)
        detection.artifacts.append(
            DetectedArtifact(name=name, source=source_rel, ecosystem=ecosystem)
        )
        command_template = SBOM_COMMANDS.get(ecosystem)
        if command_template is not None:
            detection.notes.append(
                f"{name}: no SBOM found. Generate one with: "
                + command_template.format(path=source_rel, out=f"sboms/{name}.cdx.json")
            )

    terraform_files = [path for path in files if path.suffix == ".tf"]
    if terraform_files:
        detection.terraform_source = _relative(terraform_files[0].parent, root)

    plan_candidates = [
        path for path in files if path.suffix == ".json" and "plan" in path.name.lower()
    ]
    for path in plan_candidates:
        if _looks_like_terraform_plan(path):
            detection.terraform = _relative(path, root)
            break

    if detection.terraform_source and not detection.terraform:
        tf_dir = detection.terraform_source
        detection.notes.append(
            f"Terraform source found in {tf_dir}. A plan gives far better exposure "
            "evidence than static HCL. Run: "
            f"terraform -chdir={tf_dir} plan -out=tfplan.binary && "
            f"terraform -chdir={tf_dir} show -json tfplan.binary > tfplan.json"
        )

    for path in files:
        if path.suffix not in {".yaml", ".yml"}:
            continue
        if _looks_like_kubernetes_manifest(path):
            detection.kubernetes = _relative(path.parent, root)
            break

    for path in files:
        if path.name in VULNERABILITY_REPORT_NAMES:
            detection.vulnerabilities.append(_relative(path, root))

    if not detection.vulnerabilities:
        sboms_available = sorted(
            (artifact for artifact in detection.artifacts if artifact.sbom),
            key=lambda artifact: artifact.name,
        )
        if sboms_available:
            detection.notes.append(
                "No vulnerability report found. Generate one with: "
                f"grype sbom:{sboms_available[0].sbom} -o json > grype.json"
            )
        else:
            detection.notes.append(
                "No vulnerability report found. Once an SBOM exists, generate one with: "
                "grype sbom:sboms/<artifact>.cdx.json -o json > grype.json"
            )

    return detection


__all__ = [
    "HEAD_SNIFF_BYTES",
    "LOCKFILE_ECOSYSTEMS",
    "MAX_FILES_SCANNED",
    "MAX_SBOM_IMAGE_SNIFF_BYTES",
    "SBOM_COMMANDS",
    "SBOM_SUFFIXES",
    "SKIP_DIRECTORIES",
    "VULNERABILITY_REPORT_NAMES",
    "Detection",
    "DetectedArtifact",
    "detect_repo",
]
