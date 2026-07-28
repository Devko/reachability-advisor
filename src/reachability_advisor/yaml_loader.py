# src/reachability_advisor/yaml_loader.py
"""Bounded, non-constructing YAML loading for untrusted documents."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .input_limits import InputSizeError, read_text_limited

MAX_YAML_DEPTH = 100
MAX_YAML_NODES = 200_000


class YamlError(ValueError):
    """Raised when a YAML document is unreadable or exceeds a safety bound.

    Subclasses ``ValueError`` so the CLI's top-level handler maps it to exit code 2
    without this module importing from ``cli``.
    """


def _safe_yaml_error_detail(exc: yaml.YAMLError) -> str:
    """Describe a YAML parse failure by location and problem only, never by quoting the
    surrounding document text.

    `str()` on a `yaml.error.MarkedYAMLError` (the base class of every error `safe_load`
    actually raises for malformed syntax -- `ScannerError`, `ParserError`,
    `ComposerError`, `ConstructorError`) renders a snippet of the source around the
    failure, via `Mark.__str__`/`get_snippet()` -- for example a whole line reading
    `secret: sk-supersecrettoken12345`. That is useful for a human debugging their own
    file locally, but every caller of this loader reads attacker-influenceable input: a
    pull request can edit `.reachability.yml`, and a config-declared relative path can
    (even after the repository-boundary check on it) still name a file this process can
    open but should not disclose the contents of. Echoing the parse failure verbatim into
    a CI log would hand back exactly the content that made it worth checking the boundary
    in the first place. This instead reports only the error's own structured fields --
    `context`, `problem`, and the failing mark's line/column -- which describe *where* and
    *what* went wrong without repeating any of the document's own text.
    """
    if isinstance(exc, yaml.error.MarkedYAMLError):
        parts = [
            str(part).strip()
            for part in (exc.context, exc.problem)
            if part
        ]
        detail = "; ".join(parts) or exc.__class__.__name__
        mark = exc.problem_mark or exc.context_mark
        if mark is not None:
            detail = f"{detail} (line {mark.line + 1}, column {mark.column + 1})"
        return detail
    # A non-marked YAMLError (e.g. `ReaderError`, raised for an unacceptable character) --
    # its own `__str__` already reports only a position and a codepoint/reason, never a
    # rendered snippet of surrounding text, so it is safe to use as-is.
    return str(exc)


def _check_bounds(value: Any, label: str, depth: int = 0, budget: list[int] | None = None) -> None:
    """Reject documents that are too deep or that expand to too many nodes.

    ``safe_load`` refuses to construct arbitrary Python objects, but it will happily
    expand anchors and aliases, so a small file can produce an enormous structure.
    The node budget is what stops that; the depth cap stops unbounded recursion.

    This function is itself recursive, but it cannot overflow the interpreter stack: the
    depth check is the first statement in the function body, so it raises before ever
    recursing past ``MAX_YAML_DEPTH`` frames, regardless of how deep the input actually
    goes. (Verified directly against Python structures built far past that depth, bypassing
    the parser entirely.) The real hazard is ``yaml.safe_load`` itself, which recurses while
    *parsing* -- that can raise a raw ``RecursionError`` on pure structural nesting before
    this function ever runs; callers must guard the parse call, not this one.
    """
    if budget is None:
        budget = [MAX_YAML_NODES]
    if depth > MAX_YAML_DEPTH:
        raise YamlError(f"{label}: nesting exceeds the supported depth of {MAX_YAML_DEPTH}")
    budget[0] -= 1
    if budget[0] < 0:
        raise YamlError(
            f"{label}: document expands to more than {MAX_YAML_NODES} nodes. "
            "Anchors and aliases can expand a small file into an enormous structure."
        )
    if isinstance(value, dict):
        for key, item in value.items():
            _check_bounds(key, label, depth + 1, budget)
            _check_bounds(item, label, depth + 1, budget)
    elif isinstance(value, list):
        for item in value:
            _check_bounds(item, label, depth + 1, budget)


def load_yaml_text(text: str, label: str) -> Any:
    try:
        parsed = yaml.safe_load(text)
    except RecursionError as exc:
        # PyYAML's scanner/parser/composer recurse per nesting level, so pure structural
        # nesting -- no anchors or aliases needed -- can exhaust the stack while parsing,
        # well before the result ever reaches `_check_bounds`. Surface it as a normal
        # loader error instead of an uncaught crash.
        raise YamlError(f"{label}: nesting too deep for the YAML parser") from exc
    except yaml.YAMLError as exc:
        raise YamlError(f"{label}: invalid YAML: {_safe_yaml_error_detail(exc)}") from None
    _check_bounds(parsed, label)
    return parsed


def load_yaml_documents(text: str, label: str) -> list[Any]:
    try:
        documents = list(yaml.safe_load_all(text))
    except RecursionError as exc:
        # See load_yaml_text: safe_load_all's parser recurses the same way while iterating.
        raise YamlError(f"{label}: nesting too deep for the YAML parser") from exc
    except yaml.YAMLError as exc:
        raise YamlError(f"{label}: invalid YAML: {_safe_yaml_error_detail(exc)}") from None
    for document in documents:
        _check_bounds(document, label)
    return documents


def load_yaml_mapping(path: str | Path, label: str) -> dict[str, Any]:
    file_path = Path(path)
    try:
        text = read_text_limited(file_path, label)
    except InputSizeError:
        raise
    except OSError as exc:
        raise YamlError(f"{file_path}: {label} could not be read: {exc}") from None
    parsed = load_yaml_text(text, f"{file_path}: {label}")
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise YamlError(f"{file_path}: {label} must be a mapping, got {type(parsed).__name__}")
    return parsed
