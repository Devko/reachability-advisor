"""Bounded input file reads for scanner and CI artifacts."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

DEFAULT_MAX_INPUT_BYTES = 50 * 1024 * 1024
MAX_INPUT_BYTES_ENV = "REACHABILITY_ADVISOR_MAX_INPUT_BYTES"


class InputSizeError(ValueError):
    """Raised when an input file exceeds the configured local processing limit."""


def max_input_bytes() -> int:
    raw = os.environ.get(MAX_INPUT_BYTES_ENV)
    if not raw:
        return DEFAULT_MAX_INPUT_BYTES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_INPUT_BYTES
    return value if value > 0 else DEFAULT_MAX_INPUT_BYTES


def check_input_size(path: str | Path, label: str) -> None:
    file_path = Path(path)
    size = file_path.stat().st_size
    limit = max_input_bytes()
    if size > limit:
        raise InputSizeError(
            f"{file_path}: {label} input is {size} bytes, above the configured limit of {limit} bytes. "
            f"Set {MAX_INPUT_BYTES_ENV} to a larger positive integer only for trusted inputs."
        )


def read_text_limited(path: str | Path, label: str, *, encoding: str = "utf-8") -> str:
    file_path = Path(path)
    check_input_size(file_path, label)
    return file_path.read_text(encoding=encoding)


def iter_text_lines_limited(path: str | Path, label: str, *, encoding: str = "utf-8") -> Iterator[str]:
    file_path = Path(path)
    check_input_size(file_path, label)
    with file_path.open(encoding=encoding) as handle:
        yield from handle
