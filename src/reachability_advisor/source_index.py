"""Source tree indexing helpers for built-in reachability analysis."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .source_manifests import is_manifest_file, manifest_language_for

MAX_FILE_BYTES = 1_000_000
SUPPORTED_EXTENSIONS = {".java", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go"}


@dataclass(frozen=True)
class IndexedSourceFile:
    path: Path
    language: str
    text: str


@dataclass
class SourceIndex:
    root: Path | None
    files: list[IndexedSourceFile] = field(default_factory=list)
    manifest_files: list[IndexedSourceFile] = field(default_factory=list)
    skipped_files: list[dict[str, str]] = field(default_factory=list)
    import_cache: dict[str, bool] = field(default_factory=dict)

    @property
    def languages(self) -> list[str]:
        return sorted({file.language for file in self.files if file.language != "unknown"})


def parse_source_roots(values: list[str]) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"source root must use artifact=path syntax: {value}")
        artifact, raw_path = value.split("=", 1)
        artifact = artifact.strip()
        if not artifact:
            raise ValueError(f"source root artifact name is empty: {value}")
        roots[artifact] = Path(raw_path).expanduser().resolve()
    return roots


def build_source_index(root: Path | None) -> SourceIndex:
    if root is None:
        return SourceIndex(root=None)
    root_path = Path(root)
    index = SourceIndex(root=root_path)
    if not root_path.exists() or not root_path.is_dir():
        index.skipped_files.append({"path": str(root_path), "reason": "source root does not exist or is not a directory"})
        return index
    ignored_dirs = {".git", ".hg", ".svn", "node_modules", "target", "build", "dist", ".venv", "venv", "__pycache__"}
    for current, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [dirname for dirname in dirnames if dirname not in ignored_dirs]
        current_path = Path(current)
        for filename in filenames:
            path = current_path / filename
            is_source = path.suffix.lower() in SUPPORTED_EXTENSIONS
            is_manifest = is_manifest_file(path)
            if not is_source and not is_manifest:
                continue
            try:
                size = path.stat().st_size
            except OSError as exc:
                index.skipped_files.append({"path": str(path), "reason": f"stat failed: {exc}"})
                continue
            if size > MAX_FILE_BYTES:
                index.skipped_files.append({"path": str(path), "reason": "file exceeds source scan size limit"})
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                index.skipped_files.append({"path": str(path), "reason": f"read failed: {exc}"})
                continue
            if is_source:
                index.files.append(IndexedSourceFile(path=path, language=language_for_source_path(path), text=text))
            if is_manifest:
                index.manifest_files.append(IndexedSourceFile(path=path, language=manifest_language_for(path), text=text))
    return index


def language_for_source_path(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return "javascript"
    if suffix == ".java":
        return "java"
    if suffix == ".py":
        return "python"
    if suffix == ".go":
        return "go"
    return "unknown"


__all__ = [
    "IndexedSourceFile",
    "MAX_FILE_BYTES",
    "SUPPORTED_EXTENSIONS",
    "SourceIndex",
    "build_source_index",
    "language_for_source_path",
    "parse_source_roots",
]
