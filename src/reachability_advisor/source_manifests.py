"""Package-manager manifest evidence for source reachability."""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from .models import Component, Confidence, Reachability, SourceEvidence, SourceLocation
from .purl import ecosystem_from_component, parse_purl

MANIFEST_FILENAMES = {
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "go.mod",
    "go.sum",
    "libs.versions.toml",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "pyproject.toml",
    "yarn.lock",
}


class ManifestSourceFile(Protocol):
    @property
    def path(self) -> Path:
        ...

    @property
    def language(self) -> str:
        ...

    @property
    def text(self) -> str:
        ...


def is_manifest_file(path: Path) -> bool:
    name = path.name.lower()
    return name in MANIFEST_FILENAMES or (name.startswith("requirements") and path.suffix.lower() == ".txt")


def manifest_language_for(path: Path) -> str:
    name = path.name.lower()
    if name in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"}:
        return "npm-manifest"
    if name in {"pyproject.toml", "poetry.lock"} or (name.startswith("requirements") and path.suffix.lower() == ".txt"):
        return "python-manifest"
    if name in {"build.gradle", "build.gradle.kts", "gradle.lockfile", "libs.versions.toml", "pom.xml"}:
        return "jvm-manifest"
    if name in {"go.mod", "go.sum"}:
        return "go-manifest"
    return "manifest"


def manifest_dependency_evidence(component: Component, manifests: Iterable[ManifestSourceFile]) -> SourceEvidence | None:
    ecosystem = ecosystem_from_component(component.purl, component.name)
    for manifest in manifests:
        match = _manifest_dependency_match(component, ecosystem, manifest)
        if not match:
            continue
        matched_name, index = match
        return SourceEvidence(
            reachability=Reachability.DEPENDENCY_REACHABLE,
            confidence=Confidence.LOW,
            language=manifest.language,
            reason=(
                f"package-manager manifest {manifest.path.name} declares {component.display_name}; "
                "no code import or vulnerable-function evidence was observed"
            ),
            locations=[
                SourceLocation(
                    path=manifest.path,
                    line=_line_for_match(manifest.text, index),
                    column=_column_for_match(manifest.text, index),
                    snippet=_snippet(manifest.text, index),
                )
            ],
            matched_symbols=[f"manifest:{manifest.path.name}:{matched_name}"],
        )
    return None


def _manifest_dependency_match(component: Component, ecosystem: str, manifest: ManifestSourceFile) -> tuple[str, int] | None:
    if ecosystem == "npm" and manifest.language == "npm-manifest":
        return _npm_manifest_match(component, manifest.text)
    if ecosystem == "pypi" and manifest.language == "python-manifest":
        return _python_manifest_match(component, manifest.path.name.lower(), manifest.text)
    if ecosystem == "maven" and manifest.language == "jvm-manifest":
        return _jvm_manifest_match(component, manifest.text)
    if ecosystem in {"go", "golang"} and manifest.language == "go-manifest":
        return _go_manifest_match(component, manifest.text)
    return None


def _component_manifest_names(component: Component) -> set[str]:
    parsed = parse_purl(component.purl)
    names = {component.name}
    if parsed and parsed.name:
        names.add(parsed.name)
    if parsed and parsed.name and parsed.namespace and parsed.ecosystem == "npm" and not parsed.name.startswith("@"):
        names.add(f"{parsed.namespace}/{parsed.name}")
    return {name for name in names if name}


def _component_manifest_coordinates(component: Component) -> set[str]:
    parsed = parse_purl(component.purl)
    coordinates: set[str] = set()
    name = parsed.name if parsed and parsed.name else component.name
    namespace = component.group or (parsed.namespace.replace("/", ".") if parsed and parsed.namespace else None)
    if namespace and name:
        coordinates.add(f"{namespace}:{name}")
    if component.group and component.name:
        coordinates.add(f"{component.group}:{component.name}")
    return coordinates


def _component_go_modules(component: Component) -> set[str]:
    parsed = parse_purl(component.purl)
    modules: set[str] = set()
    if parsed and parsed.namespace and parsed.name:
        modules.add(f"{parsed.namespace}/{parsed.name}")
    if "/" in component.name:
        modules.add(component.name)
    return modules


def _first_regex_match(patterns: Iterable[tuple[str, str]], text: str, flags: int = re.MULTILINE) -> tuple[str, int] | None:
    for name, pattern in patterns:
        match = re.search(pattern, text, flags=flags)
        if match:
            return name, match.start()
    return None


def _npm_manifest_match(component: Component, text: str) -> tuple[str, int] | None:
    patterns = []
    for name in sorted(_component_manifest_names(component), key=len, reverse=True):
        escaped = re.escape(name)
        patterns.extend(
            [
                (name, rf'["\']{escaped}["\']\s*:'),
                (name, rf'node_modules/{escaped}(?:["\']|$)'),
                (name, rf'(?m)^\s*["\']?{escaped}(?:@npm:|@|:)'),
                (name, rf'(?m)^\s*/?{escaped}@'),
            ]
        )
    return _first_regex_match(patterns, text)


def _python_dependency_name_pattern(name: str) -> str:
    return re.escape(_normalized_python_name(name)).replace(r"\-", r"[-_.]+")


def _normalized_python_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _toml_sections(text: str) -> list[tuple[str, int, int]]:
    headers = list(re.finditer(r"(?m)^\s*\[([^\]]+)\]\s*$", text))
    sections: list[tuple[str, int, int]] = []
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        sections.append((header.group(1).strip(), header.end(), end))
    return sections


def _match_poetry_lock_package(component: Component, text: str) -> tuple[str, int] | None:
    names = sorted(_component_manifest_names(component), key=len, reverse=True)
    package_blocks = re.finditer(r"(?ms)^\s*\[\[package\]\]\s*$.*?(?=^\s*\[\[package\]\]\s*$|\Z)", text)
    for package_block in package_blocks:
        block = package_block.group(0)
        for name in names:
            escaped = _python_dependency_name_pattern(name)
            match = re.search(rf'(?im)^\s*name\s*=\s*["\']{escaped}["\']\s*$', block)
            if match:
                return name, package_block.start() + match.start()
    return None


def _match_python_requirement_line(component: Component, text: str) -> tuple[str, int] | None:
    patterns = []
    for name in sorted(_component_manifest_names(component), key=len, reverse=True):
        escaped = _python_dependency_name_pattern(name)
        patterns.extend(
            [
                (name, rf'(?im)^\s*["\']?{escaped}["\']?\s*='),
                (name, rf'(?im)^\s*["\']{escaped}(?:[<>=~!\[\s"\']|$)'),
                (name, rf"(?im)^\s*{escaped}(?:[<>=~!\[\s]|$)"),
            ]
        )
    return _first_regex_match(patterns, text, flags=re.MULTILINE | re.IGNORECASE)


def _match_pyproject_dependency(component: Component, text: str) -> tuple[str, int] | None:
    names = sorted(_component_manifest_names(component), key=len, reverse=True)
    for section, start, end in _toml_sections(text):
        block = text[start:end]
        is_poetry_dependencies = section == "tool.poetry.dependencies" or (
            section.startswith("tool.poetry.group.") and section.endswith(".dependencies")
        )
        if is_poetry_dependencies:
            requirement_match = _match_python_requirement_line(component, block)
            if requirement_match:
                return requirement_match[0], start + requirement_match[1]
            continue
        if section == "project":
            array_match = re.search(r"(?ims)^\s*dependencies\s*=\s*\[(?P<body>.*?)\]", block)
            if not array_match:
                continue
            body = array_match.group("body")
            for name in names:
                escaped = _python_dependency_name_pattern(name)
                dependency_match = re.search(rf'(?i)["\']{escaped}(?:\[[^"\']*\])?(?:\s*[<>=~!]|["\']|\s|$)', body)
                if dependency_match:
                    return name, start + array_match.start("body") + dependency_match.start()
            continue
        if section == "project.optional-dependencies":
            for name in names:
                escaped = _python_dependency_name_pattern(name)
                dependency_match = re.search(rf'(?i)["\']{escaped}(?:\[[^"\']*\])?(?:\s*[<>=~!]|["\']|\s|$)', block)
                if dependency_match:
                    return name, start + dependency_match.start()
    return None


def _python_manifest_match(component: Component, manifest_name: str, text: str) -> tuple[str, int] | None:
    if manifest_name == "poetry.lock":
        return _match_poetry_lock_package(component, text)
    if manifest_name == "pyproject.toml":
        return _match_pyproject_dependency(component, text)
    return _match_python_requirement_line(component, text)


def _jvm_manifest_match(component: Component, text: str) -> tuple[str, int] | None:
    patterns = []
    for coordinate in sorted(_component_manifest_coordinates(component), key=len, reverse=True):
        escaped_coordinate = re.escape(coordinate)
        artifact = re.escape(coordinate.rsplit(":", 1)[-1])
        group = re.escape(coordinate.rsplit(":", 1)[0])
        patterns.extend(
            [
                (coordinate, escaped_coordinate),
                (coordinate, rf'module\s*=\s*["\']{escaped_coordinate}["\']'),
                (coordinate, rf'group\s*[:=]\s*["\']{group}["\'][^\n]{{0,160}}name\s*[:=]\s*["\']{artifact}["\']'),
                (coordinate, rf'<groupId>\s*{group}\s*</groupId>[\s\S]{{0,1200}}<artifactId>\s*{artifact}\s*</artifactId>'),
                (coordinate, rf'<artifactId>\s*{artifact}\s*</artifactId>[\s\S]{{0,1200}}<groupId>\s*{group}\s*</groupId>'),
            ]
        )
    return _first_regex_match(patterns, text)


def _go_manifest_match(component: Component, text: str) -> tuple[str, int] | None:
    patterns = []
    for module in sorted(_component_go_modules(component), key=len, reverse=True):
        escaped = re.escape(module)
        patterns.extend(
            [
                (module, rf'(?m)^\s*require\s+{escaped}\s+'),
                (module, rf'(?m)^\s*{escaped}\s+v?\d'),
            ]
        )
    return _first_regex_match(patterns, text)


def _line_for_match(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _column_for_match(text: str, index: int) -> int:
    previous_newline = text.rfind("\n", 0, index)
    return index + 1 if previous_newline == -1 else index - previous_newline


def _snippet(text: str, index: int) -> str:
    line_start = text.rfind("\n", 0, index) + 1
    line_end = text.find("\n", index)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:240]


__all__ = [
    "is_manifest_file",
    "manifest_dependency_evidence",
    "manifest_language_for",
]
