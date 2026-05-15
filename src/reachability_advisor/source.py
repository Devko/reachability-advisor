"""Source-code reachability hints for developer workflows.

The implementation is deliberately lightweight and transparent. It is designed
for CI and IDE feedback, not for perfect whole-program call-graph analysis.
The current implementation keeps the default analyzer small, but records enough
evidence to mix with stronger external analyzers when available:

* rules can be vulnerability-specific, so a package can have different sinks for
  different CVEs or advisories;
* attacker-controlled classification requires same-function input/sink evidence
  or a bounded handler-to-sink call path. Unlinked entry points elsewhere still
  increase confidence, but do not create an unsafe exploitability claim;
* CycloneDX dependency graphs can mark transitive packages as indirectly
  reachable through an imported parent dependency;
* Semgrep, SARIF, govulncheck-style JSONL, or Reachability Advisor evidence JSON
  can upgrade the built-in result when the external finding matches the artifact,
  component, package URL, or vulnerability.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import (
    Component,
    Confidence,
    Reachability,
    SbomDocument,
    SourceEvidence,
    SourceLocation,
    VulnerabilityRecord,
)
from .purl import ecosystem_from_component, parse_purl
from .source_external import (
    ExternalSourceEvidenceStore,
    load_external_source_evidence,
    merge_source_evidence,
)
from .source_index import (
    SourceIndex,
    build_source_index,
    parse_source_roots,
)
from .source_index import (
    language_for_source_path as _language_for,
)
from .source_manifests import manifest_dependency_evidence
from .source_query_families import (
    proven_query_family_ids,
    query_family_ids_for_component,
    query_family_ids_for_rule,
)
from .source_rules import BUILTIN_RULES, ReachabilityRule, load_reachability_rules


@dataclass
class FileSignal:
    path: Path
    language: str
    has_import: bool = False
    has_function: bool = False
    has_attacker: bool = False
    locations: list[SourceLocation] = field(default_factory=list)
    matched_symbols: set[str] = field(default_factory=set)
    defined_functions: set[str] = field(default_factory=set)
    sink_functions: set[str] = field(default_factory=set)
    attacker_functions: set[str] = field(default_factory=set)
    calls_by_function: dict[str, set[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class CallPath:
    attacker_file: Path
    attacker_function: str
    sink_file: Path
    sink_function: str
    called_name: str
    functions: tuple[str, ...] = ()


def source_diagnostic(code: str, severity: str, message: str, **detail: Any) -> dict[str, Any]:
    diagnostic: dict[str, Any] = {"code": code, "severity": severity, "message": message}
    if detail:
        diagnostic["detail"] = {key: value for key, value in detail.items() if value not in (None, [], {})}
    return diagnostic


def _line_for_match(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _column_for_match(text: str, index: int) -> int:
    return max(1, index - text.rfind("\n", 0, index))


def _snippet(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end == -1:
        end = len(text)
    return text[start:end].strip()[:200]


@dataclass(frozen=True)
class FunctionSegment:
    name: str
    start: int
    end: int
    text: str
    calls: frozenset[str]


CALL_KEYWORDS = {
    "catch",
    "class",
    "def",
    "for",
    "function",
    "if",
    "new",
    "return",
    "switch",
    "while",
}


def _line_offsets(text: str) -> list[int]:
    offsets = [0]
    for match in re.finditer(r"\n", text):
        offsets.append(match.end())
    return offsets


def _line_start(text: str, index: int) -> int:
    return text.rfind("\n", 0, index) + 1


def _include_decorators(text: str, start: int) -> int:
    cursor = _line_start(text, start)
    while cursor > 0:
        previous_end = cursor - 1
        previous_start = _line_start(text, previous_end)
        line = text[previous_start:previous_end].strip()
        if not line or not line.startswith("@"):
            break
        cursor = previous_start
    return cursor


def _python_call_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        parent = _python_call_names(node.value)
        full = {f"{item}.{node.attr}" for item in parent}
        full.add(node.attr)
        return full
    return set()


def _python_function_segments(text: str) -> list[FunctionSegment]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    offsets = _line_offsets(text)
    segments: list[FunctionSegment] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start_line = node.lineno
        for decorator in node.decorator_list:
            start_line = min(start_line, getattr(decorator, "lineno", start_line))
        end_line = getattr(node, "end_lineno", None) or node.lineno
        start = offsets[max(0, start_line - 1)]
        end = offsets[end_line] if end_line < len(offsets) else len(text)
        calls: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                calls.update(_python_call_names(child.func))
        segments.append(FunctionSegment(name=node.name, start=start, end=end, text=text[start:end], calls=frozenset(calls)))
    return segments


def _matching_brace(text: str, open_index: int) -> int:
    depth = 0
    in_string: str | None = None
    escape = False
    for index in range(open_index, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == in_string:
                in_string = None
            continue
        if char in {"'", '"', "`"}:
            in_string = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return len(text)


def _call_names(text: str) -> set[str]:
    calls: set[str] = set()
    for match in re.finditer(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(", text):
        name = match.group(1)
        leaf = name.rsplit(".", 1)[-1]
        if leaf in CALL_KEYWORDS:
            continue
        calls.add(name)
        calls.add(leaf)
    return calls


def _regex_function_segments(text: str, language: str) -> list[FunctionSegment]:
    patterns: tuple[str, ...]
    if language == "javascript":
        patterns = (
            r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^{};]*\)\s*\{",
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^{};]*\)\s*=>\s*\{",
            r"exports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\s*\([^{};]*\)\s*\{",
            r"module\.exports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\s*\([^{};]*\)\s*\{",
            r"(?:public|private|protected|static|async|\s)*(?<![@\w$])([A-Za-z_$][\w$]*)\s*\([^{};]*\)\s*(?::\s*[^({;]+)?\s*\{",
        )
    elif language == "java":
        patterns = (r"(?:public|private|protected|static|final|synchronized|\s)+[\w<>\[\], ?]+\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:throws\s+[^{]+)?\{",)
    elif language == "go":
        patterns = (r"func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\([^)]*\)\s*(?:[^{]*)\{",)
    else:
        return []

    segments: list[FunctionSegment] = []
    seen: set[tuple[str, int]] = set()
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.MULTILINE):
            if match.group(1) in CALL_KEYWORDS:
                continue
            open_index = text.find("{", match.end() - 1)
            if open_index == -1:
                continue
            start = _include_decorators(text, match.start())
            end = _matching_brace(text, open_index)
            key = (match.group(1), start)
            if key in seen:
                continue
            seen.add(key)
            body = text[start:end]
            segments.append(FunctionSegment(name=match.group(1), start=start, end=end, text=body, calls=frozenset(_call_names(body))))
    return segments


def _javascript_route_callback_segments(text: str) -> list[FunctionSegment]:
    segments: list[FunctionSegment] = []
    for match in re.finditer(
        r"\b(?:app|router)\.(?:get|post|put|patch|delete|all|use)\s*\([^,\n]+,\s*(?:async\s*)?\(?\s*(?:req|request)\b[^=;{}]*=>\s*\{",
        text,
        flags=re.MULTILINE,
    ):
        open_index = text.find("{", match.end() - 1)
        if open_index == -1:
            continue
        start = match.start()
        end = _matching_brace(text, open_index)
        body = text[start:end]
        name = f"route_handler_{_line_for_match(text, start)}"
        segments.append(FunctionSegment(name=name, start=start, end=end, text=body, calls=frozenset(_call_names(body))))
    for match in re.finditer(
        r"\b(?:app|router)\.(?:get|post|put|patch|delete|all|use)\s*\([^,\n]+,\s*(?:async\s*)?\(?\s*(?:req|request)\b[^=;{}]*=>\s*([^;\n]+)",
        text,
        flags=re.MULTILINE,
    ):
        start = match.start()
        end = match.end()
        body = text[start:end]
        name = f"route_handler_{_line_for_match(text, start)}"
        segments.append(FunctionSegment(name=name, start=start, end=end, text=body, calls=frozenset(_call_names(body))))
    return segments


def _javascript_expression_segments(text: str) -> list[FunctionSegment]:
    segments: list[FunctionSegment] = []
    patterns = (
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?[^=;{}\n]*\)?\s*=>\s*([^;\n]+)",
        r"exports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?[^=;{}\n]*\)?\s*=>\s*([^;\n]+)",
        r"module\.exports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?[^=;{}\n]*\)?\s*=>\s*([^;\n]+)",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.MULTILINE):
            start = match.start()
            end = match.end()
            body = text[start:end]
            segments.append(FunctionSegment(name=match.group(1), start=start, end=end, text=body, calls=frozenset(_call_names(body))))
    return segments


def _function_segments(path: Path, text: str) -> list[FunctionSegment]:
    language = _language_for(path)
    if language == "python":
        return _python_function_segments(text)
    segments = _regex_function_segments(text, language)
    if language == "javascript":
        segments.extend(_javascript_route_callback_segments(text))
        segments.extend(_javascript_expression_segments(text))
    return segments


def _matches_any(patterns: tuple[str, ...], text: str) -> bool:
    for pattern in patterns:
        try:
            if re.search(pattern, text, flags=re.MULTILINE):
                return True
        except re.error:
            continue
    return False


def _route_handler_names(text: str, language: str) -> set[str]:
    names: set[str] = set()
    if language == "javascript":
        for match in re.finditer(r"\b(?:app|router)\.(?:get|post|put|patch|delete|all|use)\s*\([^,\n]+,\s*([A-Za-z_$][\w$]*)", text):
            names.add(match.group(1))
    return names


def _add_semantic_signals(signal: FileSignal, text: str, function_patterns: tuple[str, ...], attacker_patterns: tuple[str, ...]) -> None:
    segments = _function_segments(signal.path, text)
    route_handlers = _route_handler_names(text, signal.language)
    for segment in segments:
        signal.defined_functions.add(segment.name)
        signal.calls_by_function[segment.name] = set(segment.calls)
        if _matches_any(function_patterns, segment.text):
            signal.sink_functions.add(segment.name)
        if _matches_any(attacker_patterns, segment.text) or segment.name in route_handlers:
            signal.attacker_functions.add(segment.name)
    for handler in route_handlers:
        signal.attacker_functions.add(handler)


def _find_call_path(signals: list[FileSignal], max_depth: int = 4) -> CallPath | None:
    sinks: dict[str, tuple[FileSignal, str]] = {}
    functions: dict[str, tuple[FileSignal, str]] = {}
    for signal in signals:
        for name in signal.defined_functions:
            functions.setdefault(name.lower(), (signal, name))
        if not signal.has_import or not signal.has_function:
            continue
        for name in signal.sink_functions:
            sinks.setdefault(name.lower(), (signal, name))
    if not sinks:
        return None
    for signal in signals:
        for attacker_function in sorted(signal.attacker_functions):
            queue: list[tuple[FileSignal, str, tuple[str, ...]]] = [(signal, attacker_function, (attacker_function,))]
            seen = {(str(signal.path), attacker_function.lower())}
            while queue:
                current_signal, current_function, path = queue.pop(0)
                if len(path) > max_depth:
                    continue
                for called_name in sorted(current_signal.calls_by_function.get(current_function, set())):
                    sink = sinks.get(called_name.lower())
                    if sink:
                        sink_signal, sink_function = sink
                        if not (current_signal.path == sink_signal.path and current_function == sink_function):
                            return CallPath(
                                attacker_file=signal.path,
                                attacker_function=attacker_function,
                                sink_file=sink_signal.path,
                                sink_function=sink_function,
                                called_name=called_name,
                                functions=(*path, sink_function),
                            )
                    next_function = functions.get(called_name.lower())
                    if not next_function:
                        continue
                    next_signal, next_name = next_function
                    key = (str(next_signal.path), next_name.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    queue.append((next_signal, next_name, (*path, next_name)))
    return None


def _rules_for(component: Component, vulnerability: VulnerabilityRecord | None, custom_rules: Iterable[ReachabilityRule]) -> tuple[ReachabilityRule, ...]:
    custom = tuple(rule for rule in custom_rules if rule.applies_to(component, vulnerability))
    builtin = tuple(rule for rule in BUILTIN_RULES if rule.applies_to(component, vulnerability))
    if vulnerability and custom:
        return custom
    if vulnerability and builtin:
        # Prefer vulnerability-specific builtins, otherwise fall back to package-level.
        specific = tuple(rule for rule in builtin if rule.vulnerability_ids)
        return specific or builtin
    return custom or builtin


def _generic_patterns(component: Component) -> tuple[str, ...]:
    name = component.name
    escaped = re.escape(name)
    ecosystem = ecosystem_from_component(component.purl, component.name)
    if ecosystem == "npm":
        subpath = rf"{escaped}(?:/[^'\"]+)?"
        return (
            rf"require\(['\"]{subpath}['\"]\)",
            rf"require\.resolve\(['\"]{subpath}['\"]\)",
            rf"from\s+['\"]{subpath}['\"]",
            rf"import\s+['\"]{subpath}['\"]",
            rf"import\s+[\w\s${{}}*,]+\s+from\s+['\"]{subpath}['\"]",
        )
    if ecosystem == "pypi":
        module = escaped.replace("-", "[_-]?")
        return (rf"^\s*import\s+{module}\b", rf"^\s*from\s+{module}\s+import\s+")
    if ecosystem == "maven":
        parsed = parse_purl(component.purl)
        namespace = parsed.namespace.replace(".", r"\.") if parsed and parsed.namespace else escaped
        return (rf"import\s+{namespace}\.",)
    if ecosystem in {"go", "golang"}:
        parsed = parse_purl(component.purl)
        module = re.escape((parsed.namespace + "/" if parsed and parsed.namespace else "") + (parsed.name if parsed and parsed.name else name))
        return (rf"import\s+\(?[^;]*[\"']{module}[\"']",)
    return ()


def _component_cache_key(component: Component) -> str:
    return component.purl or f"{component.group or ''}/{component.name}@{component.version or ''}"


def _component_by_ref(sbom: SbomDocument) -> dict[str, Component]:
    return {component.bom_ref: component for component in sbom.components if component.bom_ref}


def _component_display_by_ref(sbom: SbomDocument) -> dict[str, str]:
    display = _component_by_ref(sbom)
    return {ref: component.display_name for ref, component in display.items()}


def _dependency_roots(sbom: SbomDocument, refs: set[str]) -> list[str]:
    if sbom.artifact.bom_ref:
        return [sbom.artifact.bom_ref]
    all_children = {child for children in sbom.dependencies.values() for child in children}
    roots = [ref for ref in sbom.dependencies if ref not in refs and ref not in all_children]
    if roots:
        return roots
    return [ref for ref in sbom.dependencies if ref not in refs] or list(sbom.dependencies)


def _dependency_path(sbom: SbomDocument | None, component: Component) -> list[str]:
    if not sbom or not component.bom_ref or not sbom.dependencies:
        return []
    refs = set(_component_by_ref(sbom))
    roots = _dependency_roots(sbom, refs)
    queue: list[tuple[str, list[str]]] = [(root, [root]) for root in roots]
    seen = set(roots)
    while queue:
        ref, path = queue.pop(0)
        if ref == component.bom_ref:
            names = _component_display_by_ref(sbom)
            return [names.get(item, sbom.artifact.name if item == sbom.artifact.bom_ref else item) for item in path]
        for child in sbom.dependencies.get(ref, []):
            if child in seen:
                continue
            seen.add(child)
            queue.append((child, [*path, child]))
    return []


def _component_import_observed(component: Component, source_index: SourceIndex, custom_rules: Iterable[ReachabilityRule] = ()) -> bool:
    key = _component_cache_key(component)
    if key in source_index.import_cache:
        return source_index.import_cache[key]
    rules = _rules_for(component, None, custom_rules)
    patterns = tuple(dict.fromkeys(pattern for rule in rules for pattern in rule.import_patterns)) or _generic_patterns(component)
    if not patterns:
        source_index.import_cache[key] = False
        return False
    for indexed in source_index.files:
        if _matches_any(patterns, indexed.text):
            source_index.import_cache[key] = True
            return True
    source_index.import_cache[key] = False
    return False


def _dependency_reachable_evidence(
    component: Component,
    sbom: SbomDocument | None,
    source_index: SourceIndex,
    custom_rules: Iterable[ReachabilityRule],
    language: str,
) -> SourceEvidence | None:
    path = _dependency_path(sbom, component)
    if len(path) < 3 or not sbom:
        return None
    component_by_name = {component.display_name: component for component in sbom.components}
    component_by_name.update({component.name: component for component in sbom.components})
    for parent_name in path[1:-1]:
        parent = component_by_name.get(parent_name)
        if parent and _component_import_observed(parent, source_index, custom_rules):
            return SourceEvidence(
                reachability=Reachability.DEPENDENCY_REACHABLE,
                confidence=Confidence.LOW,
                language=language,
                reason=f"component is reached through SBOM dependency graph path {' -> '.join(path)}; parent dependency {parent.display_name} is imported in source",
                dependency_path=path,
                diagnostics=[
                    source_diagnostic(
                        "dependency_graph_indirect",
                        "info",
                        "Dependency graph evidence links this component through an imported parent dependency; it does not prove vulnerable API execution.",
                    )
                ],
            )
    return SourceEvidence(
        reachability=Reachability.PACKAGE_PRESENT,
        confidence=Confidence.LOW,
        language=language,
        reason=f"component appears in SBOM dependency graph path {' -> '.join(path)}, but no imported parent dependency was observed",
        dependency_path=path,
        diagnostics=[
            source_diagnostic(
                "dependency_graph_unconfirmed",
                "info",
                "The SBOM dependency graph contains this component, but no imported parent dependency was observed in source.",
            )
        ],
    )


def _scan_file(path: Path, text: str, import_patterns: tuple[str, ...], function_patterns: tuple[str, ...], attacker_patterns: tuple[str, ...]) -> FileSignal:
    signal = FileSignal(path=path, language=_language_for(path))
    for pattern_group, marker in ((import_patterns, "import"), (function_patterns, "function"), (attacker_patterns, "attacker")):
        for pattern in pattern_group:
            try:
                matches = list(re.finditer(pattern, text, flags=re.MULTILINE))
            except re.error:
                continue
            for match in matches[:3]:
                signal.matched_symbols.add(pattern)
                signal.locations.append(
                    SourceLocation(
                        path=path,
                        line=_line_for_match(text, match.start()),
                        column=_column_for_match(text, match.start()),
                        snippet=_snippet(text, match.start()),
                    )
                )
                if marker == "import":
                    signal.has_import = True
                elif marker == "function":
                    signal.has_function = True
                elif marker == "attacker":
                    signal.has_attacker = True
    _add_semantic_signals(signal, text, function_patterns, attacker_patterns)
    return signal


def analyze_component_source(
    component: Component,
    root: Path | None,
    vulnerability: VulnerabilityRecord | None = None,
    custom_rules: Iterable[ReachabilityRule] = (),
    source_index: SourceIndex | None = None,
    sbom: SbomDocument | None = None,
) -> SourceEvidence:
    index = source_index or build_source_index(root)
    if root is None and source_index is None:
        return SourceEvidence(
            reachability=Reachability.PACKAGE_PRESENT,
            confidence=Confidence.LOW,
            language="unknown",
            reason="component appears in SBOM; no source root supplied",
            diagnostics=[
                source_diagnostic(
                    "missing_source_root",
                    "warning",
                    "No source root was supplied for this artifact; built-in source reachability falls back to SBOM presence.",
                )
            ],
        )
    if not index.files:
        manifest_evidence = manifest_dependency_evidence(component, index.manifest_files)
        if manifest_evidence:
            return manifest_evidence
        return SourceEvidence(
            reachability=Reachability.PACKAGE_PRESENT,
            confidence=Confidence.LOW,
            language="unknown",
            reason="component appears in SBOM; no supported source files or matching package-manager manifest entries found",
            diagnostics=[
                source_diagnostic(
                    "no_supported_source_files",
                    "warning",
                    "No supported source files or matching package-manager manifest entries were found in the supplied source root.",
                    skipped_files=len(index.skipped_files),
                    manifest_files=len(index.manifest_files),
                )
            ],
        )

    rules = _rules_for(component, vulnerability, custom_rules)
    has_package_rule = bool(rules)
    generic_patterns = _generic_patterns(component)
    import_patterns = tuple(dict.fromkeys(pattern for rule in rules for pattern in rule.import_patterns)) or generic_patterns
    function_patterns = tuple(dict.fromkeys(pattern for rule in rules for pattern in rule.function_patterns))
    attacker_patterns = tuple(dict.fromkeys(pattern for rule in rules for pattern in rule.attacker_patterns))
    query_families = list(query_family_ids_for_component(component))

    signals: list[FileSignal] = []
    for indexed in index.files:
        signal = _scan_file(indexed.path, indexed.text, import_patterns, function_patterns, attacker_patterns)
        if signal.has_import or signal.has_function or signal.has_attacker or signal.defined_functions:
            signals.append(signal)

    if not signals and not has_package_rule:
        language = index.files[0].language if index.files else "unknown"
        dependency_evidence = _dependency_reachable_evidence(component, sbom, index, custom_rules, language)
        if dependency_evidence:
            if dependency_evidence.reachability == Reachability.PACKAGE_PRESENT:
                dependency_evidence.reason += "; no package-specific source rule exists and generic import usage was not observed"
            return dependency_evidence
        manifest_evidence = manifest_dependency_evidence(component, index.manifest_files)
        if manifest_evidence:
            return manifest_evidence
        return SourceEvidence(
            reachability=Reachability.UNKNOWN_DUE_TO_NO_RULE,
            confidence=Confidence.LOW,
            language=language,
            reason="component appears in SBOM; no package-specific source rule exists and generic import usage was not observed",
            diagnostics=[
                source_diagnostic(
                    "missing_package_rule",
                    "warning",
                    "No package-specific source rule matched this component and generic import evidence was not observed.",
                    package=component.display_name,
                    ecosystem=ecosystem_from_component(component.purl, component.name),
                )
            ],
        )

    if not signals:
        language = index.files[0].language if index.files else "unknown"
        dependency_evidence = _dependency_reachable_evidence(component, sbom, index, custom_rules, language)
        if dependency_evidence:
            return dependency_evidence
        manifest_evidence = manifest_dependency_evidence(component, index.manifest_files)
        if manifest_evidence:
            return manifest_evidence
        return SourceEvidence(
            reachability=Reachability.PACKAGE_PRESENT,
            confidence=Confidence.LOW,
            language=language,
            reason="component appears in SBOM, but source usage was not observed",
            diagnostics=[
                source_diagnostic(
                    "source_usage_not_observed",
                    "info",
                    "A source rule exists, but no import, vulnerable-function, or input evidence matched the scanned source root.",
                    package=component.display_name,
                    rule=_rule_text(rules, vulnerability),
                )
            ],
        )

    has_import_any = any(signal.has_import for signal in signals)
    has_function_any = any(signal.has_function for signal in signals)
    has_attacker_any = any(signal.has_attacker for signal in signals)
    same_function_attacker = any(signal.has_import and bool(signal.sink_functions & signal.attacker_functions) for signal in signals)
    same_file_function = any(signal.has_import and signal.has_function for signal in signals)
    imported_only = any(signal.has_import for signal in signals)
    call_path = _find_call_path(signals)
    locations = [location for signal in signals for location in signal.locations][:8]
    symbols = sorted({symbol for signal in signals for symbol in signal.matched_symbols})
    language = _dominant_language(signals)
    rule_text = _rule_text(rules, vulnerability)

    if call_path:
        call_symbol = f"call_path:{call_path.attacker_function}->{call_path.called_name}->{call_path.sink_function}"
        if call_path.functions:
            call_symbol = "call_path:" + "->".join(call_path.functions)
        return SourceEvidence(
            reachability=Reachability.ATTACKER_CONTROLLED,
            confidence=Confidence.HIGH if vulnerability and rules else Confidence.MEDIUM,
            language=language,
            reason=(
                f"{rule_text}; direct source call path links attacker-controlled entrypoint "
                f"{call_path.attacker_function} in {call_path.attacker_file.name} to vulnerable-function sink "
                f"{call_path.sink_function} in {call_path.sink_file.name}"
            ),
            locations=locations,
            matched_symbols=sorted({*symbols, call_symbol}),
            query_families=query_families,
        )

    if same_function_attacker:
        return SourceEvidence(
            reachability=Reachability.ATTACKER_CONTROLLED,
            confidence=Confidence.HIGH if vulnerability and rules else Confidence.MEDIUM,
            language=language,
            reason=f"{rule_text}; same function contains vulnerable-function hint and attacker-controlled entrypoint/input hint",
            locations=locations,
            matched_symbols=symbols,
            query_families=query_families,
        )
    if same_file_function:
        reason = f"{rule_text}; same source file contains import and vulnerable-function usage hints"
        if has_attacker_any:
            reason += "; attacker entrypoint was observed elsewhere but no same-function or bounded call-path link was inferred"
        diagnostics = []
        if has_attacker_any:
            diagnostics.append(
                source_diagnostic(
                    "unlinked_attacker_input",
                    "info",
                    "Attacker/input evidence was observed, but it was not linked to the vulnerable function by same-function or bounded call-path analysis.",
                )
            )
        return SourceEvidence(
            reachability=Reachability.FUNCTION_REACHABLE,
            confidence=Confidence.MEDIUM,
            language=language,
            reason=reason,
            locations=locations,
            matched_symbols=symbols,
            query_families=query_families,
            diagnostics=diagnostics,
        )
    if has_import_any and has_function_any:
        return SourceEvidence(
            reachability=Reachability.FUNCTION_REACHABLE,
            confidence=Confidence.LOW,
            language=language,
            reason=f"{rule_text}; import and vulnerable-function hints were observed in the source root but not the same file",
            locations=locations,
            matched_symbols=symbols,
            query_families=query_families,
            diagnostics=[
                source_diagnostic(
                    "cross_file_unlinked_function",
                    "info",
                    "Import and vulnerable-function hints were observed, but not in the same file and no bounded call path was inferred.",
                )
            ],
        )
    if imported_only:
        return SourceEvidence(
            reachability=Reachability.IMPORTED,
            confidence=Confidence.MEDIUM,
            language=language,
            reason=f"{rule_text}; source imports or requires the package",
            locations=locations,
            matched_symbols=symbols,
            query_families=query_families,
        )
    dependency_evidence = _dependency_reachable_evidence(component, sbom, index, custom_rules, language)
    if dependency_evidence:
        return dependency_evidence
    manifest_evidence = manifest_dependency_evidence(component, index.manifest_files)
    if manifest_evidence:
        return manifest_evidence
    return SourceEvidence(
        reachability=Reachability.PACKAGE_PRESENT,
        confidence=Confidence.LOW,
        language=language,
        reason="component appears in SBOM, but package import was not observed",
        diagnostics=[
            source_diagnostic(
                "import_not_observed",
                "info",
                "The component appears in the SBOM, but package import evidence was not observed in the scanned source root.",
                package=component.display_name,
            )
        ],
    )


def _dominant_language(signals: list[FileSignal]) -> str:
    counts: dict[str, int] = {}
    for signal in signals:
        counts[signal.language] = counts.get(signal.language, 0) + 1
    if not counts:
        return "unknown"
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)[0][0]


def _rule_text(rules: tuple[ReachabilityRule, ...], vulnerability: VulnerabilityRecord | None) -> str:
    if not rules:
        return "generic package rule"
    if vulnerability and any(rule.vulnerability_ids for rule in rules):
        return f"vulnerability-specific rule for {vulnerability.id}"
    descriptions = [rule.description for rule in rules if rule.description]
    return descriptions[0] if descriptions else "package-specific rule"


def source_coverage_report(
    sboms: list[SbomDocument],
    source_roots: Mapping[str, Path],
    indexes: Mapping[str, SourceIndex],
    findings: list[Any],
    external_evidence: ExternalSourceEvidenceStore | None = None,
) -> dict[str, Any]:
    by_artifact: dict[str, list[Any]] = {}
    for finding in findings:
        by_artifact.setdefault(finding.artifact.name, []).append(finding)
    artifacts: list[dict[str, Any]] = []
    totals: dict[str, Any] = {
        "artifact_count": len(sboms),
        "artifacts_with_source_root": 0,
        "files_scanned": 0,
        "manifest_files_scanned": 0,
        "files_skipped": 0,
        "findings_analyzed": len(findings),
        "findings_with_external_evidence": 0,
        "findings_with_builtin_only_evidence": 0,
        "findings_with_dependency_graph_path": 0,
        "findings_with_manifest_evidence": 0,
        "findings_with_package_specific_rule": 0,
        "findings_with_rule_gap": 0,
        "findings_with_weak_source_evidence": 0,
        "critical_findings": 0,
        "critical_findings_with_dependency_only_source": 0,
        "critical_findings_with_external_evidence": 0,
        "critical_findings_missing_external_evidence": 0,
        "critical_findings_requiring_query_family": 0,
        "critical_findings_with_required_query_family": 0,
        "critical_findings_missing_query_family": 0,
        "critical_findings_requiring_proven_query_family": 0,
        "critical_findings_with_proven_query_family": 0,
        "critical_findings_missing_proven_query_family": 0,
        "critical_findings_without_maintained_query_family": 0,
        "source_diagnostic_counts": {},
    }
    proven_families = set(proven_query_family_ids())
    external_selector_diagnostics = external_evidence.selector_diagnostics() if external_evidence else {"records": 0, "matchable_records": 0, "artifact_only_records": 0, "unscoped_records": 0}
    state_counts: dict[str, int] = {}
    for sbom in sboms:
        index = indexes.get(sbom.artifact.name, SourceIndex(root=source_roots.get(sbom.artifact.name)))
        artifact_findings = by_artifact.get(sbom.artifact.name, [])
        if sbom.artifact.name in source_roots:
            totals["artifacts_with_source_root"] += 1
        totals["files_scanned"] += len(index.files)
        totals["manifest_files_scanned"] += len(index.manifest_files)
        totals["files_skipped"] += len(index.skipped_files)
        artifact_states: dict[str, int] = {}
        artifact_diagnostics: dict[str, int] = {}
        critical_packages: dict[str, dict[str, Any]] = {}
        artifact_query_family_required = 0
        artifact_query_family_covered = 0
        for finding in artifact_findings:
            state = finding.source.reachability.value
            artifact_states[state] = artifact_states.get(state, 0) + 1
            state_counts[state] = state_counts.get(state, 0) + 1
            for diagnostic in finding.source.diagnostics:
                code = str(diagnostic.get("code") or "unknown")
                artifact_diagnostics[code] = artifact_diagnostics.get(code, 0) + 1
                totals["source_diagnostic_counts"][code] = totals["source_diagnostic_counts"].get(code, 0) + 1
            if finding.source.evidence_source != "builtin":
                totals["findings_with_external_evidence"] += 1
            else:
                totals["findings_with_builtin_only_evidence"] += 1
            if finding.source.dependency_path:
                totals["findings_with_dependency_graph_path"] += 1
            if any(str(symbol).startswith("manifest:") for symbol in finding.source.matched_symbols):
                totals["findings_with_manifest_evidence"] += 1
            if state == Reachability.UNKNOWN_DUE_TO_NO_RULE.value:
                totals["findings_with_rule_gap"] += 1
            elif "package-specific" in str(finding.source.reason).lower() or "vulnerability-specific" in str(finding.source.reason).lower():
                totals["findings_with_package_specific_rule"] += 1
            if state in {Reachability.UNKNOWN_DUE_TO_NO_RULE.value, Reachability.PACKAGE_PRESENT.value, Reachability.DEPENDENCY_REACHABLE.value}:
                totals["findings_with_weak_source_evidence"] += 1
            if _critical_source_gate_applies(finding):
                totals["critical_findings"] += 1
                required_query_families = set(query_family_ids_for_component(finding.component))
                has_external_evidence = finding.source.evidence_source != "builtin"
                evidence_query_families = _evidence_query_families(finding, required_query_families) if has_external_evidence else set()
                unproven_query_families = sorted(required_query_families - proven_families)
                family_gap = not required_query_families
                if family_gap:
                    totals["critical_findings_without_maintained_query_family"] += 1
                unmapped_family = {"unmapped-package-family"} if family_gap else set()
                missing_query_families = sorted((required_query_families - evidence_query_families) | set(unproven_query_families) | unmapped_family)
                unproven_query_families = sorted(set(unproven_query_families) | unmapped_family)
                package_key = finding.component.purl or finding.component.display_name
                package_row = critical_packages.setdefault(
                    package_key,
                    {
                        "component": finding.component.display_name,
                        "purl": finding.component.purl,
                        "vulnerabilities": [],
                        "external_evidence": False,
                        "required_query_families": set(),
                        "evidence_query_families": set(),
                        "missing_query_families": set(),
                        "unproven_query_families": set(),
                        "states": {},
                    },
                )
                package_row["vulnerabilities"].append(finding.vulnerability.id)
                package_row["states"][state] = package_row["states"].get(state, 0) + 1
                package_row["required_query_families"].update(required_query_families)
                package_row["evidence_query_families"].update(evidence_query_families)
                package_row["missing_query_families"].update(missing_query_families)
                package_row["unproven_query_families"].update(unproven_query_families)
                if state in {
                    Reachability.ABSENT.value,
                    Reachability.UNKNOWN_DUE_TO_NO_RULE.value,
                    Reachability.PACKAGE_PRESENT.value,
                    Reachability.DEPENDENCY_REACHABLE.value,
                }:
                    totals["critical_findings_with_dependency_only_source"] += 1
                if finding.source.evidence_source != "builtin":
                    totals["critical_findings_with_external_evidence"] += 1
                    package_row["external_evidence"] = True
                else:
                    totals["critical_findings_missing_external_evidence"] += 1
                totals["critical_findings_requiring_query_family"] += 1
                totals["critical_findings_requiring_proven_query_family"] += 1
                artifact_query_family_required += 1
                if has_external_evidence and not missing_query_families:
                    totals["critical_findings_with_required_query_family"] += 1
                    totals["critical_findings_with_proven_query_family"] += 1
                    artifact_query_family_covered += 1
                else:
                    totals["critical_findings_missing_query_family"] += 1
                    totals["critical_findings_missing_proven_query_family"] += 1
        critical_package_rows = [_critical_package_row(row) for row in critical_packages.values()]
        critical_package_rows = sorted(critical_package_rows, key=lambda row: str(row["component"]))
        critical_packages_with_external = sum(1 for row in critical_package_rows if row["external_evidence"])
        artifacts.append(
            {
                "artifact": sbom.artifact.name,
                "source_root": str(source_roots.get(sbom.artifact.name)) if sbom.artifact.name in source_roots else None,
                "source_root_exists": bool(index.root and index.root.exists() and index.root.is_dir()),
                "files_scanned": len(index.files),
                "manifest_files_scanned": len(index.manifest_files),
                "files_skipped": len(index.skipped_files),
                "languages": index.languages,
                "findings_analyzed": len(artifact_findings),
                "states": artifact_states,
                "source_diagnostics": artifact_diagnostics,
                "critical_packages": critical_package_rows,
                "critical_package_coverage": round(critical_packages_with_external / len(critical_package_rows), 4) if critical_package_rows else 1.0,
                "critical_query_family_coverage": round(artifact_query_family_covered / artifact_query_family_required, 4) if artifact_query_family_required else 1.0,
                "skipped_files": index.skipped_files[:20],
            }
        )
    totals["states"] = state_counts
    strong_states = {
        Reachability.DEPENDENCY_REACHABLE.value,
        Reachability.IMPORTED.value,
        Reachability.FUNCTION_REACHABLE.value,
        Reachability.ATTACKER_CONTROLLED.value,
    }
    strong = sum(count for state, count in state_counts.items() if state in strong_states)
    totals["source_evidence_coverage"] = round(strong / len(findings), 4) if findings else 1.0
    totals["source_rule_coverage"] = round((len(findings) - totals["findings_with_rule_gap"]) / len(findings), 4) if findings else 1.0
    matchable_external = external_selector_diagnostics.get("matchable_records", 0)
    external_records = external_selector_diagnostics.get("records", 0)
    totals["external_evidence_usable_ratio"] = round(matchable_external / external_records, 4) if external_records else 1.0
    totals["external_evidence_records"] = len(external_evidence.records) if external_evidence else 0
    totals["external_evidence_providers"] = external_evidence.provider_counts() if external_evidence else {}
    totals["external_evidence_selector_diagnostics"] = external_selector_diagnostics
    totals["external_evidence_selected_ratio"] = round(totals["findings_with_external_evidence"] / len(findings), 4) if findings else 1.0
    totals["critical_external_evidence_coverage"] = round(totals["critical_findings_with_external_evidence"] / totals["critical_findings"], 4) if totals["critical_findings"] else 1.0
    family_required = int(totals["critical_findings_requiring_query_family"])
    family_covered = int(totals["critical_findings_with_required_query_family"])
    totals["critical_query_family_coverage"] = round(family_covered / family_required, 4) if family_required else 1.0
    proven_family_required = int(totals["critical_findings_requiring_proven_query_family"])
    proven_family_covered = int(totals["critical_findings_with_proven_query_family"])
    totals["critical_proven_query_family_coverage"] = round(proven_family_covered / proven_family_required, 4) if proven_family_required else 1.0
    totals["proven_query_families"] = sorted(proven_families)
    return {
        "schema_version": "1.0",
        "summary": totals,
        "artifacts": artifacts,
        "notes": [
            "Source evidence coverage counts findings with dependency graph, import, vulnerable API, or request-controlled evidence.",
            "No-rule findings are rule coverage gaps; package-present findings are evidence gaps.",
            "Package-manager manifest evidence is weak dependency evidence. It does not prove runtime import or vulnerable API execution.",
            "External evidence must match a component/package, package URL, or vulnerability selector; artifact only narrows a selector match.",
            "Critical findings for maintained package families also need matching external query-family evidence.",
            "Critical findings for packages outside the maintained family catalog are coverage gaps until a proven family is added.",
            "Critical query-family evidence only satisfies production gates when the family is in the maintained proven-query list.",
            "Built-in source rules are advisory fallback evidence. Production gates should import Semgrep, CodeQL/SARIF, govulncheck, or native evidence.",
            "Production profile fails when critical findings only have dependency-level or weaker source evidence.",
        ],
    }


def _critical_source_gate_applies(finding: Any) -> bool:
    vulnerability = getattr(finding, "vulnerability", None)
    tier = str(getattr(getattr(finding, "tier", ""), "value", getattr(finding, "tier", ""))).lower()
    severity = str(getattr(vulnerability, "severity", "") or "").lower()
    cvss = getattr(vulnerability, "cvss", None)
    epss = getattr(vulnerability, "epss", None)
    return (
        tier in {"high", "urgent"}
        or severity == "critical"
        or (isinstance(cvss, (int, float)) and cvss >= 9.0)
        or bool(getattr(vulnerability, "known_exploited", False))
        or (isinstance(epss, (int, float)) and epss >= 0.5)
    )


def _evidence_query_families(finding: Any, required_query_families: set[str]) -> set[str]:
    source = finding.source
    families = {str(item).lower().replace("_", "-") for item in getattr(source, "query_families", []) if str(item)}
    if str(getattr(source, "evidence_source", "")).lower() == "govulncheck" and ecosystem_from_component(finding.component.purl, finding.component.name) == "go":
        # govulncheck reports vulnerability-specific call stacks instead of a
        # package-family rule ID, so it satisfies maintained Go family gates.
        families.update(required_query_families)
        families.add("go-vuln-callstack")
    return families


def _critical_package_row(row: dict[str, Any]) -> dict[str, Any]:
    converted = dict(row)
    converted["vulnerabilities"] = sorted({str(item) for item in converted.get("vulnerabilities", [])})
    for key in ("required_query_families", "evidence_query_families", "missing_query_families", "unproven_query_families"):
        values = converted.get(key, set())
        if isinstance(values, set):
            converted[key] = sorted(values)
    return converted


def semgrep_rules_yaml(rules: Iterable[ReachabilityRule] = BUILTIN_RULES) -> str:
    lines = ["rules:"]
    for rule in rules:
        languages = _semgrep_languages(rule.ecosystem)
        if not languages:
            continue
        rule_id_base = _semgrep_rule_id(rule)
        for state, required_patterns in (
            (Reachability.FUNCTION_REACHABLE, (*rule.import_patterns, *rule.function_patterns)),
            (Reachability.ATTACKER_CONTROLLED, (*rule.import_patterns, *rule.function_patterns, *rule.attacker_patterns)),
        ):
            if not required_patterns or (state == Reachability.ATTACKER_CONTROLLED and not rule.attacker_patterns):
                continue
            lines.extend(
                [
                    f"  - id: {rule_id_base}.{state.value}",
                    "    severity: INFO",
                    f"    languages: [{', '.join(languages)}]",
                    f"    message: {_yaml_string(rule.description or f'{rule.package_name} source evidence')}",
                    "    metadata:",
                    "      reachability_advisor:",
                    f"        ecosystem: {_yaml_string(rule.ecosystem)}",
                    f"        package: {_yaml_string(rule.package_name)}",
                    f"        query_families: [{', '.join(_yaml_string(item) for item in query_family_ids_for_rule(rule.ecosystem, rule.package_name))}]",
                    f"        state: {_yaml_string(state.value)}",
                    "        confidence: medium",
                    f"        vulnerability_ids: [{', '.join(_yaml_string(item) for item in rule.vulnerability_ids)}]",
                    "    patterns:",
                ]
            )
            for pattern in required_patterns:
                lines.append(f"      - pattern-regex: {_yaml_string(pattern)}")
    return "\n".join(lines) + "\n"


def _semgrep_languages(ecosystem: str) -> list[str]:
    return {
        "maven": ["java"],
        "npm": ["javascript", "typescript"],
        "pypi": ["python"],
        "go": ["go"],
        "golang": ["go"],
    }.get(ecosystem, [])


def _semgrep_rule_id(rule: ReachabilityRule) -> str:
    package = re.sub(r"[^a-z0-9_.-]+", "-", rule.package_name.lower()).strip("-")
    ecosystem = re.sub(r"[^a-z0-9_.-]+", "-", rule.ecosystem.lower()).strip("-")
    if rule.vulnerability_ids:
        vuln = re.sub(r"[^a-z0-9_.-]+", "-", rule.vulnerability_ids[0].lower()).strip("-")
        return f"reachability.{ecosystem}.{package}.{vuln}"
    return f"reachability.{ecosystem}.{package}"


def _yaml_string(value: str) -> str:
    return json.dumps(value)


__all__ = [
    "BUILTIN_RULES",
    "ExternalSourceEvidenceStore",
    "ReachabilityRule",
    "analyze_component_source",
    "build_source_index",
    "load_reachability_rules",
    "load_external_source_evidence",
    "merge_source_evidence",
    "parse_source_roots",
    "semgrep_rules_yaml",
    "source_coverage_report",
]
