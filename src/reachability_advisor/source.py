"""Source-code reachability hints for developer workflows.

The implementation is deliberately lightweight and transparent. It is designed
for CI and IDE feedback, not for perfect whole-program call-graph analysis.
Version 4 improves the logic in two important ways:

* rules can be vulnerability-specific, so a package can have different sinks for
  different CVEs or advisories;
* attacker-controlled classification requires import/use/input evidence in the
  same file. Entry points elsewhere still increase confidence, but do not create
  an unsafe exploitability claim.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .models import Component, Confidence, Reachability, SourceEvidence, SourceLocation, VulnerabilityRecord
from .purl import ecosystem_from_component, parse_purl

MAX_FILE_BYTES = 1_000_000
SUPPORTED_EXTENSIONS = {".java", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go"}


@dataclass(frozen=True)
class ReachabilityRule:
    ecosystem: str
    package_name: str
    import_patterns: tuple[str, ...]
    function_patterns: tuple[str, ...] = ()
    attacker_patterns: tuple[str, ...] = ()
    vulnerability_ids: tuple[str, ...] = ()
    description: str = ""

    def applies_to(self, component: Component, vulnerability: VulnerabilityRecord | None = None) -> bool:
        ecosystem = ecosystem_from_component(component.purl, component.name)
        parsed = parse_purl(component.purl)
        candidate_names = {component.name.lower()}
        if parsed and parsed.name:
            candidate_names.add(parsed.name.lower())
        if self.ecosystem != ecosystem or self.package_name.lower() not in candidate_names:
            return False
        if not self.vulnerability_ids or vulnerability is None:
            return True
        ids = {vulnerability.id.lower(), *(alias.lower() for alias in vulnerability.aliases)}
        return any(item.lower() in ids for item in self.vulnerability_ids)


@dataclass
class FileSignal:
    path: Path
    language: str
    has_import: bool = False
    has_function: bool = False
    has_attacker: bool = False
    locations: list[SourceLocation] = field(default_factory=list)
    matched_symbols: set[str] = field(default_factory=set)


BUILTIN_RULES: tuple[ReachabilityRule, ...] = (
    ReachabilityRule(
        ecosystem="maven",
        package_name="log4j-core",
        vulnerability_ids=("CVE-2021-44228", "CVE-2021-45046"),
        import_patterns=(r"import\s+org\.apache\.logging\.log4j\.",),
        function_patterns=(r"LogManager\.getLogger\s*\(", r"\.log\s*\(", r"\.info\s*\(", r"\.error\s*\("),
        attacker_patterns=(r"@(Get|Post|Put|Delete|Patch)Mapping", r"@RequestMapping", r"HttpServletRequest", r"@RequestBody"),
        description="Log4j logger usage plus HTTP/controller input hints",
    ),
    ReachabilityRule(
        ecosystem="maven",
        package_name="jackson-databind",
        import_patterns=(r"import\s+com\.fasterxml\.jackson\.databind\.",),
        function_patterns=(r"new\s+ObjectMapper\s*\(", r"\.readValue\s*\(", r"\.writeValueAsString\s*\("),
        attacker_patterns=(r"@RequestBody", r"HttpServletRequest", r"request\.get", r"@PostMapping"),
        description="Jackson ObjectMapper use on request-like inputs",
    ),
    ReachabilityRule(
        ecosystem="maven",
        package_name="guava",
        import_patterns=(r"import\s+com\.google\.common\.",),
        function_patterns=(r"ImmutableList\.", r"Joiner\.on", r"Splitter\.on", r"Hashing\."),
        description="Common Guava API usage",
    ),
    ReachabilityRule(
        ecosystem="npm",
        package_name="lodash",
        import_patterns=(r"require\(['\"]lodash['\"]\)", r"from\s+['\"]lodash['\"]", r"import\s+_\s+from\s+['\"]lodash['\"]"),
        function_patterns=(r"_\.merge\s*\(", r"_\.template\s*\(", r"_\.set\s*\(", r"lodash\.merge\s*\("),
        attacker_patterns=(r"req\.(body|query|params)", r"event\.body", r"JSON\.parse\s*\(.*event\.body", r"exports\.handler", r"app\.(get|post|put|delete)\s*\("),
        description="Lodash merge/template/set usage near request or Lambda inputs",
    ),
    ReachabilityRule(
        ecosystem="npm",
        package_name="minimist",
        import_patterns=(r"require\(['\"]minimist['\"]\)", r"from\s+['\"]minimist['\"]"),
        function_patterns=(r"minimist\s*\(", r"parseArgs\s*\("),
        description="minimist argument parser use",
    ),
    ReachabilityRule(
        ecosystem="pypi",
        package_name="requests",
        import_patterns=(r"^\s*import\s+requests\b", r"^\s*from\s+requests\s+import\s+"),
        function_patterns=(r"requests\.(get|post|put|delete|patch)\s*\(",),
        attacker_patterns=(r"flask\.request", r"request\.args", r"request\.json", r"FastAPI\(", r"@app\.(get|post|put|delete)"),
        description="requests usage in Python web handlers",
    ),
)


def load_reachability_rules(path: str | Path | None) -> tuple[ReachabilityRule, ...]:
    if not path:
        return ()
    rule_path = Path(path)
    data = json.loads(rule_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError(f"{rule_path}: expected object with a rules list")
    rules: list[ReachabilityRule] = []
    for index, item in enumerate(data["rules"]):
        if not isinstance(item, dict):
            raise ValueError(f"{rule_path}: rule {index} must be an object")
        ecosystem = str(item.get("ecosystem") or "").lower().strip()
        package = str(item.get("package") or item.get("package_name") or "").strip()
        imports = _tuple_patterns(item.get("import_patterns"))
        if not ecosystem or not package or not imports:
            raise ValueError(f"{rule_path}: rule {index} needs ecosystem, package, and import_patterns")
        rules.append(
            ReachabilityRule(
                ecosystem=ecosystem,
                package_name=package,
                import_patterns=imports,
                function_patterns=_tuple_patterns(item.get("function_patterns")),
                attacker_patterns=_tuple_patterns(item.get("attacker_patterns")),
                vulnerability_ids=_tuple_patterns(item.get("vulnerabilities") or item.get("vulnerability_ids")),
                description=str(item.get("description") or "custom reachability rule"),
            )
        )
    return tuple(rules)


def _tuple_patterns(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return ()


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


def _iter_source_files(root: Path) -> list[Path]:
    if not root.exists() or not root.is_dir():
        return []
    files: list[Path] = []
    ignored_dirs = {".git", ".hg", ".svn", "node_modules", "target", "build", "dist", ".venv", "venv", "__pycache__"}
    for path in root.rglob("*"):
        if any(part in ignored_dirs for part in path.parts):
            continue
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        files.append(path)
    return files


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
        return (rf"require\(['\"]{escaped}['\"]\)", rf"from\s+['\"]{escaped}['\"]")
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


def _language_for(path: Path) -> str:
    if path.suffix == ".java":
        return "java"
    if path.suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return "javascript"
    if path.suffix == ".py":
        return "python"
    if path.suffix == ".go":
        return "go"
    return "unknown"


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
    return signal


def analyze_component_source(
    component: Component,
    root: Path | None,
    vulnerability: VulnerabilityRecord | None = None,
    custom_rules: Iterable[ReachabilityRule] = (),
) -> SourceEvidence:
    if root is None:
        return SourceEvidence(
            reachability=Reachability.PACKAGE_PRESENT,
            confidence=Confidence.LOW,
            language="unknown",
            reason="component appears in SBOM; no source root supplied",
        )
    files = _iter_source_files(root)
    if not files:
        return SourceEvidence(
            reachability=Reachability.PACKAGE_PRESENT,
            confidence=Confidence.LOW,
            language="unknown",
            reason="component appears in SBOM; no supported source files found",
        )

    rules = _rules_for(component, vulnerability, custom_rules)
    import_patterns = tuple(dict.fromkeys(pattern for rule in rules for pattern in rule.import_patterns)) or _generic_patterns(component)
    function_patterns = tuple(dict.fromkeys(pattern for rule in rules for pattern in rule.function_patterns))
    attacker_patterns = tuple(dict.fromkeys(pattern for rule in rules for pattern in rule.attacker_patterns))

    signals: list[FileSignal] = []
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        signal = _scan_file(file_path, text, import_patterns, function_patterns, attacker_patterns)
        if signal.has_import or signal.has_function or signal.has_attacker:
            signals.append(signal)

    if not signals:
        language = _language_for(files[0]) if files else "unknown"
        return SourceEvidence(
            reachability=Reachability.PACKAGE_PRESENT,
            confidence=Confidence.LOW,
            language=language,
            reason="component appears in SBOM, but source usage was not observed",
        )

    has_import_any = any(signal.has_import for signal in signals)
    has_function_any = any(signal.has_function for signal in signals)
    has_attacker_any = any(signal.has_attacker for signal in signals)
    same_file_attacker = any(signal.has_import and signal.has_function and signal.has_attacker for signal in signals)
    same_file_function = any(signal.has_import and signal.has_function for signal in signals)
    imported_only = any(signal.has_import for signal in signals)
    locations = [location for signal in signals for location in signal.locations][:8]
    symbols = sorted({symbol for signal in signals for symbol in signal.matched_symbols})
    language = _dominant_language(signals)
    rule_text = _rule_text(rules, vulnerability)

    if same_file_attacker:
        return SourceEvidence(
            reachability=Reachability.ATTACKER_CONTROLLED,
            confidence=Confidence.HIGH if vulnerability and rules else Confidence.MEDIUM,
            language=language,
            reason=f"{rule_text}; same source file contains import, vulnerable-function hint, and attacker-controlled entrypoint hint",
            locations=locations,
            matched_symbols=symbols,
        )
    if same_file_function:
        reason = f"{rule_text}; same source file contains import and vulnerable-function usage hints"
        if has_attacker_any:
            reason += "; attacker entrypoint was observed elsewhere but no same-file link was inferred"
        return SourceEvidence(
            reachability=Reachability.FUNCTION_REACHABLE,
            confidence=Confidence.MEDIUM,
            language=language,
            reason=reason,
            locations=locations,
            matched_symbols=symbols,
        )
    if has_import_any and has_function_any:
        return SourceEvidence(
            reachability=Reachability.FUNCTION_REACHABLE,
            confidence=Confidence.LOW,
            language=language,
            reason=f"{rule_text}; import and vulnerable-function hints were observed in the source root but not the same file",
            locations=locations,
            matched_symbols=symbols,
        )
    if imported_only:
        return SourceEvidence(
            reachability=Reachability.IMPORTED,
            confidence=Confidence.MEDIUM,
            language=language,
            reason=f"{rule_text}; source imports or requires the package",
            locations=locations,
            matched_symbols=symbols,
        )
    return SourceEvidence(
        reachability=Reachability.PACKAGE_PRESENT,
        confidence=Confidence.LOW,
        language=language,
        reason="component appears in SBOM, but package import was not observed",
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


__all__ = [
    "BUILTIN_RULES",
    "ReachabilityRule",
    "analyze_component_source",
    "load_reachability_rules",
    "parse_source_roots",
]
