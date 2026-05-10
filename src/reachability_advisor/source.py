"""Source-code reachability hints for developer workflows.

The implementation is deliberately lightweight and transparent. It is designed
for CI and IDE feedback, not for perfect whole-program call-graph analysis.
Version 4 improves the logic in two important ways:

* rules can be vulnerability-specific, so a package can have different sinks for
  different CVEs or advisories;
* attacker-controlled classification requires import/use/input evidence in the
  same file or a direct handler-to-sink call path. Unlinked entry points
  elsewhere still increase confidence, but do not create an unsafe exploitability
  claim.
"""

from __future__ import annotations

import ast
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
        function_patterns=(r"new\s+ObjectMapper\s*\(", r"\.readValue\s*\(", r"\.writeValueAsString\s*\(", r"enableDefaultTyping\s*\(", r"activateDefaultTyping\s*\("),
        attacker_patterns=(r"@RequestBody", r"HttpServletRequest", r"request\.get", r"@PostMapping"),
        description="Jackson ObjectMapper use on request-like inputs",
    ),
    ReachabilityRule(
        ecosystem="maven",
        package_name="snakeyaml",
        import_patterns=(r"import\s+org\.yaml\.snakeyaml\.",),
        function_patterns=(r"new\s+Yaml\s*\(", r"\.load(?:All|As)?\s*\("),
        attacker_patterns=(r"@RequestBody", r"HttpServletRequest", r"request\.get", r"@PostMapping", r"@RequestParam"),
        description="SnakeYAML deserialization of request-controlled YAML",
    ),
    ReachabilityRule(
        ecosystem="maven",
        package_name="commons-text",
        import_patterns=(r"import\s+org\.apache\.commons\.text\.",),
        function_patterns=(r"StringSubstitutor\s*\(", r"StringSubstitutor\.createInterpolator\s*\(", r"\.replace\s*\("),
        attacker_patterns=(r"@RequestBody", r"@RequestParam", r"HttpServletRequest", r"request\.get"),
        description="Commons Text interpolation/template processing",
    ),
    ReachabilityRule(
        ecosystem="maven",
        package_name="jjwt-api",
        import_patterns=(r"import\s+io\.jsonwebtoken\.",),
        function_patterns=(r"Jwts\.parser(?:Builder)?\s*\(", r"\.parseClaimsJws\s*\(", r"\.parse\s*\("),
        attacker_patterns=(r"Authorization", r"@RequestHeader", r"HttpServletRequest", r"request\.getHeader"),
        description="JJWT token parsing or verification on request headers",
    ),
    ReachabilityRule(
        ecosystem="maven",
        package_name="xercesImpl",
        import_patterns=(r"import\s+javax\.xml\.", r"import\s+org\.w3c\.dom\.", r"import\s+org\.xml\.sax\."),
        function_patterns=(r"DocumentBuilderFactory\.newInstance\s*\(", r"SAXParserFactory\.newInstance\s*\(", r"\.parse\s*\("),
        attacker_patterns=(r"@RequestBody", r"HttpServletRequest", r"request\.getInputStream", r"MultipartFile"),
        description="XML parser use on request-controlled XML",
    ),
    ReachabilityRule(
        ecosystem="maven",
        package_name="commons-compress",
        import_patterns=(r"import\s+org\.apache\.commons\.compress\.",),
        function_patterns=(r"ArchiveStreamFactory\s*\(", r"ZipArchiveInputStream\s*\(", r"TarArchiveInputStream\s*\(", r"\.getNext.*Entry\s*\("),
        attacker_patterns=(r"MultipartFile", r"@RequestBody", r"HttpServletRequest", r"request\.getInputStream"),
        description="Archive extraction from request-controlled uploads",
    ),
    ReachabilityRule(
        ecosystem="maven",
        package_name="guava",
        import_patterns=(r"import\s+com\.google\.common\.",),
        function_patterns=(r"ImmutableList\.", r"Joiner\.on", r"Splitter\.on", r"Hashing\."),
        description="Common Guava API usage",
    ),
    ReachabilityRule(
        ecosystem="maven",
        package_name="spring-web",
        import_patterns=(r"import\s+org\.springframework\.web\.", r"import\s+org\.springframework\.http\."),
        function_patterns=(r"@(RestController|Controller)", r"@(Get|Post|Put|Delete|Patch)Mapping", r"@RequestMapping", r"WebClient\.", r"RestTemplate\s*\("),
        attacker_patterns=(r"@RequestBody", r"@RequestParam", r"@PathVariable", r"HttpServletRequest", r"ServerHttpRequest"),
        description="Spring Web controller or HTTP client handling request data",
    ),
    ReachabilityRule(
        ecosystem="maven",
        package_name="spring-webmvc",
        import_patterns=(r"import\s+org\.springframework\.web\.", r"import\s+org\.springframework\.http\."),
        function_patterns=(r"@(RestController|Controller)", r"@(Get|Post|Put|Delete|Patch)Mapping", r"@RequestMapping", r"ModelAndView\s*\("),
        attacker_patterns=(r"@RequestBody", r"@RequestParam", r"@PathVariable", r"HttpServletRequest"),
        description="Spring MVC controller handling request data",
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
        package_name="axios",
        import_patterns=(r"require\(['\"]axios['\"]\)", r"from\s+['\"]axios['\"]", r"import\s+axios\s+from\s+['\"]axios['\"]"),
        function_patterns=(r"axios\.(get|post|put|patch|delete|request)\s*\(", r"axios\s*\(\s*\{"),
        attacker_patterns=(r"req\.(body|query|params)", r"event\.body", r"request\.(body|query|params)", r"app\.(get|post|put|delete)\s*\("),
        description="Axios outbound request built near request-controlled inputs",
    ),
    ReachabilityRule(
        ecosystem="npm",
        package_name="jsonwebtoken",
        import_patterns=(r"require\(['\"]jsonwebtoken['\"]\)", r"from\s+['\"]jsonwebtoken['\"]", r"import\s+(?:jwt|\*)\s+from\s+['\"]jsonwebtoken['\"]"),
        function_patterns=(r"\bjwt\.(verify|decode|sign)\s*\(", r"jsonwebtoken\.(verify|decode|sign)\s*\("),
        attacker_patterns=(r"req\.(headers|cookies|body)", r"Authorization", r"event\.headers", r"request\.headers"),
        description="JWT parsing or verification on request-controlled tokens",
    ),
    ReachabilityRule(
        ecosystem="npm",
        package_name="ejs",
        import_patterns=(r"require\(['\"]ejs['\"]\)", r"from\s+['\"]ejs['\"]"),
        function_patterns=(r"ejs\.(render|compile|renderFile)\s*\(", r"\.render\s*\("),
        attacker_patterns=(r"req\.(body|query|params)", r"event\.body", r"app\.(get|post|put|delete)\s*\("),
        description="EJS template rendering near request-controlled inputs",
    ),
    ReachabilityRule(
        ecosystem="npm",
        package_name="handlebars",
        import_patterns=(r"require\(['\"]handlebars['\"]\)", r"from\s+['\"]handlebars['\"]"),
        function_patterns=(r"Handlebars\.compile\s*\(", r"handlebars\.compile\s*\("),
        attacker_patterns=(r"req\.(body|query|params)", r"event\.body", r"app\.(get|post|put|delete)\s*\("),
        description="Handlebars template compilation near request-controlled inputs",
    ),
    ReachabilityRule(
        ecosystem="npm",
        package_name="js-yaml",
        import_patterns=(r"require\(['\"]js-yaml['\"]\)", r"from\s+['\"]js-yaml['\"]"),
        function_patterns=(r"yaml\.load\s*\(", r"jsyaml\.load\s*\(", r"safeLoad\s*\("),
        attacker_patterns=(r"req\.(body|query|params)", r"event\.body", r"app\.(get|post|put|delete)\s*\("),
        description="js-yaml deserialization near request-controlled inputs",
    ),
    ReachabilityRule(
        ecosystem="npm",
        package_name="xml2js",
        import_patterns=(r"require\(['\"]xml2js['\"]\)", r"from\s+['\"]xml2js['\"]"),
        function_patterns=(r"parseString(?:Promise)?\s*\(", r"new\s+xml2js\.Parser\s*\(", r"\.parseString\s*\("),
        attacker_patterns=(r"req\.(body|query|params)", r"event\.body", r"app\.(get|post|put|delete)\s*\("),
        description="XML parsing near request-controlled input",
    ),
    ReachabilityRule(
        ecosystem="npm",
        package_name="adm-zip",
        import_patterns=(r"require\(['\"]adm-zip['\"]\)", r"from\s+['\"]adm-zip['\"]"),
        function_patterns=(r"new\s+AdmZip\s*\(", r"\.extractAllTo\s*\("),
        attacker_patterns=(r"req\.(body|file|files)", r"multer", r"event\.body"),
        description="Archive extraction from request-controlled uploads",
    ),
    ReachabilityRule(
        ecosystem="npm",
        package_name="minimist",
        import_patterns=(r"require\(['\"]minimist['\"]\)", r"from\s+['\"]minimist['\"]"),
        function_patterns=(r"minimist\s*\(", r"parseArgs\s*\("),
        description="minimist argument parser use",
    ),
    ReachabilityRule(
        ecosystem="npm",
        package_name="express",
        import_patterns=(r"require\(['\"]express['\"]\)", r"from\s+['\"]express['\"]", r"import\s+express\s+from\s+['\"]express['\"]"),
        function_patterns=(
            r"express\s*\(",
            r"express\.Router\s*\(",
            r"\b(app|router)\.(get|post|put|patch|delete|all|use)\s*\(",
            r"\bres\.(send|json|redirect|location|render|status)\s*\(",
        ),
        attacker_patterns=(
            r"\b(req|request)\.(body|query|params|headers|cookies|url|originalUrl)\b",
            r"\b(app|router)\.(get|post|put|patch|delete|all)\s*\([^,\n]+,\s*(async\s*)?\(?\s*(req|request)\b",
        ),
        description="Express application or router entrypoint handling request objects",
    ),
    ReachabilityRule(
        ecosystem="npm",
        package_name="platform-express",
        import_patterns=(r"from\s+['\"]@nestjs/platform-express['\"]", r"require\(['\"]@nestjs/platform-express['\"]\)", r"from\s+['\"]@nestjs/common['\"]"),
        function_patterns=(r"@Controller\s*\(", r"@(Get|Post|Put|Patch|Delete|All)\s*\(", r"NestFactory\.create\s*\("),
        attacker_patterns=(r"@Body\s*\(", r"@Param\s*\(", r"@Query\s*\(", r"@Req\s*\(", r"Request\b"),
        description="NestJS Express-platform controller handling request data",
    ),
    ReachabilityRule(
        ecosystem="pypi",
        package_name="requests",
        import_patterns=(r"^\s*import\s+requests\b", r"^\s*from\s+requests\s+import\s+"),
        function_patterns=(r"requests\.(get|post|put|delete|patch)\s*\(",),
        attacker_patterns=(r"flask\.request", r"request\.args", r"request\.json", r"FastAPI\(", r"@app\.(get|post|put|delete)"),
        description="requests usage in Python web handlers",
    ),
    ReachabilityRule(
        ecosystem="pypi",
        package_name="pyyaml",
        import_patterns=(r"^\s*import\s+yaml\b", r"^\s*from\s+yaml\s+import\s+"),
        function_patterns=(r"yaml\.load\s*\(", r"\bload\s*\("),
        attacker_patterns=(r"flask\.request", r"request\.(args|json|data|form|files|body)", r"FastAPI\(", r"@app\.(get|post|put|delete)"),
        description="PyYAML deserialization of request-controlled YAML",
    ),
    ReachabilityRule(
        ecosystem="pypi",
        package_name="jinja2",
        import_patterns=(r"^\s*import\s+jinja2\b", r"^\s*from\s+jinja2\s+import\s+"),
        function_patterns=(r"Environment\s*\(", r"Template\s*\(", r"\.from_string\s*\(", r"\.render\s*\("),
        attacker_patterns=(r"flask\.request", r"request\.(args|json|data|form)", r"FastAPI\(", r"@app\.(get|post|put|delete)"),
        description="Jinja2 template construction/rendering near request-controlled input",
    ),
    ReachabilityRule(
        ecosystem="pypi",
        package_name="pyjwt",
        import_patterns=(r"^\s*import\s+jwt\b", r"^\s*from\s+jwt\s+import\s+"),
        function_patterns=(r"jwt\.(decode|encode)\s*\(", r"\bdecode\s*\("),
        attacker_patterns=(r"Authorization", r"request\.(headers|cookies|json)", r"flask\.request", r"FastAPI\("),
        description="PyJWT token parsing or verification on request-controlled tokens",
    ),
    ReachabilityRule(
        ecosystem="pypi",
        package_name="lxml",
        import_patterns=(r"^\s*import\s+lxml\b", r"^\s*from\s+lxml\s+import\s+"),
        function_patterns=(r"etree\.(fromstring|parse|XMLParser)\s*\(", r"\.xpath\s*\("),
        attacker_patterns=(r"request\.(data|body|files|json|form)", r"flask\.request", r"@app\.(get|post|put|delete)"),
        description="lxml XML parsing near request-controlled input",
    ),
    ReachabilityRule(
        ecosystem="pypi",
        package_name="django",
        import_patterns=(r"^\s*import\s+django\b", r"^\s*from\s+django\s+import\s+", r"^\s*from\s+django\.",),
        function_patterns=(r"render\s*\(", r"redirect\s*\(", r"JsonResponse\s*\(", r"Template\s*\("),
        attacker_patterns=(r"\brequest\.(GET|POST|body|headers|FILES|META)\b", r"def\s+\w+\s*\(\s*request\b"),
        description="Django view handling request-controlled input",
    ),
    ReachabilityRule(
        ecosystem="pypi",
        package_name="fastapi",
        import_patterns=(r"^\s*import\s+fastapi\b", r"^\s*from\s+fastapi\s+import\s+"),
        function_patterns=(r"FastAPI\s*\(", r"APIRouter\s*\(", r"@(app|router)\.(get|post|put|patch|delete|api_route)\s*\("),
        attacker_patterns=(r"Request\b", r"\b(request|req)\.(query_params|headers|path_params|json|body)\b", r"@(app|router)\.(get|post|put|patch|delete|api_route)\s*\("),
        description="FastAPI application or router entrypoint handling HTTP request data",
    ),
    ReachabilityRule(
        ecosystem="pypi",
        package_name="chainlit",
        import_patterns=(r"^\s*import\s+chainlit\b", r"^\s*from\s+chainlit\s+import\s+"),
        function_patterns=(r"@cl\.(on_message|on_chat_start|on_audio_chunk|on_file_upload)", r"\bcl\.Message\b", r"\bcl\.(AskFileMessage|AskUserMessage)\b"),
        attacker_patterns=(r"@cl\.on_message", r"\bmessage\.(content|elements|metadata)\b", r"\bcl\.Message\b"),
        description="Chainlit chat/message handler processing user-controlled messages",
    ),
    ReachabilityRule(
        ecosystem="pypi",
        package_name="aiohttp",
        import_patterns=(r"^\s*import\s+aiohttp\b", r"^\s*from\s+aiohttp\s+import\s+"),
        function_patterns=(r"\bClientSession\s*\(", r"\bweb\.Application\s*\(", r"\bweb\.RouteTableDef\s*\(", r"@routes\.(get|post|put|patch|delete)\s*\("),
        attacker_patterns=(r"\bweb\.Request\b", r"\brequest\.(query|query_string|match_info|headers|json|post)\b", r"@routes\.(get|post|put|patch|delete)\s*\("),
        description="aiohttp client/server use with HTTP request or route entrypoint evidence",
    ),
    ReachabilityRule(
        ecosystem="go",
        package_name="jwt",
        import_patterns=(r"import\s+\(?[^;]*[\"']github\.com/golang-jwt/jwt(?:/v[0-9]+)?[\"']", r"import\s+\(?[^;]*[\"']github\.com/dgrijalva/jwt-go[\"']"),
        function_patterns=(r"jwt\.Parse(?:WithClaims)?\s*\(", r"ParseWithClaims\s*\("),
        attacker_patterns=(r"\*http\.Request", r"\.Header\.Get\s*\(", r"\.URL\.Query\s*\(", r"gin\.Context"),
        description="Go JWT parsing from HTTP request context",
    ),
    ReachabilityRule(
        ecosystem="go",
        package_name="yaml.v2",
        import_patterns=(r"import\s+\(?[^;]*[\"']gopkg\.in/yaml\.v2[\"']", r"import\s+\(?[^;]*[\"']gopkg\.in/yaml\.v3[\"']"),
        function_patterns=(r"yaml\.Unmarshal\s*\(", r"yaml\.NewDecoder\s*\("),
        attacker_patterns=(r"\*http\.Request", r"\.Body", r"gin\.Context"),
        description="Go YAML parsing from HTTP request context",
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
    if language == "javascript":
        patterns = (
            r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{",
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{",
            r"exports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\s*\([^)]*\)\s*\{",
            r"module\.exports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\s*\([^)]*\)\s*\{",
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


def _function_segments(path: Path, text: str) -> list[FunctionSegment]:
    language = _language_for(path)
    if language == "python":
        return _python_function_segments(text)
    return _regex_function_segments(text, language)


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


def _find_direct_call_path(signals: list[FileSignal]) -> CallPath | None:
    sinks: dict[str, tuple[FileSignal, str]] = {}
    for signal in signals:
        if not signal.has_import or not signal.has_function:
            continue
        for name in signal.sink_functions:
            sinks.setdefault(name.lower(), (signal, name))
    if not sinks:
        return None
    for signal in signals:
        for attacker_function in sorted(signal.attacker_functions):
            for called_name in sorted(signal.calls_by_function.get(attacker_function, set())):
                sink = sinks.get(called_name.lower())
                if not sink:
                    continue
                sink_signal, sink_function = sink
                if signal.path == sink_signal.path and attacker_function == sink_function:
                    continue
                return CallPath(
                    attacker_file=signal.path,
                    attacker_function=attacker_function,
                    sink_file=sink_signal.path,
                    sink_function=sink_function,
                    called_name=called_name,
                )
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
    _add_semantic_signals(signal, text, function_patterns, attacker_patterns)
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
    has_package_rule = bool(rules)
    generic_patterns = _generic_patterns(component)
    import_patterns = tuple(dict.fromkeys(pattern for rule in rules for pattern in rule.import_patterns)) or generic_patterns
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

    if not signals and not has_package_rule:
        language = _language_for(files[0]) if files else "unknown"
        return SourceEvidence(
            reachability=Reachability.UNKNOWN_DUE_TO_NO_RULE,
            confidence=Confidence.LOW,
            language=language,
            reason="component appears in SBOM; no package-specific source rule exists and generic import usage was not observed",
        )

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
    call_path = _find_direct_call_path(signals)
    locations = [location for signal in signals for location in signal.locations][:8]
    symbols = sorted({symbol for signal in signals for symbol in signal.matched_symbols})
    language = _dominant_language(signals)
    rule_text = _rule_text(rules, vulnerability)

    if call_path:
        call_symbol = f"call_path:{call_path.attacker_function}->{call_path.called_name}->{call_path.sink_function}"
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
        )

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
            reason += "; attacker entrypoint was observed elsewhere but no same-file or direct call-path link was inferred"
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
