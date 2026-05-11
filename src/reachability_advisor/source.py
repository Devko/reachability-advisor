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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .models import Component, Confidence, Reachability, SbomDocument, SourceEvidence, SourceLocation, VulnerabilityRecord
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
class IndexedSourceFile:
    path: Path
    language: str
    text: str


@dataclass
class SourceIndex:
    root: Path | None
    files: list[IndexedSourceFile] = field(default_factory=list)
    skipped_files: list[dict[str, str]] = field(default_factory=list)
    import_cache: dict[str, bool] = field(default_factory=dict)

    @property
    def languages(self) -> list[str]:
        return sorted({file.language for file in self.files if file.language != "unknown"})


@dataclass(frozen=True)
class CallPath:
    attacker_file: Path
    attacker_function: str
    sink_file: Path
    sink_function: str
    called_name: str
    functions: tuple[str, ...] = ()


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
        attacker_patterns=(r"req\.(body|query|params)", r"event\.body", r"request\.(body|query|params)", r"@Body\s*\(", r"@Param\s*\(", r"@Query\s*\(", r"app\.(get|post|put|delete)\s*\("),
        description="Axios outbound request built near request-controlled inputs",
    ),
    ReachabilityRule(
        ecosystem="npm",
        package_name="request",
        import_patterns=(
            r"require\(['\"]request['\"]\)",
            r"import\s+[A-Za-z_$][\w$]*\s*=\s*require\(['\"]request['\"]\)",
            r"from\s+['\"]request['\"]",
        ),
        function_patterns=(
            r"\brequest\s*\(",
            r"\brequest\.(get|post|put|patch|delete|defaults)\s*\(",
            r"\blocalVarRequest\s*\(",
            r"\blocalVarRequest\.(get|post|put|patch|delete|defaults)\s*\(",
        ),
        attacker_patterns=(
            r"req\.(body|query|params|headers)",
            r"event\.body",
            r"@Body\s*\(",
            r"@Param\s*\(",
            r"@Query\s*\(",
            r"\b(app|router)\.(get|post|put|patch|delete|all)\s*\(",
        ),
        description="Node request HTTP client use near HTTP handler inputs",
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
        package_name="multer",
        import_patterns=(r"require\(['\"]multer['\"]\)", r"from\s+['\"]multer['\"]", r"import\s+multer\s+from\s+['\"]multer['\"]"),
        function_patterns=(r"multer\s*\(", r"\.(single|array|fields|none|any)\s*\("),
        attacker_patterns=(r"req\.(file|files|body)", r"@UploadedFile\s*\(", r"@UploadedFiles\s*\(", r"fileFilter", r"storage"),
        description="Multer upload handling near request-controlled file inputs",
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
        package_name="systeminformation",
        import_patterns=(r"require\(['\"]systeminformation['\"]\)", r"from\s+['\"]systeminformation['\"]", r"from\s+['\"]systeminformation/lib/"),
        function_patterns=(r"\bsi\.[A-Za-z_]\w*\s*\(", r"\bsysteminformation\.[A-Za-z_]\w*\s*\("),
        description="systeminformation API use",
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


def build_source_index(root: Path | None) -> SourceIndex:
    if root is None:
        return SourceIndex(root=None)
    root_path = Path(root)
    index = SourceIndex(root=root_path)
    if not root_path.exists() or not root_path.is_dir():
        index.skipped_files.append({"path": str(root_path), "reason": "source root does not exist or is not a directory"})
        return index
    ignored_dirs = {".git", ".hg", ".svn", "node_modules", "target", "build", "dist", ".venv", "venv", "__pycache__"}
    for path in root_path.rglob("*"):
        if any(part in ignored_dirs for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
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
        index.files.append(IndexedSourceFile(path=path, language=_language_for(path), text=text))
    return index


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
            )
    return SourceEvidence(
        reachability=Reachability.PACKAGE_PRESENT,
        confidence=Confidence.LOW,
        language=language,
        reason=f"component appears in SBOM dependency graph path {' -> '.join(path)}, but no imported parent dependency was observed",
        dependency_path=path,
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


REACHABILITY_STRENGTH = {
    Reachability.ABSENT: 0,
    Reachability.UNKNOWN_DUE_TO_NO_RULE: 1,
    Reachability.PACKAGE_PRESENT: 2,
    Reachability.DEPENDENCY_REACHABLE: 3,
    Reachability.IMPORTED: 4,
    Reachability.FUNCTION_REACHABLE: 5,
    Reachability.ATTACKER_CONTROLLED: 6,
}


@dataclass(frozen=True)
class ExternalSourceEvidenceRecord:
    evidence: SourceEvidence
    artifact: str | None = None
    component: str | None = None
    vulnerability: str | None = None
    package_purl: str | None = None


@dataclass
class ExternalSourceEvidenceStore:
    records: list[ExternalSourceEvidenceRecord] = field(default_factory=list)

    def best_for(self, artifact: str, component: Component, vulnerability: VulnerabilityRecord) -> SourceEvidence | None:
        candidates: list[SourceEvidence] = []
        component_names = {component.name.lower(), component.display_name.lower()}
        if component.purl:
            component_names.add(component.purl.lower())
        vuln_ids = {vulnerability.id.lower(), *(alias.lower() for alias in vulnerability.aliases)}
        for record in self.records:
            if record.artifact and record.artifact != artifact:
                continue
            if record.vulnerability and record.vulnerability.lower() not in vuln_ids:
                continue
            if record.package_purl:
                if not component.purl:
                    continue
                if record.package_purl.lower() != component.purl.lower():
                    continue
            if record.component and record.component.lower() not in component_names:
                continue
            if not record.component and not record.package_purl and not record.vulnerability:
                continue
            candidates.append(record.evidence)
        if not candidates:
            return None
        return max(candidates, key=lambda item: (REACHABILITY_STRENGTH[item.reachability], _confidence_strength(item.confidence)))


def _confidence_strength(confidence: Confidence) -> int:
    return {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}[confidence]


def merge_source_evidence(base: SourceEvidence, external: SourceEvidence | None) -> SourceEvidence:
    if external is None:
        return base
    base_key = (REACHABILITY_STRENGTH[base.reachability], _confidence_strength(base.confidence))
    external_key = (REACHABILITY_STRENGTH[external.reachability], _confidence_strength(external.confidence))
    if external_key < base_key:
        return base
    locations = [*external.locations, *base.locations][:8]
    symbols = list(dict.fromkeys([*external.matched_symbols, *base.matched_symbols]))
    dependency_path = external.dependency_path or base.dependency_path
    reason = external.reason
    if base.reason and base.reachability != external.reachability:
        reason = f"{external.reason}; built-in analyzer reported {base.reachability.value}: {base.reason}"
    return SourceEvidence(
        reachability=external.reachability,
        confidence=external.confidence,
        language=external.language if external.language != "unknown" else base.language,
        reason=reason,
        locations=locations,
        matched_symbols=symbols,
        dependency_path=dependency_path,
        evidence_source=external.evidence_source,
    )


def load_external_source_evidence(paths: Iterable[str | Path]) -> ExternalSourceEvidenceStore:
    store = ExternalSourceEvidenceStore()
    for path in paths:
        evidence_path = Path(path)
        text = evidence_path.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
            store.records.extend(_external_records_from_data(data, evidence_path))
        except json.JSONDecodeError:
            for line in text.splitlines():
                if not line.strip():
                    continue
                store.records.extend(_external_records_from_data(json.loads(line), evidence_path))
    return store


def _external_records_from_data(data: Any, path: Path) -> list[ExternalSourceEvidenceRecord]:
    if isinstance(data, dict) and isinstance(data.get("evidence"), list):
        return [_record_from_plain(item, path) for item in data["evidence"] if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [_record_from_finding(item, path) for item in data["findings"] if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        if data.get("version") == "2.1.0" or data.get("$schema"):
            return _records_from_sarif(data, path)
        return [_record_from_semgrep(item, path) for item in data["results"] if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("runs"), list):
        return _records_from_sarif(data, path)
    if isinstance(data, list):
        return [_record_from_plain(item, path) for item in data if isinstance(item, dict)]
    # govulncheck can emit JSON lines. If a caller parsed one line, support it.
    if isinstance(data, dict) and ("finding" in data or "osv" in data):
        record = _record_from_govulncheck(data, path)
        return [record] if record else []
    return []


def _state(value: Any, default: Reachability = Reachability.FUNCTION_REACHABLE) -> Reachability:
    try:
        return Reachability(str(value or default.value))
    except ValueError:
        return default


def _confidence(value: Any, default: Confidence = Confidence.MEDIUM) -> Confidence:
    try:
        return Confidence(str(value or default.value))
    except ValueError:
        return default


def _locations(items: Any, base_path: Path) -> list[SourceLocation]:
    locations: list[SourceLocation] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        raw_path = item.get("path") or item.get("uri") or item.get("file")
        if not raw_path:
            continue
        locations.append(
            SourceLocation(
                path=Path(str(raw_path)),
                line=int(item.get("line") or item.get("startLine") or 1),
                column=int(item.get("column") or item.get("startColumn") or 1),
                snippet=str(item.get("snippet") or ""),
            )
        )
    return locations


def _record_from_plain(item: dict[str, Any], path: Path) -> ExternalSourceEvidenceRecord:
    source = str(item.get("tool") or item.get("source") or path.name)
    evidence = SourceEvidence(
        reachability=_state(item.get("state") or item.get("reachability")),
        confidence=_confidence(item.get("confidence")),
        language=str(item.get("language") or "unknown"),
        reason=str(item.get("reason") or f"external source evidence from {source}"),
        locations=_locations(item.get("locations"), path),
        matched_symbols=[str(symbol) for symbol in item.get("matched_symbols", []) or []],
        dependency_path=[str(part) for part in item.get("dependency_path", []) or []],
        evidence_source=source,
    )
    return ExternalSourceEvidenceRecord(
        evidence=evidence,
        artifact=str(item.get("artifact")) if item.get("artifact") else None,
        component=str(item.get("component") or item.get("package")) if item.get("component") or item.get("package") else None,
        vulnerability=str(item.get("vulnerability") or item.get("vulnerability_id")) if item.get("vulnerability") or item.get("vulnerability_id") else None,
        package_purl=str(item.get("purl") or item.get("package_purl")) if item.get("purl") or item.get("package_purl") else None,
    )


def _record_from_finding(item: dict[str, Any], path: Path) -> ExternalSourceEvidenceRecord:
    source = item.get("source_reachability") if isinstance(item.get("source_reachability"), dict) else {}
    plain = {
        "artifact": item.get("artifact", {}).get("name") if isinstance(item.get("artifact"), dict) else None,
        "component": item.get("component", {}).get("name") if isinstance(item.get("component"), dict) else None,
        "purl": item.get("component", {}).get("purl") if isinstance(item.get("component"), dict) else None,
        "vulnerability": item.get("vulnerability", {}).get("id") if isinstance(item.get("vulnerability"), dict) else None,
        "state": source.get("state"),
        "confidence": source.get("confidence"),
        "language": source.get("language"),
        "reason": source.get("reason"),
        "locations": source.get("locations"),
        "matched_symbols": source.get("matched_symbols"),
        "dependency_path": source.get("dependency_path"),
        "tool": source.get("evidence_source") or "reachability-advisor",
    }
    return _record_from_plain(plain, path)


def _record_from_semgrep(item: dict[str, Any], path: Path) -> ExternalSourceEvidenceRecord:
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    ra = metadata.get("reachability_advisor") if isinstance(metadata.get("reachability_advisor"), dict) else metadata
    start = item.get("start") if isinstance(item.get("start"), dict) else {}
    plain = {
        "artifact": ra.get("artifact"),
        "component": ra.get("component") or ra.get("package"),
        "purl": ra.get("purl") or ra.get("package_purl"),
        "vulnerability": ra.get("vulnerability") or ra.get("vulnerability_id"),
        "state": ra.get("state") or ra.get("reachability") or Reachability.FUNCTION_REACHABLE.value,
        "confidence": ra.get("confidence") or Confidence.MEDIUM.value,
        "language": ra.get("language") or _language_for(Path(str(item.get("path") or ""))),
        "reason": extra.get("message") or f"Semgrep rule {item.get('check_id')}",
        "locations": [{"path": item.get("path"), "line": start.get("line", 1), "column": start.get("col", 1)}],
        "matched_symbols": [str(item.get("check_id"))],
        "tool": "semgrep",
    }
    return _record_from_plain(plain, path)


def _records_from_sarif(data: dict[str, Any], path: Path) -> list[ExternalSourceEvidenceRecord]:
    records: list[ExternalSourceEvidenceRecord] = []
    for run in data.get("runs", []) or []:
        if not isinstance(run, dict):
            continue
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "sarif") if isinstance(run.get("tool"), dict) else "sarif"
        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
            locations = []
            for location in result.get("locations", []) or []:
                physical = location.get("physicalLocation") if isinstance(location, dict) else {}
                artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
                region = physical.get("region", {}) if isinstance(physical, dict) else {}
                locations.append({"path": artifact.get("uri"), "line": region.get("startLine", 1), "column": region.get("startColumn", 1)})
            plain = {
                "artifact": props.get("artifact"),
                "component": props.get("component") or props.get("package"),
                "purl": props.get("purl") or props.get("package_purl"),
                "vulnerability": props.get("vulnerability") or result.get("ruleId"),
                "state": props.get("reachability") or props.get("source_state") or Reachability.FUNCTION_REACHABLE.value,
                "confidence": props.get("confidence") or Confidence.MEDIUM.value,
                "reason": result.get("message", {}).get("text") if isinstance(result.get("message"), dict) else f"SARIF result {result.get('ruleId')}",
                "locations": locations,
                "matched_symbols": [str(result.get("ruleId"))],
                "tool": str(tool_name),
            }
            records.append(_record_from_plain(plain, path))
    return records


def _record_from_govulncheck(item: dict[str, Any], path: Path) -> ExternalSourceEvidenceRecord | None:
    finding = item.get("finding") if isinstance(item.get("finding"), dict) else item
    vuln = finding.get("osv") or finding.get("osv_id") or finding.get("id")
    trace = finding.get("trace") if isinstance(finding.get("trace"), list) else []
    if not vuln:
        return None
    package = None
    locations = []
    for frame in trace:
        if not isinstance(frame, dict):
            continue
        package = frame.get("module") or frame.get("package") or package
        position = frame.get("position") if isinstance(frame.get("position"), dict) else {}
        if position.get("filename"):
            locations.append({"path": position.get("filename"), "line": position.get("line", 1), "column": position.get("column", 1)})
    return _record_from_plain(
        {
            "component": package,
            "vulnerability": vuln,
            "state": Reachability.FUNCTION_REACHABLE.value,
            "confidence": Confidence.HIGH.value,
            "reason": "govulncheck reported a call stack to a vulnerable function",
            "locations": locations,
            "tool": "govulncheck",
            "language": "go",
        },
        path,
    )


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
        )
    if not index.files:
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
        return SourceEvidence(
            reachability=Reachability.UNKNOWN_DUE_TO_NO_RULE,
            confidence=Confidence.LOW,
            language=language,
            reason="component appears in SBOM; no package-specific source rule exists and generic import usage was not observed",
        )

    if not signals:
        language = index.files[0].language if index.files else "unknown"
        dependency_evidence = _dependency_reachable_evidence(component, sbom, index, custom_rules, language)
        if dependency_evidence:
            return dependency_evidence
        return SourceEvidence(
            reachability=Reachability.PACKAGE_PRESENT,
            confidence=Confidence.LOW,
            language=language,
            reason="component appears in SBOM, but source usage was not observed",
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
        )

    if same_function_attacker:
        return SourceEvidence(
            reachability=Reachability.ATTACKER_CONTROLLED,
            confidence=Confidence.HIGH if vulnerability and rules else Confidence.MEDIUM,
            language=language,
            reason=f"{rule_text}; same function contains vulnerable-function hint and attacker-controlled entrypoint/input hint",
            locations=locations,
            matched_symbols=symbols,
        )
    if same_file_function:
        reason = f"{rule_text}; same source file contains import and vulnerable-function usage hints"
        if has_attacker_any:
            reason += "; attacker entrypoint was observed elsewhere but no same-function or bounded call-path link was inferred"
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
    dependency_evidence = _dependency_reachable_evidence(component, sbom, index, custom_rules, language)
    if dependency_evidence:
        return dependency_evidence
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


def source_coverage_report(
    sboms: list[SbomDocument],
    source_roots: dict[str, Path],
    indexes: dict[str, SourceIndex],
    findings: list[Any],
    external_evidence: ExternalSourceEvidenceStore | None = None,
) -> dict[str, Any]:
    by_artifact: dict[str, list[Any]] = {}
    for finding in findings:
        by_artifact.setdefault(finding.artifact.name, []).append(finding)
    artifacts: list[dict[str, Any]] = []
    totals = {
        "artifact_count": len(sboms),
        "artifacts_with_source_root": 0,
        "files_scanned": 0,
        "files_skipped": 0,
        "findings_analyzed": len(findings),
        "findings_with_external_evidence": 0,
        "findings_with_dependency_graph_path": 0,
    }
    state_counts: dict[str, int] = {}
    for sbom in sboms:
        index = indexes.get(sbom.artifact.name, SourceIndex(root=source_roots.get(sbom.artifact.name)))
        artifact_findings = by_artifact.get(sbom.artifact.name, [])
        if sbom.artifact.name in source_roots:
            totals["artifacts_with_source_root"] += 1
        totals["files_scanned"] += len(index.files)
        totals["files_skipped"] += len(index.skipped_files)
        artifact_states: dict[str, int] = {}
        for finding in artifact_findings:
            state = finding.source.reachability.value
            artifact_states[state] = artifact_states.get(state, 0) + 1
            state_counts[state] = state_counts.get(state, 0) + 1
            if finding.source.evidence_source != "builtin":
                totals["findings_with_external_evidence"] += 1
            if finding.source.dependency_path:
                totals["findings_with_dependency_graph_path"] += 1
        artifacts.append(
            {
                "artifact": sbom.artifact.name,
                "source_root": str(source_roots.get(sbom.artifact.name)) if sbom.artifact.name in source_roots else None,
                "source_root_exists": bool(index.root and index.root.exists() and index.root.is_dir()),
                "files_scanned": len(index.files),
                "files_skipped": len(index.skipped_files),
                "languages": index.languages,
                "findings_analyzed": len(artifact_findings),
                "states": artifact_states,
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
    totals["external_evidence_records"] = len(external_evidence.records) if external_evidence else 0
    return {
        "schema_version": "1.0",
        "summary": totals,
        "artifacts": artifacts,
        "notes": [
            "Source evidence coverage counts findings with dependency graph, import, vulnerable API, or request-controlled evidence.",
            "No-rule findings are rule coverage gaps; package-present findings are evidence gaps.",
            "External evidence must match a component/package, package URL, or vulnerability selector; artifact only narrows a selector match.",
        ],
    }


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
