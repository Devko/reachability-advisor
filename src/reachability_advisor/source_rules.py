"""Reachability rule model, built-in rules, and custom rule loading."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .input_limits import read_text_limited
from .models import Component, VulnerabilityRecord
from .purl import ecosystem_from_component, parse_purl


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
    data = json.loads(read_text_limited(rule_path, "reachability rules"))
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


__all__ = ["BUILTIN_RULES", "ReachabilityRule", "load_reachability_rules"]
