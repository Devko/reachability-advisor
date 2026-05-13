"""Maintained Semgrep and CodeQL assets for package-family coverage."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .source_query_families import PackageFamilyQueryPack


@dataclass(frozen=True)
class MaintainedSemgrepRule:
    id: str
    family: str
    languages: tuple[str, ...]
    message: str
    patterns: tuple[str, ...]
    packages: tuple[str, ...]
    state: str = "function_reachable"
    confidence: str = "medium"


SEMGREP_QUERY_RULES: dict[str, tuple[MaintainedSemgrepRule, ...]] = {
    "http-client": (
        MaintainedSemgrepRule("reachability.http-client.js.outbound-request", "http-client", ("javascript", "typescript"), "HTTP client call that can become SSRF evidence", (r"\b(axios|request|got|fetch)\s*(\.|\()", r"\b(req|request|ctx)\."), ("axios", "request", "got", "node-fetch"), "attacker_controlled", "high"),
        MaintainedSemgrepRule("reachability.http-client.python.requests", "http-client", ("python",), "Python requests/httpx outbound request", (r"\b(requests|httpx|aiohttp)\.", r"\b(request|params|query|args)\b"), ("requests", "httpx", "aiohttp"), "attacker_controlled", "high"),
        MaintainedSemgrepRule("reachability.http-client.java.client", "http-client", ("java",), "Java HTTP client or Spring Web outbound request", (r"\b(RestTemplate|WebClient|HttpClient|OkHttpClient)\b", r"\b(request|param|body|url)\b"), ("spring-web", "httpclient", "okhttp"), "attacker_controlled", "high"),
        MaintainedSemgrepRule("reachability.http-client.go.net-http", "http-client", ("go",), "Go net/http outbound request", (r"\bhttp\.(Get|Post|NewRequest|DefaultClient)\b", r"\br\.(URL|Form|Header|Body)\b"), ("net/http",), "attacker_controlled", "high"),
    ),
    "logging": (
        MaintainedSemgrepRule("reachability.logging.java.log4j", "logging", ("java",), "Log4j logger receives request-controlled input", (r"\bLogManager\.getLogger\b|org\.apache\.logging\.log4j", r"\blogger\.(info|warn|error|fatal|log)\s*\(", r"(@RequestParam|@RequestBody|HttpServletRequest|\brequest\b)"), ("log4j-core",), "attacker_controlled", "high"),
        MaintainedSemgrepRule("reachability.logging.js.logger", "logging", ("javascript", "typescript"), "Node logger receives request input", (r"\b(winston|pino|logger)\.", r"\b(req|request)\."), ("winston", "pino"), "attacker_controlled", "medium"),
    ),
    "deserialization": (
        MaintainedSemgrepRule("reachability.deserialization.python.yaml", "deserialization", ("python",), "Unsafe YAML load from request input", (r"\byaml\.load\s*\(", r"\b(request|body|data|args|params)\b"), ("pyyaml",), "attacker_controlled", "high"),
        MaintainedSemgrepRule("reachability.deserialization.java.jackson", "deserialization", ("java",), "Jackson or SnakeYAML deserialization", (r"\b(ObjectMapper|Yaml)\b", r"\.(readValue|load|loadAs)\s*\(", r"(@RequestBody|HttpServletRequest|\brequest\b)"), ("jackson-databind", "snakeyaml"), "attacker_controlled", "high"),
        MaintainedSemgrepRule("reachability.deserialization.js.yaml", "deserialization", ("javascript", "typescript"), "JavaScript YAML or serialization parse sink", (r"\b(jsyaml|yaml|serialize)\.", r"\b(load|parse|deserialize)\s*\(", r"\b(req|request)\."), ("js-yaml", "serialize-javascript"), "attacker_controlled", "high"),
        MaintainedSemgrepRule("reachability.deserialization.go.yaml", "deserialization", ("go",), "Go YAML/JSON unmarshal from request input", (r"\b(yaml|json)\.Unmarshal\s*\(", r"\br\.(Body|Form|URL)\b"), ("gopkg.in/yaml.v3", "encoding/json"), "attacker_controlled", "medium"),
    ),
    "template-engine": (
        MaintainedSemgrepRule("reachability.template.js.render", "template-engine", ("javascript", "typescript"), "Template render with request-controlled template or context", (r"\b(ejs|pug|handlebars|nunjucks)\.", r"\b(render|compile)\s*\(", r"\b(req|request)\."), ("ejs", "pug", "handlebars", "nunjucks"), "attacker_controlled", "high"),
        MaintainedSemgrepRule("reachability.template.python.render", "template-engine", ("python",), "Python template render with request-controlled input", (r"\b(render_template_string|Template)\b", r"\b(request|args|form|data)\b"), ("jinja2", "django"), "attacker_controlled", "high"),
        MaintainedSemgrepRule("reachability.template.java.render", "template-engine", ("java",), "Java template engine render sink", (r"\b(TemplateEngine|FreeMarker|Thymeleaf|Template)\b", r"\.(process|render)\s*\(", r"(@RequestParam|@RequestBody|\brequest\b)"), ("thymeleaf", "freemarker"), "attacker_controlled", "medium"),
    ),
    "archive-file-io": (
        MaintainedSemgrepRule("reachability.archive.js.upload-path", "archive-file-io", ("javascript", "typescript"), "Upload, archive, or path construction from request input", (r"\b(multer|adm-zip|tar|path)\b", r"\b(req|request)\."), ("multer", "adm-zip", "tar"), "attacker_controlled", "high"),
        MaintainedSemgrepRule("reachability.archive.java.zip-slip", "archive-file-io", ("java",), "Archive extraction or file path from request input", (r"\b(ZipInputStream|ZipFile|File|Paths)\b", r"\b(getName|resolve|normalize)\s*\(", r"(\brequest\b|MultipartFile|@RequestParam)"), ("commons-compress", "commons-fileupload"), "attacker_controlled", "high"),
        MaintainedSemgrepRule("reachability.archive.python.path", "archive-file-io", ("python",), "Python file path or upload sink from request input", (r"\b(os\.path|pathlib|zipfile|tarfile)\b", r"\b(request|filename|args|form)\b"), ("werkzeug", "python-multipart"), "attacker_controlled", "medium"),
        MaintainedSemgrepRule("reachability.archive.go.path", "archive-file-io", ("go",), "Go archive or path sink from request input", (r"\b(filepath|zip|tar)\.", r"\br\.(URL|Form|MultipartForm)\b"), ("archive/zip", "path/filepath"), "attacker_controlled", "medium"),
    ),
    "auth-token-crypto": (
        MaintainedSemgrepRule("reachability.auth.js.jwt", "auth-token-crypto", ("javascript", "typescript"), "JWT parse or verification sink", (r"\b(jwt|jose)\.", r"\b(verify|decode|sign)\s*\(", r"\b(req|request|authorization|token)\b"), ("jsonwebtoken", "jose"), "function_reachable", "medium"),
        MaintainedSemgrepRule("reachability.auth.python.jwt", "auth-token-crypto", ("python",), "Python JWT parse or verification sink", (r"\b(jwt|jose)\.", r"\b(decode|encode)\s*\(", r"\b(request|authorization|token)\b"), ("pyjwt", "python-jose"), "function_reachable", "medium"),
        MaintainedSemgrepRule("reachability.auth.java.jwt", "auth-token-crypto", ("java",), "Java JWT parser sink", (r"\bJwts\.parser", r"\b(parseClaimsJws|parse)\s*\(", r"\b(Authorization|RequestHeader|request)\b"), ("jjwt-api",), "function_reachable", "medium"),
        MaintainedSemgrepRule("reachability.auth.go.jwt", "auth-token-crypto", ("go",), "Go JWT parser sink", (r"\bjwt\.Parse", r"\br\.(Header|URL|Form)\b"), ("github.com/golang-jwt/jwt/v4",), "function_reachable", "medium"),
    ),
    "web-handler": (
        MaintainedSemgrepRule("reachability.web.js.handler", "web-handler", ("javascript", "typescript"), "Node request handler source", (r"\b(app|router)\.(get|post|put|delete|patch)\s*\(", r"\b(req|res|request|response)\b"), ("express", "koa", "fastify"), "function_reachable", "medium"),
        MaintainedSemgrepRule("reachability.web.python.handler", "web-handler", ("python",), "Python web handler source", (r"@(app|router)\.(get|post|put|delete|patch)\s*\(", r"\b(Request|request|FastAPI|Flask)\b"), ("fastapi", "flask", "django"), "function_reachable", "medium"),
        MaintainedSemgrepRule("reachability.web.java.handler", "web-handler", ("java",), "Java Spring web handler source", (r"@(Get|Post|Put|Delete|Patch|Request)Mapping", r"(@RequestParam|@RequestBody|HttpServletRequest)"), ("spring-web",), "function_reachable", "medium"),
        MaintainedSemgrepRule("reachability.web.go.handler", "web-handler", ("go",), "Go HTTP handler source", (r"\bhttp\.HandleFunc\s*\(", r"\bhttp\.ResponseWriter\b", r"\*http\.Request\b"), ("net/http", "github.com/gin-gonic/gin"), "function_reachable", "medium"),
    ),
}


def semgrep_query_pack_yaml(query_pack: PackageFamilyQueryPack) -> str:
    rules = SEMGREP_QUERY_RULES.get(query_pack.id, ())
    lines = ["rules:"]
    for rule in rules:
        lines.extend(
            [
                f"  - id: {rule.id}",
                "    severity: INFO",
                f"    languages: [{', '.join(rule.languages)}]",
                f"    message: {_yaml_string(rule.message)}",
                "    metadata:",
                "      reachability_advisor:",
                f"        query_families: [{_yaml_string(rule.family)}]",
                f"        state: {_yaml_string(rule.state)}",
                f"        confidence: {_yaml_string(rule.confidence)}",
                f"        packages: [{', '.join(_yaml_string(package) for package in rule.packages)}]",
                "    patterns:",
            ]
        )
        lines.extend(f"      - pattern-regex: {_yaml_string(pattern)}" for pattern in rule.patterns)
    return "\n".join(lines) + "\n"


def codeql_query_pack_suite(query_pack: PackageFamilyQueryPack) -> str:
    lines = [
        f"# Reachability Advisor CodeQL package-family suite: {query_pack.id}",
        "# The suite runs upstream CodeQL security queries that produce SARIF/code-flow evidence.",
    ]
    for query_id in query_pack.codeql_queries:
        lines.extend(["- include:", f"    id: {query_id}"])
    return "\n".join(lines) + "\n"


def codeql_query_pack_metadata(query_pack: PackageFamilyQueryPack) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "kind": "reachability-advisor-codeql-query-pack",
        "query_family": query_pack.id,
        "title": query_pack.title,
        "selectors": list(query_pack.package_selectors),
        "upstream_codeql_queries": list(query_pack.codeql_queries),
        "evidence_contract": {
            "required_metadata": ["component or purl or vulnerability", "query_family"],
            "query_family": query_pack.id,
        },
    }


def query_pack_sample_coverage(expectations: dict[str, Any], sample_root: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    total = 0
    covered = 0
    for sample in expectations.get("samples", []):
        if not isinstance(sample, dict):
            continue
        sample_path = sample_root / str(sample.get("path") or "")
        source_text = _read_sample_text(sample_path)
        for component in sample.get("components", []) if isinstance(sample.get("components"), list) else []:
            if not isinstance(component, dict):
                continue
            for family in component.get("expected_query_families", []) if isinstance(component.get("expected_query_families"), list) else []:
                total += 1
                family_id = str(family)
                matched_rules = _matching_rules(family_id, source_text, str(component.get("name") or ""))
                is_covered = bool(matched_rules)
                covered += 1 if is_covered else 0
                rows.append(
                    {
                        "sample": sample.get("id"),
                        "component": component.get("name"),
                        "query_family": family_id,
                        "covered": is_covered,
                        "matched_rules": matched_rules,
                    }
                )
    return {
        "schema_version": "1.0",
        "summary": {
            "expected": total,
            "covered": covered,
            "coverage": round(covered / total, 4) if total else 1.0,
        },
        "samples": rows,
    }


def _matching_rules(family_id: str, source_text: str, component: str) -> list[str]:
    matched: list[str] = []
    normalized_component = component.lower()
    for rule in SEMGREP_QUERY_RULES.get(family_id, ()):
        if normalized_component and normalized_component not in {package.lower() for package in rule.packages}:
            continue
        if all(re.search(pattern, source_text, flags=re.IGNORECASE | re.MULTILINE) for pattern in rule.patterns):
            matched.append(rule.id)
    return matched


def _read_sample_text(sample_path: Path) -> str:
    chunks: list[str] = []
    for path in sample_path.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".js", ".ts", ".py", ".java", ".go", ".json", ".xml", ".txt", ".mod"}:
            chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(chunks)


def _yaml_string(value: str) -> str:
    return json.dumps(value)


__all__ = [
    "SEMGREP_QUERY_RULES",
    "codeql_query_pack_metadata",
    "codeql_query_pack_suite",
    "query_pack_sample_coverage",
    "semgrep_query_pack_yaml",
]
