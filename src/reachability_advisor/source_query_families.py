"""Package-family source query packs.

Release source evidence is only useful when the external analyzer ran queries
that are relevant to the risky package. This module owns the mapping from SBOM
components to maintained query families so coverage gates can distinguish
generic external evidence from package-family evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Component
from .purl import ecosystem_from_component, parse_purl


@dataclass(frozen=True)
class PackageFamilyQueryPack:
    id: str
    title: str
    ecosystems: tuple[str, ...]
    package_selectors: tuple[str, ...]
    tools: tuple[str, ...]
    semgrep_tags: tuple[str, ...]
    codeql_queries: tuple[str, ...]
    expected_samples: tuple[str, ...]
    description: str

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "ecosystems": list(self.ecosystems),
            "package_selectors": list(self.package_selectors),
            "tools": list(self.tools),
            "semgrep_tags": list(self.semgrep_tags),
            "codeql_queries": list(self.codeql_queries),
            "expected_samples": list(self.expected_samples),
            "description": self.description,
        }


QUERY_PACKS: tuple[PackageFamilyQueryPack, ...] = (
    PackageFamilyQueryPack(
        id="http-client",
        title="HTTP client and SSRF sinks",
        ecosystems=("npm", "pypi", "maven", "go"),
        package_selectors=(
            "axios",
            "got",
            "node-fetch",
            "request",
            "requests",
            "urllib3",
            "aiohttp",
            "httpx",
            "httpclient",
            "apache-httpclient",
            "okhttp",
            "spring-web",
            "net/http",
            "github.com/go-resty/resty/v2",
        ),
        tools=("semgrep", "codeql", "govulncheck"),
        semgrep_tags=("http-client", "ssrf", "request-sink"),
        codeql_queries=("js/request-forgery", "py/request-forgery", "java/ssrf", "go/request-forgery"),
        expected_samples=("npm-express-ssrf", "python-fastapi-ssrf", "go-http-handler"),
        description="Queries must prove outbound request construction or a call path from request input to an HTTP client.",
    ),
    PackageFamilyQueryPack(
        id="logging",
        title="Logging sinks",
        ecosystems=("maven", "npm"),
        package_selectors=(
            "log4j-core",
            "org.apache.logging.log4j/log4j-core",
            "logback-classic",
            "ch.qos.logback/logback-classic",
            "winston",
            "pino",
        ),
        tools=("semgrep", "codeql"),
        semgrep_tags=("logging", "log-injection", "jndi"),
        codeql_queries=("java/log-injection", "java/jndi-injection"),
        expected_samples=("maven-spring-log4shell",),
        description="Queries must cover logging APIs and request-controlled message or lookup paths.",
    ),
    PackageFamilyQueryPack(
        id="deserialization",
        title="Deserialization and parser sinks",
        ecosystems=("npm", "pypi", "maven", "go"),
        package_selectors=(
            "jackson-databind",
            "com.fasterxml.jackson.core/jackson-databind",
            "snakeyaml",
            "org.yaml/snakeyaml",
            "pyyaml",
            "yaml",
            "js-yaml",
            "serialize-javascript",
            "encoding/json",
            "gopkg.in/yaml.v3",
        ),
        tools=("semgrep", "codeql", "govulncheck"),
        semgrep_tags=("deserialization", "yaml", "json-parser"),
        codeql_queries=("java/unsafe-deserialization", "py/unsafe-deserialization", "js/unsafe-deserialization", "go/unsafe-unmarshal"),
        expected_samples=("python-yaml-loader", "go-yaml-loader"),
        description="Queries must cover parser construction and untrusted data reaching unsafe load or unmarshal APIs.",
    ),
    PackageFamilyQueryPack(
        id="template-engine",
        title="Template and expression sinks",
        ecosystems=("npm", "pypi", "maven"),
        package_selectors=(
            "ejs",
            "handlebars",
            "pug",
            "nunjucks",
            "jinja2",
            "django",
            "thymeleaf",
            "org.thymeleaf/thymeleaf",
            "freemarker",
        ),
        tools=("semgrep", "codeql"),
        semgrep_tags=("template", "ssti", "expression-eval"),
        codeql_queries=("js/template-injection", "py/template-injection", "java/template-injection"),
        expected_samples=("npm-template-injection", "python-jinja-template"),
        description="Queries must cover attacker-controlled template names, templates, or expression contexts.",
    ),
    PackageFamilyQueryPack(
        id="archive-file-io",
        title="Archive, upload, and path traversal sinks",
        ecosystems=("npm", "pypi", "maven", "go"),
        package_selectors=(
            "multer",
            "formidable",
            "adm-zip",
            "tar",
            "commons-fileupload",
            "commons-compress",
            "org.apache.commons/commons-compress",
            "werkzeug",
            "python-multipart",
            "archive/zip",
            "path/filepath",
        ),
        tools=("semgrep", "codeql", "govulncheck"),
        semgrep_tags=("file-upload", "archive", "path-traversal"),
        codeql_queries=("js/path-injection", "py/path-injection", "java/zipslip", "go/path-injection"),
        expected_samples=("npm-upload-path", "maven-zip-slip"),
        description="Queries must cover archive extraction, upload handling, and untrusted path construction.",
    ),
    PackageFamilyQueryPack(
        id="auth-token-crypto",
        title="Token and crypto verification sinks",
        ecosystems=("npm", "pypi", "maven", "go"),
        package_selectors=(
            "jsonwebtoken",
            "jose",
            "pyjwt",
            "python-jose",
            "jjwt-api",
            "io.jsonwebtoken/jjwt-api",
            "github.com/golang-jwt/jwt/v4",
            "golang.org/x/crypto",
        ),
        tools=("semgrep", "codeql", "govulncheck"),
        semgrep_tags=("jwt", "crypto", "token-verification"),
        codeql_queries=("js/jwt-missing-verification", "py/jwt-missing-verification", "java/jwt-missing-verification", "go/jwt"),
        expected_samples=("go-jwt-verification",),
        description="Queries must cover token parsing, signature validation, and weak cryptographic verification paths.",
    ),
    PackageFamilyQueryPack(
        id="web-handler",
        title="Web handlers and request input",
        ecosystems=("npm", "pypi", "maven", "go"),
        package_selectors=(
            "express",
            "koa",
            "fastify",
            "flask",
            "django",
            "fastapi",
            "spring-web",
            "org.springframework/spring-web",
            "github.com/gin-gonic/gin",
            "net/http",
        ),
        tools=("semgrep", "codeql", "govulncheck"),
        semgrep_tags=("web-handler", "request-source"),
        codeql_queries=("js/remote-flow-source", "py/remote-flow-source", "java/remote-flow-source", "go/remote-flow-source"),
        expected_samples=("npm-express-ssrf", "python-fastapi-ssrf", "go-http-handler"),
        description="Queries must identify request handlers and request-controlled data sources for package-specific sinks.",
    ),
)

QUERY_PACKS_BY_ID: dict[str, PackageFamilyQueryPack] = {pack.id: pack for pack in QUERY_PACKS}

PROVEN_QUERY_FAMILIES: tuple[str, ...] = (
    "archive-file-io",
    "auth-token-crypto",
    "deserialization",
    "http-client",
    "logging",
    "template-engine",
    "web-handler",
)


def query_family_ids_for_component(component: Component) -> tuple[str, ...]:
    """Return maintained query-family IDs relevant to a component."""

    ecosystem = ecosystem_from_component(component.purl, component.name)
    names = _component_names(component)
    matches = [
        pack.id
        for pack in QUERY_PACKS
        if ecosystem in pack.ecosystems and names.intersection({_normalize_package_name(selector) for selector in pack.package_selectors})
    ]
    return tuple(sorted(set(matches)))


def query_family_ids_for_rule(ecosystem: str, package_name: str) -> tuple[str, ...]:
    names = {_normalize_package_name(package_name)}
    return tuple(
        sorted(
            pack.id
            for pack in QUERY_PACKS
            if ecosystem in pack.ecosystems and names.intersection({_normalize_package_name(selector) for selector in pack.package_selectors})
        )
    )


def normalize_query_family_ids(values: Any) -> tuple[str, ...]:
    """Normalize user/tool supplied query-family metadata."""

    if values in (None, ""):
        return ()
    raw_values: list[Any] = list(values) if isinstance(values, (list, tuple, set)) else [values]
    normalized = []
    for value in raw_values:
        for part in str(value).replace(";", ",").split(","):
            family = part.strip().lower().replace("_", "-")
            if family:
                normalized.append(family)
    return tuple(sorted(set(normalized)))


def proven_query_family_ids() -> tuple[str, ...]:
    """Return package families whose maintained queries have checked-in true-positive samples."""

    return PROVEN_QUERY_FAMILIES


def query_family_is_proven(family_id: str) -> bool:
    return family_id.lower().replace("_", "-") in PROVEN_QUERY_FAMILIES


def _component_names(component: Component) -> set[str]:
    names = {component.name, component.display_name}
    parsed = parse_purl(component.purl)
    if parsed:
        if parsed.name:
            names.add(parsed.name)
        if parsed.namespace and parsed.name:
            names.add(f"{parsed.namespace}/{parsed.name}")
    if component.group:
        names.add(f"{component.group}/{component.name}")
    return {_normalize_package_name(name) for name in names if name}


def _normalize_package_name(value: str) -> str:
    return value.strip().lower().replace("_", "-").replace("\\", "/")


__all__ = [
    "QUERY_PACKS",
    "QUERY_PACKS_BY_ID",
    "PackageFamilyQueryPack",
    "PROVEN_QUERY_FAMILIES",
    "normalize_query_family_ids",
    "proven_query_family_ids",
    "query_family_is_proven",
    "query_family_ids_for_component",
    "query_family_ids_for_rule",
]
