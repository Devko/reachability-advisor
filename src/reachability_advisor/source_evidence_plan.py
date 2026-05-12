"""Source evidence workflow planning.

The scanner can import Semgrep, CodeQL/SARIF, govulncheck, and native evidence.
This module turns that contract into concrete local commands that CI jobs can
run before ``reachability-advisor scan``. It does not execute external tools.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SourceEvidenceCommand:
    tool: str
    purpose: str
    command: str
    output: str
    required_for: str = "production"

    def to_json(self) -> dict[str, str]:
        return {
            "tool": self.tool,
            "purpose": self.purpose,
            "command": self.command,
            "output": self.output,
            "required_for": self.required_for,
        }


SOURCE_EVIDENCE_PROFILES: dict[str, dict[str, Any]] = {
    "generic": {
        "ecosystems": ["unknown"],
        "tools": ["semgrep"],
        "critical_package_families": ["project-specific package rules"],
        "minimum_release_gate": "critical findings need package, purl, or vulnerability selectors",
    },
    "javascript-typescript": {
        "ecosystems": ["npm", "pnpm", "yarn"],
        "tools": ["semgrep", "codeql"],
        "critical_package_families": ["http clients", "template engines", "jwt", "yaml/xml parsers", "archive extraction", "web handlers"],
        "minimum_release_gate": "critical findings need Semgrep/CodeQL evidence with package, purl, or vulnerability selectors",
    },
    "java-kotlin": {
        "ecosystems": ["maven", "gradle"],
        "tools": ["semgrep", "codeql"],
        "critical_package_families": ["logging", "deserialization", "yaml/xml parsers", "jwt", "web handlers"],
        "minimum_release_gate": "critical findings need Semgrep/CodeQL evidence with package, purl, or vulnerability selectors",
    },
    "python": {
        "ecosystems": ["pypi", "poetry", "pip"],
        "tools": ["semgrep", "codeql"],
        "critical_package_families": ["http clients", "template engines", "yaml/xml parsers", "jwt", "web handlers"],
        "minimum_release_gate": "critical findings need Semgrep/CodeQL evidence with package, purl, or vulnerability selectors",
    },
    "go": {
        "ecosystems": ["go", "golang"],
        "tools": ["govulncheck", "semgrep", "codeql"],
        "critical_package_families": ["govulncheck vulnerable calls", "jwt", "yaml/xml parsers", "web handlers"],
        "minimum_release_gate": "critical findings need govulncheck or CodeQL/Semgrep call-path evidence",
    },
}


def recommend_source_evidence_commands(
    *,
    source_root: str = ".",
    output_dir: str = "reachability",
    language: str | None = None,
    package_manager: str | None = None,
) -> list[SourceEvidenceCommand]:
    """Return concrete commands for external source evidence generation."""

    out = output_dir.rstrip("/\\") or "reachability"
    src = source_root or "."
    language_key = (language or "").lower()
    package_key = (package_manager or "").lower()
    commands = [
        SourceEvidenceCommand(
            tool="reachability-advisor",
            purpose="export Semgrep starter rules with reachability metadata",
            command=f"reachability-advisor export-semgrep-rules --out {out}/semgrep-reachability.yml",
            output=f"{out}/semgrep-reachability.yml",
            required_for="setup",
        ),
        SourceEvidenceCommand(
            tool="semgrep",
            purpose="produce package/vulnerability-selectable source evidence",
            command=f"semgrep scan --config {out}/semgrep-reachability.yml --json --output {out}/semgrep-results.json {src}",
            output=f"{out}/semgrep-results.json",
        ),
    ]
    if language_key in {"javascript", "typescript", "java", "python", "go", "golang"} or package_key in {"npm", "pnpm", "yarn", "maven", "gradle", "pypi", "poetry", "pip", "go", "golang"}:
        codeql_language = _codeql_language(language_key, package_key)
        commands.extend(
            [
                SourceEvidenceCommand(
                    tool="codeql",
                    purpose="create a CodeQL database for data-flow analysis",
                    command=f"codeql database create {out}/codeql-db --language={codeql_language} --source-root {src}",
                    output=f"{out}/codeql-db",
                    required_for="setup",
                ),
                SourceEvidenceCommand(
                    tool="codeql",
                    purpose="export CodeQL data-flow paths as SARIF",
                    command=f"codeql database analyze {out}/codeql-db {_codeql_query_suite(codeql_language)} --format=sarif-latest --output {out}/codeql.sarif",
                    output=f"{out}/codeql.sarif",
                ),
            ]
        )
    if language_key in {"go", "golang"} or package_key in {"go", "golang"}:
        commands.append(
            SourceEvidenceCommand(
                tool="govulncheck",
                purpose="produce Go vulnerable-call evidence",
                command=f"govulncheck -json {src}/... > {out}/govulncheck.jsonl",
                output=f"{out}/govulncheck.jsonl",
            )
        )
    return commands


def source_evidence_profile(*, language: str | None = None, package_manager: str | None = None) -> dict[str, Any]:
    codeql_language = _codeql_language((language or "").lower(), (package_manager or "").lower())
    profile = SOURCE_EVIDENCE_PROFILES.get(codeql_language, SOURCE_EVIDENCE_PROFILES["generic"])
    return {"name": codeql_language, **profile}


def render_source_evidence_plan_markdown(commands: list[SourceEvidenceCommand]) -> str:
    evidence_outputs = [item.output for item in commands if item.required_for == "production" and item.tool != "reachability-advisor"]
    lines = [
        "# Source Evidence Plan",
        "",
        "Generate these artifacts before `reachability-advisor scan --analysis-profile production`.",
        "Pass generated JSON/SARIF/JSONL files through repeated `--source-evidence-in` flags.",
        "Release gates require critical findings to be covered by external analyzer evidence.",
        "",
    ]
    for item in commands:
        lines.extend(
            [
                f"## {item.tool}",
                "",
                item.purpose,
                "",
                "```bash",
                item.command,
                "```",
                "",
                f"Output: `{item.output}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Scan handoff",
            "",
            "```bash",
            "reachability-advisor scan \\",
            "  --analysis-profile production \\",
        ]
    )
    lines.extend(f"  --source-evidence-in {output} \\" for output in evidence_outputs)
    lines.extend(
        [
            "  --source-coverage-out reachability/source-coverage.json \\",
            "  ...",
            "```",
            "",
            "Production gates reject unscoped external evidence and dependency-only source evidence on critical findings.",
            "",
        ]
    )
    return "\n".join(lines)


def write_source_evidence_plan_json(path: str | Path, commands: list[SourceEvidenceCommand]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "kind": "reachability-advisor-source-evidence-plan",
        "profiles": SOURCE_EVIDENCE_PROFILES,
        "commands": [command.to_json() for command in commands],
    }
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _codeql_language(language: str, package_manager: str) -> str:
    if language in {"javascript", "typescript"} or package_manager in {"npm", "pnpm", "yarn"}:
        return "javascript-typescript"
    if language in {"go", "golang"} or package_manager in {"go", "golang"}:
        return "go"
    if language in {"java"} or package_manager in {"maven", "gradle"}:
        return "java-kotlin"
    if language == "python" or package_manager in {"pypi", "poetry", "pip"}:
        return "python"
    return "generic"


def _codeql_query_suite(language: str) -> str:
    return {
        "javascript-typescript": "codeql/javascript-queries:Security-extended",
        "go": "codeql/go-queries:Security-extended",
        "java-kotlin": "codeql/java-queries:Security-extended",
        "python": "codeql/python-queries:Security-extended",
    }.get(language, "codeql/javascript-queries:Security-extended")


__all__ = [
    "SourceEvidenceCommand",
    "SOURCE_EVIDENCE_PROFILES",
    "recommend_source_evidence_commands",
    "render_source_evidence_plan_markdown",
    "source_evidence_profile",
    "write_source_evidence_plan_json",
]
