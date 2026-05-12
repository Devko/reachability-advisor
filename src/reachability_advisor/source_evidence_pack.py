"""Maintained source evidence pack writer.

The source evidence plan tells users which tools to run. This module writes the
versioned assets those tools should consume: Semgrep rules, CodeQL suite
metadata, govulncheck configuration notes, and a manifest with release-gate
coverage expectations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .source import BUILTIN_RULES, semgrep_rules_yaml
from .source_evidence_plan import source_evidence_profile

PACK_SCHEMA_VERSION = "1.0"
PACK_VERSION = "2026-05-12"


@dataclass(frozen=True)
class SourceEvidencePack:
    root: Path
    profile: dict[str, Any]
    files: tuple[Path, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": PACK_SCHEMA_VERSION,
            "kind": "reachability-advisor-source-evidence-pack",
            "version": PACK_VERSION,
            "root": str(self.root),
            "profile": self.profile,
            "files": [str(path) for path in self.files],
            "release_gate": {
                "requires_external_evidence": True,
                "critical_external_evidence_coverage": 1.0,
                "rejects_dependency_only_critical_source": True,
                "selector_contract": "artifact plus package URL, component, or vulnerability selector",
            },
        }


def write_source_evidence_pack(
    output_dir: str | Path,
    *,
    language: str | None = None,
    package_manager: str | None = None,
) -> SourceEvidencePack:
    """Write maintained source evidence assets and return their manifest."""

    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    profile = source_evidence_profile(language=language, package_manager=package_manager)
    files: list[Path] = []

    semgrep_path = root / "semgrep-reachability.yml"
    semgrep_path.write_text(semgrep_rules_yaml(BUILTIN_RULES), encoding="utf-8")
    files.append(semgrep_path)

    codeql_dir = root / "codeql"
    codeql_dir.mkdir(exist_ok=True)
    codeql_suite = codeql_dir / "reachability-suite.qls"
    codeql_suite.write_text(_codeql_suite(profile["name"]), encoding="utf-8")
    files.append(codeql_suite)
    codeql_readme = codeql_dir / "README.md"
    codeql_readme.write_text(_codeql_readme(profile), encoding="utf-8")
    files.append(codeql_readme)

    govuln_dir = root / "govulncheck"
    govuln_dir.mkdir(exist_ok=True)
    govuln_config = govuln_dir / "reachability-govulncheck.json"
    govuln_config.write_text(json.dumps(_govulncheck_profile(profile), indent=2), encoding="utf-8")
    files.append(govuln_config)

    manifest = SourceEvidencePack(root=root, profile=profile, files=tuple(files))
    manifest_path = root / "source-evidence-pack.json"
    manifest_path.write_text(json.dumps(manifest.to_json(), indent=2), encoding="utf-8")
    files.append(manifest_path)
    return SourceEvidencePack(root=root, profile=profile, files=tuple(files))


def _codeql_suite(profile_name: str) -> str:
    suite = {
        "javascript-typescript": "codeql/javascript-queries:Security-extended",
        "go": "codeql/go-queries:Security-extended",
        "java-kotlin": "codeql/java-queries:Security-extended",
        "python": "codeql/python-queries:Security-extended",
    }.get(profile_name, "codeql/javascript-queries:Security-extended")
    return "\n".join(
        [
            "# Reachability Advisor CodeQL suite",
            "# Uses the upstream Security-extended suite and imports SARIF paths as external evidence.",
            f"- queries: {suite}",
            "",
        ]
    )


def _codeql_readme(profile: dict[str, Any]) -> str:
    families = ", ".join(str(item) for item in profile.get("critical_package_families", []))
    return "\n".join(
        [
            "# Reachability Advisor CodeQL Pack",
            "",
            f"Profile: `{profile['name']}`",
            "",
            f"Critical package families: {families or 'project-specific'}",
            "",
            "Run CodeQL with `reachability-suite.qls` and pass the SARIF output to",
            "`reachability-advisor scan --source-evidence-in`.",
            "",
        ]
    )


def _govulncheck_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": PACK_SCHEMA_VERSION,
        "tool": "govulncheck",
        "enabled": "govulncheck" in profile.get("tools", []),
        "command": "govulncheck -json ./... > reachability/govulncheck.jsonl",
        "selector_contract": "govulncheck vulnerable call stacks are matched by module/package and vulnerability id",
        "minimum_release_gate": profile.get("minimum_release_gate"),
    }


__all__ = ["PACK_VERSION", "SourceEvidencePack", "write_source_evidence_pack"]
