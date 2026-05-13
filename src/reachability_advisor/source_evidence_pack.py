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

from .source import BUILTIN_RULES, ReachabilityRule, semgrep_rules_yaml
from .source_evidence_plan import source_evidence_profile
from .source_query_assets import (
    codeql_query_pack_metadata,
    codeql_query_pack_suite,
    semgrep_query_pack_yaml,
)
from .source_query_families import QUERY_PACKS, PackageFamilyQueryPack

PACK_SCHEMA_VERSION = "1.0"
PACK_VERSION = "2026-05-13"


@dataclass(frozen=True)
class EcosystemEvidencePack:
    name: str
    ecosystems: tuple[str, ...]
    semgrep_ecosystems: tuple[str, ...]
    codeql_language: str
    codeql_suite: str
    tools: tuple[str, ...]
    critical_package_families: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ecosystems": list(self.ecosystems),
            "semgrep_ecosystems": list(self.semgrep_ecosystems),
            "codeql_language": self.codeql_language,
            "codeql_suite": self.codeql_suite,
            "tools": list(self.tools),
            "critical_package_families": list(self.critical_package_families),
            "coverage_gate": {
                "critical_external_evidence_coverage": 1.0,
                "critical_query_family_coverage": 1.0,
                "requires_matchable_selector": True,
                "requires_relevant_query_family": True,
                "rejects_dependency_only_critical_source": True,
            },
        }


ECOSYSTEM_PACKS: tuple[EcosystemEvidencePack, ...] = (
    EcosystemEvidencePack(
        name="npm",
        ecosystems=("npm", "pnpm", "yarn"),
        semgrep_ecosystems=("npm",),
        codeql_language="javascript-typescript",
        codeql_suite="codeql/javascript-queries:Security-extended",
        tools=("semgrep", "codeql"),
        critical_package_families=("http-client", "template-engine", "auth-token-crypto", "deserialization", "archive-file-io", "web-handler"),
    ),
    EcosystemEvidencePack(
        name="maven-gradle",
        ecosystems=("maven", "gradle"),
        semgrep_ecosystems=("maven",),
        codeql_language="java-kotlin",
        codeql_suite="codeql/java-queries:Security-extended",
        tools=("semgrep", "codeql"),
        critical_package_families=("logging", "deserialization", "auth-token-crypto", "archive-file-io", "web-handler", "http-client"),
    ),
    EcosystemEvidencePack(
        name="python",
        ecosystems=("pypi", "poetry", "pip"),
        semgrep_ecosystems=("pypi",),
        codeql_language="python",
        codeql_suite="codeql/python-queries:Security-extended",
        tools=("semgrep", "codeql"),
        critical_package_families=("http-client", "template-engine", "deserialization", "auth-token-crypto", "web-handler", "archive-file-io"),
    ),
    EcosystemEvidencePack(
        name="go",
        ecosystems=("go", "golang"),
        semgrep_ecosystems=("go", "golang"),
        codeql_language="go",
        codeql_suite="codeql/go-queries:Security-extended",
        tools=("govulncheck", "semgrep", "codeql"),
        critical_package_families=("http-client", "deserialization", "auth-token-crypto", "web-handler", "archive-file-io"),
    ),
)


@dataclass(frozen=True)
class SourceEvidencePack:
    root: Path
    profile: dict[str, Any]
    ecosystem_packs: tuple[EcosystemEvidencePack, ...]
    query_packs: tuple[PackageFamilyQueryPack, ...]
    files: tuple[Path, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": PACK_SCHEMA_VERSION,
            "kind": "reachability-advisor-source-evidence-pack",
            "version": PACK_VERSION,
            "root": str(self.root),
            "profile": self.profile,
            "profiles": [pack.to_json() for pack in self.ecosystem_packs],
            "query_packs": [pack.to_json() for pack in self.query_packs],
            "files": [str(path) for path in self.files],
            "release_gate": {
                "requires_external_evidence": True,
                "critical_external_evidence_coverage": 1.0,
                "critical_query_family_coverage": 1.0,
                "rejects_dependency_only_critical_source": True,
                "requires_relevant_query_family": True,
                "selector_contract": "artifact plus package URL, component, or vulnerability selector",
                "required_profiles": [pack.name for pack in self.ecosystem_packs],
                "required_query_packs": [pack.id for pack in self.query_packs],
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

    semgrep_dir = root / "semgrep" / "profiles"
    semgrep_dir.mkdir(parents=True, exist_ok=True)
    for pack_profile in ECOSYSTEM_PACKS:
        profile_rules = _rules_for_pack(pack_profile)
        profile_path = semgrep_dir / f"{pack_profile.name}.yml"
        profile_path.write_text(semgrep_rules_yaml(profile_rules), encoding="utf-8")
        files.append(profile_path)

    query_pack_dir = root / "query-packs"
    query_pack_dir.mkdir(exist_ok=True)
    semgrep_query_dir = root / "semgrep" / "query-packs"
    semgrep_query_dir.mkdir(parents=True, exist_ok=True)
    for query_pack in QUERY_PACKS:
        metadata_path = query_pack_dir / f"{query_pack.id}.json"
        metadata_path.write_text(json.dumps(query_pack.to_json(), indent=2), encoding="utf-8")
        files.append(metadata_path)
        semgrep_query_path = semgrep_query_dir / f"{query_pack.id}.yml"
        semgrep_query_path.write_text(semgrep_query_pack_yaml(query_pack), encoding="utf-8")
        files.append(semgrep_query_path)
    index_path = query_pack_dir / "index.json"
    index_path.write_text(json.dumps({"query_packs": [pack.to_json() for pack in QUERY_PACKS]}, indent=2), encoding="utf-8")
    files.append(index_path)

    codeql_dir = root / "codeql"
    codeql_dir.mkdir(exist_ok=True)
    codeql_suite = codeql_dir / "reachability-suite.qls"
    codeql_suite.write_text(_codeql_suite(profile["name"]), encoding="utf-8")
    files.append(codeql_suite)
    codeql_readme = codeql_dir / "README.md"
    codeql_readme.write_text(_codeql_readme(profile), encoding="utf-8")
    files.append(codeql_readme)
    codeql_profiles = codeql_dir / "profiles"
    codeql_profiles.mkdir(exist_ok=True)
    for pack_profile in ECOSYSTEM_PACKS:
        profile_dir = codeql_profiles / pack_profile.name
        profile_dir.mkdir(exist_ok=True)
        suite_path = profile_dir / "reachability-suite.qls"
        suite_path.write_text(_codeql_suite(pack_profile.codeql_language), encoding="utf-8")
        files.append(suite_path)
        qlpack_path = profile_dir / "qlpack.yml"
        qlpack_path.write_text(_codeql_pack_yaml(pack_profile), encoding="utf-8")
        files.append(qlpack_path)
        readme_path = profile_dir / "README.md"
        readme_path.write_text(_codeql_profile_readme(pack_profile), encoding="utf-8")
        files.append(readme_path)
    codeql_query_dir = codeql_dir / "query-packs"
    codeql_query_dir.mkdir(exist_ok=True)
    for query_pack in QUERY_PACKS:
        family_dir = codeql_query_dir / query_pack.id
        family_dir.mkdir(exist_ok=True)
        family_suite = family_dir / "reachability-suite.qls"
        family_suite.write_text(codeql_query_pack_suite(query_pack), encoding="utf-8")
        files.append(family_suite)
        metadata_path = family_dir / "metadata.json"
        metadata_path.write_text(json.dumps(codeql_query_pack_metadata(query_pack), indent=2), encoding="utf-8")
        files.append(metadata_path)

    govuln_dir = root / "govulncheck"
    govuln_dir.mkdir(exist_ok=True)
    govuln_config = govuln_dir / "reachability-govulncheck.json"
    govuln_config.write_text(json.dumps(_govulncheck_profile(profile), indent=2), encoding="utf-8")
    files.append(govuln_config)
    go_config = govuln_dir / "profiles-go.json"
    go_config.write_text(json.dumps(_govulncheck_profile(source_evidence_profile(language="go")), indent=2), encoding="utf-8")
    files.append(go_config)

    manifest = SourceEvidencePack(root=root, profile=profile, ecosystem_packs=ECOSYSTEM_PACKS, query_packs=QUERY_PACKS, files=tuple(files))
    manifest_path = root / "source-evidence-pack.json"
    manifest_path.write_text(json.dumps(manifest.to_json(), indent=2), encoding="utf-8")
    files.append(manifest_path)
    return SourceEvidencePack(root=root, profile=profile, ecosystem_packs=ECOSYSTEM_PACKS, query_packs=QUERY_PACKS, files=tuple(files))


def _rules_for_pack(pack_profile: EcosystemEvidencePack) -> tuple[ReachabilityRule, ...]:
    ecosystems = set(pack_profile.semgrep_ecosystems)
    return tuple(rule for rule in BUILTIN_RULES if rule.ecosystem in ecosystems)


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


def _codeql_pack_yaml(pack_profile: EcosystemEvidencePack) -> str:
    dependencies = {
        "javascript-typescript": "codeql/javascript-all",
        "go": "codeql/go-all",
        "java-kotlin": "codeql/java-all",
        "python": "codeql/python-all",
    }
    return "\n".join(
        [
            f"name: reachability-advisor/{pack_profile.name}",
            "version: 1.0.0",
            "library: true",
            "dependencies:",
            f"  {dependencies[pack_profile.codeql_language]}: \"*\"",
            "",
        ]
    )


def _codeql_profile_readme(pack_profile: EcosystemEvidencePack) -> str:
    families = ", ".join(pack_profile.critical_package_families)
    return "\n".join(
        [
            f"# Reachability Advisor CodeQL Profile: {pack_profile.name}",
            "",
            f"CodeQL language: `{pack_profile.codeql_language}`",
            "",
            f"Critical package families: {families}",
            "",
            "Use `reachability-suite.qls` for CodeQL SARIF generation. Reachability Advisor imports",
            "SARIF path evidence when results include `reachability_advisor`, `package`, `purl`, or",
            "`vulnerability` selectors.",
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


__all__ = ["ECOSYSTEM_PACKS", "PACK_VERSION", "QUERY_PACKS", "SourceEvidencePack", "write_source_evidence_pack"]
