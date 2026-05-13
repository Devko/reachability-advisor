"""Maintained SAST/DAST profile catalog.

Security evidence is only release-gate quality when the scanner profile covers
the weakness class being imported. This module owns the local profile catalog,
the generated scanner assets, and the coverage checks for checked-in examples.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PACK_SCHEMA_VERSION = "1.0"
PACK_VERSION = "2026-05-13"


@dataclass(frozen=True)
class SecurityEvidenceProfile:
    id: str
    scanner_type: str
    title: str
    cwes: tuple[str, ...]
    tools: tuple[str, ...]
    expected_samples: tuple[str, ...]
    description: str

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scanner_type": self.scanner_type,
            "title": self.title,
            "cwes": list(self.cwes),
            "tools": list(self.tools),
            "expected_samples": list(self.expected_samples),
            "description": self.description,
            "coverage_gate": {
                "critical_profile_coverage": 1.0,
                "requires_cwe": True,
                "requires_maintained_profile": True,
            },
        }


@dataclass(frozen=True)
class SecurityEvidencePack:
    root: Path
    profiles: tuple[SecurityEvidenceProfile, ...]
    files: tuple[Path, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": PACK_SCHEMA_VERSION,
            "kind": "reachability-advisor-security-evidence-pack",
            "version": PACK_VERSION,
            "root": str(self.root),
            "profiles": [profile.to_json() for profile in self.profiles],
            "files": [str(path) for path in self.files],
            "release_gate": {
                "critical_profile_coverage": 1.0,
                "requires_cwe": True,
                "requires_maintained_profile": True,
                "selector_contract": "artifact plus scanner rule, source location, tested URL, CWE, or route",
                "required_profiles": [profile.id for profile in self.profiles],
            },
        }


SECURITY_EVIDENCE_PROFILES: tuple[SecurityEvidenceProfile, ...] = (
    SecurityEvidenceProfile(
        id="sast-web-injection",
        scanner_type="sast",
        title="SAST web injection profile",
        cwes=("CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-918"),
        tools=("semgrep", "codeql", "sarif"),
        expected_samples=("node-express-xss", "nodejs-goof-command-injection", "python-flask-sqli"),
        description="Static analysis profile for request-controlled web, command, SQL, path, eval, and SSRF sinks.",
    ),
    SecurityEvidenceProfile(
        id="sast-parser-deserialization",
        scanner_type="sast",
        title="SAST parser and deserialization profile",
        cwes=("CWE-502", "CWE-611", "CWE-776"),
        tools=("semgrep", "codeql", "sarif"),
        expected_samples=("python-yaml-deserialization",),
        description="Static analysis profile for unsafe deserialization, XML, YAML, and parser expansion sinks.",
    ),
    SecurityEvidenceProfile(
        id="sast-authz-access-control",
        scanner_type="sast",
        title="SAST authorization profile",
        cwes=("CWE-639", "CWE-862", "CWE-863"),
        tools=("semgrep", "codeql", "sarif"),
        expected_samples=("node-missing-authz",),
        description="Static analysis profile for missing authorization, insecure direct object access, and broken access-control paths.",
    ),
    SecurityEvidenceProfile(
        id="dast-web-app",
        scanner_type="dast",
        title="DAST web application profile",
        cwes=("CWE-22", "CWE-79", "CWE-89", "CWE-352", "CWE-601", "CWE-918"),
        tools=("sarif", "generic-json", "dast-json"),
        expected_samples=("dast-reflected-xss", "dast-ssrf-probe"),
        description="Dynamic testing profile for externally observed web weaknesses and tested URLs.",
    ),
)

SECURITY_PROFILES_BY_ID: dict[str, SecurityEvidenceProfile] = {profile.id: profile for profile in SECURITY_EVIDENCE_PROFILES}
PROVEN_SECURITY_PROFILE_IDS: tuple[str, ...] = tuple(profile.id for profile in SECURITY_EVIDENCE_PROFILES)


def profiles_for_security_record(scanner_type: str, cwe: str | None, weakness: str | None = None) -> tuple[str, ...]:
    """Return maintained profile IDs that cover an imported SAST/DAST record."""

    normalized_type = str(scanner_type or "sast").lower()
    normalized_cwe = normalize_cwe(cwe)
    weakness_text = str(weakness or "").lower()
    matches = []
    for profile in SECURITY_EVIDENCE_PROFILES:
        if profile.scanner_type != normalized_type:
            continue
        if normalized_cwe and normalized_cwe in profile.cwes:
            matches.append(profile.id)
            continue
        if not normalized_cwe and _weakness_matches_profile(weakness_text, profile):
            matches.append(profile.id)
    return tuple(sorted(set(matches)))


def security_record_requires_profile(record: Any) -> bool:
    severity = str(getattr(record, "severity", "") or "").lower()
    cvss = getattr(record, "cvss", None)
    return severity in {"critical", "high"} or (isinstance(cvss, (int, float)) and cvss >= 7.0)


def security_evidence_profile_report(records: list[Any], unmapped: list[dict[str, Any]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    profile_counts: dict[str, int] = {}
    totals: dict[str, Any] = {
        "records": len(records),
        "records_with_cwe": 0,
        "records_with_profile": 0,
        "critical_records": 0,
        "critical_records_with_profile": 0,
        "critical_records_missing_profile": 0,
        "unmapped_records": len(unmapped),
        "critical_profile_coverage": 1.0,
        "profile_catalog_version": PACK_VERSION,
        "proven_security_profiles": list(PROVEN_SECURITY_PROFILE_IDS),
    }
    for record in records:
        cwe = normalize_cwe(getattr(record, "cwe", None))
        profile_ids = profiles_for_security_record(
            str(getattr(record, "scanner_type", "sast")),
            cwe,
            str(getattr(record, "weakness", "")),
        )
        requires_profile = security_record_requires_profile(record)
        if cwe:
            totals["records_with_cwe"] += 1
        if profile_ids:
            totals["records_with_profile"] += 1
            for profile_id in profile_ids:
                profile_counts[profile_id] = profile_counts.get(profile_id, 0) + 1
        if requires_profile:
            totals["critical_records"] += 1
            if profile_ids:
                totals["critical_records_with_profile"] += 1
            else:
                totals["critical_records_missing_profile"] += 1
        rows.append(
            {
                "rule_id": getattr(record, "rule_id", None),
                "scanner_type": getattr(record, "scanner_type", None),
                "tool": getattr(record, "tool", None),
                "severity": getattr(record, "severity", None),
                "cwe": cwe,
                "weakness": getattr(record, "weakness", None),
                "requires_profile": requires_profile,
                "profiles": list(profile_ids),
                "profile_status": "covered" if profile_ids else "missing",
            }
        )
    critical_records = int(totals["critical_records"])
    totals["critical_profile_coverage"] = round(int(totals["critical_records_with_profile"]) / critical_records, 4) if critical_records else 1.0
    return {
        "schema_version": PACK_SCHEMA_VERSION,
        "summary": totals,
        "profiles": [
            {
                **profile.to_json(),
                "records": profile_counts.get(profile.id, 0),
                "proven": profile.id in PROVEN_SECURITY_PROFILE_IDS,
            }
            for profile in SECURITY_EVIDENCE_PROFILES
        ],
        "records": rows,
    }


def security_profile_sample_coverage(expectations: dict[str, Any], sample_root: Path) -> dict[str, Any]:
    """Measure profile/CWE coverage for checked-in vulnerable security examples."""

    rows: list[dict[str, Any]] = []
    profile_rows: dict[str, dict[str, Any]] = {}
    total = 0
    covered = 0
    true_positive = 0
    for sample in expectations.get("samples", []) if isinstance(expectations.get("samples"), list) else []:
        if not isinstance(sample, dict):
            continue
        sample_id = str(sample.get("id") or "")
        expected_profiles = {str(item) for item in sample.get("expected_profiles", []) if str(item)}
        expected_cwes = {normalize_cwe(str(item)) for item in sample.get("expected_cwes", []) if normalize_cwe(str(item))}
        evidence_files = [_resolve_fixture_path(sample_root, str(item)) for item in sample.get("evidence_files", []) if str(item)]
        records = _load_security_records(evidence_files)
        observed_profiles: set[str] = set()
        observed_cwes: set[str] = set()
        for record in records:
            cwe = normalize_cwe(getattr(record, "cwe", None))
            if cwe:
                observed_cwes.add(cwe)
            observed_profiles.update(profiles_for_security_record(str(getattr(record, "scanner_type", "sast")), cwe, str(getattr(record, "weakness", ""))))
        profile_covered = expected_profiles.issubset(observed_profiles)
        cwe_covered = expected_cwes.issubset(observed_cwes)
        row_covered = profile_covered and cwe_covered
        total += 1
        covered += 1 if row_covered else 0
        true_positive += 1 if row_covered else 0
        for profile_id in expected_profiles:
            profile_row = profile_rows.setdefault(profile_id, {"profile": profile_id, "expected": 0, "covered": 0, "true_positives": 0, "samples": set()})
            profile_row["expected"] += 1
            profile_row["covered"] += 1 if profile_id in observed_profiles else 0
            profile_row["true_positives"] += 1 if row_covered else 0
            profile_row["samples"].add(sample_id)
        rows.append(
            {
                "sample": sample_id,
                "scanner_type": sample.get("scanner_type"),
                "path": sample.get("path"),
                "expected_profiles": sorted(expected_profiles),
                "observed_profiles": sorted(observed_profiles),
                "expected_cwes": sorted(expected_cwes),
                "observed_cwes": sorted(observed_cwes),
                "covered": row_covered,
                "true_positive": row_covered,
            }
        )
    profile_coverage = []
    for row in sorted(profile_rows.values(), key=lambda item: item["profile"]):
        expected = int(row["expected"])
        profile_coverage.append(
            {
                "profile": row["profile"],
                "expected": expected,
                "covered": row["covered"],
                "true_positives": row["true_positives"],
                "coverage": round(row["covered"] / expected, 4) if expected else 1.0,
                "true_positive_coverage": round(row["true_positives"] / expected, 4) if expected else 1.0,
                "samples": sorted(row["samples"]),
            }
        )
    return {
        "schema_version": PACK_SCHEMA_VERSION,
        "summary": {
            "expected": total,
            "covered": covered,
            "coverage": round(covered / total, 4) if total else 1.0,
            "profiles": len(profile_coverage),
            "profiles_fully_covered": sum(1 for row in profile_coverage if row["coverage"] == 1.0),
            "true_positive_coverage": round(true_positive / total, 4) if total else 1.0,
        },
        "profiles": profile_coverage,
        "samples": rows,
    }


def write_security_evidence_pack(output_dir: str | Path) -> SecurityEvidencePack:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    files: list[Path] = []

    semgrep_dir = root / "semgrep" / "profiles"
    semgrep_dir.mkdir(parents=True, exist_ok=True)
    for profile in SECURITY_EVIDENCE_PROFILES:
        if profile.scanner_type != "sast":
            continue
        path = semgrep_dir / f"{profile.id}.yml"
        path.write_text(_semgrep_profile_yaml(profile), encoding="utf-8")
        files.append(path)
    combined = root / "semgrep" / "security.yml"
    combined.write_text(_combined_semgrep_yaml(profile for profile in SECURITY_EVIDENCE_PROFILES if profile.scanner_type == "sast"), encoding="utf-8")
    files.append(combined)

    dast_dir = root / "dast"
    dast_dir.mkdir(exist_ok=True)
    for profile in SECURITY_EVIDENCE_PROFILES:
        if profile.scanner_type != "dast":
            continue
        path = dast_dir / f"{profile.id}.json"
        path.write_text(json.dumps(profile.to_json(), indent=2), encoding="utf-8")
        files.append(path)

    index = root / "security-evidence-pack.json"
    pack = SecurityEvidencePack(root=root, profiles=SECURITY_EVIDENCE_PROFILES, files=tuple(files))
    index.write_text(json.dumps(pack.to_json(), indent=2), encoding="utf-8")
    files.append(index)
    return SecurityEvidencePack(root=root, profiles=SECURITY_EVIDENCE_PROFILES, files=tuple(files))


def normalize_cwe(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"\bCWE[-_ ]?(\d+)\b", str(value), flags=re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else None


def _weakness_matches_profile(weakness: str, profile: SecurityEvidenceProfile) -> bool:
    if profile.id == "sast-web-injection":
        return any(token in weakness for token in ("xss", "injection", "ssrf", "path", "command", "sql", "eval"))
    if profile.id == "sast-parser-deserialization":
        return any(token in weakness for token in ("deserialization", "yaml", "xml", "parser"))
    if profile.id == "sast-authz-access-control":
        return any(token in weakness for token in ("authorization", "authorisation", "access", "idor"))
    if profile.id == "dast-web-app":
        return any(token in weakness for token in ("xss", "injection", "ssrf", "csrf", "redirect", "path"))
    return False


def _load_security_records(paths: list[Path]) -> list[Any]:
    if not paths:
        return []
    from .security_evidence import load_security_evidence

    return load_security_evidence(paths)


def _resolve_fixture_path(sample_root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    for candidate in (sample_root / path, sample_root.parent / path, sample_root.parents[1] / path):
        if candidate.exists():
            return candidate
    return sample_root / path


def _semgrep_profile_yaml(profile: SecurityEvidenceProfile) -> str:
    lines = ["rules:"]
    for cwe in profile.cwes:
        rule_id = f"security.{profile.id}.{cwe.lower()}"
        lines.extend(
            [
                f"  - id: {rule_id}",
                "    severity: WARNING",
                "    languages: [javascript, typescript, python, java, go]",
                f"    message: {_yaml_string(profile.title + ' ' + cwe)}",
                "    metadata:",
                "      reachability_advisor:",
                f"        scanner_type: {_yaml_string(profile.scanner_type)}",
                f"        security_profile: {_yaml_string(profile.id)}",
                f"        cwe: {_yaml_string(cwe)}",
                "    patterns:",
                f"      - pattern-regex: {_yaml_string(_pattern_for_cwe(cwe))}",
            ]
        )
    return "\n".join(lines) + "\n"


def _combined_semgrep_yaml(profiles: Any) -> str:
    lines = ["rules:"]
    for profile in profiles:
        profile_lines = _semgrep_profile_yaml(profile).splitlines()
        lines.extend(profile_lines[1:])
    return "\n".join(lines) + "\n"


def _pattern_for_cwe(cwe: str) -> str:
    return {
        "CWE-22": r"(path|filepath|File|open|sendFile)",
        "CWE-78": r"(exec|spawn|system|ProcessBuilder)",
        "CWE-79": r"(res\.send|innerHTML|render_template_string|Html)",
        "CWE-89": r"(query|execute|rawQuery|Statement)",
        "CWE-94": r"(eval|Function|exec)",
        "CWE-502": r"(deserialize|ObjectInputStream|yaml\.load)",
        "CWE-611": r"(DocumentBuilderFactory|SAXParser|xml)",
        "CWE-776": r"(entityExpansion|XMLInputFactory|xml)",
        "CWE-639": r"(userId|accountId|tenantId)",
        "CWE-862": r"(authorize|authenticated|permission)",
        "CWE-863": r"(role|policy|permission)",
        "CWE-918": r"(requests\.get|axios|fetch|http\.Get|RestTemplate)",
    }.get(cwe, r".+")


def _yaml_string(value: str) -> str:
    return json.dumps(value)


__all__ = [
    "PROVEN_SECURITY_PROFILE_IDS",
    "SECURITY_EVIDENCE_PROFILES",
    "SECURITY_PROFILES_BY_ID",
    "SecurityEvidencePack",
    "SecurityEvidenceProfile",
    "normalize_cwe",
    "profiles_for_security_record",
    "security_evidence_profile_report",
    "security_profile_sample_coverage",
    "security_record_requires_profile",
    "write_security_evidence_pack",
]
