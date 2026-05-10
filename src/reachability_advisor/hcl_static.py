"""Conservative Terraform HCL source auditing.

Reachability Advisor's strongest deployment-context evidence comes from
``terraform show -json`` plan files because plans contain evaluated resource
values.  Real open-source projects, however, often publish module source only.
This module adds an intentionally conservative HCL source pass for CI/IDE and
real-world validation workflows:

* account for resource/module blocks without running Terraform;
* classify resource types against the same multi-cloud manifest used for plans;
* extract only simple, local evidence such as image-like attributes and obvious
  public exposure literals;
* report unresolved variables/modules as visibility gaps instead of treating
  them as safe or fully understood.

The parser is not a full Terraform interpreter.  It is a static coverage and
hint extractor designed to answer: "Does this public Terraform source contain
resource shapes our plan analyzer understands, and where do we need a real plan
for stronger evidence?"
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Artifact
from .terraform import TerraformAnalysis, TerraformAnalyzer, TerraformResource, coverage_report, extract_resources, provider_for_type


class HclAuditError(ValueError):
    """Raised when a Terraform source directory cannot be audited."""


@dataclass(frozen=True)
class HclBlock:
    """A minimal Terraform block extracted from a ``.tf`` file."""

    kind: str
    type: str | None
    name: str
    body: str
    file: str
    line: int

    @property
    def address(self) -> str:
        if self.kind == "resource" and self.type:
            return f"{self.type}.{self.name}"
        if self.kind == "data" and self.type:
            return f"data.{self.type}.{self.name}"
        return f"module.{self.name}"


@dataclass(frozen=True)
class HclProjectAudit:
    """Audited Terraform source tree."""

    root: Path
    files: tuple[Path, ...]
    resources: tuple[HclBlock, ...]
    modules: tuple[HclBlock, ...]
    data_blocks: tuple[HclBlock, ...]
    synthetic_plan: dict[str, Any]
    coverage: dict[str, Any]
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_json(self) -> dict[str, Any]:
        resource_types = sorted({block.type for block in self.resources if block.type})
        module_rows = [_module_row(block) for block in self.modules]
        images = _image_summary(self.resources)
        return {
            "schema_version": "4.1",
            "mode": "hcl_static",
            "root": str(self.root),
            "files": [str(path) for path in self.files],
            "summary": {
                "tf_files": len(self.files),
                "resource_blocks": len(self.resources),
                "module_blocks": len(self.modules),
                "data_blocks": len(self.data_blocks),
                "resource_types": len(resource_types),
                "literal_image_references": len(images["literal"]),
                "unresolved_image_references": len(images["unresolved"]),
                "module_expansion_gaps": len(self.modules),
            },
            "resource_types_seen": resource_types,
            "resources": [_block_row(block) for block in self.resources],
            "modules": module_rows,
            "data": [_block_row(block) for block in self.data_blocks],
            "image_references": images,
            "coverage": self.coverage,
            "warnings": list(self.warnings),
            "notes": [
                "HCL static mode does not evaluate variables, count/for_each, modules, data sources, locals, or provider defaults.",
                "Use terraform show -json for production gating when a plan is available.",
                "Module blocks are reported as visibility gaps because their child resources are not expanded without Terraform.",
            ],
        }


RESOURCE_RE = re.compile(r'\bresource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)
DATA_RE = re.compile(r'\bdata\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)
MODULE_RE = re.compile(r'\bmodule\s+"([^"]+)"\s*\{', re.MULTILINE)
ASSIGNMENT_RE = re.compile(r'^\s*([A-Za-z0-9_:\-\.]+)\s*=\s*(.+?)\s*$', re.MULTILINE)
IMAGE_KEY_RE = re.compile(r'\b(image|image_uri|image_url|container_image|docker_image|docker_image_name|linux_fx_version)\s*=\s*([^\n]+)', re.IGNORECASE)
PUBLIC_CIDR_RE = re.compile(r'("0\.0\.0\.0/0"|"::/0"|\bInternet\b|"\*"|\ballUsers\b|"allUsers")', re.IGNORECASE)


BASE_UNSUPPORTED_TYPES = {
    "random_string",
    "random_id",
    "random_pet",
    "null_resource",
    "time_sleep",
    "local_file",
    "template_file",
}


def audit_hcl_project(path: str | Path, artifacts: list[Artifact] | None = None) -> HclProjectAudit:
    """Audit a Terraform source directory and return coverage and static hints."""

    root = Path(path)
    if not root.exists():
        raise HclAuditError(f"Terraform source path does not exist: {root}")
    if root.is_file():
        files = (root,)
        root_dir = root.parent
    else:
        root_dir = root
        files = tuple(sorted(p for p in root.rglob("*.tf") if ".terraform" not in p.parts))
    if not files:
        raise HclAuditError(f"no Terraform .tf files found under: {root}")
    resources: list[HclBlock] = []
    modules: list[HclBlock] = []
    data_blocks: list[HclBlock] = []
    warnings: list[str] = []
    for tf_file in files:
        try:
            text = tf_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = tf_file.read_text(encoding="utf-8", errors="replace")
            warnings.append(f"{tf_file}: decoded with replacement characters")
        resources.extend(_extract_blocks(text, tf_file, RESOURCE_RE, kind="resource"))
        data_blocks.extend(_extract_blocks(text, tf_file, DATA_RE, kind="data"))
        modules.extend(_extract_blocks(text, tf_file, MODULE_RE, kind="module"))
    synthetic_plan = hcl_blocks_to_plan(resources)
    plan_resources = extract_resources(synthetic_plan)
    coverage = coverage_report(plan_resources, artifacts or [], _artifact_matches(plan_resources, artifacts or []))
    coverage["source_mode"] = "hcl_static"
    coverage["hcl_summary"] = {
        "root": str(root),
        "tf_files": len(files),
        "resource_blocks": len(resources),
        "module_blocks": len(modules),
        "data_blocks": len(data_blocks),
    }
    coverage.setdefault("visibility_gaps", [])
    for block in modules:
        coverage["visibility_gaps"].append(
            {
                "address": block.address,
                "type": "module",
                "provider": "unknown",
                "reason": "module child resources are not expanded in HCL static mode; generate a Terraform plan for semantic coverage",
                "source": f"{block.file}:{block.line}",
            }
        )
    for block in resources:
        if block.type in BASE_UNSUPPORTED_TYPES:
            continue
        for image in _image_values(block.body):
            if _is_unresolved_expression(image):
                coverage["visibility_gaps"].append(
                    {
                        "address": block.address,
                        "type": block.type or "unknown",
                        "provider": provider_for_type(block.type or ""),
                        "reason": f"image reference is unresolved expression: {image}",
                        "source": f"{block.file}:{block.line}",
                    }
                )
    return HclProjectAudit(
        root=root_dir.resolve(),
        files=tuple(path.resolve() for path in files),
        resources=tuple(resources),
        modules=tuple(modules),
        data_blocks=tuple(data_blocks),
        synthetic_plan=synthetic_plan,
        coverage=coverage,
        warnings=tuple(warnings),
    )


def analyze_terraform_source(path: str | Path | None, artifacts: list[Artifact]) -> TerraformAnalysis:
    """Analyze Terraform HCL source as a weak deployment-context signal."""

    if not path:
        from .terraform import empty_coverage_report

        return TerraformAnalysis(contexts={}, coverage=empty_coverage_report())
    audit = audit_hcl_project(path, artifacts=artifacts)
    analysis = TerraformAnalyzer(audit.synthetic_plan, artifacts, source_name=f"hcl:{Path(path).name}").analyze()
    coverage = analysis.coverage
    coverage["source_mode"] = "hcl_static"
    coverage["hcl_audit"] = audit.to_json()
    # Preserve module/unresolved visibility gaps from the source-level report.
    coverage.setdefault("visibility_gaps", [])
    coverage["visibility_gaps"].extend(audit.coverage.get("visibility_gaps", []))
    coverage["hcl_summary"] = audit.coverage.get("hcl_summary", {})
    return TerraformAnalysis(contexts=analysis.contexts, coverage=coverage)


def hcl_blocks_to_plan(resources: list[HclBlock] | tuple[HclBlock, ...]) -> dict[str, Any]:
    """Convert HCL resource blocks to a Terraform-plan-shaped JSON object."""

    plan_resources: list[dict[str, Any]] = []
    for block in resources:
        if not block.type:
            continue
        values = _values_from_body(block.body, block.type)
        values["__hcl_file"] = block.file
        values["__hcl_line"] = block.line
        plan_resources.append({"address": block.address, "type": block.type, "name": block.name, "values": values})
    return {"planned_values": {"root_module": {"resources": plan_resources}}}


def render_hcl_audit_markdown(report: dict[str, Any]) -> str:
    """Render a compact Markdown report for maintainers and OWASP reviewers."""

    summary = report.get("summary", {})
    coverage = report.get("coverage", {})
    coverage_summary = coverage.get("summary", {}) if isinstance(coverage, dict) else {}
    lines = [
        "# Terraform HCL Static Audit",
        "",
        f"Root: `{report.get('root', '')}`",
        "",
        "## Summary",
        "",
        f"- Terraform files: {summary.get('tf_files', 0)}",
        f"- Resource blocks: {summary.get('resource_blocks', 0)}",
        f"- Module blocks: {summary.get('module_blocks', 0)}",
        f"- Data blocks: {summary.get('data_blocks', 0)}",
        f"- Literal image references: {summary.get('literal_image_references', 0)}",
        f"- Unresolved image references: {summary.get('unresolved_image_references', 0)}",
        f"- Resource accounting coverage: {coverage_summary.get('resource_accounting_coverage', 'n/a')}",
        f"- Semantic classification coverage: {coverage_summary.get('semantic_classification_coverage', 'n/a')}",
        "",
        "## Resource types seen",
        "",
    ]
    resource_types = report.get("resource_types_seen") or []
    if resource_types:
        lines.extend(f"- `{rtype}`" for rtype in resource_types)
    else:
        lines.append("No resource blocks found.")
    gaps = coverage.get("visibility_gaps", []) if isinstance(coverage, dict) else []
    lines.extend(["", "## Visibility gaps", ""])
    if gaps:
        for gap in gaps[:50]:
            lines.append(f"- `{gap.get('address', 'unknown')}`: {gap.get('reason', 'unclassified')}")
        if len(gaps) > 50:
            lines.append(f"- ... {len(gaps) - 50} more gaps")
    else:
        lines.append("No visibility gaps reported by the static audit.")
    lines.extend(
        [
            "",
            "## Notes",
            "",
            "This is a static HCL audit. It does not evaluate variables, modules, locals, provider defaults, count, or for_each. Use `terraform show -json` for stronger deployment-context evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def _extract_blocks(text: str, file: Path, regex: re.Pattern[str], kind: str) -> list[HclBlock]:
    blocks: list[HclBlock] = []
    for match in regex.finditer(text):
        open_brace = text.find("{", match.end() - 1)
        if open_brace == -1:
            continue
        close_brace = _find_matching_brace(text, open_brace)
        if close_brace == -1:
            continue
        line = text.count("\n", 0, match.start()) + 1
        body = text[open_brace + 1 : close_brace]
        if kind in {"resource", "data"}:
            block = HclBlock(kind=kind, type=match.group(1), name=match.group(2), body=body, file=str(file), line=line)
        else:
            block = HclBlock(kind=kind, type=None, name=match.group(1), body=body, file=str(file), line=line)
        blocks.append(block)
    return blocks


def _find_matching_brace(text: str, open_brace: int) -> int:
    depth = 0
    in_string = False
    escape = False
    for i in range(open_brace, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _values_from_body(body: str, resource_type: str) -> dict[str, Any]:
    values: dict[str, Any] = {}
    assignments = _simple_assignments(body)
    values.update(assignments)
    image_values = _image_values(body)
    if image_values:
        values["image"] = image_values
    if "container_definitions" in assignments:
        values["container_definitions"] = assignments["container_definitions"]
    if PUBLIC_CIDR_RE.search(body):
        if resource_type.startswith("aws_security_group"):
            values.setdefault("ingress", [{"cidr_blocks": _cidr_values(body), "ipv6_cidr_blocks": _ipv6_cidr_values(body)}])
        if resource_type == "google_compute_firewall":
            values.setdefault("source_ranges", _source_values(body) or _cidr_values(body))
        if resource_type.startswith("azurerm_network_security"):
            sources = _source_values(body) or _cidr_values(body) or ["Internet"]
            values.setdefault("source_address_prefix", sources[0] if len(sources) == 1 else sources)
            values.setdefault("direction", _string_attr(body, "direction") or "Inbound")
            values.setdefault("access", _string_attr(body, "access") or "Allow")
    if "external_enabled" in body:
        external = _bool_attr(body, "external_enabled")
        if external is not None:
            values.setdefault("ingress", [{"external_enabled": external}])
    if resource_type.startswith("kubernetes_") and _string_attr(body, "type"):
        values["type"] = _string_attr(body, "type")
    for key in ("role", "member", "members", "role_definition_name", "role_definition_id", "policy_arn", "authorization_type", "function_name", "service", "name", "internal"):
        parsed = _attr_value(body, key)
        if parsed is not None:
            values.setdefault(key, parsed)
    return values


def _simple_assignments(body: str) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for match in ASSIGNMENT_RE.finditer(body):
        key = match.group(1).strip()
        if "." in key or key in {"for_each", "count", "depends_on", "provider"}:
            continue
        values.setdefault(key, _parse_hcl_value(match.group(2).strip()))
    return values


def _parse_hcl_value(raw: str) -> Any:
    raw = raw.split("#", 1)[0].split("}", 1)[0].strip().rstrip(",")
    if raw.startswith('"') and '"' in raw[1:]:
        return raw[1 : raw.find('"', 1)]
    if raw.lower() == "true":
        return True
    if raw.lower() == "false":
        return False
    if raw.startswith("["):
        strings = re.findall(r'"([^"]+)"', raw)
        return strings if strings else raw
    return raw


def _attr_value(body: str, key: str) -> Any:
    pattern = re.compile(rf'\b{re.escape(key)}\s*=\s*([^\n]+)', re.IGNORECASE)
    match = pattern.search(body)
    if not match:
        return None
    return _parse_hcl_value(match.group(1))


def _string_attr(body: str, key: str) -> str | None:
    value = _attr_value(body, key)
    return str(value) if value is not None else None


def _bool_attr(body: str, key: str) -> bool | None:
    value = _attr_value(body, key)
    return value if isinstance(value, bool) else None


def _image_values(body: str) -> list[str]:
    values: list[str] = []
    for match in IMAGE_KEY_RE.finditer(body):
        parsed = _parse_hcl_value(match.group(2))
        if isinstance(parsed, list):
            values.extend(str(item) for item in parsed)
        else:
            values.append(str(parsed))
    return list(dict.fromkeys(value for value in values if value))


def _cidr_values(body: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r'"((?:\d{1,3}\.){3}\d{1,3}/\d+|Internet|\*)"', body, flags=re.IGNORECASE)))


def _ipv6_cidr_values(body: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r'"(::/0)"', body, flags=re.IGNORECASE)))


def _source_values(body: str) -> list[str]:
    values: list[str] = []
    for key in ("source_ranges", "source_address_prefix", "source_address_prefixes"):
        parsed = _attr_value(body, key)
        if isinstance(parsed, list):
            values.extend(str(item) for item in parsed)
        elif parsed:
            values.append(str(parsed))
    return list(dict.fromkeys(values))


def _is_unresolved_expression(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith("var.") or stripped.startswith("local.") or stripped.startswith("each.") or "${" in stripped


def _image_summary(resources: tuple[HclBlock, ...]) -> dict[str, list[dict[str, Any]]]:
    literal: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    for block in resources:
        for image in _image_values(block.body):
            row = {"address": block.address, "image": image, "source": f"{block.file}:{block.line}"}
            if _is_unresolved_expression(image):
                unresolved.append(row)
            else:
                literal.append(row)
    return {"literal": literal, "unresolved": unresolved}


def _artifact_matches(resources: list[TerraformResource], artifacts: list[Artifact]) -> list[dict[str, Any]]:
    # A full artifact match is calculated by TerraformAnalyzer during scan.  For
    # stand-alone HCL audit, avoid duplicating that logic; the coverage report is
    # focused on source shape rather than findings.  It still supports artifact
    # counts through the supplied list.
    return []


def _block_row(block: HclBlock) -> dict[str, Any]:
    return {
        "kind": block.kind,
        "address": block.address,
        "type": block.type,
        "name": block.name,
        "provider": provider_for_type(block.type or "") if block.type else "unknown",
        "file": block.file,
        "line": block.line,
        "image_references": _image_values(block.body),
    }


def _module_row(block: HclBlock) -> dict[str, Any]:
    row = _block_row(block)
    row["source"] = _string_attr(block.body, "source")
    row["version"] = _string_attr(block.body, "version")
    row["image_like_arguments"] = [
        {"key": match.group(1), "value": str(_parse_hcl_value(match.group(2)))}
        for match in IMAGE_KEY_RE.finditer(block.body)
    ]
    return row


__all__ = [
    "HclAuditError",
    "HclBlock",
    "HclProjectAudit",
    "analyze_terraform_source",
    "audit_hcl_project",
    "hcl_blocks_to_plan",
    "render_hcl_audit_markdown",
]
