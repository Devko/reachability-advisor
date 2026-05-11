"""Explicit deployment-context loading for CI/IDE workflows.

Teams can provide a small context JSON file or a local Terraform plan JSON.  The
Terraform path delegates to the multi-cloud Terraform analyzer.  Missing context
is treated as unknown, never as safe.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Artifact, Confidence, ContextEvidence
from .terraform import (
    TerraformContextError,
    analyze_terraform_plan,
    classify_policy,
    classify_role_text,
    extract_resources,
    max_privilege,
)


class ContextError(ValueError):
    """Raised when context JSON or Terraform JSON cannot be parsed."""


def _context_from_mapping(raw: dict[str, Any], source: str) -> ContextEvidence:
    evidence = raw.get("evidence") if isinstance(raw.get("evidence"), list) else []
    confidence = str(raw.get("confidence") or "medium").lower()
    if confidence not in {"high", "medium", "low"}:
        confidence = "medium"
    return ContextEvidence(
        environment=str(raw.get("environment") or "unknown").lower(),
        exposure=str(raw.get("exposure") or "unknown").lower(),
        privilege=str(raw.get("privilege") or "unknown").lower(),
        criticality=str(raw.get("criticality") or "unknown").lower(),
        iam_impacts=[str(item).lower() for item in raw.get("iam_impacts", [])] if isinstance(raw.get("iam_impacts"), list) else [],
        owner=str(raw.get("owner")) if raw.get("owner") else None,
        source=source,
        confidence=Confidence(confidence),
        evidence=[str(item) for item in evidence],
    )


def load_context_file(path: str | Path | None) -> dict[str, ContextEvidence]:
    if not path:
        return {}
    context_path = Path(path)
    try:
        data = json.loads(context_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ContextError(f"{context_path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ContextError(f"{context_path}: expected a JSON object")
    artifacts = data.get("artifacts", data)
    if not isinstance(artifacts, dict):
        raise ContextError(f"{context_path}: artifacts must be a mapping")
    result: dict[str, ContextEvidence] = {}
    for artifact_name, raw_context in artifacts.items():
        if isinstance(raw_context, dict):
            result[str(artifact_name)] = _context_from_mapping(raw_context, source=f"context:{context_path.name}")
    return result


def infer_context_from_terraform(path: str | Path | None, artifacts: list[Artifact]) -> dict[str, ContextEvidence]:
    """Infer conservative context from a Terraform plan JSON.

    This compatibility wrapper returns only contexts.  Use
    ``terraform.analyze_terraform_plan`` when a coverage report is also needed.
    """

    try:
        return analyze_terraform_plan(path, artifacts).contexts
    except TerraformContextError as exc:
        raise ContextError(str(exc)) from exc


# Backward-compatible helpers used by older tests and contributors.
def _planned_resources(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"address": resource.address, "type": resource.type, "name": resource.name, "values": resource.values} for resource in extract_resources(plan)]


def _classify_policy(policy: Any) -> str:
    return classify_policy(policy)


def _max_privilege(left: str, right: str) -> str:
    return max_privilege(left, right)


def _privilege_rank(value: str) -> int:
    return {"unknown": 0, "none": 1, "limited": 2, "sensitive": 3, "admin": 4}.get(value, 0)


def _classify_role_text(value: Any) -> str:
    return classify_role_text(value)
