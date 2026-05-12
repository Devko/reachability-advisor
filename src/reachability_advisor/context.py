"""Explicit deployment-context loading for CI/IDE workflows.

Teams can provide a small context JSON file or a local Terraform plan JSON.  The
Terraform path delegates to the multi-cloud Terraform analyzer.  Missing context
is treated as unknown, never as safe.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .iam_capabilities import dedupe_iam_capabilities
from .models import Artifact, Confidence, ContextEvidence
from .terraform import (
    TerraformContextError,
    analyze_terraform_plan,
)


class ContextError(ValueError):
    """Raised when context JSON or Terraform JSON cannot be parsed."""


def _context_from_mapping(raw: dict[str, Any], source: str) -> ContextEvidence:
    raw_evidence = raw.get("evidence")
    evidence = raw_evidence if isinstance(raw_evidence, list) else []
    raw_capabilities = raw.get("iam_capabilities")
    iam_capabilities = dedupe_iam_capabilities([dict(item) for item in raw_capabilities if isinstance(item, dict)]) if isinstance(raw_capabilities, list) else []
    raw_effective_access = raw.get("effective_access")
    effective_access = [dict(item) for item in raw_effective_access if isinstance(item, dict)] if isinstance(raw_effective_access, list) else []
    raw_effective_exposure = raw.get("effective_exposure")
    effective_exposure = [dict(item) for item in raw_effective_exposure if isinstance(item, dict)] if isinstance(raw_effective_exposure, list) else []
    raw_network_paths = raw.get("network_paths")
    network_paths = [dict(item) for item in raw_network_paths if isinstance(item, dict)] if isinstance(raw_network_paths, list) else []
    confidence = str(raw.get("confidence") or "medium").lower()
    if confidence not in {"high", "medium", "low"}:
        confidence = "medium"
    return ContextEvidence(
        environment=str(raw.get("environment") or "unknown").lower(),
        exposure=str(raw.get("exposure") or "unknown").lower(),
        privilege=str(raw.get("privilege") or "unknown").lower(),
        criticality=str(raw.get("criticality") or "unknown").lower(),
        iam_impacts=[str(item).lower() for item in raw.get("iam_impacts", [])] if isinstance(raw.get("iam_impacts"), list) else [],
        iam_capabilities=iam_capabilities,
        effective_access=effective_access,
        effective_exposure=effective_exposure,
        network_paths=network_paths,
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
    """Return artifact contexts from Terraform plan JSON.

    The full analyzer also returns coverage and mapping detail. This helper is
    intentionally small for callers that only need context enrichment.
    """

    try:
        return analyze_terraform_plan(path, artifacts).contexts
    except TerraformContextError as exc:
        raise ContextError(str(exc)) from exc
