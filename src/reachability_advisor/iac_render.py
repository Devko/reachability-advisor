"""Rendered IaC helper command planning."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class IacRenderCommand:
    tool: str
    purpose: str
    command: str
    output: str

    def to_json(self) -> dict[str, str]:
        return {
            "tool": self.tool,
            "purpose": self.purpose,
            "command": self.command,
            "output": self.output,
        }


def recommend_iac_render_commands(
    *,
    terraform_dir: str | None = None,
    helm_chart: str | None = None,
    helm_release: str = "app",
    helm_namespace: str = "default",
    helm_values: list[str] | None = None,
    kustomize_dir: str | None = None,
    output_dir: str = "reachability",
) -> list[IacRenderCommand]:
    out = output_dir.rstrip("/\\") or "reachability"
    commands: list[IacRenderCommand] = []
    terraform_root = terraform_dir.rstrip("/\\") if terraform_dir else None
    if terraform_dir or helm_chart or kustomize_dir:
        commands.append(
            IacRenderCommand(
                tool="shell",
                purpose="create the local directory used for rendered evidence",
                command=f"mkdir -p {out}",
                output=out,
            )
        )
    if terraform_dir:
        assert terraform_root is not None
        commands.extend(
            [
                IacRenderCommand(
                    tool="terraform",
                    purpose="create a Terraform plan from the deployable module",
                    command=f"terraform -chdir={terraform_dir} plan -out=tfplan.binary",
                    output=f"{terraform_root}/tfplan.binary",
                ),
                IacRenderCommand(
                    tool="terraform",
                    purpose="render Terraform plan JSON for release-gate context",
                    command=f"terraform -chdir={terraform_dir} show -json tfplan.binary > {out}/tfplan.json",
                    output=f"{out}/tfplan.json",
                ),
            ]
        )
    if helm_chart:
        values = " ".join(f"--values {value}" for value in helm_values or [])
        commands.append(
            IacRenderCommand(
                tool="helm",
                purpose="render Helm templates to Kubernetes manifests",
                command=f"helm template {helm_release} {helm_chart} --namespace {helm_namespace} {values} > {out}/helm-rendered.yaml".strip(),
                output=f"{out}/helm-rendered.yaml",
            )
        )
    if kustomize_dir:
        commands.append(
            IacRenderCommand(
                tool="kustomize",
                purpose="render Kustomize overlays to Kubernetes manifests",
                command=f"kustomize build {kustomize_dir} > {out}/kustomize-rendered.yaml",
                output=f"{out}/kustomize-rendered.yaml",
            )
        )
    return commands


def render_iac_render_plan_markdown(commands: list[IacRenderCommand]) -> str:
    lines = [
        "# Rendered IaC Plan",
        "",
        "Generate these artifacts before `reachability-advisor scan --analysis-profile production`.",
        "Terraform source and unrendered Helm/Kustomize inputs are advisory; release gates need rendered plan/manifests.",
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
            "Pass `tfplan.json` with `--terraform-plan` and rendered Kubernetes YAML with repeated `--kubernetes-manifest` flags.",
            "",
        ]
    )
    return "\n".join(lines)


def write_iac_render_plan_json(path: str | Path, commands: list[IacRenderCommand]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "kind": "reachability-advisor-rendered-iac-plan",
                "commands": [command.to_json() for command in commands],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


__all__ = [
    "IacRenderCommand",
    "recommend_iac_render_commands",
    "render_iac_render_plan_markdown",
    "write_iac_render_plan_json",
]
