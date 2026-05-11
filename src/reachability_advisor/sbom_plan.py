"""SBOM generation planning for developer workflows.

The scanner intentionally does not shell out to SBOM generators.  Instead it can
produce a pinned command plan that teams can copy into CI and adapt to their
ecosystem. This keeps the scanner dependency-light while documenting how to
generate an SBOM for a deployable artifact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class SbomCommand:
    tool: str
    purpose: str
    command: str
    output: str
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict[str, object]:
        return asdict(self)


def recommend_sbom_commands(artifact: str, source_root: str | None = None, image: str | None = None, ecosystem: str | None = None, output_dir: str = "sboms") -> list[SbomCommand]:
    safe_artifact = artifact.replace("/", "-").replace(":", "-").replace("@", "-")
    output_path = f"{output_dir}/{safe_artifact}.cdx.json"
    source = source_root or "."
    commands: list[SbomCommand] = []
    if image:
        commands.append(
            SbomCommand(
                tool="syft",
                purpose="container image SBOM",
                command=f"syft {image} -o cyclonedx-json={output_path}",
                output=output_path,
                notes=("Best when the deployed runtime artifact is a container image.", "Add artifact image properties if the generator does not include them."),
            )
        )
        commands.append(
            SbomCommand(
                tool="trivy",
                purpose="container image SBOM",
                command=f"trivy image --format cyclonedx --output {output_path} {image}",
                output=output_path,
                notes=("Alternative image SBOM generator that can also scan for vulnerabilities.",),
            )
        )
    commands.append(
        SbomCommand(
            tool="trivy",
            purpose="filesystem/source SBOM",
            command=f"trivy fs --format cyclonedx --output {output_path} {source}",
            output=output_path,
            notes=("Use for pre-build IDE/PR feedback; image SBOM is preferred for final deployed artifacts.",),
        )
    )
    ecosystem_l = (ecosystem or "").lower()
    if ecosystem_l in {"maven", "java"}:
        commands.append(
            SbomCommand(
                tool="cyclonedx-maven-plugin",
                purpose="Java/Maven aggregate SBOM",
                command="mvn -q org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -DoutputFormat=json",
                output="target/bom.json",
                notes=("Good for Maven projects and multi-module builds.", "Copy or rename target/bom.json to the SBOM path consumed by Reachability Advisor."),
            )
        )
    elif ecosystem_l in {"npm", "node", "javascript", "typescript"}:
        commands.append(
            SbomCommand(
                tool="npm",
                purpose="Node/npm SBOM",
                command=f"npm sbom --sbom-format cyclonedx > {output_path}",
                output=output_path,
                notes=("First-party npm command for npm projects.",),
            )
        )
    elif ecosystem_l in {"pypi", "python"}:
        commands.append(
            SbomCommand(
                tool="cyclonedx-py",
                purpose="Python environment SBOM",
                command=f"cyclonedx-py environment --of JSON -o {output_path}",
                output=output_path,
                notes=("Most accurate after installing the environment that will be packaged.",),
            )
        )
    return commands


def render_sbom_plan_markdown(artifact: str, commands: Iterable[SbomCommand]) -> str:
    lines = [f"# SBOM generation plan for `{artifact}`", "", "Generate one CycloneDX JSON SBOM per deployable artifact. Prefer image/runtime SBOMs for pipeline gates and source/filesystem SBOMs for early IDE or PR feedback.", ""]
    for command in commands:
        lines.append(f"## {command.tool}: {command.purpose}")
        lines.append("")
        lines.append("```bash")
        lines.append(command.command)
        lines.append("```")
        lines.append(f"Output: `{command.output}`")
        if command.notes:
            lines.append("")
            for note in command.notes:
                lines.append(f"- {note}")
        lines.append("")
    lines.append("## Recommended SBOM metadata")
    lines.append("")
    lines.append("Add or preserve metadata that lets Reachability Advisor map the SBOM to a source root and a deployed artifact:")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps({"metadata": {"component": {"name": artifact, "properties": [{"name": "container:image", "value": "registry.example.com/team/app:tag"}, {"name": "environment", "value": "prod"}, {"name": "owner", "value": "team-name"}]}}}, indent=2))
    lines.append("```")
    return "\n".join(lines)


def write_sbom_plan_json(path: str | Path, artifact: str, commands: list[SbomCommand]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"schema_version": "4.0", "artifact": artifact, "commands": [command.to_json() for command in commands]}, indent=2), encoding="utf-8")


__all__ = ["SbomCommand", "recommend_sbom_commands", "render_sbom_plan_markdown", "write_sbom_plan_json"]
