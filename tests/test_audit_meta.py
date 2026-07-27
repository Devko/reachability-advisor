"""Regression tests for the `meta` audit group: release gates, docs, packaging, and sample parity."""

from __future__ import annotations

import contextlib
import io
import json
import re
import shlex
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from scripts import run_complex_app_validation, validate_release

from reachability_advisor.cli_parser import build_parser

ROOT = Path(__file__).resolve().parents[1]
# `docs/superpowers/` holds design specs and implementation plans, which describe commands
# that do not exist yet -- that is their purpose. Documentation-drift checks apply to
# user-facing docs, where a command that fails to parse is a broken instruction.
DESIGN_DOC_PREFIX = "docs/superpowers/"
DOC_FILES = [
    path
    for path in sorted(ROOT.glob("docs/**/*.md"))
    if not path.relative_to(ROOT).as_posix().startswith(DESIGN_DOC_PREFIX)
] + [ROOT / "README.md"]
SCAN_COMMAND = re.compile(
    r"^(?:PYTHONPATH=\S+\s+)?(?:reachability-advisor|ra|python -m reachability_advisor)\s+(.*)$"
)
FENCED_BLOCK = re.compile(r"```[^\n]*\n(.*?)```", re.S)


def _fenced_blocks(text: str) -> list[tuple[int, list[str]]]:
    """Return (first line number, raw lines) for every fenced code block."""
    blocks = []
    for match in FENCED_BLOCK.finditer(text):
        start = text[: match.start()].count("\n") + 2
        blocks.append((start, match.group(1).splitlines()))
    return blocks


def _documented_invocations() -> list[tuple[Path, list[str]]]:
    """Every CLI invocation in a fenced doc block, with continuations joined and $VARS filled in."""
    invocations: list[tuple[Path, list[str]]] = []
    for path in DOC_FILES:
        for _, lines in _fenced_blocks(path.read_text(encoding="utf-8")):
            for line in "\n".join(lines).replace("\\\n", " ").splitlines():
                match = SCAN_COMMAND.match(line.strip())
                if match is None or "..." in match.group(1):
                    continue
                argv: list[str] = []
                for token in shlex.split(match.group(1)):
                    if token.startswith("#"):
                        # bash truncates the logical line here, dropping every flag below it.
                        break
                    if re.fullmatch(r"\$\{\w+\[@\]\}", token):
                        # A shell array that expands to zero or more real arguments.
                        continue
                    argv.append("placeholder" if "$" in token else token)
                invocations.append((path, argv))
    return invocations


def _scan_argv(command_line: str) -> list[str]:
    return shlex.split(command_line.split(" scan ", 1)[1])


def _flag_pairs(argv: list[str]) -> list[tuple[str, str | None]]:
    pairs: list[tuple[str, str | None]] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if not token.startswith("--"):
            index += 1
            continue
        value = argv[index + 1] if index + 1 < len(argv) and not argv[index + 1].startswith("--") else None
        pairs.append((token, value))
        index += 2 if value is not None else 1
    return pairs


def _makefile_target_body(name: str) -> str:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(name)}:\n((?:\t.*\n|\n)+)", text, re.M)
    assert match is not None, f"Makefile has no {name} target"
    return match.group(1).replace("\\\n", " ").replace("\t", " ")


class BenchmarkSnapshotGateTests(unittest.TestCase):
    """The release gate must not be a tautology: it has to be able to fail."""

    def test_release_gate_fails_when_the_comparator_cannot_detect_inflation(self) -> None:
        expectations = ROOT / "fixtures" / "benchmarks" / "real-app-tier-snapshots.json"
        real_run_cli = validate_release.run_cli

        def blind_run_cli(args: list[str]) -> None:
            real_run_cli(args)
            if args and args[0] == "benchmark-snapshots":
                out = Path(args[args.index("--out") + 1])
                report = json.loads(out.read_text(encoding="utf-8"))
                report["status"] = "passed"
                report["failed_count"] = 0
                out.write_text(json.dumps(report, indent=2), encoding="utf-8")

        with tempfile.TemporaryDirectory() as tmp:
            checks: list[dict[str, str]] = []
            with (
                mock.patch.object(validate_release, "run_cli", blind_run_cli),
                self.assertRaises(validate_release.ReleaseCheckError) as raised,
            ):
                validate_release.check_benchmark_snapshot_comparator(Path(tmp), expectations, checks)
            self.assertIn("inflated urgent tier", str(raised.exception))
            self.assertEqual(checks, [])

    def test_release_gate_passes_and_records_a_truthful_check_name(self) -> None:
        expectations = ROOT / "fixtures" / "benchmarks" / "real-app-tier-snapshots.json"
        with tempfile.TemporaryDirectory() as tmp:
            checks: list[dict[str, str]] = []
            validate_release.check_benchmark_snapshot_comparator(Path(tmp), expectations, checks)
            inflated_report = json.loads(
                (Path(tmp) / "benchmark-snapshot-inflated-report.json").read_text(encoding="utf-8")
            )
            matching_report = json.loads(
                (Path(tmp) / "benchmark-snapshot-matching-report.json").read_text(encoding="utf-8")
            )

        self.assertEqual([check["name"] for check in checks], ["benchmark snapshot regression comparator"])
        self.assertEqual(matching_report["status"], "passed")
        self.assertEqual(inflated_report["status"], "failed")
        # The artifact must not claim to be a real-app distribution gate; it never runs the corpus.
        self.assertNotIn("real-app benchmark snapshot regression gate", json.dumps(checks))

    def test_inflated_document_actually_differs_from_the_expectations(self) -> None:
        expectations: dict[str, Any] = json.loads(
            (ROOT / "fixtures" / "benchmarks" / "real-app-tier-snapshots.json").read_text(encoding="utf-8")
        )
        matching = validate_release._snapshot_benchmark_document(expectations)
        inflated = validate_release._snapshot_benchmark_document(expectations, inflate_urgent=1)

        self.assertEqual(matching["aggregate"]["tier_counts"], expectations["snapshots"][0]["expected_tier_counts"])
        self.assertNotEqual(inflated["aggregate"]["tier_counts"], matching["aggregate"]["tier_counts"])
        self.assertEqual(inflated["aggregate"]["tier_counts"]["urgent"], 1)
        self.assertTrue(inflated["cases"])
        for case in inflated["cases"]:
            self.assertEqual(case["tier_counts"]["urgent"], 1)

    def test_external_complex_target_gates_on_the_real_benchmark(self) -> None:
        body = _makefile_target_body("external-complex")

        self.assertIn("--benchmark-expectations fixtures/benchmarks/real-app-tier-snapshots.json", body)
        self.assertIn("--fail-on-benchmark-regression", body)
        # The flags must exist on the script the target runs.
        parsed = run_complex_app_validation.build_parser().parse_args(
            ["--no-clone", "--strict", "--benchmark-expectations", "x.json", "--fail-on-benchmark-regression"]
        )
        self.assertEqual(parsed.benchmark_expectations, "x.json")
        self.assertTrue(parsed.fail_on_benchmark_regression)


class DocumentedCommandTests(unittest.TestCase):
    def test_every_documented_cli_invocation_parses(self) -> None:
        parser = build_parser()
        invocations = _documented_invocations()
        self.assertGreater(len(invocations), 20)

        failures: list[str] = []
        for path, argv in invocations:
            try:
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    parser.parse_args(argv)
            except SystemExit:
                message = stderr.getvalue().strip().splitlines()[-1]
                failures.append(f"{path.relative_to(ROOT)}: {' '.join(argv)[:80]} -> {message}")
        self.assertEqual(failures, [])

    def test_no_comment_line_truncates_a_backslash_continued_command(self) -> None:
        # A `#` line between a trailing `\` and its continuation is valid bash that silently drops
        # every following flag, so it cannot be caught by `bash -n`.
        offenders: list[str] = []
        for path in DOC_FILES:
            for start, lines in _fenced_blocks(path.read_text(encoding="utf-8")):
                for index in range(len(lines) - 1):
                    if lines[index].rstrip().endswith("\\") and lines[index + 1].lstrip().startswith("#"):
                        offenders.append(f"{path.relative_to(ROOT)}:{start + index + 1}")
        self.assertEqual(offenders, [])

    def test_pipeline_release_gate_example_keeps_every_gate_flag(self) -> None:
        text = (ROOT / "docs" / "pipeline.md").read_text(encoding="utf-8")
        commands = [
            argv
            for path, argv in _documented_invocations()
            if path == ROOT / "docs" / "pipeline.md" and argv and argv[0] == "scan"
        ]
        self.assertTrue(commands)
        # The "Run reachability prioritization" workflow step is the only scan that imports SAST.
        sast_commands = [argv for argv in commands if "--sast-in" in argv]
        self.assertEqual(len(sast_commands), 1)
        gate_command = sast_commands[0]

        self.assertIn("--dast-in", text)  # guidance kept, just not inside the continuation
        for flag in (
            "--terraform-plan",
            "--analysis-profile",
            "--require-strong-source-for-critical",
            "--require-release-ready",
            "--min-critical-external-source-coverage",
            "--out",
            "--sarif-out",
            "--markdown-out",
            "--annotations-out",
            "--fail-on-tier",
        ):
            self.assertIn(flag, gate_command)


class PackagingTests(unittest.TestCase):
    def test_dev_extra_supplies_the_declared_build_backend(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        build_requires = re.search(r"\[build-system\].*?requires\s*=\s*\[(.*?)\]", pyproject, re.S)
        dev_extra = re.search(r"^dev\s*=\s*\[(.*?)^\]", pyproject, re.S | re.M)

        self.assertIsNotNone(build_requires)
        self.assertIsNotNone(dev_extra)
        assert build_requires is not None and dev_extra is not None
        backend_pins = re.findall(r'"([^"]+)"', build_requires.group(1))
        dev_pins = re.findall(r'"([^"]+)"', dev_extra.group(1))

        self.assertIn("setuptools>=77", backend_pins)
        # `make package` runs `python -m build --no-isolation`, so the documented dev install must
        # already provide the backend, with the same floor so the two pins cannot drift.
        for pin in backend_pins:
            self.assertIn(pin, dev_pins)

    def test_sdist_manifest_ships_every_repository_path_the_tests_read(self) -> None:
        manifest_path = ROOT / "MANIFEST.in"
        self.assertTrue(manifest_path.exists(), "MANIFEST.in is required so the shipped tests can run")
        manifest = manifest_path.read_text(encoding="utf-8")
        grafted = set(re.findall(r"^graft\s+(\S+)", manifest, re.M))
        included = set(re.findall(r"^include\s+(.+)$", manifest, re.M))
        included_names = {name for line in included for name in line.split()}

        referenced: set[str] = set()
        for test_file in sorted(ROOT.glob("tests/*.py")):
            for reference in re.findall(r'ROOT\s*/\s*"([^"]+)"', test_file.read_text(encoding="utf-8")):
                referenced.add(reference.split("/")[0])
        self.assertIn("samples", referenced)
        self.assertIn("action.yml", referenced)

        # setuptools always ships these, and `src/` reaches the wheel through the package config.
        always_shipped = {"src", "pyproject.toml", "README.md", "MANIFEST.in", "LICENSE", "NOTICE", "setup.cfg"}
        missing = []
        for name in sorted(referenced - always_shipped):
            target = ROOT / name
            if target.is_dir() and name not in grafted:
                missing.append(f"graft {name}")
            elif target.is_file() and name not in included_names:
                missing.append(f"include {name}")
        self.assertEqual(missing, [])
        # Local upstream clones are gitignored and must never be redistributed.
        self.assertIn("prune external_corpus/worktrees", manifest)


class SampleWorkflowTests(unittest.TestCase):
    def _make_sample_argv(self) -> list[str]:
        body = _makefile_target_body("sample")
        line = next(line for line in body.splitlines() if " scan " in line)
        return _scan_argv(line)

    def _run_sample_argv(self) -> list[str]:
        script = (ROOT / "scripts" / "run_sample.sh").read_text(encoding="utf-8").replace("\\\n", " ")
        line = next(line for line in script.splitlines() if " scan " in line)
        return _scan_argv(line)

    def test_make_sample_and_run_sample_pass_identical_flags(self) -> None:
        make_pairs = _flag_pairs(self._make_sample_argv())
        script_pairs = _flag_pairs(self._run_sample_argv())

        self.assertTrue(make_pairs)
        self.assertEqual(sorted(make_pairs), sorted(script_pairs))

    def test_quickstart_promises_only_files_the_sample_command_writes(self) -> None:
        quickstart = (ROOT / "docs" / "quickstart.md").read_text(encoding="utf-8")
        section = quickstart.split("The command writes:", 1)[1].split("\n## ", 1)[0]
        promised = set(re.findall(r"`(outputs/[^`]+)`", section))
        written = {value for _, value in _flag_pairs(self._run_sample_argv()) if value and value.startswith("outputs/")}

        self.assertIn("outputs/evidence-graph.json", promised)
        self.assertIn("outputs/kubernetes-coverage.json", promised)
        self.assertEqual(promised - written, set())

    def test_sample_command_parses_with_the_real_cli_parser(self) -> None:
        parser = build_parser()
        for argv in (self._make_sample_argv(), self._run_sample_argv()):
            with contextlib.redirect_stderr(io.StringIO()):
                parsed = parser.parse_args(["scan", *argv])
            self.assertEqual(parsed.command, "scan")


if __name__ == "__main__":
    unittest.main()
