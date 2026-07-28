# tests/test_config_detect.py
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

import reachability_advisor.config_detect as config_detect
from reachability_advisor.config_detect import (
    LOCKFILE_ECOSYSTEMS,
    SBOM_COMMANDS,
    detect_repo,
)


def _tree(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


class DetectRepoTests(unittest.TestCase):
    def test_detects_an_existing_cyclonedx_sbom(self) -> None:
        root = _tree({"sboms/api.cdx.json": '{"bomFormat":"CycloneDX","components":[]}'})
        detection = detect_repo(root)
        self.assertEqual([item.sbom for item in detection.artifacts], ["sboms/api.cdx.json"])

    def test_detects_an_ecosystem_from_a_lockfile_and_names_the_sbom_command(self) -> None:
        root = _tree({"services/api/package-lock.json": "{}"})
        detection = detect_repo(root)
        artifact = detection.artifacts[0]
        self.assertEqual(artifact.source, "services/api")
        self.assertEqual(artifact.ecosystem, "npm")
        self.assertIsNone(artifact.sbom)
        self.assertTrue(any("syft" in note for note in detection.notes))

    def test_detects_terraform_and_kubernetes(self) -> None:
        root = _tree({
            "infra/main.tf": 'resource "aws_instance" "a" {}\n',
            "k8s/deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\n",
        })
        detection = detect_repo(root)
        self.assertEqual(detection.terraform_source, "infra")
        self.assertEqual(detection.kubernetes, "k8s")

    def test_does_not_invent_paths_that_do_not_exist(self) -> None:
        detection = detect_repo(_tree({"README.md": "# empty\n"}))
        self.assertEqual(detection.artifacts, [])
        self.assertIsNone(detection.terraform)
        self.assertIsNone(detection.kubernetes)

    def test_ignores_vendor_and_dependency_directories(self) -> None:
        root = _tree({"node_modules/pkg/package-lock.json": "{}", "app/package-lock.json": "{}"})
        detection = detect_repo(root)
        self.assertEqual([item.source for item in detection.artifacts], ["app"])


class DetectRepoHardeningTests(unittest.TestCase):
    """Detection walks an untrusted repository: it must degrade, never crash or hang."""

    def test_symlink_directory_cycle_does_not_hang(self) -> None:
        root = _tree({"README.md": "# ok\n"})
        (root / "loop").symlink_to(root, target_is_directory=True)
        started = time.monotonic()
        detection = detect_repo(root)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 5.0, "a symlink cycle must not cause unbounded recursion")
        self.assertEqual(detection.artifacts, [])

    def test_symlink_directory_cycle_is_never_descended_into(self) -> None:
        # A self-referencing symlink cycle is, in practice, also bounded by the
        # OS's own path-length limit (Linux ENAMETOOLONG) even if followlinks
        # were mistakenly enabled -- os.walk's default onerror=None makes that
        # failure silent, so a purely timing-based assertion can pass for the
        # wrong reason. Assert on the actual mechanism instead: with
        # followlinks=False the symlinked directory is listed but never
        # descended into, so the one real file under root must be found
        # exactly once, not once per level of the cycle the OS happens to
        # tolerate before giving up.
        root = _tree({"README.md": "# ok\n"})
        (root / "loop").symlink_to(root, target_is_directory=True)
        walked = config_detect._walk(root)
        self.assertEqual(len(walked.files), 1)
        self.assertEqual(walked.files[0].name, "README.md")

    def test_broken_symlink_is_skipped_without_crashing(self) -> None:
        root = _tree({})
        (root / "dangling.yaml").symlink_to(root / "does-not-exist")
        detection = detect_repo(root)
        self.assertIsNone(detection.kubernetes)

    def test_fifo_named_like_a_manifest_is_not_opened(self) -> None:
        root = _tree({})
        os.mkfifo(root / "deploy.yaml")
        detection = detect_repo(root)
        self.assertIsNone(detection.kubernetes)

    def test_device_symlink_named_like_an_sbom_is_skipped(self) -> None:
        root = _tree({})
        (root / "sboms").mkdir()
        os.symlink("/dev/zero", root / "sboms" / "app.cdx.json")
        detection = detect_repo(root)
        # The file exists at that path (it is a valid detection target by name), but its
        # content must never be read as a regular file would be.
        self.assertEqual(len(detection.artifacts), 1)
        self.assertIsNone(detection.artifacts[0].image)

    def test_unreadable_file_is_skipped_without_crashing(self) -> None:
        root = _tree({"secret/deploy.yaml": "apiVersion: v1\nkind: Pod\n"})
        target = root / "secret" / "deploy.yaml"
        target.chmod(0o000)
        try:
            detection = detect_repo(root)
        finally:
            target.chmod(0o644)
        self.assertIsNone(detection.kubernetes)

    def test_nonexistent_root_does_not_raise(self) -> None:
        missing = Path(tempfile.mkdtemp()) / "does-not-exist"
        detection = detect_repo(missing)
        self.assertEqual(detection.artifacts, [])
        # Must not be confused with "scanned a real, empty repository" --
        # os.walk on a missing path degrades to an empty walk on its own
        # (it does not raise), so a report of "nothing found" here would be
        # misleading unless it specifically says the path itself is the
        # problem. A merely non-empty notes list is not enough: the always-
        # present "no vulnerability report" note would satisfy that on its
        # own and mask a regression here.
        self.assertTrue(any("not a directory" in note for note in detection.notes))

    def test_root_that_is_a_file_not_a_directory_does_not_raise(self) -> None:
        root = _tree({"README.md": "# ok\n"})
        detection = detect_repo(root / "README.md")
        self.assertEqual(detection.artifacts, [])
        self.assertTrue(any("not a directory" in note for note in detection.notes))


class DetectRepoDeterminismTests(unittest.TestCase):
    def test_repeated_runs_produce_identical_output(self) -> None:
        root = _tree({
            "sboms/api.cdx.json": '{"bomFormat":"CycloneDX"}',
            "services/api/package-lock.json": "{}",
            "services/web/requirements.txt": "flask\n",
            "infra/main.tf": 'resource "x" "y" {}\n',
            "k8s/deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\n",
        })
        first = detect_repo(root)
        second = detect_repo(root)
        self.assertEqual(first, second)


class DetectRepoCollisionTests(unittest.TestCase):
    """Two artifacts sharing a candidate name must both be reported, distinctly."""

    def test_two_lockfile_directories_with_the_same_basename_are_both_reported(self) -> None:
        root = _tree({
            "backend/api/package-lock.json": "{}",
            "frontend/api/package-lock.json": "{}",
        })
        detection = detect_repo(root)
        sources = sorted(item.source for item in detection.artifacts if item.source)
        names = [item.name for item in detection.artifacts]
        self.assertEqual(sources, ["backend/api", "frontend/api"])
        self.assertEqual(len(names), len(set(names)), f"duplicate names: {names}")

    def test_two_sboms_with_the_same_stem_are_both_reported(self) -> None:
        root = _tree({
            "sboms/api.cdx.json": '{"bomFormat":"CycloneDX"}',
            "archive/api.cdx.json": '{"bomFormat":"CycloneDX"}',
        })
        detection = detect_repo(root)
        boms = sorted(item.sbom for item in detection.artifacts if item.sbom)
        names = [item.name for item in detection.artifacts]
        self.assertEqual(boms, ["archive/api.cdx.json", "sboms/api.cdx.json"])
        self.assertEqual(len(names), len(set(names)), f"duplicate names: {names}")

    def test_multiple_lockfiles_in_the_same_directory_produce_one_artifact(self) -> None:
        root = _tree({"app/poetry.lock": "", "app/requirements.txt": "flask\n"})
        detection = detect_repo(root)
        self.assertEqual([item.source for item in detection.artifacts], ["app"])

    def test_triple_collision_falls_back_to_a_numbered_name(self) -> None:
        # "api.cdx.json" at root claims "api". "sub/api.cdx.json" collides on
        # "api" and falls back to "sub-api". A third file literally named
        # "sub-api.cdx.json" then collides with *that* fallback too, forcing
        # the numeric-suffix branch -- neither of the first two strategies
        # is enough, but the artifact must still be reported, not dropped.
        root = _tree({
            "api.cdx.json": '{"bomFormat":"CycloneDX"}',
            "sub-api.cdx.json": '{"bomFormat":"CycloneDX"}',
            "sub/api.cdx.json": '{"bomFormat":"CycloneDX"}',
        })
        detection = detect_repo(root)
        names = [item.name for item in detection.artifacts]
        boms = [item.sbom for item in detection.artifacts]
        self.assertEqual(len(names), len(set(names)), f"duplicate names: {names}")
        self.assertEqual(len(boms), 3)
        self.assertIn("sub-api-2", names)

    def test_quadruple_collision_advances_past_a_taken_numbered_name(self) -> None:
        # Same as above, plus a fourth file that claims "sub-api-2" outright
        # before the colliding one is processed, forcing the numeric loop to
        # advance past its first candidate too.
        root = _tree({
            "api.cdx.json": '{"bomFormat":"CycloneDX"}',
            "sub-api.cdx.json": '{"bomFormat":"CycloneDX"}',
            "sub-api-2.cdx.json": '{"bomFormat":"CycloneDX"}',
            "sub/api.cdx.json": '{"bomFormat":"CycloneDX"}',
        })
        detection = detect_repo(root)
        names = [item.name for item in detection.artifacts]
        self.assertEqual(len(names), len(set(names)), f"duplicate names: {names}")
        self.assertIn("sub-api-3", names)


class DetectRepoTerraformPlanTests(unittest.TestCase):
    def test_detects_an_existing_terraform_plan_json(self) -> None:
        root = _tree({
            "reachability/tfplan.json": '{"format_version": "1.2", "planned_values": {}}',
        })
        detection = detect_repo(root)
        self.assertEqual(detection.terraform, "reachability/tfplan.json")

    def test_does_not_suggest_generating_a_plan_when_one_already_exists(self) -> None:
        root = _tree({
            "infra/main.tf": 'resource "x" "y" {}\n',
            "tfplan.json": '{"format_version": "1.2", "planned_values": {}}',
        })
        detection = detect_repo(root)
        self.assertEqual(detection.terraform, "tfplan.json")
        self.assertEqual(detection.terraform_source, "infra")
        self.assertFalse(any("plan gives far better" in note for note in detection.notes))

    def test_suggests_generating_a_plan_when_only_source_exists(self) -> None:
        root = _tree({"infra/main.tf": 'resource "x" "y" {}\n'})
        detection = detect_repo(root)
        self.assertIsNone(detection.terraform)
        note = next(n for n in detection.notes if "plan gives far better" in n)
        self.assertIn("terraform -chdir=infra plan", note)
        self.assertIn("terraform -chdir=infra show -json tfplan.binary > tfplan.json", note)

    def test_unrelated_json_named_plan_but_not_shaped_like_one_is_ignored(self) -> None:
        root = _tree({"docs/migration-plan.json": '{"steps": ["a", "b"]}'})
        detection = detect_repo(root)
        self.assertIsNone(detection.terraform)

    def test_plan_named_fifo_is_not_opened_and_is_not_treated_as_a_plan(self) -> None:
        root = _tree({})
        os.mkfifo(root / "tfplan.json")
        detection = detect_repo(root)
        self.assertIsNone(detection.terraform)


class DetectRepoSbomImageTests(unittest.TestCase):
    def test_extracts_container_image_from_sbom_metadata(self) -> None:
        sbom = json.dumps({
            "bomFormat": "CycloneDX",
            "metadata": {
                "component": {
                    "name": "api",
                    "properties": [
                        {"name": "container:image", "value": "registry.example.com/team/api:1.2.3"}
                    ],
                }
            },
        })
        root = _tree({"sboms/api.cdx.json": sbom})
        detection = detect_repo(root)
        self.assertEqual(detection.artifacts[0].image, "registry.example.com/team/api:1.2.3")

    def test_sbom_without_image_property_leaves_image_none(self) -> None:
        root = _tree({"sboms/api.cdx.json": '{"bomFormat":"CycloneDX","components":[]}'})
        detection = detect_repo(root)
        self.assertIsNone(detection.artifacts[0].image)

    def test_malformed_sbom_json_does_not_crash_and_sbom_is_still_reported(self) -> None:
        root = _tree({"sboms/api.cdx.json": "{not valid json"})
        detection = detect_repo(root)
        self.assertEqual(detection.artifacts[0].sbom, "sboms/api.cdx.json")
        self.assertIsNone(detection.artifacts[0].image)

    def test_sbom_that_is_a_json_array_not_an_object_does_not_crash(self) -> None:
        root = _tree({"sboms/api.cdx.json": "[]"})
        detection = detect_repo(root)
        self.assertEqual(detection.artifacts[0].sbom, "sboms/api.cdx.json")
        self.assertIsNone(detection.artifacts[0].image)

    def test_non_dict_property_entries_are_skipped(self) -> None:
        sbom = json.dumps({
            "metadata": {"component": {"properties": ["not-a-dict", 42, None]}}
        })
        root = _tree({"sboms/api.cdx.json": sbom})
        detection = detect_repo(root)
        self.assertIsNone(detection.artifacts[0].image)

    def test_properties_present_but_none_match_the_image_names(self) -> None:
        sbom = json.dumps({
            "metadata": {
                "component": {
                    "properties": [{"name": "owner", "value": "team-name"}]
                }
            }
        })
        root = _tree({"sboms/api.cdx.json": sbom})
        detection = detect_repo(root)
        self.assertIsNone(detection.artifacts[0].image)

    def test_image_property_with_a_non_string_value_is_ignored(self) -> None:
        sbom = json.dumps({
            "metadata": {
                "component": {
                    "properties": [{"name": "container:image", "value": None}]
                }
            }
        })
        root = _tree({"sboms/api.cdx.json": sbom})
        detection = detect_repo(root)
        self.assertIsNone(detection.artifacts[0].image)

    def test_oversized_sbom_skips_image_extraction_but_still_reports_the_sbom(self) -> None:
        sbom = json.dumps({
            "metadata": {
                "component": {
                    "properties": [{"name": "container:image", "value": "example/api:1"}]
                }
            }
        })
        root = _tree({"sboms/api.cdx.json": sbom})
        original_cap = config_detect.MAX_SBOM_IMAGE_SNIFF_BYTES
        config_detect.MAX_SBOM_IMAGE_SNIFF_BYTES = 4
        try:
            detection = detect_repo(root)
        finally:
            config_detect.MAX_SBOM_IMAGE_SNIFF_BYTES = original_cap
        self.assertEqual(detection.artifacts[0].sbom, "sboms/api.cdx.json")
        self.assertIsNone(detection.artifacts[0].image)


class DetectRepoMiscTests(unittest.TestCase):
    def test_root_level_kubernetes_manifest_is_detected(self) -> None:
        root = _tree({"deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\n"})
        detection = detect_repo(root)
        self.assertEqual(detection.kubernetes, ".")

    def test_vulnerability_note_names_a_concrete_sbom_when_one_exists(self) -> None:
        root = _tree({"sboms/api.cdx.json": '{"bomFormat":"CycloneDX"}'})
        detection = detect_repo(root)
        note = next(n for n in detection.notes if "grype" in n)
        self.assertIn("grype sbom:sboms/api.cdx.json", note)

    def test_vulnerability_note_is_generic_when_no_sbom_exists(self) -> None:
        detection = detect_repo(_tree({"README.md": "# x\n"}))
        note = next(n for n in detection.notes if "grype" in n)
        self.assertIn("<artifact>", note)

    def test_lockfile_ecosystems_all_have_an_sbom_command(self) -> None:
        self.assertTrue(set(LOCKFILE_ECOSYSTEMS.values()) <= set(SBOM_COMMANDS.keys()))

    def test_an_ecosystem_missing_its_sbom_command_is_reported_without_a_broken_note(self) -> None:
        # This can only happen if LOCKFILE_ECOSYSTEMS and SBOM_COMMANDS drift out of
        # sync (guarded above); simulate that drift directly to prove the runtime
        # guard degrades safely instead of emitting a note with a missing command.
        root = _tree({"services/api/package-lock.json": "{}"})
        original = dict(config_detect.SBOM_COMMANDS)
        del config_detect.SBOM_COMMANDS["npm"]
        try:
            detection = detect_repo(root)
        finally:
            config_detect.SBOM_COMMANDS.clear()
            config_detect.SBOM_COMMANDS.update(original)
        self.assertEqual(detection.artifacts[0].ecosystem, "npm")
        self.assertFalse(any("no SBOM found" in note for note in detection.notes))

    def test_an_existing_vulnerability_report_is_detected_and_suppresses_the_note(self) -> None:
        root = _tree({
            "sboms/api.cdx.json": '{"bomFormat":"CycloneDX"}',
            "grype.json": "[]",
        })
        detection = detect_repo(root)
        self.assertEqual(detection.vulnerabilities, ["grype.json"])
        self.assertFalse(any("No vulnerability report found" in note for note in detection.notes))


class DetectRepoScaleTests(unittest.TestCase):
    def test_large_but_plausible_tree_is_not_truncated(self) -> None:
        root = Path(tempfile.mkdtemp())
        for index in range(1500):
            package_dir = root / f"pkg{index}"
            package_dir.mkdir()
            (package_dir / "file.txt").write_text("x", encoding="utf-8")
        detection = detect_repo(root)
        self.assertFalse(any("stopped early" in note for note in detection.notes))

    def test_pathological_tree_trips_the_circuit_breaker(self) -> None:
        root = Path(tempfile.mkdtemp())
        original_cap = config_detect.MAX_FILES_SCANNED
        config_detect.MAX_FILES_SCANNED = 50
        try:
            for index in range(200):
                (root / f"file{index}.txt").write_text("x", encoding="utf-8")
            detection = detect_repo(root)
        finally:
            config_detect.MAX_FILES_SCANNED = original_cap
        self.assertTrue(any("stopped early" in note for note in detection.notes))


if __name__ == "__main__":
    unittest.main()
