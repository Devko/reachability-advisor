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

    def test_a_deeply_nested_collision_produces_a_bounded_unique_name(self) -> None:
        # Regression: YAML limits an implicit mapping key to 1024 characters. The old
        # fallback (identity.replace("/", "-")) used the *entire* relative path with
        # no bound at all -- reproduced end to end: a 120-level-deep collision like
        # this one used to produce a name over 1200 characters, which `init` would
        # happily write and report success for, and `load_config` could never parse
        # back ("while scanning a simple key"). See config_detect._bounded_fallback_name.
        root = _tree({"api/package-lock.json": "{}"})
        deep = root
        for i in range(120):
            deep = deep / f"directory{i:03d}"
        (deep / "api").mkdir(parents=True)
        (deep / "api" / "package-lock.json").write_text("{}", encoding="utf-8")

        detection = detect_repo(root)
        names = [item.name for item in detection.artifacts]
        self.assertEqual(len(names), len(set(names)), f"duplicate names: {names}")
        too_long = [name for name in names if len(name) > config_detect.MAX_ARTIFACT_NAME_LENGTH]
        self.assertEqual(too_long, [], f"name(s) exceeded the bound: {too_long}")


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
        self.assertFalse(any("plan gives far better" in note for note in detection.notes))

    def test_terraform_source_is_not_set_when_a_rendered_plan_is_also_present(self) -> None:
        # Final-review blocker: detect_repo used to set BOTH iac.terraform and
        # iac.terraform_source whenever a repository had a rendered plan alongside `.tf`
        # source -- a completely ordinary shape (checked-in plan + the source it was
        # rendered from). `init` wrote that as a valid-looking config, and `scan` (cli.py:
        # "Choose one Terraform input") immediately refused it: `init` exit 0, `scan`
        # exit 2 on the very config `init` just wrote. A rendered plan is strictly
        # stronger evidence than static HCL, so it is always preferred; terraform_source
        # must stay unset, not merely deprioritized, and the config the schema/CLI would
        # actually reject must never be producible by `init` in the first place.
        root = _tree({
            "infra/main.tf": 'resource "x" "y" {}\n',
            "tfplan.json": '{"format_version": "1.2", "planned_values": {}}',
        })
        detection = detect_repo(root)
        self.assertEqual(detection.terraform, "tfplan.json")
        self.assertIsNone(detection.terraform_source)
        # The user still deserves to know the source tree exists and why it was skipped.
        self.assertTrue(
            any("Terraform source also found in infra" in note for note in detection.notes),
            detection.notes,
        )

    def test_init_never_writes_both_terraform_keys_and_the_resulting_config_loads(self) -> None:
        # End-to-end version of the test above, through `init` and `load_config`: pins
        # that the *written config* -- not just the in-memory Detection -- never contains
        # both keys, and that config_schema/cli would accept it (scan's own conflict
        # check, mirrored in doctor.py, is exercised separately in test_doctor.py's
        # DiagnoseTests.test_terraform_plan_and_terraform_source_both_declared_is_a_conflict).
        from reachability_advisor.cli import main
        from reachability_advisor.config import CONFIG_FILENAME, load_config

        root = _tree({
            "infra/main.tf": 'resource "x" "y" {}\n',
            "tfplan.json": '{"format_version": "1.2", "planned_values": {}}',
        })
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertIn("terraform", loaded.config.iac)
        self.assertNotIn("terraform_source", loaded.config.iac)

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


class BoundedFallbackNameTests(unittest.TestCase):
    """Direct unit tests for the truncate-plus-hash scheme fixing Critical 1."""

    def test_a_short_name_is_left_untouched(self) -> None:
        self.assertEqual(config_detect._bounded_fallback_name("services-api"), "services-api")

    def test_a_name_at_exactly_the_limit_is_left_untouched(self) -> None:
        name = "a" * config_detect.MAX_ARTIFACT_NAME_LENGTH
        self.assertEqual(config_detect._bounded_fallback_name(name), name)

    def test_a_name_one_over_the_limit_is_truncated(self) -> None:
        name = "a" * (config_detect.MAX_ARTIFACT_NAME_LENGTH + 1)
        bounded = config_detect._bounded_fallback_name(name)
        self.assertLessEqual(len(bounded), config_detect.MAX_ARTIFACT_NAME_LENGTH)
        self.assertNotEqual(bounded, name)

    def test_two_long_names_sharing_a_prefix_do_not_collide_after_truncation(self) -> None:
        # Without hashing the *whole* original string, two artifacts nested under a
        # long shared ancestor path would truncate to the exact same fallback name.
        prefix = "shared-ancestor-directory-" * 10
        name_a = config_detect._bounded_fallback_name(prefix + "service-a")
        name_b = config_detect._bounded_fallback_name(prefix + "service-b")
        self.assertNotEqual(name_a, name_b)
        self.assertLessEqual(len(name_a), config_detect.MAX_ARTIFACT_NAME_LENGTH)
        self.assertLessEqual(len(name_b), config_detect.MAX_ARTIFACT_NAME_LENGTH)

    def test_non_utf8_clean_names_are_bounded_without_crashing(self) -> None:
        # A real, untrusted repository can produce a path containing a lone surrogate
        # (os.walk decodes non-UTF8 filenames with surrogateescape). Hashing must not
        # raise UnicodeEncodeError on that input.
        name = "d\udcffir/" * 200 + "tail"
        bounded = config_detect._bounded_fallback_name(name)
        self.assertLessEqual(len(bounded), config_detect.MAX_ARTIFACT_NAME_LENGTH)


class CandidateNameSharingTests(unittest.TestCase):
    """config_render.py's duplicate-detection asks this module the exact question
    detect_repo already answered (via artifact_candidate_name), instead of keeping
    its own, independently-diverging copy of the algorithm -- see Important 5."""

    def test_sbom_candidate_name_strips_a_known_suffix(self) -> None:
        self.assertEqual(config_detect.sbom_candidate_name("sboms/api.cdx.json"), "api")

    def test_sbom_candidate_name_falls_back_to_the_whole_stem_for_an_unknown_suffix(self) -> None:
        self.assertEqual(config_detect.sbom_candidate_name("sboms/api.json"), "api.json")

    def test_source_candidate_name_uses_the_directory_basename(self) -> None:
        self.assertEqual(config_detect.source_candidate_name("services/api", "myrepo"), "api")

    def test_source_candidate_name_falls_back_to_root_name_for_the_repository_root(self) -> None:
        self.assertEqual(config_detect.source_candidate_name(".", "myrepo"), "myrepo")

    def test_artifact_candidate_name_for_a_root_source_needs_a_known_root_name(self) -> None:
        # Without a known root name (e.g. a hand-built Detection with root_name=""), a
        # source of "." has no candidate to derive -- under-flagging a possible
        # duplicate is the safe failure mode, not inventing a name.
        self.assertIsNone(
            config_detect.artifact_candidate_name(sbom=None, source=".", root_name="")
        )
        self.assertEqual(
            config_detect.artifact_candidate_name(sbom=None, source=".", root_name="myrepo"),
            "myrepo",
        )

    def test_artifact_candidate_name_prefers_sbom_over_source(self) -> None:
        self.assertEqual(
            config_detect.artifact_candidate_name(
                sbom="sboms/api.cdx.json", source="services/other", root_name="myrepo"
            ),
            "api",
        )

    def test_artifact_candidate_name_is_none_with_neither_sbom_nor_source(self) -> None:
        self.assertIsNone(
            config_detect.artifact_candidate_name(sbom=None, source=None, root_name="myrepo")
        )


if __name__ == "__main__":
    unittest.main()
