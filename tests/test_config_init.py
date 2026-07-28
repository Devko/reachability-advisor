# tests/test_config_init.py
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.config import CONFIG_FILENAME, load_config
from reachability_advisor.config_detect import DetectedArtifact, Detection, detect_repo
from reachability_advisor.config_render import render_config


def _repo(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


class InitTests(unittest.TestCase):
    # -- brief's own tests, verbatim --------------------------------------

    def test_writes_a_config_that_loads_back(self) -> None:
        root = _repo({"sboms/api.cdx.json": '{"bomFormat":"CycloneDX","components":[]}'})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        written = root / CONFIG_FILENAME
        self.assertTrue(written.is_file())
        loaded = load_config(written)
        self.assertIn("api", loaded.config.artifacts)

    def test_records_missing_evidence_as_todo_comments(self) -> None:
        root = _repo({"app/package-lock.json": "{}"})
        main(["init", "--root", str(root)])
        text = (root / CONFIG_FILENAME).read_text(encoding="utf-8")
        self.assertIn("# TODO", text)
        self.assertIn("syft", text)

    def test_refuses_to_overwrite_an_existing_config(self) -> None:
        root = _repo({CONFIG_FILENAME: "version: 1\n"})
        self.assertEqual(main(["init", "--root", str(root)]), 2)
        self.assertEqual((root / CONFIG_FILENAME).read_text(encoding="utf-8"), "version: 1\n")

    def test_refresh_writes_a_side_file_instead_of_overwriting(self) -> None:
        root = _repo({
            CONFIG_FILENAME: "version: 1\n# keep this comment\n",
            "sboms/api.cdx.json": "{}",
        })
        self.assertEqual(main(["init", "--root", str(root), "--refresh"]), 0)
        self.assertIn("# keep this comment", (root / CONFIG_FILENAME).read_text(encoding="utf-8"))
        self.assertTrue((root / ".reachability.detected.yml").is_file())

    # -- exit codes and --refresh edge cases -------------------------------

    def test_refresh_on_a_repo_with_no_existing_config_writes_directly(self) -> None:
        # --refresh only exists to protect a config that is already there. When there
        # is nothing to protect, it must not turn into an error: a platform team
        # scripting `init --refresh` across many repos (some configured, some not)
        # needs the same command to work either way.
        root = _repo({"sboms/api.cdx.json": "{}"})
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["init", "--root", str(root), "--refresh"])
        self.assertEqual(code, 0)
        self.assertTrue((root / CONFIG_FILENAME).is_file())
        self.assertFalse((root / ".reachability.detected.yml").exists())
        self.assertIn(str(root / CONFIG_FILENAME), buffer.getvalue())

    def test_root_that_is_not_a_directory_exits_two(self) -> None:
        root = _repo({"marker.txt": "x"})
        not_a_dir = root / "marker.txt"
        self.assertEqual(main(["init", "--root", str(not_a_dir)]), 2)
        self.assertFalse((root / CONFIG_FILENAME).is_file())

    def test_root_that_does_not_exist_exits_two(self) -> None:
        root = _repo({})
        missing = root / "does-not-exist"
        self.assertEqual(main(["init", "--root", str(missing)]), 2)

    def test_successful_write_reports_the_next_step(self) -> None:
        root = _repo({"sboms/api.cdx.json": "{}"})
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["init", "--root", str(root)])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn(str(root / CONFIG_FILENAME), output)
        self.assertIn("doctor", output)

    # -- detects nothing: still valid, still teaches the next step --------

    def test_detects_nothing_still_writes_a_valid_and_loadable_config(self) -> None:
        root = _repo({"README.md": "hello"})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        text = (root / CONFIG_FILENAME).read_text(encoding="utf-8")
        self.assertIn("no artifacts detected", text)
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertEqual(loaded.config.artifacts, {})
        self.assertEqual(loaded.config.iac, {})
        self.assertEqual(loaded.config.gate.profile, "advisory")
        self.assertEqual(loaded.config.gate.fail_on, "high")

    def test_render_config_on_empty_detection_is_directly_callable(self) -> None:
        # render_config must not depend on detect_repo ever having been called; an
        # empty, all-defaults Detection is a legitimate input on its own.
        rendered = render_config(Detection())
        self.assertIn("version: 1", rendered)
        self.assertIn("no artifacts detected", rendered)

    # -- never invent a path: a lockfile-only repo never claims an SBOM ---

    def test_lockfile_only_repo_does_not_claim_an_sbom_and_still_validates(self) -> None:
        root = _repo({"services/api/package-lock.json": "{}"})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        artifact = loaded.config.artifacts["api"]
        self.assertIsNone(artifact.sbom)
        self.assertEqual(artifact.source, "services/api")
        # "ecosystem" is detection-only metadata, not part of the artifact schema
        # (config_schema.ARTIFACT_KEYS = {sbom, source, image, manifest}); it must
        # never be emitted as a real YAML key, or a perfectly valid detection would
        # make init write a config that fails its own strictness gate.
        text = (root / CONFIG_FILENAME).read_text(encoding="utf-8")
        self.assertNotIn("ecosystem:", text)
        # Right at the point of the gap, not just in the aggregate TODO block at
        # the top of the file: a reader scanning the "api:" artifact block itself
        # must see that it has no sbom, without having to cross-reference notes.
        self.assertIn("# TODO: no SBOM found for api", text)

    # -- possible duplicates: emitted separately, never silently merged ---

    def test_possible_duplicate_artifacts_are_both_emitted_with_a_todo(self) -> None:
        root = _repo({
            "sboms/api.cdx.json": '{"bomFormat":"CycloneDX","components":[]}',
            "app/api/package-lock.json": "{}",
        })
        detection = detect_repo(root)
        names = {artifact.name for artifact in detection.artifacts}
        self.assertEqual(names, {"api", "app-api"})  # pin config_detect's own naming

        self.assertEqual(main(["init", "--root", str(root)]), 0)
        text = (root / CONFIG_FILENAME).read_text(encoding="utf-8")

        loaded = load_config(root / CONFIG_FILENAME)
        # Both survive as distinct artifacts -- neither was dropped or merged.
        self.assertIn("api", loaded.config.artifacts)
        self.assertIn("app-api", loaded.config.artifacts)
        self.assertEqual(loaded.config.artifacts["api"].sbom, "sboms/api.cdx.json")
        self.assertEqual(loaded.config.artifacts["api"].source, None)
        self.assertEqual(loaded.config.artifacts["app-api"].source, "app/api")
        self.assertEqual(loaded.config.artifacts["app-api"].sbom, None)
        # And the user is told, by name, that these look like the same thing --
        # right inside each artifact's own block, not only in an aggregate note
        # at the top of the file a reader could miss while scanning "artifacts:".
        self.assertIn("duplicate", text.lower())
        self.assertIn("api", text)
        self.assertIn("app-api", text)
        self.assertIn("# TODO: possible duplicate of app-api", text)
        self.assertIn("# TODO: possible duplicate of api", text)

    def test_no_duplicate_todo_when_names_do_not_collide(self) -> None:
        root = _repo({
            "sboms/api.cdx.json": "{}",
            "services/billing/package-lock.json": "{}",
        })
        main(["init", "--root", str(root)])
        text = (root / CONFIG_FILENAME).read_text(encoding="utf-8")
        self.assertNotIn("duplicate", text.lower())

    # -- hostile-but-real paths must round-trip through load_config -------

    def test_hostile_characters_in_a_detected_path_round_trip(self) -> None:
        hostile_dir = "wei\"rd:'name# café%- [a,b]"
        root = _repo({f"sboms/{hostile_dir}/api.cdx.json": "{}"})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        artifact = next(iter(loaded.config.artifacts.values()))
        self.assertEqual(artifact.sbom, f"sboms/{hostile_dir}/api.cdx.json")

    def test_hostile_characters_in_an_artifact_name_round_trip(self) -> None:
        # The artifact *name* becomes a YAML mapping key, not just a value -- a
        # colon in a bare key would otherwise be read as introducing a nested
        # mapping.
        hostile_dir = "a: b # not a comment"
        root = _repo({f"{hostile_dir}/package-lock.json": "{}"})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertIn(hostile_dir, loaded.config.artifacts)
        self.assertEqual(loaded.config.artifacts[hostile_dir].source, hostile_dir)

    def test_embedded_newline_in_a_detected_sbom_value_round_trips(self) -> None:
        hostile_dir = "we\nird"
        root = _repo({f"sboms/{hostile_dir}/api.cdx.json": "{}"})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        artifact = next(iter(loaded.config.artifacts.values()))
        self.assertEqual(artifact.sbom, f"sboms/{hostile_dir}/api.cdx.json")

    def test_embedded_newline_in_an_artifact_name_round_trips(self) -> None:
        # Here the newline lands in the artifact's own name, which is rendered as a
        # bare YAML mapping *key* (`  {name}:`), not just a value. A single-quoted
        # multi-line key breaks the surrounding block mapping ("mapping values are
        # not allowed here") unless it is forced onto one physical line.
        hostile_dir = "we\nird"
        root = _repo({f"{hostile_dir}/package-lock.json": "{}"})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertIn(hostile_dir, loaded.config.artifacts)

    def test_vulnerability_reports_with_a_comma_in_the_directory_round_trip(self) -> None:
        # evidence.vulnerabilities is rendered as a YAML flow sequence ([a, b]),
        # where a comma is a structural separator -- a naively-joined, unquoted
        # path containing one would silently split into two list entries.
        hostile_dir = "reports, weird"
        root = _repo({f"{hostile_dir}/grype.json": "{}"})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertEqual(loaded.config.evidence["vulnerabilities"], (f"{hostile_dir}/grype.json",))

    def test_a_long_vulnerabilities_list_is_not_line_wrapped(self) -> None:
        # PyYAML wraps a long flow sequence at its default 80-column width; a
        # wrapped flow list still *parses* correctly (found by running `init`
        # against this project's own real vulnerability-report list, which is
        # long enough to hit the default width), but it is needlessly hard to
        # read and hand-edit in a file this tool explicitly writes for a human
        # to edit -- so it is still pinned here, not just left as a comment.
        files = {f"reports/service-{i:02d}/grype.json": "{}" for i in range(6)}
        root = _repo(files)
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        text = (root / CONFIG_FILENAME).read_text(encoding="utf-8")
        vulnerabilities_line = next(
            line for line in text.splitlines() if line.startswith("  vulnerabilities: [")
        )
        self.assertTrue(vulnerabilities_line.rstrip().endswith("]"))

    def test_a_long_path_with_spaces_does_not_get_line_wrapped(self) -> None:
        # PyYAML wraps a long scalar at its default 80-column width by inserting a
        # line-fold at an existing space, even with no quoting otherwise required.
        # When that value is an artifact's own name (a mapping key), the wrapped,
        # unindented continuation line breaks the surrounding block mapping
        # ("mapping values are not allowed here") -- found by running `init`
        # against this project's own real, long directory names.
        long_dir = "this is a very long directory name with many spaces in it " * 2
        root = _repo({f"{long_dir.strip()}/package-lock.json": "{}"})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertIn(long_dir.strip(), loaded.config.artifacts)

    def test_iac_paths_with_special_characters_round_trip(self) -> None:
        root = _repo({
            "infra: prod/main.tf": "resource \"x\" \"y\" {}\n",
        })
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertEqual(loaded.config.iac.get("terraform_source"), "infra: prod")

    # -- a fuller repo shape: rendered plan, kubernetes, and an SBOM-embedded image

    def test_full_repo_shape_renders_terraform_plan_kubernetes_and_image(self) -> None:
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
        root = _repo({
            "sboms/api.cdx.json": sbom,
            "reachability/tfplan.json": '{"format_version": "1.2", "planned_values": {}}',
            "k8s/deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\n",
        })
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        artifact = loaded.config.artifacts["api"]
        self.assertEqual(artifact.image, "registry.example.com/team/api:1.2.3")
        self.assertEqual(loaded.config.iac["terraform"], "reachability/tfplan.json")
        self.assertEqual(loaded.config.iac["kubernetes"], "k8s")


class RenderConfigDirectTests(unittest.TestCase):
    """Edge cases in `_natural_key`/`_duplicate_groups` that `detect_repo` itself
    never produces (every real `DetectedArtifact` always carries a `sbom` or a
    `source`), but that `render_config` -- a public function taking any
    `Detection` -- must still handle without crashing or over-flagging."""

    def test_spdx_and_cyclonedx_sboms_with_the_same_stem_are_flagged_as_duplicates(self) -> None:
        # Exercises SBOM_SUFFIXES actually being tried in order: the first entry
        # (.cdx.json) must not match "api.spdx.json", so the loop has to advance
        # to the second before it can find a shared natural key with "api.cdx.json".
        detection = Detection(artifacts=[
            DetectedArtifact(name="api", sbom="sboms/api.cdx.json"),
            DetectedArtifact(name="api-2", sbom="other/api.spdx.json"),
        ])
        rendered = render_config(detection)
        self.assertIn("duplicate", rendered.lower())
        self.assertIn("api-2", rendered)

    def test_natural_key_falls_back_to_the_whole_stem_for_an_unrecognized_sbom_suffix(self) -> None:
        detection = Detection(artifacts=[
            DetectedArtifact(name="a", sbom="weird/api.json"),
            DetectedArtifact(name="b", sbom="other/api.json"),
        ])
        rendered = render_config(detection)
        # Neither ".cdx.json" nor ".spdx.json" match "api.json", so the whole
        # filename is the fallback natural key -- both share it literally, so
        # they are still (correctly) flagged.
        self.assertIn("duplicate", rendered.lower())

    def test_artifacts_with_neither_sbom_nor_source_are_never_flagged_as_duplicates(self) -> None:
        detection = Detection(artifacts=[
            DetectedArtifact(name="a", image="registry.example/a:1"),
            DetectedArtifact(name="b", image="registry.example/a:1"),
        ])
        rendered = render_config(detection)
        self.assertNotIn("duplicate", rendered.lower())

    def test_a_source_that_is_the_repository_root_is_never_flagged_as_a_duplicate(self) -> None:
        detection = Detection(artifacts=[
            DetectedArtifact(name="root-svc", source="."),
            DetectedArtifact(name="other-root-svc", source="."),
        ])
        rendered = render_config(detection)
        self.assertNotIn("duplicate", rendered.lower())


if __name__ == "__main__":
    unittest.main()
