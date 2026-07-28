# tests/test_config_init.py
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import yaml

import reachability_advisor.config_render as config_render
from reachability_advisor.cli import main
from reachability_advisor.config import CONFIG_FILENAME, load_config
from reachability_advisor.config_detect import DetectedArtifact, Detection, detect_repo
from reachability_advisor.config_render import RenderConfigError, render_config


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

    # -- TOCTOU: a file appearing between the exists() check and the write --------

    def test_a_file_created_between_the_exists_check_and_the_write_is_not_clobbered(
        self,
    ) -> None:
        # Regression: the old code's final write was `target.write_text(rendered)`,
        # unconditional after an earlier `target.exists()` check -- a file created in
        # that window would be silently overwritten, exit 0, no warning. Patching
        # Path.exists to always report False reproduces exactly that stale read
        # (cmd_init's own checks now see "does not exist") without needing a second,
        # real concurrent process; a real, pre-existing config file is still sitting
        # on disk the whole time. Exclusive creation ("x" mode) is what must still
        # refuse to overwrite it regardless of what the earlier check believed.
        root = _repo({"sboms/api.cdx.json": "{}"})
        target = root / CONFIG_FILENAME
        target.write_text("version: 1\n# a real, pre-existing config\n", encoding="utf-8")

        with mock.patch.object(Path, "exists", return_value=False):
            code = main(["init", "--root", str(root)])

        self.assertEqual(code, 2)
        self.assertIn("# a real, pre-existing config", target.read_text(encoding="utf-8"))

    # -- dangling symlink: refuse rather than write through it (Minor 6) ----------

    def test_writing_through_a_dangling_symlink_refuses_rather_than_following_it(self) -> None:
        root = _repo({"sboms/api.cdx.json": "{}"})
        target = root / CONFIG_FILENAME
        missing = root / "does-not-exist.yml"
        target.symlink_to(missing)

        self.assertEqual(main(["init", "--root", str(root)]), 2)
        self.assertTrue(target.is_symlink(), "the symlink itself must be left alone")
        self.assertFalse(missing.exists(), "must never silently create the resolved target")

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

    def test_a_source_at_the_repository_root_is_flagged_against_a_same_named_sbom(
        self,
    ) -> None:
        # Important 5 regression: for source == ".", detect_repo gives the artifact
        # the real candidate root.name -- but the old config_render._natural_key
        # independently recomputed PurePosixPath(".").name, which is always empty,
        # and returned None instead, so a genuine duplicate that config_detect itself
        # would flag went unflagged. Reproduced here with an SBOM whose stem equals
        # the repository's own directory name, alongside a lockfile-derived artifact
        # whose source is the repo root -- exactly the pairing that must now match.
        root = _repo({})
        (root / f"{root.name}.cdx.json").write_text("{}", encoding="utf-8")
        (root / "package-lock.json").write_text("{}", encoding="utf-8")

        detection = detect_repo(root)
        self.assertEqual(detection.root_name, root.name)
        self.assertEqual(len(detection.artifacts), 2)
        sboms = [a for a in detection.artifacts if a.sbom]
        sources = [a for a in detection.artifacts if a.source == "."]
        self.assertEqual(len(sboms), 1)
        self.assertEqual(len(sources), 1)

        self.assertEqual(main(["init", "--root", str(root)]), 0)
        text = (root / CONFIG_FILENAME).read_text(encoding="utf-8")
        self.assertIn("duplicate", text.lower())
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertEqual(len(loaded.config.artifacts), 2)

    # -- YAML's 1024-character simple-key limit (Critical 1) --------------

    def test_a_deeply_nested_duplicate_directory_still_produces_a_loadable_config(
        self,
    ) -> None:
        # Reproduces the reviewer's exact repro end to end: two directories named
        # "api", one nested 120 levels deep. The old fallback name
        # (identity.replace("/", "-"), the full relative path) exceeded YAML's
        # 1024-character implicit-mapping-key limit -- `init` still reported exit 0,
        # and load_config then failed with "while scanning a simple key". This must
        # now both succeed and load back cleanly.
        root = _repo({"api/package-lock.json": "{}"})
        deep = root
        for i in range(120):
            deep = deep / f"directory{i:03d}"
        (deep / "api").mkdir(parents=True)
        (deep / "api" / "package-lock.json").write_text("{}", encoding="utf-8")

        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertEqual(len(loaded.config.artifacts), 2)

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

    def test_control_character_in_a_detected_name_still_loads_back(self) -> None:
        # Critical 2 regression, reproduced end to end: a name containing a raw
        # control character (here \x01) used to land unescaped in a `# TODO`
        # comment -- `_comment` only handled \r and \n. YAML forbids an unescaped
        # control byte *anywhere* in a document, so the whole file failed to parse
        # (confirmed directly: yaml.safe_load raised "special characters are not
        # allowed"), while `init` still reported success. See config_render._comment.
        hostile_dir = "we\x01ird"
        root = _repo({f"{hostile_dir}/package-lock.json": "{}"})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        text = (root / CONFIG_FILENAME).read_text(encoding="utf-8")
        self.assertNotIn("\x01", text)
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

    def test_a_source_that_is_the_repository_root_is_flagged_when_root_name_is_known(
        self,
    ) -> None:
        # Important 5 regression, at the render_config level directly (see
        # InitTests.test_a_source_at_the_repository_root_is_flagged_against_a_same_named_sbom
        # for the full detect_repo -> init -> load_config version). With a known
        # `root_name` -- exactly what detect_repo always sets -- a source of "."
        # shares its candidate name with an SBOM whose stem equals that root name,
        # and must now be flagged, unlike the unknown-root_name case above.
        detection = Detection(
            root_name="myrepo",
            artifacts=[
                DetectedArtifact(name="myrepo", sbom="sboms/myrepo.cdx.json"),
                DetectedArtifact(name="root-svc", source="."),
            ],
        )
        rendered = render_config(detection)
        self.assertIn("duplicate", rendered.lower())
        self.assertIn("root-svc", rendered)


class RenderConfigGateBlockTests(unittest.TestCase):
    """Important 4: pin the `gate:` block actually being emitted.

    Deleting all three `gate:`-emitting lines from `render_config` left all existing
    tests green before this class existed: `GateConfig`'s dataclass defaults
    coincidentally match the hardcoded values, and a missing `gate:` key degrades
    cleanly to `{}` in validate_config. Asserting only on `loaded.config.gate.*`
    cannot tell "explicitly written" apart from "defaulted because absent" -- so this
    parses the *raw* YAML text directly (bypassing schema defaulting entirely) and
    checks the key is actually there, in addition to checking the rendered text.
    """

    def test_gate_block_is_present_in_the_rendered_text(self) -> None:
        rendered = render_config(Detection())
        self.assertIn("\ngate:\n", rendered)
        self.assertIn("  profile: advisory", rendered)
        self.assertIn("  fail_on: high", rendered)

    def test_gate_block_is_present_in_the_raw_parsed_yaml_not_just_schema_defaults(
        self,
    ) -> None:
        rendered = render_config(Detection())
        raw = yaml.safe_load(rendered)
        # Parsed with plain yaml.safe_load, not load_config/validate_config: this
        # mapping has no schema defaults applied at all, so "gate" in raw can only be
        # true if render_config actually wrote the key.
        self.assertIn("gate", raw)
        self.assertEqual(raw["gate"], {"profile": "advisory", "fail_on": "high"})


class ScalarQuotingTests(unittest.TestCase):
    """Regression tests for characters that corrupt in single quotes."""

    def test_nel_character_round_trips_through_scalar(self) -> None:
        # NEL (U+0085, NEXT LINE) corrupts silently in single quotes: PyYAML folds it
        # to a space, causing 'svc\x85name' to parse as 'svc name'. The fix uses
        # double quotes for NEL-containing values.
        nel_value = "svc\x85name"
        scalar = config_render._scalar(nel_value)
        parsed = yaml.safe_load(scalar)
        self.assertEqual(parsed, nel_value, f"NEL char corrupted: got {repr(parsed)}")

    def test_nel_as_artifact_path(self) -> None:
        # End-to-end test: a detected path containing NEL survives init and load.
        nel_dir = "path\x85with\x85nel"
        root = _repo({f"sboms/{nel_dir}/api.cdx.json": "{}"})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        artifact = next(iter(loaded.config.artifacts.values()))
        self.assertEqual(artifact.sbom, f"sboms/{nel_dir}/api.cdx.json")

    def test_nel_as_artifact_name(self) -> None:
        # NEL in an artifact name (which becomes a YAML mapping key).
        nel_dir = "api\x85service"
        root = _repo({f"{nel_dir}/package-lock.json": "{}"})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertIn(nel_dir, loaded.config.artifacts)
        self.assertEqual(loaded.config.artifacts[nel_dir].source, nel_dir)


class RenderConfigRoundTripGuardTests(unittest.TestCase):
    """The general guard: render_config must refuse to return a document it cannot
    load and validate back, rather than hand back something broken with no error.
    """

    def test_guard_rejects_yaml_that_does_not_parse(self) -> None:
        with self.assertRaises(RenderConfigError):
            config_render._verify_round_trips("version: 1\n  bad: [1, 2\n")

    def test_guard_rejects_a_document_that_fails_schema_validation(self) -> None:
        with self.assertRaises(RenderConfigError):
            config_render._verify_round_trips("gate:\n  profile: not-a-real-profile\n")

    def test_guard_accepts_a_well_formed_document(self) -> None:
        config_render._verify_round_trips("version: 1\n")  # must not raise

    def test_render_config_raises_if_an_artifact_name_is_too_long_to_load_back(self) -> None:
        # render_config is a public function accepting any Detection -- even one
        # whose artifact name was never bounded by config_detect (e.g. a hand-built
        # Detection, or some future detection code path that forgets to bound it).
        # The guard must catch this class of defect regardless of which code path
        # produced the too-long name, not only detect_repo's own fallback.
        too_long_name = "x" * 1200
        detection = Detection(artifacts=[DetectedArtifact(name=too_long_name, source="src")])
        with self.assertRaises(RenderConfigError):
            render_config(detection)

    def test_render_config_raises_instead_of_returning_broken_yaml_if_comment_sanitizing_regresses(
        self,
    ) -> None:
        # Simulates a future regression reintroducing exactly the Critical-2 defect
        # (an unescaped control character reaching a comment) by neutering _comment
        # itself. Proves the general guard is an independent safety net, not just a
        # restatement of "the two known causes are fixed": render_config must fail
        # loudly here even though the specific bug that motivated the guard no longer
        # exists in _comment's real implementation.
        detection = Detection(notes=["poisoned"])
        original_comment = config_render._comment
        config_render._comment = lambda text: text.replace("poisoned", "poi\x01soned")
        try:
            with self.assertRaises(RenderConfigError):
                render_config(detection)
        finally:
            config_render._comment = original_comment


if __name__ == "__main__":
    unittest.main()
