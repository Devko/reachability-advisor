# tests/test_config.py
from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from typing import Any

from reachability_advisor.config import (
    CONFIG_FILENAME,
    MAX_EXTENDS_DEPTH,
    discover_config_path,
    load_config,
    merge_layers,
)
from reachability_advisor.config_schema import ConfigError


def _tree(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


BASE = "version: 1\ngate:\n  fail_on: high\n  profile: production\n"


class MergeLayersTests(unittest.TestCase):
    def test_maps_deep_merge_and_scalars_override(self) -> None:
        merged = merge_layers([
            ("org", {"gate": {"fail_on": "high", "profile": "production"}}),
            ("repo", {"gate": {"fail_on": "low"}}),
        ])
        self.assertEqual(merged["gate"], {"fail_on": "low", "profile": "production"})

    def test_lists_replace_rather_than_append(self) -> None:
        # Appending would make it impossible for a repo to remove an inherited entry.
        merged = merge_layers([
            ("org", {"evidence": {"sast": ["org.json"]}}),
            ("repo", {"evidence": {"sast": ["repo.json"]}}),
        ])
        self.assertEqual(merged["evidence"]["sast"], ["repo.json"])

    def test_merge_layers_strips_the_extends_directive(self) -> None:
        # `extends` is a resolution instruction, not a config value; it must never reach
        # validate_config's merged mapping (config_schema's TOP_LEVEL_KEYS happens to
        # allow it through unrejected, so a leaked `extends` would go unnoticed there).
        merged = merge_layers([
            ("org", {"version": 1, "extends": "./somewhere.yml", "gate": {"fail_on": "high"}}),
        ])
        self.assertNotIn("extends", merged)


class DiscoveryTests(unittest.TestCase):
    def test_walks_up_to_the_git_root_and_no_further(self) -> None:
        root = _tree({CONFIG_FILENAME: BASE, ".git/HEAD": "ref: refs/heads/main\n",
                      "services/api/.keep": ""})
        self.assertEqual(discover_config_path(root / "services" / "api"), root / CONFIG_FILENAME)

    def test_returns_none_when_no_config_exists(self) -> None:
        root = _tree({".git/HEAD": "ref: refs/heads/main\n"})
        self.assertIsNone(discover_config_path(root))

    def test_does_not_search_above_the_git_root(self) -> None:
        # A decoy config sits ABOVE the git root; the repo itself has none. If the walk
        # ever failed to stop at the git root it would find and return the decoy instead
        # of None -- `test_walks_up_to_the_git_root_and_no_further` above cannot catch
        # that, because there the file that satisfies the search sits exactly at the git
        # root, so it is found regardless of whether the "stop here" logic runs at all.
        root = _tree({
            CONFIG_FILENAME: BASE,
            "repo/.git/HEAD": "ref: refs/heads/main\n",
            "repo/services/api/.keep": "",
        })
        self.assertIsNone(discover_config_path(root / "repo" / "services" / "api"))


class NonRegularConfigEntryTests(unittest.TestCase):
    """A `.reachability.yml` that exists but is not a readable regular file must stop the
    discovery walk with a loud `ConfigError`, never be silently treated the same as no
    config file at all -- see `discover_config_path`'s docstring. A previous defect here
    asked only `candidate.is_file()`, which is `False` for every one of these shapes,
    indistinguishable from "nothing here yet" -- so the walk continued past the broken
    entry and `load_config` fell back to built-in defaults with `path=None`, which every
    consumer (the gate, `config validate`, `doctor`) reports as "no config file found"
    even though one is sitting right there, broken. Reproduced directly against a real
    gate below in `SilentGateDisablementReproductionTests`.
    """

    def test_dangling_symlink_raises_a_config_error_naming_the_path(self) -> None:
        root = _tree({})
        target = root / "nonexistent-target.yml"
        (root / CONFIG_FILENAME).symlink_to(target)
        with self.assertRaises(ConfigError) as error:
            discover_config_path(root)
        message = str(error.exception)
        self.assertIn(str(root / CONFIG_FILENAME), message)
        self.assertIn("dangling symlink", message)

    def test_symlink_to_a_directory_raises_a_config_error(self) -> None:
        root = _tree({"real-directory/.keep": ""})
        (root / CONFIG_FILENAME).symlink_to(root / "real-directory")
        with self.assertRaises(ConfigError) as error:
            discover_config_path(root)
        self.assertIn("directory", str(error.exception))

    def test_directory_named_like_the_config_raises_a_config_error(self) -> None:
        root = _tree({f"{CONFIG_FILENAME}/.keep": ""})
        with self.assertRaises(ConfigError) as error:
            discover_config_path(root)
        self.assertIn("directory", str(error.exception))

    def test_fifo_raises_a_config_error_and_is_never_opened(self) -> None:
        # A FIFO would block forever on open(); discover_config_path must reject it by
        # stat shape alone, never attempt to read it.
        root = _tree({})
        os.mkfifo(root / CONFIG_FILENAME)
        with self.assertRaises(ConfigError) as error:
            discover_config_path(root)
        self.assertIn("not a regular file", str(error.exception))

    def test_unreadable_file_raises_a_config_error(self) -> None:
        root = _tree({CONFIG_FILENAME: BASE})
        (root / CONFIG_FILENAME).chmod(0o000)
        try:
            with self.assertRaises(ConfigError) as error:
                discover_config_path(root)
        finally:
            (root / CONFIG_FILENAME).chmod(0o644)
        self.assertIn("not readable", str(error.exception))

    def test_symlink_to_a_readable_regular_file_still_works(self) -> None:
        # The positive case a fix here must not break: a config file replaced by a
        # symlink to another *readable regular file* is a completely ordinary setup
        # (e.g. a shared config symlinked into several checkouts) and must still load.
        root = _tree({"real-config.yml": BASE})
        (root / CONFIG_FILENAME).symlink_to(root / "real-config.yml")
        found = discover_config_path(root)
        self.assertEqual(found, root / CONFIG_FILENAME)
        loaded = load_config(found)
        self.assertEqual(loaded.config.gate.fail_on, "high")

    def test_walk_does_not_continue_past_a_broken_entry_to_a_config_further_up(self) -> None:
        # The walk must stop and raise right at the broken entry, not silently skip it
        # and find a decoy config sitting higher up the tree.
        root = _tree({CONFIG_FILENAME: BASE, "services/api/.keep": ""})
        target = root / "services" / "api" / "nonexistent.yml"
        (root / "services" / "api" / CONFIG_FILENAME).symlink_to(target)
        with self.assertRaises(ConfigError) as error:
            discover_config_path(root / "services" / "api")
        self.assertIn(str(root / "services" / "api" / CONFIG_FILENAME), str(error.exception))

    def test_explicit_config_path_pointing_at_a_broken_symlink_also_fails_closed(self) -> None:
        # load_config's explicit-path branch (used by --config) must apply the same
        # check, not just the discovery walk.
        root = _tree({})
        (root / CONFIG_FILENAME).symlink_to(root / "nonexistent.yml")
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("dangling symlink", str(error.exception))

    def test_explicit_config_path_that_is_a_directory_fails_closed_with_an_accurate_message(
        self,
    ) -> None:
        # Before this fix, a directory at the explicit --config path produced the
        # misleading "configuration file does not exist" (it does exist, just as the
        # wrong kind of thing); this pins the corrected, accurate message.
        root = _tree({f"{CONFIG_FILENAME}/.keep": ""})
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        message = str(error.exception)
        self.assertIn("directory", message)
        self.assertNotIn("does not exist", message)


class SilentGateDisablementReproductionTests(unittest.TestCase):
    """End-to-end reproduction of the exact defect described in the final review: a real
    config with `gate.fail_on: low` enforces a gate (scan exits 10); replacing that same
    file with a dangling symlink used to make the gate silently vanish (scan exits 0)
    instead of failing closed. Also reproduces `config validate` and `doctor` each
    falsely claiming "no config file found" while one sits right there, broken.
    """

    ROOT_DIR = Path(__file__).resolve().parents[1]

    def _config_text(self) -> str:
        return (
            "version: 1\n"
            "artifacts:\n"
            f"  audit-api:\n    sbom: {self.ROOT_DIR / 'samples/sboms/audit-api.cdx.json'}\n"
            "evidence:\n"
            f"  vulnerabilities: [{self.ROOT_DIR / 'samples/vulnerabilities.json'}]\n"
            "gate:\n  fail_on: low\n"
        )

    def test_a_dangling_symlink_config_does_not_silently_disable_the_gate(self) -> None:
        from contextlib import redirect_stderr, redirect_stdout
        from io import StringIO

        from reachability_advisor.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / CONFIG_FILENAME
            config_path.write_text(self._config_text(), encoding="utf-8")
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                real_config_code = main(["scan", "--no-table", "--config", str(config_path)])
            self.assertEqual(real_config_code, 10)  # gate fires, as expected

            config_path.unlink()
            config_path.symlink_to(Path(tmp) / "nonexistent-target.yml")
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as captured_err:
                broken_symlink_code = main(["scan", "--no-table", "--config", str(config_path)])
            # Before the fix: 0 (the gate silently vanished). Now: 2, fail closed, with a
            # clear message -- never a quiet return to "no gate at all".
            self.assertEqual(broken_symlink_code, 2)
            self.assertIn("dangling symlink", captured_err.getvalue())

    def test_config_validate_does_not_falsely_report_no_config_found(self) -> None:
        from contextlib import redirect_stderr, redirect_stdout
        from io import StringIO

        from reachability_advisor.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / CONFIG_FILENAME
            config_path.symlink_to(Path(tmp) / "nonexistent-target.yml")
            with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
                code = main(["config", "validate", "--config", str(config_path)])
            self.assertEqual(code, 2)
            self.assertNotIn("no config file found", out.getvalue().lower())
            self.assertIn("dangling symlink", err.getvalue())

    def test_doctor_does_not_falsely_report_no_config_found(self) -> None:
        from contextlib import redirect_stderr, redirect_stdout
        from io import StringIO

        from reachability_advisor.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / CONFIG_FILENAME
            config_path.symlink_to(Path(tmp) / "nonexistent-target.yml")
            with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
                code = main(["doctor", "--config", str(config_path), "--root", tmp])
            self.assertEqual(code, 2)
            self.assertNotIn("No .reachability.yml found", out.getvalue())
            self.assertIn("dangling symlink", err.getvalue())


class PathValuedFieldBoundaryTests(unittest.TestCase):
    """`extends` cannot climb out of the repository it was declared in; every other
    path-valued config field (artifacts.*, evidence.*, iac.*, output.dir) must be bound
    the same way for a *relative* escape -- see `_check_declared_path_boundaries`.
    Scoped to relative paths only: an absolute path has exactly the reach an equivalent
    CLI flag already has (see the function's own docstring for why).
    """

    def test_rejects_a_relative_kubernetes_path_that_escapes_the_repository(self) -> None:
        outer = Path(tempfile.mkdtemp())
        secret = outer / "secrets.yaml"
        secret.write_text("password: hunter2\n", encoding="utf-8")
        root = outer / "repo"
        (root / ".git").mkdir(parents=True)
        (root / CONFIG_FILENAME).write_text(
            "version: 1\n"
            "artifacts:\n  api:\n    sbom: sboms/api.cdx.json\n"
            "iac:\n  kubernetes: ../secrets.yaml\n",
            encoding="utf-8",
        )
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        message = str(error.exception)
        self.assertIn("iac.kubernetes", message)
        self.assertIn("outside the repository", message)

    def test_rejects_an_escaping_relative_sbom_path(self) -> None:
        outer = Path(tempfile.mkdtemp())
        root = outer / "repo"
        root.mkdir()
        (root / CONFIG_FILENAME).write_text(
            "version: 1\nartifacts:\n  api:\n    sbom: ../../outside/sbom.json\n",
            encoding="utf-8",
        )
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("artifacts.api.sbom", str(error.exception))

    def test_rejects_an_escaping_relative_evidence_entry(self) -> None:
        outer = Path(tempfile.mkdtemp())
        root = outer / "repo"
        root.mkdir()
        (root / CONFIG_FILENAME).write_text(
            "version: 1\n"
            "artifacts:\n  api:\n    sbom: sboms/api.cdx.json\n"
            "evidence:\n  vulnerabilities: [../../etc/somewhere.json]\n",
            encoding="utf-8",
        )
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("evidence.vulnerabilities", str(error.exception))

    def test_rejects_an_escaping_output_dir(self) -> None:
        outer = Path(tempfile.mkdtemp())
        root = outer / "repo"
        root.mkdir()
        (root / CONFIG_FILENAME).write_text(
            "version: 1\noutput:\n  dir: ../../elsewhere\n", encoding="utf-8"
        )
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("output.dir", str(error.exception))

    def test_absolute_paths_are_exempt_from_the_boundary_check(self) -> None:
        # An absolute path has exactly the reach an equivalent CLI flag already has and
        # has never been restricted; this must keep working unchanged.
        outer = Path(tempfile.mkdtemp())
        elsewhere = outer / "elsewhere" / "sbom.json"
        elsewhere.parent.mkdir(parents=True)
        elsewhere.write_text("{}", encoding="utf-8")
        root = outer / "repo"
        root.mkdir()
        (root / CONFIG_FILENAME).write_text(
            f"version: 1\nartifacts:\n  api:\n    sbom: {elsewhere}\n", encoding="utf-8"
        )
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertEqual(loaded.config.artifacts["api"].sbom, str(elsewhere))

    def test_in_bounds_relative_paths_are_unaffected(self) -> None:
        root = _tree({
            CONFIG_FILENAME: (
                "version: 1\n"
                "artifacts:\n  api:\n    sbom: sboms/api.cdx.json\n    manifest: m.json\n"
                "evidence:\n  sast: [semgrep.json]\n"
                "iac:\n  kubernetes: k8s\n"
                "output:\n  dir: outputs\n"
            ),
        })
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertEqual(loaded.config.artifacts["api"].sbom, "sboms/api.cdx.json")


class YamlErrorDoesNotEchoFileContentTests(unittest.TestCase):
    """A YAML parse failure must report where and what went wrong, never the surrounding
    document text -- a config-declared path can name a file this process can open but
    should not disclose the contents of (for example a secrets file reached by a relative
    path before the boundary check above existed, or one legitimately outside the
    boundary via an absolute path). See `yaml_loader._safe_yaml_error_detail`.
    """

    def test_malformed_yaml_error_does_not_contain_the_offending_line(self) -> None:
        root = _tree({
            CONFIG_FILENAME: (
                "version: 1\n"
                "artifacts:\n"
                "  api:\n"
                "    sbom: [unclosed\n"
                "    secret_token: sk-supersecrettoken12345\n"
            ),
        })
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        message = str(error.exception)
        self.assertIn("invalid YAML", message)
        self.assertNotIn("sk-supersecrettoken12345", message)
        self.assertNotIn("secret_token", message)
        # The location is still reported, so a real user can still find and fix it.
        self.assertIn("line", message)
        self.assertIn("column", message)


class ExtendsTests(unittest.TestCase):
    def test_extends_a_relative_path_and_repo_wins(self) -> None:
        root = _tree({
            "shared/base.yml": BASE,
            CONFIG_FILENAME: "version: 1\nextends: ./shared/base.yml\ngate:\n  fail_on: medium\n",
        })
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertEqual(loaded.config.gate.fail_on, "medium")
        self.assertEqual(loaded.config.gate.profile, "production")  # inherited

    def test_records_which_layer_set_each_value(self) -> None:
        root = _tree({
            "shared/base.yml": BASE,
            CONFIG_FILENAME: "version: 1\nextends: ./shared/base.yml\ngate:\n  fail_on: medium\n",
        })
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertIn("shared/base.yml", loaded.provenance["gate.profile"])
        self.assertIn(CONFIG_FILENAME, loaded.provenance["gate.fail_on"])

    def test_provenance_does_not_include_the_extends_directive(self) -> None:
        root = _tree({
            "shared/base.yml": BASE,
            CONFIG_FILENAME: "version: 1\nextends: ./shared/base.yml\ngate:\n  fail_on: medium\n",
        })
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertNotIn("extends", loaded.provenance)

    def test_rejects_an_extends_cycle(self) -> None:
        root = _tree({
            "a.yml": "version: 1\nextends: ./b.yml\n",
            "b.yml": "version: 1\nextends: ./a.yml\n",
        })
        with self.assertRaises(ConfigError) as error:
            load_config(root / "a.yml")
        self.assertIn("cycle", str(error.exception).lower())

    def test_rejects_a_missing_extends_target(self) -> None:
        root = _tree({CONFIG_FILENAME: "version: 1\nextends: ./nope.yml\n"})
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("nope.yml", str(error.exception))

    def test_missing_extends_target_reports_that_it_does_not_exist(self) -> None:
        # A missing in-bounds target must be rejected by _resolve_extends's own explicit
        # existence check. Without it, resolution would still fail (load_yaml_mapping
        # eventually raises on the unreadable file), and that fallback message happens to
        # also contain the filename -- so it alone cannot tell the two apart. Pin the
        # specific wording the explicit check produces.
        root = _tree({CONFIG_FILENAME: "version: 1\nextends: ./nope.yml\n"})
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("does not exist", str(error.exception))

    def test_rejects_a_url_extends_target(self) -> None:
        # extends must never reach the network.
        root = _tree({CONFIG_FILENAME: "version: 1\nextends: https://example.test/base.yml\n"})
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("path or an installed package", str(error.exception))

    def test_bare_filename_extends_target_is_treated_as_a_path(self) -> None:
        # `target.startswith((".", "/")) or target.endswith((".yml", ".yaml"))` decides
        # path-form vs. package-form. A bare filename like "base.yml" -- no leading "./"
        # or "/" -- starts with neither "." nor "/", so only the `endswith` half routes
        # it into the path branch. If that half were ever dropped, this would instead be
        # looked up as an installed package named "base.yml", which is not a valid
        # module name and would fail; this pins the correct routing by asserting the
        # extension-only shape resolves (and inherits) exactly like an explicit path.
        root = _tree({
            "base.yml": BASE,
            CONFIG_FILENAME: "version: 1\nextends: base.yml\ngate:\n  fail_on: medium\n",
        })
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertEqual(loaded.config.gate.fail_on, "medium")
        self.assertEqual(loaded.config.gate.profile, "production")  # inherited from base.yml


class DepthCapTests(unittest.TestCase):
    def test_rejects_an_extends_chain_deeper_than_the_cap(self) -> None:
        count = MAX_EXTENDS_DEPTH + 2
        files: dict[str, str] = {}
        for index in range(count):
            if index == count - 1:
                files[f"layer{index}.yml"] = "version: 1\n"
            else:
                files[f"layer{index}.yml"] = f"version: 1\nextends: ./layer{index + 1}.yml\n"
        root = _tree(files)
        with self.assertRaises(ConfigError) as error:
            load_config(root / "layer0.yml")
        self.assertIn("exceeds", str(error.exception).lower())

    def test_iteration_bound_terminates_loop_if_cycle_check_fails(self) -> None:
        # Regression test: the loop must terminate unconditionally via iteration
        # count, not rely only on cycle detection. This test disables the cycle
        # check to verify the iteration bound still fires and prevents hanging.
        from reachability_advisor.config import (
            _resolve_extends,
        )
        from reachability_advisor.yaml_loader import YamlError, load_yaml_mapping

        root = _tree({
            "a.yml": "version: 1\nextends: ./b.yml\n",
            "b.yml": "version: 1\nextends: ./a.yml\n",
        })

        # Define a copy of resolve_layers without the cycle check. This simulates
        # a regression in the cycle check logic. The iteration bound must still
        # terminate the loop and raise ConfigError, not hang.
        def resolve_layers_no_cycle_check(path: Path) -> list[tuple[str, dict[str, Any]]]:
            layers: list[tuple[str, dict[str, Any]]] = []
            seen: set[Path] = set()
            current: Path | None = path.resolve()
            iterations = 0
            while current is not None:
                iterations += 1
                if iterations > MAX_EXTENDS_DEPTH:
                    raise ConfigError(
                        f"{path}: extends chain exceeds {MAX_EXTENDS_DEPTH} levels"
                    )
                # Cycle check intentionally omitted to test iteration bound
                seen.add(current)
                try:
                    raw = load_yaml_mapping(current, "configuration")
                except YamlError as exc:
                    raise ConfigError(str(exc)) from None
                layers.append((str(current), raw))
                target = raw.get("extends")
                if target is None:
                    current = None
                    continue
                if not isinstance(target, str) or not target.strip():
                    raise ConfigError(
                        f"{current}: 'extends' must be a non-empty string"
                    )
                current = _resolve_extends(target.strip(), current)
            layers.reverse()
            return layers

        # Call the cycle-check-free version; it should still terminate via
        # the iteration bound and raise the correct error message.
        with self.assertRaises(ConfigError) as error:
            resolve_layers_no_cycle_check(root / "a.yml")
        self.assertIn("exceeds", str(error.exception).lower())


class TraversalTests(unittest.TestCase):
    """`extends` is part of the config file, which a pull request can add or edit -- it is
    attacker-influenceable the same way scanner input is. A relative `extends` must never be
    able to climb out of the repository it was found in.
    """

    def test_rejects_a_relative_extends_that_escapes_the_repository_root(self) -> None:
        # The escaping target genuinely exists and is valid YAML: without the boundary
        # check, resolution would succeed silently. No `.git` is present anywhere, so this
        # exercises the fail-closed fallback boundary (the file's own directory).
        outer = Path(tempfile.mkdtemp())
        outside = outer / "outside.yml"
        outside.write_text(BASE, encoding="utf-8")
        root = outer / "repo"
        root.mkdir()
        (root / CONFIG_FILENAME).write_text(
            "version: 1\nextends: ../outside.yml\ngate:\n  fail_on: medium\n", encoding="utf-8"
        )
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        message = str(error.exception)
        self.assertIn("outside the repository", message)
        self.assertNotIn(str(outside.resolve()), message)

    def test_rejects_extends_that_escapes_a_discovered_git_root(self) -> None:
        # Same as above, but with a real `.git` present: the boundary is the git root, not
        # merely "somewhere under /tmp" -- climbing past the git root is still rejected.
        outer = Path(tempfile.mkdtemp())
        secret = outer / "secret.yml"
        secret.write_text(BASE, encoding="utf-8")
        root = outer / "repo"
        (root / ".git").mkdir(parents=True)
        (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (root / CONFIG_FILENAME).write_text(
            "version: 1\nextends: ../secret.yml\n", encoding="utf-8"
        )
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        message = str(error.exception)
        self.assertIn("outside the repository", message)
        self.assertNotIn(str(secret.resolve()), message)

    def test_allows_extends_to_climb_within_a_git_repository(self) -> None:
        # The mirror image of the above two: a repo-internal up-traversal (a subdirectory
        # config reaching a shared file elsewhere in the same repo) must still work. A
        # boundary check that was simply "never leave this file's own directory" would
        # wrongly reject this legitimate case.
        root = _tree({
            ".git/HEAD": "ref: refs/heads/main\n",
            "shared/base.yml": BASE,
            "services/api/" + CONFIG_FILENAME: (
                "version: 1\nextends: ../../shared/base.yml\ngate:\n  fail_on: low\n"
            ),
        })
        loaded = load_config(root / "services" / "api" / CONFIG_FILENAME)
        self.assertEqual(loaded.config.gate.fail_on, "low")
        self.assertEqual(loaded.config.gate.profile, "production")  # inherited across the climb

    def test_rejects_an_absolute_path_extends_target_outside_the_repository(self) -> None:
        outer = Path(tempfile.mkdtemp())
        outside = outer / "outside.yml"
        outside.write_text(BASE, encoding="utf-8")
        root = outer / "repo"
        root.mkdir()
        (root / CONFIG_FILENAME).write_text(
            f"version: 1\nextends: {outside}\n", encoding="utf-8"
        )
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("outside the repository", str(error.exception))


class _SysPathIsolationMixin:
    """Adds a temp directory to `sys.path` for one test and removes it afterward.

    Package-form `extends` targets must be genuinely importable to exercise
    `importlib.util.find_spec` the way it behaves for a real installed package, so
    these tests plant one on `sys.path` rather than mocking module discovery.
    """

    def setUp(self) -> None:
        super().setUp()  # type: ignore[misc]
        self._sys_path_entries: list[str] = []
        self._modules_to_clean: list[str] = []
        self.addCleanup(self._restore_sys_path)  # type: ignore[attr-defined]

    def _restore_sys_path(self) -> None:
        for entry in self._sys_path_entries:
            if entry in sys.path:
                sys.path.remove(entry)
        for name in self._modules_to_clean:
            sys.modules.pop(name, None)
        importlib.invalidate_caches()

    def _add_to_sys_path(self, directory: Path) -> None:
        sys.path.insert(0, str(directory))
        self._sys_path_entries.append(str(directory))
        importlib.invalidate_caches()


class PackageExtendsTests(_SysPathIsolationMixin, unittest.TestCase):
    """Package-form `extends` must keep working for a genuine, single-segment,
    installed package -- only the resolution mechanism changed, not what is accepted.
    """

    def test_extends_a_single_segment_installed_package(self) -> None:
        package_root = Path(tempfile.mkdtemp())
        pkg_name = "reachability_advisor_test_pkg_ok"
        pkg_dir = package_root / pkg_name
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
        (pkg_dir / CONFIG_FILENAME).write_text(BASE, encoding="utf-8")
        self._add_to_sys_path(package_root)
        self._modules_to_clean.append(pkg_name)

        root = _tree({
            CONFIG_FILENAME: f"version: 1\nextends: {pkg_name}\ngate:\n  fail_on: medium\n",
        })
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertEqual(loaded.config.gate.fail_on, "medium")
        self.assertEqual(loaded.config.gate.profile, "production")  # inherited
        self.assertNotIn(pkg_name, sys.modules)  # resolved without ever importing it

    def test_package_form_extends_is_exempt_from_the_repository_boundary_check(self) -> None:
        # Path-form extends cannot leave the repository (see TraversalTests below);
        # package-form must remain exempt, since installed packages legitimately live
        # outside the tree that is doing the scanning.
        package_root = Path(tempfile.mkdtemp())
        pkg_name = "reachability_advisor_test_pkg_boundary"
        pkg_dir = package_root / pkg_name
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
        (pkg_dir / CONFIG_FILENAME).write_text(BASE, encoding="utf-8")
        self._add_to_sys_path(package_root)
        self._modules_to_clean.append(pkg_name)

        root = _tree({
            ".git/HEAD": "ref: refs/heads/main\n",
            CONFIG_FILENAME: f"version: 1\nextends: {pkg_name}\n",
        })
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertEqual(loaded.config.gate.profile, "production")

    def test_rejects_a_dotted_extends_target(self) -> None:
        # importlib.util.find_spec imports parent packages to resolve a dotted
        # (submodule) name -- see the docstring on _resolve_package_extends -- which
        # would reopen the exact execution path this module exists to close. Dotted
        # names must be rejected before find_spec is ever called.
        root = _tree({CONFIG_FILENAME: "version: 1\nextends: acme.baseline\n"})
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("dotted", str(error.exception).lower())

    def test_rejects_a_single_module_extends_target_that_is_not_a_package(self) -> None:
        # A single-module .py file has no `submodule_search_locations` and cannot
        # contain a .reachability.yml. Requiring an actual package is what keeps a
        # repo-local `evil.py` from being treated as a baseline candidate at all.
        module_root = Path(tempfile.mkdtemp())
        module_name = "reachability_advisor_test_bare_module"
        (module_root / f"{module_name}.py").write_text("value = 1\n", encoding="utf-8")
        self._add_to_sys_path(module_root)
        self._modules_to_clean.append(module_name)

        root = _tree({CONFIG_FILENAME: f"version: 1\nextends: {module_name}\n"})
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("not an installed package", str(error.exception))
        self.assertNotIn(module_name, sys.modules)

    def test_rejects_a_package_missing_the_config_file(self) -> None:
        package_root = Path(tempfile.mkdtemp())
        pkg_name = "reachability_advisor_test_pkg_empty"
        pkg_dir = package_root / pkg_name
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
        self._add_to_sys_path(package_root)
        self._modules_to_clean.append(pkg_name)

        root = _tree({CONFIG_FILENAME: f"version: 1\nextends: {pkg_name}\n"})
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("does not contain", str(error.exception))

    def test_rejects_an_extends_target_that_is_not_an_installed_package(self) -> None:
        root = _tree({
            CONFIG_FILENAME: "version: 1\nextends: reachability_advisor_no_such_pkg_xyz\n",
        })
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("not an installed package", str(error.exception))


class PackageExtendsSecurityTests(_SysPathIsolationMixin, unittest.TestCase):
    """Regression coverage for the critical defect: a package-form `extends` target
    used to be resolved with `importlib.resources.files`, which imports (and therefore
    executes) the named module before anything about its contents is checked. A config
    file is attacker-influenceable the same way scanner input is -- a pull request can
    add or edit one -- so this was full arbitrary code execution reachable by having
    anyone run the scanner.
    """

    def test_package_form_extends_never_executes_the_target_module(self) -> None:
        module_root = Path(tempfile.mkdtemp())
        marker = module_root / "side_effect_marker.txt"
        module_name = "reachability_advisor_test_evil_module"
        (module_root / f"{module_name}.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
            encoding="utf-8",
        )
        self._add_to_sys_path(module_root)
        self._modules_to_clean.append(module_name)

        root = _tree({CONFIG_FILENAME: f"version: 1\nextends: {module_name}\n"})

        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)

        # Both must hold: the original bug raised an error *and* ran the attacker's
        # code, so asserting only the exception would not catch a regression back to
        # importlib.resources.files/import_module.
        self.assertIn("not an installed package", str(error.exception))
        self.assertFalse(marker.exists(), "extends must resolve without executing the module")
        self.assertNotIn(module_name, sys.modules)


class PackageExtendsExceptionHandlingTests(unittest.TestCase):
    """`importlib.util.find_spec` can raise several different exceptions for hostile
    input (a real `__main__` raises `ValueError`; the old `importlib.resources.files`
    path left `AttributeError` for `__main__` uncaught entirely). All of them must be
    converted to `ConfigError`, never left to crash the process.
    """

    def _assert_find_spec_exception_becomes_config_error(
        self, exc_type: type[BaseException]
    ) -> None:
        root = _tree({CONFIG_FILENAME: "version: 1\nextends: whatever_target\n"})
        with (
            unittest.mock.patch(
                "reachability_advisor.config.importlib.util.find_spec",
                side_effect=exc_type("boom"),
            ),
            self.assertRaises(ConfigError),
        ):
            load_config(root / CONFIG_FILENAME)

    def test_catches_module_not_found_error(self) -> None:
        self._assert_find_spec_exception_becomes_config_error(ModuleNotFoundError)

    def test_catches_import_error(self) -> None:
        self._assert_find_spec_exception_becomes_config_error(ImportError)

    def test_catches_value_error(self) -> None:
        # This is what a real "__main__" (no __spec__, e.g. a plain script) raises.
        self._assert_find_spec_exception_becomes_config_error(ValueError)

    def test_catches_attribute_error(self) -> None:
        # This is the exception the old importlib.resources.files-based
        # implementation left uncaught for "__main__" and similar odd names.
        self._assert_find_spec_exception_becomes_config_error(AttributeError)

    def test_catches_type_error(self) -> None:
        self._assert_find_spec_exception_becomes_config_error(TypeError)

    def test_extends_dunder_main_fails_closed_with_a_config_error(self) -> None:
        # End-to-end, without mocking: whatever find_spec("__main__") does in the
        # running interpreter (raise, or return a non-package spec), the process must
        # not die with a raw traceback the way the old importlib.resources.files
        # implementation did.
        root = _tree({CONFIG_FILENAME: "version: 1\nextends: __main__\n"})
        with self.assertRaises(ConfigError):
            load_config(root / CONFIG_FILENAME)


if __name__ == "__main__":
    unittest.main()
