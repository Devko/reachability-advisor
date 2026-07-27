# tests/test_config.py
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
