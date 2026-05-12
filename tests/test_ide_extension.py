from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class IdeExtensionTests(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not available")
    def test_vscode_extension_helpers(self) -> None:
        subprocess.run(["node", str(ROOT / "ide/vscode/extension.test.js")], cwd=ROOT, check=True)

