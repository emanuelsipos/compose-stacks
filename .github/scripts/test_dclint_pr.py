#!/usr/bin/env python3

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("dclint_pr.py")
SPEC = importlib.util.spec_from_file_location("dclint_pr", SCRIPT)
dclint_pr = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(dclint_pr)


class DclintPrTests(unittest.TestCase):
    def test_changed_compose_files_only_returns_existing_compose_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=root,
                check=True,
            )
            compose = root / "stack" / "compose.yaml"
            compose.parent.mkdir()
            compose.write_text("services: {}\n")
            (root / "stack" / "fragment.yml").write_text("services: {}\n")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "initial"], cwd=root, check=True)
            before = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            compose.write_text("services:\n  app: {}\n")
            (root / "stack" / "deleted-compose.yml").write_text("services: {}\n")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "update"], cwd=root, check=True)
            (root / "stack" / "deleted-compose.yml").unlink()
            subprocess.run(["git", "add", "-u"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "delete"], cwd=root, check=True)

            files = dclint_pr.changed_compose_files(before, "HEAD", root)

            self.assertEqual(files, [compose])

    def test_dclint_command_passes_relative_paths_and_strict_options(self):
        root = Path("/workspace")
        files = [root / "a" / "compose.yaml", root / "b" / "compose.yml"]

        self.assertEqual(
            dclint_pr.dclint_command(files, root),
            [
                "npx",
                "--yes",
                "dclint@3.1.0",
                "a/compose.yaml",
                "b/compose.yml",
                "--formatter",
                "github",
                "--max-warnings",
                "0",
            ],
        )

    def test_main_skips_linter_when_no_compose_files_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(dclint_pr, "changed_compose_files", return_value=[]),
                mock.patch.object(dclint_pr.subprocess, "run") as run,
                mock.patch.object(dclint_pr, "write_summary"),
                mock.patch("pathlib.Path.cwd", return_value=root),
            ):
                self.assertEqual(dclint_pr.main(["dclint_pr.py", "base", "head"]), 0)

            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
