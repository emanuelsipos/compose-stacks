#!/usr/bin/env python3

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("security_scan.py")
SPEC = importlib.util.spec_from_file_location("security_scan", SCRIPT)
security_scan = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(security_scan)


class SecurityScanTests(unittest.TestCase):
    def test_all_deployment_files_include_compose_fragments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "stack").mkdir()
            (root / ".github").mkdir()
            (root / "stack" / "compose.yaml").write_text("services: {}\n")
            (root / "stack" / "fragment.yml").write_text("service: {}\n")
            (root / ".github" / "workflow.yml").write_text("jobs: {}\n")

            files = security_scan.all_deployment_files(root)

            self.assertEqual(
                [path.relative_to(root).as_posix() for path in files],
                ["stack/compose.yaml", "stack/fragment.yml"],
            )

    def test_changed_deployment_files_include_shared_yaml(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=root,
                check=True,
            )
            (root / "_common").mkdir()
            shared = root / "_common" / "base.yaml"
            shared.write_text("services: {}\n")
            subprocess.run(["git", "add", "_common/base.yaml"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "initial"], cwd=root, check=True)
            before = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            shared.write_text("services:\n  app: {}\n")
            subprocess.run(["git", "add", "_common/base.yaml"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "update"], cwd=root, check=True)

            files = security_scan.changed_deployment_files(before, "HEAD", root)

            self.assertEqual(files, [shared])

    def test_image_matrix_is_stable_and_deduplicated(self):
        matrix = security_scan.image_matrix(["example/a:1", "example/a:1", "example/b:2"])
        images = " ".join(item["images"] for item in matrix["include"]).split()
        self.assertEqual(sorted(images), ["example/a:1", "example/b:2"])
        self.assertTrue(all(len(item["id"]) == 2 for item in matrix["include"]))

    def test_combine_sarif_preserves_every_run(self):
        combined = security_scan.combine_sarif(
            [
                {"$schema": "schema", "runs": [{"id": "first"}]},
                {"$schema": "schema", "runs": [{"id": "second"}]},
            ]
        )
        self.assertEqual(combined["$schema"], "schema")
        self.assertEqual(combined["runs"], [{"id": "first"}, {"id": "second"}])

    def test_combine_sarif_rejects_empty_input(self):
        with self.assertRaises(ValueError):
            security_scan.combine_sarif([])


if __name__ == "__main__":
    unittest.main()
