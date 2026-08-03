#!/usr/bin/env python3

import importlib.util
import hashlib
import io
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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

    def test_kics_scan_path_includes_fragments(self):
        root = Path("/workspace")
        with mock.patch.object(
            security_scan,
            "changed_deployment_files",
            return_value=[
                root / "jupiter/immich/hwaccel.transcoding.yaml",
                root / "jupiter/qbittorrent/gluetun.yaml",
            ],
        ):
            path = security_scan.kics_scan_path(
                "pull_request", "base", "head", root
            )

        self.assertEqual(
            path,
            "jupiter/immich/hwaccel.transcoding.yaml,"
            "jupiter/qbittorrent/gluetun.yaml",
        )

    def test_kics_scan_path_skips_pr_without_deployment_yaml(self):
        with mock.patch.object(
            security_scan, "changed_deployment_files", return_value=[]
        ):
            path = security_scan.kics_scan_path(
                "pull_request", "base", "head", Path("/workspace")
            )

        self.assertIsNone(path)

    def test_kics_scan_path_rejects_ambiguous_filename(self):
        root = Path("/workspace")
        with mock.patch.object(
            security_scan,
            "changed_deployment_files",
            return_value=[root / "stack/fragment,extra.yaml"],
        ):
            with self.assertRaisesRegex(SystemExit, "commas or newlines"):
                security_scan.kics_scan_path(
                    "pull_request", "base", "head", root
                )

    def test_image_matrix_is_stable_and_deduplicated(self):
        matrix = security_scan.image_matrix(["example/a:1", "example/a:1", "example/b:2"])
        images = " ".join(item["images"] for item in matrix["include"]).split()
        self.assertEqual(sorted(images), ["example/a:1", "example/b:2"])
        self.assertTrue(all(len(item["id"]) == 2 for item in matrix["include"]))

    def test_combine_sarif_merges_runs_and_remaps_indices(self):
        combined = security_scan.combine_sarif(
            [
                {
                    "$schema": "schema",
                    "runs": [{
                        "tool": {"driver": {"name": "Trivy", "rules": [{"id": "A"}]}},
                        "artifacts": [{"location": {"uri": "first"}}],
                        "results": [{
                            "ruleId": "A",
                            "ruleIndex": 0,
                            "locations": [{
                                "physicalLocation": {"artifactLocation": {"index": 0}}
                            }],
                        }],
                    }],
                },
                {
                    "$schema": "schema",
                    "runs": [{
                        "tool": {
                            "driver": {
                                "name": "Trivy",
                                "rules": [{"id": "B"}, {"id": "A"}],
                            }
                        },
                        "artifacts": [{"location": {"uri": "second"}}],
                        "results": [
                            {
                                "ruleId": "B",
                                "ruleIndex": 0,
                                "locations": [{
                                    "physicalLocation": {
                                        "artifactLocation": {"index": 0}
                                    }
                                }],
                            },
                            {"ruleId": "A", "ruleIndex": 1},
                        ],
                    }],
                },
            ]
        )

        self.assertEqual(combined["$schema"], "schema")
        self.assertEqual(len(combined["runs"]), 1)
        run = combined["runs"][0]
        self.assertEqual(
            [rule["id"] for rule in run["tool"]["driver"]["rules"]], ["A", "B"]
        )
        self.assertEqual(
            [result["ruleIndex"] for result in run["results"]], [0, 1, 0]
        )
        self.assertEqual(
            run["results"][1]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["index"],
            1,
        )
        self.assertEqual(len(run["artifacts"]), 2)

    def test_combine_sarif_rejects_empty_input(self):
        with self.assertRaises(ValueError):
            security_scan.combine_sarif([])
        with self.assertRaises(ValueError):
            security_scan.combine_sarif([{"runs": []}])

    def test_kics_command_adds_optional_filters(self):
        arguments = security_scan.parser().parse_args(
            [
                "kics",
                "--path",
                ".",
                "--formats",
                "json,sarif",
                "--output",
                "results",
                "--queries",
                "assets/queries",
                "--libraries",
                "assets/libraries",
                "--exclude-results",
                "one,two",
                "--exclude-severities",
                "medium,low",
            ]
        )

        command = security_scan.kics_command(arguments, Path("/workspace"))

        self.assertEqual(command[0], str(Path("kics").resolve()))
        self.assertEqual(
            command[-4:],
            ["--exclude-severities", "medium,low", "--exclude-results", "one,two"],
        )

    def test_exclusion_ids_ignore_documentation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=root,
                check=True,
            )
            exclusions = root / ".kics-exclude"
            exclusions.mkdir()
            (exclusions / "README.md").write_text("# Documentation\n")
            similarity_id = "a" * 64
            (exclusions / "HIGH_finding").write_text(f"{similarity_id}\n")
            subprocess.run(["git", "add", ".kics-exclude"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "initial"], cwd=root, check=True)

            values = security_scan.exclusion_ids(root, "HEAD")

            self.assertEqual(values, [similarity_id])

    def test_verify_kics_pins_accepts_matching_versions(self):
        checkout = (
            "repository: Checkmarx/kics\n"
            f"ref: {'a' * 40} # v{security_scan.KICS_VERSION}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            workflow = Path(directory) / "security-scan.yml"
            workflow.write_text(checkout * security_scan.KICS_QUERY_REF_COUNT)
            arguments = security_scan.parser().parse_args(
                ["verify-kics-pins", "--workflow", str(workflow)]
            )

            security_scan.verify_kics_pins(arguments)

    def test_verify_kics_pins_rejects_mismatched_version(self):
        checkout = (
            "repository: Checkmarx/kics\n"
            f"ref: {'a' * 40} # v{security_scan.KICS_VERSION}\n"
        )
        mismatch = (
            "repository: Checkmarx/kics\n"
            f"ref: {'b' * 40} # v99.0.0\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            workflow = Path(directory) / "security-scan.yml"
            workflow.write_text(checkout + mismatch)
            arguments = security_scan.parser().parse_args(
                ["verify-kics-pins", "--workflow", str(workflow)]
            )

            with self.assertRaisesRegex(SystemExit, "do not match"):
                security_scan.verify_kics_pins(arguments)

    def test_verify_kics_pins_rejects_missing_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            workflow = Path(directory) / "security-scan.yml"
            workflow.write_text(
                "repository: Checkmarx/kics\n"
                f"ref: {'a' * 40} # v{security_scan.KICS_VERSION}\n"
            )
            arguments = security_scan.parser().parse_args(
                ["verify-kics-pins", "--workflow", str(workflow)]
            )

            with self.assertRaisesRegex(SystemExit, "Expected"):
                security_scan.verify_kics_pins(arguments)

    def test_install_kics_verifies_and_extracts_archive(self):
        archive = io.BytesIO()
        payload = b"kics binary"
        with tarfile.open(fileobj=archive, mode="w:gz") as package:
            member = tarfile.TarInfo("kics")
            member.size = len(payload)
            package.addfile(member, io.BytesIO(payload))
        archive_bytes = archive.getvalue()

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "kics"
            arguments = security_scan.parser().parse_args(
                ["install-kics", "--destination", str(destination)]
            )
            with (
                mock.patch.object(
                    security_scan,
                    "KICS_ARCHIVE_SHA256",
                    hashlib.sha256(archive_bytes).hexdigest(),
                ),
                mock.patch.object(
                    security_scan.urllib.request,
                    "urlopen",
                    return_value=io.BytesIO(archive_bytes),
                ),
            ):
                security_scan.install_kics(arguments)

            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
