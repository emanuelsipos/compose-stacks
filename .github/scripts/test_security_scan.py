#!/usr/bin/env python3

import importlib.util
import hashlib
import io
import json
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
        for name in ["fragment,extra.yaml", "fragment\rskip=true.yaml", "fragment\nextra.yaml"]:
            with self.subTest(name=name), mock.patch.object(
                security_scan,
                "changed_deployment_files",
                return_value=[root / "stack" / name],
            ):
                with self.assertRaisesRegex(SystemExit, "commas or line breaks"):
                    security_scan.kics_scan_path(
                        "pull_request", "base", "head", root
                    )

    def test_write_output_rejects_line_breaks(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with mock.patch.dict("os.environ", {"GITHUB_OUTPUT": str(output)}):
                for value in ["safe\rinjected=true", "safe\ninjected=true"]:
                    with self.subTest(value=value), self.assertRaisesRegex(
                        ValueError, "line breaks"
                    ):
                        security_scan.write_output("path", value)
            self.assertFalse(output.exists())

    def test_image_matrix_is_stable_and_deduplicated(self):
        matrix = security_scan.image_matrix(["example/a:1", "example/a:1", "example/b:2"])
        images = " ".join(item["images"] for item in matrix["include"]).split()
        self.assertEqual(sorted(images), ["example/a:1", "example/b:2"])
        self.assertTrue(all(len(item["id"]) == 2 for item in matrix["include"]))

    def test_full_image_matrix_includes_empty_buckets(self):
        matrix = security_scan.image_matrix(
            ["example/a:1"],
            bucket_count=4,
            include_empty=True,
        )

        self.assertEqual(
            [item["id"] for item in matrix["include"]],
            ["00", "01", "02", "03"],
        )
        self.assertEqual(
            sum(bool(item["images"]) for item in matrix["include"]),
            1,
        )

    def test_full_image_matrix_preserves_categories_when_empty(self):
        matrix = security_scan.image_matrix([], include_empty=True)

        self.assertEqual(
            [item["id"] for item in matrix["include"]],
            [f"{bucket:02d}" for bucket in range(security_scan.IMAGE_BUCKET_COUNT)],
        )
        self.assertTrue(all(item["images"] == "" for item in matrix["include"]))

    def test_image_bucket_mapping_is_stable(self):
        matrix = security_scan.image_matrix(["example/a:1"])

        self.assertEqual(matrix["include"], [{"id": "04", "images": "example/a:1"}])

    def test_image_bucket_ignores_tag_and_digest(self):
        references = [
            "ghcr.io/example/app:1@sha256:" + "a" * 64,
            "ghcr.io/example/app:2@sha256:" + "b" * 64,
        ]

        matrix = security_scan.image_matrix(references)

        self.assertEqual(len(matrix["include"]), 1)
        self.assertEqual(matrix["include"][0]["images"].split(), references)

    def test_partial_image_matrix_pairs_only_matching_baseline_repositories(self):
        current = ["ghcr.io/example/app:2@sha256:" + "b" * 64]
        baseline = [
            "ghcr.io/example/app:1@sha256:" + "a" * 64,
            "ghcr.io/example/other:1@sha256:" + "c" * 64,
        ]

        matrix = security_scan.image_matrix(current, baseline_images=baseline)

        self.assertEqual(matrix["include"][0]["images"], current[0])
        self.assertEqual(
            matrix["include"][0]["baseline_images"], baseline[0]
        )

    def test_partial_image_matrix_rejects_ambiguous_repository_baseline(self):
        current = ["ghcr.io/example/app:3@sha256:" + "c" * 64]
        baseline = [
            "ghcr.io/example/app:1@sha256:" + "a" * 64,
            "ghcr.io/example/app:2@sha256:" + "b" * 64,
        ]

        matrix = security_scan.image_matrix(current, baseline_images=baseline)

        self.assertEqual(matrix["include"][0]["baseline_images"], "")

    def test_partial_image_matrix_rejects_ambiguous_current_repository(self):
        current = [
            "ghcr.io/example/app:2@sha256:" + "b" * 64,
            "ghcr.io/example/app:3@sha256:" + "c" * 64,
        ]
        baseline = ["ghcr.io/example/app:1@sha256:" + "a" * 64]

        matrix = security_scan.image_matrix(current, baseline_images=baseline)

        self.assertEqual(matrix["include"][0]["baseline_images"], "")

    def test_canonical_image_repository(self):
        self.assertEqual(
            security_scan.canonical_image_repository(
                "wangqiru/ttrss:nightly-2026-07-20@sha256:" + "a" * 64
            ),
            "docker.io/wangqiru/ttrss",
        )
        self.assertEqual(
            security_scan.canonical_image_repository("nginx:1.29"),
            "docker.io/library/nginx",
        )
        self.assertEqual(
            security_scan.canonical_image_repository(
                "ghcr.io/ente/server@sha256:" + "b" * 64
            ),
            "ghcr.io/ente/server",
        )
        self.assertEqual(
            security_scan.canonical_image_repository(
                "registry.example:5000/team/app:v2"
            ),
            "registry.example:5000/team/app",
        )

    def test_image_scan_files_marks_complete_and_partial_inventories(self):
        root = Path("/workspace")
        full_files = [root / "stack/compose.yaml"]
        changed_files = [root / "stack/fragment.yaml"]
        with (
            mock.patch.object(
                security_scan,
                "all_deployment_files",
                return_value=full_files,
            ),
            mock.patch.object(
                security_scan,
                "changed_deployment_files",
                return_value=changed_files,
            ),
        ):
            scheduled = security_scan.image_scan_files(
                "schedule", "", "", "", "all", root
            )
            pushed = security_scan.image_scan_files(
                "push", "a" * 40, "", "", "all", root
            )
            non_trivy_dispatch = security_scan.image_scan_files(
                "workflow_dispatch", "", "", "", "kics", root
            )

        self.assertEqual(scheduled, (full_files, True))
        self.assertEqual(pushed, (changed_files, False))
        self.assertEqual(non_trivy_dispatch, ([], False))

    def test_plan_outputs_complete_matrix_for_scheduled_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stack = root / "stack"
            stack.mkdir()
            (stack / "compose.yaml").write_text(
                "services:\n  app:\n    image: example/app:1\n"
            )
            output = root / "github-output"
            arguments = security_scan.parser().parse_args(
                ["plan", "--event", "schedule", "--root", str(root)]
            )
            with mock.patch.dict(
                "os.environ",
                {"GITHUB_OUTPUT": str(output)},
                clear=False,
            ):
                security_scan.plan(arguments)

            values = dict(
                line.split("=", 1)
                for line in output.read_text().splitlines()
            )
            matrix = json.loads(values["matrix"])

        self.assertEqual(values["count"], "1")
        self.assertEqual(values["full_inventory"], "true")
        self.assertEqual(values["gate_new"], "false")
        self.assertEqual(
            len(matrix["include"]),
            security_scan.IMAGE_BUCKET_COUNT,
        )

    def test_partial_plan_limits_baseline_to_changed_paths(self):
        root = Path("/workspace")
        files = [root / "stack/compose.yaml"]
        arguments = security_scan.parser().parse_args(
            [
                "plan",
                "--event",
                "pull_request",
                "--base",
                "base",
                "--head",
                "head",
                "--root",
                str(root),
            ]
        )
        with (
            mock.patch.object(
                security_scan, "image_scan_files", return_value=(files, False)
            ),
            mock.patch.object(
                security_scan, "images_from_files", return_value=["example/app:2"]
            ),
            mock.patch.object(
                security_scan,
                "images_from_git_ref",
                return_value=["example/app:1"],
            ) as baseline,
            mock.patch.object(security_scan, "write_output"),
        ):
            security_scan.plan(arguments)

        baseline.assert_called_once_with("base", root, files)

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

    def test_normalize_image_sarif_adds_stable_repository_identity(self):
        document = {
            "runs": [{
                "tool": {"driver": {"name": "Trivy", "rules": [{"id": "CVE-1"}]}},
                "properties": {"imageName": "old"},
                "results": [{
                    "ruleId": "CVE-1",
                    "message": {
                        "text": "Package: example-lib\nInstalled Version: 1.0"
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "example/app",
                                "uriBaseId": "ROOTPATH",
                            }
                        }
                    }],
                }],
            }]
        }
        first_reference = "ghcr.io/example/app:1@sha256:" + "a" * 64
        second_reference = "ghcr.io/example/app:2@sha256:" + "b" * 64

        first = security_scan.normalize_image_sarif(document, first_reference)
        second = security_scan.normalize_image_sarif(document, second_reference)
        other_repository = security_scan.normalize_image_sarif(
            document,
            "ghcr.io/example/other:1@sha256:" + "c" * 64,
        )
        first_run = first["runs"][0]
        first_result = first_run["results"][0]
        second_result = second["runs"][0]["results"][0]
        other_result = other_repository["runs"][0]["results"][0]

        self.assertEqual(
            first_run["properties"],
            {
                "imageRepository": "ghcr.io/example/app",
                "imageReference": first_reference,
            },
        )
        self.assertEqual(
            first_result["properties"]["imageRepository"],
            "ghcr.io/example/app",
        )
        self.assertEqual(
            first_result["properties"]["imageTarget"],
            "example/app",
        )
        self.assertEqual(
            first_result["locations"][0]["physicalLocation"]["artifactLocation"],
            {"uri": "container-images/ghcr.io/example/app/container"},
        )
        self.assertEqual(
            first_result["partialFingerprints"],
            second_result["partialFingerprints"],
        )
        self.assertEqual(
            first_result["locations"],
            second_result["locations"],
        )
        self.assertNotEqual(
            first_result["partialFingerprints"],
            other_result["partialFingerprints"],
        )

    def test_combine_sarif_removes_single_image_run_properties(self):
        combined = security_scan.combine_sarif([
            {
                "runs": [{
                    "tool": {"driver": {"name": "Trivy", "rules": []}},
                    "properties": {"imageName": "first"},
                    "results": [],
                }]
            }
        ])

        self.assertNotIn("properties", combined["runs"][0])

    def test_normalize_image_sarif_updates_indexed_artifacts(self):
        document = {
            "runs": [{
                "tool": {"driver": {"name": "Trivy", "rules": []}},
                "artifacts": [{
                    "location": {
                        "uri": "usr/bin/example",
                        "uriBaseId": "ROOTPATH",
                    }
                }],
                "results": [{
                    "ruleId": "CVE-1",
                    "message": {"text": "Package: example-lib"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"index": 0}
                        }
                    }],
                }],
            }]
        }

        normalized = security_scan.normalize_image_sarif(
            document,
            "registry.example:5000/team/app:1",
        )
        run = normalized["runs"][0]

        self.assertEqual(
            run["artifacts"][0]["location"],
            {
                "uri": (
                    "container-images/registry.example:5000/"
                    "team/app/container"
                )
            },
        )
        self.assertEqual(
            run["results"][0]["properties"]["imageTarget"],
            "usr/bin/example",
        )
        self.assertIn(
            "primaryLocationLineHash",
            run["results"][0]["partialFingerprints"],
        )

    def test_normalize_image_sarif_ignores_scanner_target_for_identity(self):
        def document(target):
            return {
                "runs": [{
                    "tool": {"driver": {"name": "Trivy", "rules": []}},
                    "results": [{
                        "ruleId": "CVE-1",
                        "message": {"text": "Package: example-lib"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": target}
                            }
                        }],
                    }],
                }]
            }

        first = security_scan.normalize_image_sarif(
            document("alpine-3.22"),
            "ghcr.io/example/app:1@sha256:" + "a" * 64,
        )["runs"][0]["results"][0]
        second = security_scan.normalize_image_sarif(
            document("alpine-3.23"),
            "ghcr.io/example/app:2@sha256:" + "b" * 64,
        )["runs"][0]["results"][0]

        self.assertEqual(first["locations"], second["locations"])
        self.assertEqual(
            first["partialFingerprints"],
            second["partialFingerprints"],
        )
        self.assertNotEqual(
            first["properties"]["imageTarget"],
            second["properties"]["imageTarget"],
        )

    def test_combine_sarif_rejects_empty_input(self):
        with self.assertRaises(ValueError):
            security_scan.combine_sarif([])
        with self.assertRaises(ValueError):
            security_scan.combine_sarif([{"runs": []}])

    def test_combine_sarif_files_emits_empty_trivy_snapshot(self):
        combined = security_scan.combine_sarif_files([])

        self.assertEqual(combined["version"], "2.1.0")
        self.assertEqual(len(combined["runs"]), 1)
        run = combined["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Trivy")
        self.assertEqual(run["tool"]["driver"]["rules"], [])
        self.assertEqual(run["results"], [])

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

    def test_kics_fingerprint_is_line_stable_and_content_specific(self):
        finding = {
            "file_name": "stack/compose.yaml",
            "line": 10,
            "similarity_id": "a" * 64,
            "issue_type": "IncorrectValue",
            "search_key": "services.app.privileged",
            "expected_value": "false",
            "actual_value": "true",
        }
        moved = dict(finding, line=20, similarity_id="b" * 64)
        distinct = dict(finding, search_key="services.worker.privileged")

        self.assertEqual(
            security_scan.kics_finding_fingerprint("query", finding),
            security_scan.kics_finding_fingerprint("query", moved),
        )
        self.assertNotEqual(
            security_scan.kics_finding_fingerprint("query", finding),
            security_scan.kics_finding_fingerprint("query", distinct),
        )
        self.assertNotEqual(
            security_scan.kics_finding_fingerprint("query", finding, 0),
            security_scan.kics_finding_fingerprint("query", finding, 1),
        )

    def test_kics_filter_suppresses_only_reviewed_duplicate_occurrence(self):
        finding = {
            "file_name": "stack/compose.yaml",
            "line": 10,
            "similarity_id": "a" * 64,
            "issue_type": "IncorrectValue",
            "search_key": "services.app.volumes",
            "expected_value": "safe",
            "actual_value": "sensitive",
        }
        query_id = "query-id"
        json_document = {
            "queries": [{"query_id": query_id, "files": [finding, finding.copy()]}]
        }
        sarif_result = {
            "ruleId": query_id,
            "message": {"text": "sensitive"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "stack/compose.yaml"},
                "region": {"startLine": 10},
            }}],
        }
        sarif_document = {"runs": [{"results": [sarif_result, sarif_result.copy()]}]}
        reviewed = {security_scan.kics_finding_fingerprint(query_id, finding, 0)}

        filtered_json, suppressed, findings = security_scan.filter_kics_json(
            json_document, reviewed
        )
        filtered_sarif = security_scan.filter_kics_sarif(
            sarif_document, suppressed, findings
        )

        self.assertEqual(len(filtered_json["queries"][0]["files"]), 1)
        self.assertEqual(len(filtered_sarif["runs"][0]["results"]), 2)

    def test_legacy_exclusion_maps_only_exact_similarity_id(self):
        first = {
            "file_name": "stack/compose.yaml",
            "similarity_id": "a" * 64,
            "issue_type": "IncorrectValue",
            "search_key": "services.first.privileged",
            "expected_value": "false",
            "actual_value": "true",
        }
        second = dict(
            first,
            similarity_id="b" * 64,
            search_key="services.second.privileged",
        )
        baseline = {
            "queries": [{"query_id": "query-id", "files": [first, second]}]
        }
        records = [{"fingerprints": [], "similarity_id": "a" * 64}]

        with mock.patch.object(
            security_scan, "exclusion_records", return_value=records
        ):
            fingerprints = security_scan.exclusion_fingerprints(
                Path("/workspace"), "main", baseline
            )

        self.assertEqual(
            fingerprints,
            {security_scan.kics_finding_fingerprint("query-id", first)},
        )

    def test_sarif_difference_keeps_only_new_vulnerability_identities(self):
        def result(identity):
            return {
                "ruleId": identity,
                "partialFingerprints": {"primaryLocationLineHash": identity},
            }

        current = {"runs": [{"results": [result("existing"), result("new")]}]}
        baseline = {"runs": [{"results": [result("existing")]}]}

        difference, count = security_scan.sarif_difference(current, baseline)

        self.assertEqual(count, 1)
        self.assertEqual(
            [item["ruleId"] for item in difference["runs"][0]["results"]],
            ["new"],
        )

    def test_kics_renovate_group_requires_queries_and_binary(self):
        config = json.loads((SCRIPT.parents[2] / "renovate.json5").read_text())
        kics_rule = next(
            rule
            for rule in config["packageRules"]
            if rule.get("groupName") == "kics"
        )

        self.assertEqual(
            kics_rule["minimumGroupSize"],
            security_scan.KICS_QUERY_REF_COUNT + 1,
        )
        self.assertEqual(
            set(kics_rule["matchDepNames"]),
            {"Checkmarx/kics", "Checkmarx/kics (linux_amd64 archive)"},
        )

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
