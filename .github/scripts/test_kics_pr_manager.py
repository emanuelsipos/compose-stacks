#!/usr/bin/env python3

import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from unittest import mock


SCRIPT = Path(__file__).with_name("kics-pr-manager.py")
SPEC = importlib.util.spec_from_file_location("kics_pr_manager", SCRIPT)
kics_pr_manager = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(kics_pr_manager)


def finding(similarity_id: str = "a" * 64) -> dict:
    return {
        "query_id": "query-id",
        "query_name": "No New Privileges Not Set",
        "severity": "HIGH",
        "description": "description",
        "file_name": "stack/compose.yaml",
        "line": 12,
        "similarity_id": similarity_id,
        "issue_type": "MissingAttribute",
        "search_key": "services.app.security_opt",
        "expected_value": "required",
        "actual_value": "missing",
        "fingerprint": "b" * 64,
    }


class KicsPRManagerTests(unittest.TestCase):
    def test_parse_reopen_accepts_all_and_hex_prefixes(self):
        self.assertEqual(kics_pr_manager.parse_reopen("all"), {"*"})
        self.assertEqual(
            kics_pr_manager.parse_reopen("abcdef12,0123456789"),
            {"abcdef12", "0123456789"},
        )

    def test_parse_reopen_rejects_short_or_non_lowercase_hex(self):
        for value in ("abc", "ABCDEF12", "not-hex!!"):
            with self.subTest(value=value):
                with self.assertRaises(kics_pr_manager.argparse.ArgumentTypeError):
                    kics_pr_manager.parse_reopen(value)

    def test_exclude_filename_and_file_are_deterministic(self):
        item = finding()
        expected = (
            "HIGH_No-New-Privileges-Not-Set_stack-compose.yaml_L12_bbbbbbbb"
        )
        self.assertEqual(kics_pr_manager.exclude_filename(item), expected)

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(
                kics_pr_manager, "KICS_EXCLUDE_DIR", str(Path(directory) / "exclude")
            ):
                created, name = kics_pr_manager.apply_exclude_file(item)
                content = kics_pr_manager.excl_path(item).read_text()

        self.assertTrue(created)
        self.assertEqual(name, expected)
        self.assertEqual(
            content,
            f"{item['similarity_id']}\n{item['query_id']}\n{item['file_name']}\n"
            f"finding-v1:{item['fingerprint']}\n",
        )

    def test_prefetch_indexes_fingerprint_and_legacy_markers(self):
        fingerprint = "b" * 64
        similarity = "a" * 64
        prs = [{
            "body": (
                f"<!-- kics-finding:{fingerprint} -->\n"
                f"<!-- kics-sim:{similarity} -->"
            ),
            "state": "open",
        }]
        with mock.patch.object(kics_pr_manager, "gh", return_value=prs):
            index = kics_pr_manager.prefetch_all_kics_prs("token", "owner/repo")

        self.assertIs(index[fingerprint], prs[0])
        self.assertIs(index[similarity], prs[0])

    def test_prefetch_fails_closed_on_later_page_error(self):
        page = [{"body": "", "state": "closed"}] * 100
        with mock.patch.object(
            kics_pr_manager,
            "gh",
            side_effect=[page, kics_pr_manager.GitHubAPIError("rate limited")],
        ):
            with self.assertRaises(kics_pr_manager.GitHubAPIError):
                kics_pr_manager.prefetch_all_kics_prs("token", "owner/repo")

    def test_prefetch_rejects_invalid_api_data(self):
        with mock.patch.object(kics_pr_manager, "gh", return_value=None):
            with self.assertRaises(kics_pr_manager.GitHubAPIError):
                kics_pr_manager.prefetch_all_kics_prs("token", "owner/repo")

    def test_gh_allows_only_expected_not_found(self):
        not_found = HTTPError("url", 404, "missing", {}, io.BytesIO(b"missing"))
        try:
            with mock.patch.object(kics_pr_manager, "urlopen", side_effect=not_found):
                self.assertIsNone(
                    kics_pr_manager.gh(
                        "GET", "/missing", "token", allow_not_found=True
                    )
                )
        finally:
            not_found.close()

        server_error = HTTPError("url", 500, "error", {}, io.BytesIO(b"error"))
        try:
            with mock.patch.object(kics_pr_manager, "urlopen", side_effect=server_error):
                with self.assertRaises(kics_pr_manager.GitHubAPIError):
                    kics_pr_manager.gh("GET", "/broken", "token")
        finally:
            server_error.close()

    def test_open_pr_state_skips_all_git_operations(self):
        item = finding()
        existing = {
            item["similarity_id"]: {"state": "open", "number": 42, "merged_at": None}
        }
        with (
            mock.patch.object(kics_pr_manager, "excl_path", return_value=Path("missing")),
            mock.patch.object(kics_pr_manager, "fingerprint_match_on_disk", return_value=""),
            mock.patch.object(kics_pr_manager, "create_branch_from_origin") as create,
        ):
            result = kics_pr_manager.process_finding(
                item, existing, "token", "owner/repo", "main", False, "main", set(), [1]
            )

        self.assertEqual(result, "open")
        create.assert_not_called()

    def test_untracked_remote_branch_fails_before_checkout(self):
        item = finding()
        with (
            mock.patch.object(kics_pr_manager, "excl_path", return_value=Path("missing")),
            mock.patch.object(kics_pr_manager, "fingerprint_match_on_disk", return_value=""),
            mock.patch.object(kics_pr_manager, "remote_branch_exists", return_value=True),
            mock.patch.object(kics_pr_manager, "create_branch_from_origin") as create,
            mock.patch.object(kics_pr_manager, "open_pr") as open_pr,
            mock.patch.object(kics_pr_manager.subprocess, "run"),
        ):
            result = kics_pr_manager.process_finding(
                item, {}, "token", "owner/repo", "main", False, "main", set(), [1]
            )

        self.assertEqual(result, "error")
        create.assert_not_called()
        open_pr.assert_not_called()

    def test_dry_run_respects_pr_budget(self):
        item = finding()
        with (
            mock.patch.object(kics_pr_manager, "excl_path", return_value=Path("missing")),
            mock.patch.object(kics_pr_manager, "fingerprint_match_on_disk", return_value=""),
        ):
            exhausted = kics_pr_manager.process_finding(
                item, {}, "token", "owner/repo", "main", True, "main", set(), [0]
            )
            available = kics_pr_manager.process_finding(
                item, {}, "token", "owner/repo", "main", True, "main", set(), [1]
            )

        self.assertEqual(exhausted, "rate-limited")
        self.assertEqual(available, "would-open")

    def test_pr_limit_is_bounded_positive_integer(self):
        self.assertEqual(kics_pr_manager.bounded_positive_integer("20"), 20)
        for value in ("0", "101", "nope"):
            with self.subTest(value=value):
                with self.assertRaises(kics_pr_manager.argparse.ArgumentTypeError):
                    kics_pr_manager.bounded_positive_integer(value)


if __name__ == "__main__":
    unittest.main()
