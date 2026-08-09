#!/usr/bin/env python3
"""
kics-pr-manager.py

Per-finding KICS suppression PR manager.

For each finding in the KICS results JSON the script:

  1. Derives a branch name from the finding's stable fingerprint.

  2. Checks whether the exact finding fingerprint is already accepted in a
     .kics-exclude/<name> file.
     -> skip.

  3. Looks up the finding in a pre-fetched PR index (one bulk REST call
     at startup -- avoids per-finding search API calls that hit the strict
     installation rate limit of 10 req/min).

  4. Acts on the PR state:
       open       -> skip (already under review)
       dismissed  -> skip, unless --reopen matches this finding
       merged     -> previous suppression is absent; fall through to open a
                    fingerprint suppression PR
       none       -> open a fingerprint suppression PR

Suppression strategy -- stable content fingerprints:
  KICS v2.1.x inline `# kics-scan ignore-line` comments are silently
  ignored for all YAML constructs (confirmed in production logs). Inline
  suppression has been removed. Every finding is handled by writing a
  .kics-exclude/<descriptive-name> file whose content includes a stable
  fingerprint. The workflow filters raw KICS JSON and SARIF using only those
  reviewed fingerprints.

PR rate limiting:
  Pass --pr-limit N to open at most N PRs per run (default: 20).
  Subsequent findings that would have opened a PR are skipped and reported
  as 'rate-limited' in the summary. Increase the limit or run again to
  process more.

Usage:
    python3 kics-pr-manager.py \\
        --kics      kics-results/results.json \\
        --repo      owner/repo \\
        --token     $GITHUB_TOKEN \\
        --base      main \\
        [--dry-run] \\
        [--pr-limit N]   (default 20) \\
        [--reopen all|<fingerprint_prefix>[,<fingerprint_prefix>,...]]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


# -- Constants -----------------------------------------------------------------

LABEL_NAME    = "kics-suppression"
LABEL_COLOR   = "e11d48"
LABEL_DESC    = "KICS security finding awaiting suppression review"
BRANCH_PREFIX = "security/kics-"
FINDING_TAG = "kics-finding"
KICS_EXCLUDE_DIR = ".kics-exclude"
DEFAULT_PR_LIMIT = 20


class GitHubAPIError(RuntimeError):
    """Raised when GitHub API state cannot be fetched or changed safely."""


# -- GitHub API ----------------------------------------------------------------

def gh(
    method: str,
    path: str,
    token: str,
    payload: dict | None = None,
    *,
    allow_not_found: bool = False,
) -> dict | list | None:
    url = f"https://api.github.com{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    })
    try:
        with urlopen(req) as r:
            return json.loads(r.read())
    except HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"  GitHub {method} {path} -> {e.code}: {body[:300]}", file=sys.stderr)
        if e.code == 404 and allow_not_found:
            return None
        raise GitHubAPIError(
            f"GitHub {method} {path} failed with HTTP {e.code}"
        ) from e


def ensure_label(token: str, repo: str) -> None:
    if gh(
        "GET", f"/repos/{repo}/labels/{LABEL_NAME}", token, allow_not_found=True
    ):
        return
    gh("POST", f"/repos/{repo}/labels", token, {
        "name": LABEL_NAME,
        "color": LABEL_COLOR,
        "description": LABEL_DESC,
    })


# -- Bulk PR prefetch ----------------------------------------------------------

def prefetch_all_kics_prs(token: str, repo: str) -> dict[str, dict]:
    """
    Fetch all PRs (open + closed + merged) once at startup and return a
    dict keyed by exact finding fingerprint.

    Uses GET /repos/{repo}/pulls (5 000 req/h) instead of
    GET /search/issues per finding (10 req/min for installations).
    The pulls API returns merged_at directly -- no second round-trip needed.
    """
    pr_index: dict[str, dict] = {}
    page = 1
    marker_re = re.compile(
        rf"<!--\s*{re.escape(FINDING_TAG)}:([a-f0-9]{{64}})\s*-->"
    )
    total_fetched = 0

    print("Prefetching PR history...", end="", flush=True)
    while True:
        batch = gh(
            "GET",
            f"/repos/{repo}/pulls?state=all&per_page=100&page={page}&sort=updated&direction=desc",
            token,
        )
        if not isinstance(batch, list):
            raise GitHubAPIError("GitHub pull request listing returned invalid data")
        if not batch:
            break
        for pr in batch:
            body = pr.get("body") or ""
            for finding_id in marker_re.findall(body):
                if finding_id in pr_index:
                    raise GitHubAPIError(
                        "Multiple pull requests contain KICS finding marker "
                        + finding_id
                    )
                pr_index[finding_id] = pr
        total_fetched += len(batch)
        print(".", end="", flush=True)
        if len(batch) < 100:
            break
        page += 1

    print(f" done ({total_fetched} PRs scanned, {len(pr_index)} KICS findings tracked)")
    return pr_index


def find_pr(finding: dict, pr_index: dict[str, dict]) -> dict | None:
    return pr_index.get(finding["fingerprint"])


def pr_state(pr: dict) -> str:
    if pr["state"] == "open":
        return "open"
    if pr.get("merged_at"):
        return "merged"
    return "dismissed"


def open_pr(token: str, repo: str, branch: str, title: str, body: str, base: str) -> dict | None:
    pr = gh("POST", f"/repos/{repo}/pulls", token, {
        "title": title,
        "body": body,
        "head": branch,
        "base": base,
    })
    if not pr:
        return None
    gh("POST", f"/repos/{repo}/issues/{pr['number']}/labels", token, {
        "labels": [LABEL_NAME],
    })
    return pr


# -- Suppression ---------------------------------------------------------------
#
# KICS v2.1.x inline `# kics-scan ignore-line` comments are silently broken
# for all YAML constructs (confirmed in production: lines with the correct
# comment still appear in scan output). Inline suppression has been removed.
# Every finding is handled via .kics-exclude/<descriptive-name>.

def exclude_filename(finding: dict) -> str:
    """
    Human-readable .kics-exclude filename.
    Format: {SEVERITY}_{Query-Name}_{file-path}_L{line}_{fingerprint8}
    """
    def slug(s: str) -> str:
        s = s.replace("/", "-").replace("\\", "-").replace(" ", "-")
        s = re.sub(r"[^A-Za-z0-9._-]", "", s)
        return s.strip("-")

    return (
        f"{finding['severity']}_"
        f"{slug(finding['query_name'])[:60]}_"
        f"{slug(finding['file_name'])[:60]}_"
        f"L{finding['line']}_"
        f"{finding['fingerprint'][:8]}"
    )


def excl_path(finding: dict) -> Path:
    return Path(KICS_EXCLUDE_DIR) / exclude_filename(finding)


def fingerprint_match_on_disk(finding: dict) -> str:
    excl_dir = Path(KICS_EXCLUDE_DIR)
    if not excl_dir.is_dir():
        return ""
    marker = f"finding-v2:{finding['fingerprint']}"
    for f in excl_dir.iterdir():
        if f.is_file() and marker in f.read_text(encoding="utf-8").splitlines():
            return f.name
    return ""


def apply_exclude_file(finding: dict) -> tuple[bool, str]:
    """
    Write .kics-exclude/<n> with structured content (one field per line):
        line 1: similarity_id  -- scanner metadata, not enforcement identity
        line 2: query_id
        line 3: file_name
        line 4: exact finding fingerprint
    """
    target = excl_path(finding)
    if target.exists():
        return False, f"exclusion file already on disk ({target.name})"
    existing = fingerprint_match_on_disk(finding)
    if existing:
        return False, f"finding fingerprint already suppressed ({existing})"
    target.parent.mkdir(exist_ok=True)
    target.write_text(
        finding["similarity_id"] + "\n"
        + finding["query_id"]    + "\n"
        + finding["file_name"]   + "\n"
        + "finding-v2:" + finding["fingerprint"] + "\n"
    )
    return True, target.name


# -- Git helpers ---------------------------------------------------------------

def run(cmd: list[str], **kwargs) -> str:
    result = subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs)
    return result.stdout.strip()


def git(*args: str) -> str:
    return run(["git", *args])


def branch_for(fingerprint: str) -> str:
    return f"{BRANCH_PREFIX}{fingerprint[:16]}"


def create_branch_from_origin(base: str, branch: str) -> None:
    git("fetch", "origin", base)
    git("checkout", "-B", branch, f"origin/{base}")


def commit_and_push(files: list[str], message: str, branch: str) -> None:
    for f in files:
        git("add", f)
    git("commit", "-m", message)
    git("push", "origin", f"HEAD:{branch}", "--force-with-lease")


def current_branch() -> str:
    return git("rev-parse", "--abbrev-ref", "HEAD")


def remote_branch_exists(branch: str) -> bool:
    result = subprocess.run(
        ["git", "ls-remote", "--exit-code", "--heads", "origin", branch],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 2:
        return False
    raise subprocess.CalledProcessError(
        result.returncode, result.args, output=result.stdout, stderr=result.stderr
    )


# -- PR content ----------------------------------------------------------------

def finding_tag(fingerprint: str) -> str:
    return f"{FINDING_TAG}:{fingerprint}"


def make_pr_body(finding: dict, note: str = "") -> str:
    sim_id     = finding["similarity_id"]
    fingerprint = finding["fingerprint"]
    query_id   = finding["query_id"]
    query_name = finding["query_name"]
    severity   = finding["severity"]
    file_name  = finding["file_name"]
    line       = finding["line"]
    docs_url   = f"https://docs.kics.io/latest/queries/dockercompose-queries/{query_id}/"
    fname      = exclude_filename(finding)

    suppression_desc = (
        f"exact finding fingerprint in `.kics-exclude/{fname}`"
    )
    if note:
        suppression_desc += f" ({note})"

    lines = [
        f"## [{severity}] {query_name}",
        "",
        "| | |",
        "|---|---|",
        f"| **Rule** | [`{query_id}`]({docs_url}) |",
        f"| **Severity** | `{severity}` |",
        f"| **Location** | `{file_name}:{line}` |",
        f"| **Suppression** | {suppression_desc} |",
        "",
        "### Finding",
        "",
        finding.get("description", ""),
        "",
        "### Review",
        "",
        "- [ ] Read the rule docs linked above",
        "- [ ] Confirm this is a false positive or intentional deviation for this location",
        "- [ ] Replace `TODO: add justification` with a real reason in the file",
        "",
        "**Merge** -> `.kics-exclude/` file lands on main; excluded from next scan.",
        "**Close without merging** -> permanently dismissed; this PR will never be re-opened.",
        "",
        "---",
        f"<!-- {finding_tag(fingerprint)} -->",
    ]
    return "\n".join(lines)


# -- Core logic ----------------------------------------------------------------

def load_findings(kics_json_path: str) -> list[dict]:
    with open(kics_json_path) as f:
        data = json.load(f)
    raw_findings: list[tuple[dict, dict, tuple[str, ...]]] = []
    for query in data.get("queries", []):
        for file_result in query.get("files", []):
            content_identity = (
                query["query_id"],
                file_result["file_name"].replace("\\", "/").removeprefix("./"),
                file_result.get("issue_type", ""),
                file_result.get("search_key", ""),
                file_result.get("expected_value", ""),
                file_result.get("actual_value", ""),
            )
            identity = (
                *content_identity,
                str(file_result.get("line", 0)),
                str(file_result.get("search_line", 0)),
            )
            raw_findings.append((query, file_result, identity))

    identity_counts = Counter(identity for _, _, identity in raw_findings)
    if any(count > 1 for count in identity_counts.values()):
        raise ValueError(
            "KICS results contain duplicate finding content identities; "
            "refusing to generate order-index fingerprints"
        )

    findings = []
    for query, file_result, identity in raw_findings:
        digest_input = "\0".join(["kics-finding-v2", *identity])
        findings.append({
            "query_id":      query["query_id"],
            "query_name":    query["query_name"],
            "severity":      query["severity"],
            "description":   query.get("description", ""),
            "file_name":     file_result["file_name"],
            "line":          file_result["line"],
            "similarity_id": file_result["similarity_id"],
            "issue_type": file_result.get("issue_type", ""),
            "search_key": file_result.get("search_key", ""),
            "expected_value": file_result.get("expected_value", ""),
            "actual_value": file_result.get("actual_value", ""),
            "fingerprint": hashlib.sha256(digest_input.encode()).hexdigest(),
        })
    return findings


def process_finding(
    finding: dict,
    pr_index: dict[str, dict],
    token: str,
    repo: str,
    base_branch: str,
    dry_run: bool,
    original_branch: str,
    reopen_set: set[str],
    pr_budget: list[int],   # mutable [remaining] so callers see updates
) -> str:
    """
    Process one finding. Returns one of:
    'excluded' | 'open' | 'dismissed' | 'opened' | 'skipped' |
    'error' | 'would-open' | 'rate-limited'
    """
    sim_id     = finding["similarity_id"]
    fingerprint = finding["fingerprint"]
    query_name = finding["query_name"]
    severity   = finding["severity"]
    file_name  = finding["file_name"]
    line       = finding["line"]
    branch     = branch_for(fingerprint)

    print(f"\n  [{severity}] {query_name}")
    print(f"  {file_name}:{line}")
    print(f"  sim: {sim_id[:16]}...")
    print(f"  finding: {fingerprint[:16]}...")

    # ---- 1. Already excluded on disk? --------------------------------
    fingerprint_hit = fingerprint_match_on_disk(finding)
    if fingerprint_hit:
        print(f"  -> skip: finding fingerprint suppressed by {fingerprint_hit}")
        return "excluded"

    # -- 2. Check PR history ---------------------------------------------------
    existing = find_pr(finding, pr_index)
    pr_note = ""

    if existing:
        state  = pr_state(existing)
        pr_num = existing["number"]

        if state == "open":
            print(f"  -> skip: PR #{pr_num} already open")
            return "open"

        if state == "dismissed":
            force = "*" in reopen_set or any(
                fingerprint.startswith(p)
                for p in reopen_set
            )
            if not force:
                print(f"  -> skip: PR #{pr_num} dismissed")
                return "dismissed"
            print(f"  -> PR #{pr_num} dismissed but --reopen matches; reprocessing")

        if state == "merged":
            print(f"  -> PR #{pr_num} merged but suppression is absent; replacing it")
            pr_note = f"replaces merged suppression PR #{pr_num} that is no longer present"

    # -- 3. Rate limit check ---------------------------------------------------
    if pr_budget[0] <= 0:
        print("  -> rate-limited: PR budget exhausted for this run")
        return "rate-limited"

    if dry_run:
        print("  -> [dry-run] would open PR")
        return "would-open"

    # -- 4. Apply fingerprint suppression --------------------------------------
    try:
        if existing is None and remote_branch_exists(branch):
            print(f"  -> error: untracked remote branch {branch} already exists")
            return "error"
        create_branch_from_origin(base_branch, branch)

        ok, reason = apply_exclude_file(finding)
        if not ok:
            print(f"  -> skip: {reason}")
            git("checkout", original_branch)
            return "skipped"

        commit_msg = "\n".join([
            f"security: suppress [{severity}] {query_name}",
            "",
            f"File:       {file_name}:{line}",
            f"Rule:       {finding['query_id']}",
            "Suppression: finding-v2 fingerprint",
            f"Similarity: {sim_id}",
            f"Fingerprint: {fingerprint}",
        ])
        commit_and_push([str(excl_path(finding))], commit_msg, branch)

        title = f"security: [{severity}] {query_name} in {file_name}"
        body  = make_pr_body(finding, note=pr_note)
        pr = open_pr(token, repo, branch, title, body, base_branch)
        if pr:
            pr_budget[0] -= 1
            print(f"  -> opened PR #{pr['number']}: {pr['html_url']}  (budget remaining: {pr_budget[0]})")
            return "opened"
        else:
            print("  -> failed to open PR (check permissions)")
            return "error"

    except subprocess.CalledProcessError as e:
        print(f"  -> git error: {e.stderr}", file=sys.stderr)
        return "error"
    finally:
        subprocess.run(["git", "checkout", original_branch], capture_output=True)


# -- Entry point ---------------------------------------------------------------

def parse_reopen(value: str) -> set[str]:
    raw = value.strip()
    if not raw:
        return set()
    if raw == "all":
        return {"*"}
    prefixes = {part.strip() for part in raw.split(",") if part.strip()}
    invalid = sorted(
        prefix for prefix in prefixes if not re.fullmatch(r"[a-f0-9]{8,64}", prefix)
    )
    if invalid:
        raise argparse.ArgumentTypeError(
            "--reopen values must be 'all' or lowercase hexadecimal "
            "finding fingerprint prefixes between 8 and 64 characters"
        )
    return prefixes


def bounded_positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if not 1 <= parsed <= 100:
        raise argparse.ArgumentTypeError("must be between 1 and 100")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kics",      required=True, help="Path to KICS results JSON")
    parser.add_argument("--repo",      required=True, help="owner/repo")
    parser.add_argument("--token",     required=True, help="GitHub token")
    parser.add_argument("--base",      default="main", help="Base branch (default: main)")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Scan and print actions without making changes")
    parser.add_argument("--pr-limit",  type=bounded_positive_integer,
                        default=DEFAULT_PR_LIMIT,
                        metavar="N",
                        help=f"Max PRs to open per run (default: {DEFAULT_PR_LIMIT}). "
                             "Prevents runaway PR creation when many new findings appear. "
                             "Run again to process remaining findings.")
    parser.add_argument("--reopen",    type=parse_reopen, default=set(),
                        metavar="all|FINGERPRINT[,FINGERPRINT,...]",
                        help="Reprocess dismissed findings. Pass 'all' or comma-separated "
                              "finding fingerprint prefixes (>=8 chars). Only findings in the current "
                             "KICS results are affected.")
    args = parser.parse_args()

    findings = load_findings(args.kics)
    print(f"Loaded {len(findings)} findings from {args.kics}")

    if not findings:
        print("Nothing to do.")
        return

    if args.dry_run:
        print("[dry-run mode -- no PRs will be opened or branches pushed]")

    reopen_set = args.reopen
    if reopen_set == {"*"}:
        print("--reopen all: dismissed findings will be reprocessed")
    elif reopen_set:
        print(f"--reopen: reprocessing dismissed findings matching: {reopen_set}")

    pr_budget = [args.pr_limit]
    print(f"PR limit: {args.pr_limit} per run")

    ensure_label(args.token, args.repo)

    pr_index = prefetch_all_kics_prs(args.token, args.repo)

    orig_branch = current_branch()
    print(f"Starting from branch: {orig_branch}\n")

    stats: dict[str, int] = {}

    for i, finding in enumerate(findings, 1):
        print(f"[{i}/{len(findings)}]", end="")
        result = process_finding(
            finding, pr_index, args.token, args.repo,
            args.base, args.dry_run, orig_branch,
            reopen_set=reopen_set,
            pr_budget=pr_budget,
        )
        stats[result] = stats.get(result, 0) + 1

    print(f"\n{'-' * 50}")
    print("Summary:")
    for state, count in sorted(stats.items()):
        print(f"  {state:20s}: {count}")

    if stats.get("rate-limited", 0):
        print(f"\n  (!)  {stats['rate-limited']} findings hit the PR limit.")
        print(f"     Re-run with --pr-limit {args.pr_limit + DEFAULT_PR_LIMIT} to process more,")
        print("     or wait for the next scheduled workflow run.")
    if stats.get("error", 0):
        raise SystemExit(f"{stats['error']} finding(s) failed to process")


if __name__ == "__main__":
    main()
