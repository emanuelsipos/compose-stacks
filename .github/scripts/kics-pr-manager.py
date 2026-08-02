#!/usr/bin/env python3
"""
kics-pr-manager.py

Per-finding KICS suppression PR manager.

For each finding in the KICS results JSON the script:

  1. Derives a branch name from the finding's similarity_id.

  2. Checks whether a .kics-exclude/<name> file already exists on disk.
     If it does, the exclusion is already committed to main and will be
     picked up by the next scan via the exclude_results action input.
     -> skip.

  3. Looks up the finding in a pre-fetched PR index (one bulk REST call
     at startup -- avoids per-finding search API calls that hit the strict
     installation rate limit of 10 req/min).

  4. Acts on the PR state:
       open       -> skip (already under review)
       dismissed  -> skip, unless --reopen matches this finding
       merged     -> previous suppression was inline (no longer supported);
                    fall through to open an exclude-results PR
       none       -> open an exclude-results PR

Suppression strategy -- ALWAYS exclude-results:
  KICS v2.1.x inline `# kics-scan ignore-line` comments are silently
  ignored for all YAML constructs (confirmed in production logs). Inline
  suppression has been removed. Every finding is handled by writing a
  .kics-exclude/<descriptive-name> file whose content is the similarity_id.
  The workflow reads all .kics-exclude/ files and passes the IDs as the
  exclude_results action input before each KICS scan.

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
        [--reopen all|<sim_prefix>[,<sim_prefix>,...]]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


# -- Constants -----------------------------------------------------------------

LABEL_NAME    = "kics-suppression"
LABEL_COLOR   = "e11d48"
LABEL_DESC    = "KICS security finding awaiting suppression review"
BRANCH_PREFIX = "security/kics-"
SIMILARITY_TAG = "kics-sim"
KICS_EXCLUDE_DIR = ".kics-exclude"
DEFAULT_PR_LIMIT = 20


# -- GitHub API ----------------------------------------------------------------

def gh(method: str, path: str, token: str, payload: dict | None = None) -> dict | list | None:
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
        return None


def ensure_label(token: str, repo: str) -> None:
    if gh("GET", f"/repos/{repo}/labels/{LABEL_NAME}", token):
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
    dict keyed by similarity_id.

    Uses GET /repos/{repo}/pulls (5 000 req/h) instead of
    GET /search/issues per finding (10 req/min for installations).
    The pulls API returns merged_at directly -- no second round-trip needed.
    """
    pr_index: dict[str, dict] = {}
    page = 1
    marker_re = re.compile(rf"<!--\s*{re.escape(SIMILARITY_TAG)}:([a-f0-9]+)\s*-->")
    total_fetched = 0

    print("Prefetching PR history...", end="", flush=True)
    while True:
        batch = gh(
            "GET",
            f"/repos/{repo}/pulls?state=all&per_page=100&page={page}&sort=updated&direction=desc",
            token,
        )
        if not batch or not isinstance(batch, list):
            break
        for pr in batch:
            body = pr.get("body") or ""
            for sim_id in marker_re.findall(body):
                if sim_id not in pr_index:
                    pr_index[sim_id] = pr
        total_fetched += len(batch)
        print(".", end="", flush=True)
        if len(batch) < 100:
            break
        page += 1

    print(f" done ({total_fetched} PRs scanned, {len(pr_index)} KICS findings tracked)")
    return pr_index


def find_pr(similarity_id: str, pr_index: dict[str, dict]) -> dict | None:
    return pr_index.get(similarity_id)


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


# -- Suppression -- always exclude-results -------------------------------------
#
# KICS v2.1.x inline `# kics-scan ignore-line` comments are silently broken
# for all YAML constructs (confirmed in production: lines with the correct
# comment still appear in scan output). Inline suppression has been removed.
# Every finding is handled via .kics-exclude/<descriptive-name>.

def exclude_filename(finding: dict) -> str:
    """
    Human-readable .kics-exclude filename.
    Format: {SEVERITY}_{Query-Name}_{file-path}_L{line}_{sim8}
    Uniqueness: sim8 suffix; readability: everything else.
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
        f"{finding['similarity_id'][:8]}"
    )


def excl_path(finding: dict) -> Path:
    return Path(KICS_EXCLUDE_DIR) / exclude_filename(finding)


def slug_match_on_disk(finding: dict) -> str:
    """
    Return the filename of an existing .kics-exclude/ entry that matches this
    finding by slug prefix (SEVERITY_QuerySlug_FileSlug_), or "" if none found.

    Handles sim_id drift: when a compose file is edited, KICS recomputes the
    similarity_id from changed content. The .kics-exclude file was named with
    the OLD sim_id, so excl_path(finding).exists() returns False. This function
    catches that case using the stable slug prefix that doesn't include sim_id.
    """
    excl_dir = Path(KICS_EXCLUDE_DIR)
    if not excl_dir.is_dir():
        return ""

    def _slug(s: str) -> str:
        s = s.replace("/", "-").replace("\\", "-").replace(" ", "-")
        s = re.sub(r"[^A-Za-z0-9._-]", "", s)
        return s.strip("-")

    prefix = (
        f"{finding['severity']}_"
        f"{_slug(finding['query_name'])[:60]}_"
        f"{_slug(finding['file_name'])[:60]}_"
    )
    for f in excl_dir.iterdir():
        if f.name.startswith(prefix):
            return f.name
    return ""


def apply_exclude_file(finding: dict) -> tuple[bool, str]:
    """
    Write .kics-exclude/<n> with structured content (one field per line):
        line 1: similarity_id  -- passed to --exclude-results
        line 2: query_id       -- for precise filtering
        line 3: file_name      -- for slug-independent suppression matching

    The sim_id drifts when files change; query_id + file_name are stable.
    The Build KICS exclude list step reads only line 1 for --exclude-results.
    The slug filter in the workflow uses the filename prefix, not the content.
    """
    target = excl_path(finding)
    if target.exists():
        return False, f"exclusion file already on disk ({target.name})"
    existing = slug_match_on_disk(finding)
    if existing:
        return False, f"already suppressed by name match ({existing})"
    target.parent.mkdir(exist_ok=True)
    target.write_text(
        finding["similarity_id"] + "\n"
        + finding["query_id"]    + "\n"
        + finding["file_name"]   + "\n"
    )
    return True, target.name


# -- Git helpers ---------------------------------------------------------------

def run(cmd: list[str], **kwargs) -> str:
    result = subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs)
    return result.stdout.strip()


def git(*args: str) -> str:
    return run(["git", *args])


def branch_for(similarity_id: str) -> str:
    return f"{BRANCH_PREFIX}{similarity_id[:16]}"


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


# -- PR content ----------------------------------------------------------------

def sim_tag(similarity_id: str) -> str:
    return f"{SIMILARITY_TAG}:{similarity_id}"


def make_pr_body(finding: dict, note: str = "") -> str:
    sim_id     = finding["similarity_id"]
    query_id   = finding["query_id"]
    query_name = finding["query_name"]
    severity   = finding["severity"]
    file_name  = finding["file_name"]
    line       = finding["line"]
    docs_url   = f"https://docs.kics.io/latest/queries/dockercompose-queries/{query_id}/"
    fname      = exclude_filename(finding)

    suppression_desc = (
        f"exclusion file at `.kics-exclude/{fname}` -- passed to KICS via "
        f"`exclude_results` action input at scan time"
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
        f"<!-- {sim_tag(sim_id)} -->",
    ]
    return "\n".join(lines)


# -- Core logic ----------------------------------------------------------------

def load_findings(kics_json_path: str) -> list[dict]:
    with open(kics_json_path) as f:
        data = json.load(f)
    findings = []
    for query in data.get("queries", []):
        for file_result in query.get("files", []):
            findings.append({
                "query_id":      query["query_id"],
                "query_name":    query["query_name"],
                "severity":      query["severity"],
                "description":   query.get("description", ""),
                "file_name":     file_result["file_name"],
                "line":          file_result["line"],
                "similarity_id": file_result["similarity_id"],
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
    query_name = finding["query_name"]
    severity   = finding["severity"]
    file_name  = finding["file_name"]
    line       = finding["line"]
    branch     = branch_for(sim_id)

    print(f"\n  [{severity}] {query_name}")
    print(f"  {file_name}:{line}")
    print(f"  sim: {sim_id[:16]}...")

    # ---- 1. Already excluded on disk? --------------------------------
    # Exact match first (fast), then slug prefix (handles sim_id drift).
    if excl_path(finding).exists():
        print(f"  -> skip: .kics-exclude/{excl_path(finding).name} already on disk")
        return "excluded"
    slug_hit = slug_match_on_disk(finding)
    if slug_hit:
        print(f"  -> skip: already suppressed by name match ({slug_hit})")
        return "excluded"

    # -- 2. Check PR history ---------------------------------------------------
    existing = find_pr(sim_id, pr_index)
    pr_note = ""

    if existing:
        state  = pr_state(existing)
        pr_num = existing["number"]

        if state == "open":
            print(f"  -> skip: PR #{pr_num} already open")
            return "open"

        if state == "dismissed":
            force = "*" in reopen_set or any(
                sim_id.startswith(p) for p in reopen_set
            )
            if not force:
                print(f"  -> skip: PR #{pr_num} dismissed")
                return "dismissed"
            print(f"  -> PR #{pr_num} dismissed but --reopen matches; reprocessing")

        if state == "merged":
            # The merged PR used inline suppression (now removed). Inline never
            # worked in KICS v2.1.x, so the finding still fires. Open a new
            # exclude-results PR to replace the defunct inline suppression.
            print(f"  -> PR #{pr_num} merged (was inline, ineffective); replacing with exclude-results")
            pr_note = f"replaces merged inline PR #{pr_num} -- inline suppression broken in KICS v2.1.x"

    # -- 3. Rate limit check ---------------------------------------------------
    if pr_budget[0] <= 0:
        print("  -> rate-limited: PR budget exhausted for this run")
        return "rate-limited"

    if dry_run:
        print("  -> [dry-run] would open PR")
        return "would-open"

    # -- 4. Apply exclude-results suppression ----------------------------------
    try:
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
            f"Suppression: exclude-results",
            f"Similarity: {sim_id}",
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

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kics",      required=True, help="Path to KICS results JSON")
    parser.add_argument("--repo",      required=True, help="owner/repo")
    parser.add_argument("--token",     required=True, help="GitHub token")
    parser.add_argument("--base",      default="main", help="Base branch (default: main)")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Scan and print actions without making changes")
    parser.add_argument("--pr-limit",  type=int, default=DEFAULT_PR_LIMIT,
                        metavar="N",
                        help=f"Max PRs to open per run (default: {DEFAULT_PR_LIMIT}). "
                             "Prevents runaway PR creation when many new findings appear. "
                             "Run again to process remaining findings.")
    parser.add_argument("--reopen",    default="",
                        metavar="all|SIM[,SIM,...]",
                        help="Reprocess dismissed findings. Pass 'all' or comma-separated "
                             "similarity_id prefixes (>=8 chars). Only findings in the current "
                             "KICS results are affected.")
    args = parser.parse_args()

    findings = load_findings(args.kics)
    print(f"Loaded {len(findings)} findings from {args.kics}")

    if not findings:
        print("Nothing to do.")
        return

    if args.dry_run:
        print("[dry-run mode -- no PRs will be opened or branches pushed]")

    # Build reopen set
    reopen_set: set[str] = set()
    if args.reopen.strip():
        raw = args.reopen.strip()
        if raw.lower() == "all":
            reopen_set = {"*"}
            print("--reopen all: dismissed findings will be reprocessed")
        else:
            reopen_set = {p.strip() for p in raw.split(",") if p.strip()}
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
        print(f"     or trigger the workflow again (schedule/dispatch).")


if __name__ == "__main__":
    main()
