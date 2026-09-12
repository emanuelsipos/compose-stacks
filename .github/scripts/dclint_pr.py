#!/usr/bin/env python3
"""Run dclint against only Compose files changed by a pull request."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


COMPOSE_PATHS = (
    ":(glob)**/compose.yaml",
    ":(glob)**/compose.yml",
)


def changed_compose_files(before: str, after: str, root: Path) -> list[Path]:
    result = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
            before,
            after,
            "--",
            *COMPOSE_PATHS,
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    names = [
        name.decode(errors="surrogateescape")
        for name in result.stdout.split(b"\0")
        if name
    ]
    return [root / name for name in names if (root / name).is_file()]


def dclint_command(files: list[Path], root: Path) -> list[str]:
    return [
        "npx",
        "--yes",
        "dclint@3.1.0",
        *[path.relative_to(root).as_posix() for path in files],
        "--formatter",
        "github",
        "--max-warnings",
        "0",
    ]


def write_summary(files: list[Path], root: Path, status: str) -> None:
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary:
        return

    with Path(summary).open("a", encoding="utf-8") as output:
        output.write("### DCLint Pull Request Check\n")
        output.write(f"- Status: {status}\n")
        output.write(f"- Compose files checked: {len(files)}\n")
        for path in files:
            output.write(f"  - `{path.relative_to(root).as_posix()}`\n")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} BASE_SHA HEAD_SHA", file=sys.stderr)
        return 2

    root = Path.cwd()
    files = changed_compose_files(argv[1], argv[2], root)
    if not files:
        print("No changed Compose files; skipping dclint.")
        write_summary(files, root, "Skipped: no changed Compose files")
        return 0

    result = subprocess.run(dclint_command(files, root), cwd=root, check=False)
    status = "Success" if result.returncode == 0 else f"Failed (exit code {result.returncode})"
    write_summary(files, root, status)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
