#!/usr/bin/env python3
"""Helpers used by the security scan workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


DEPLOYMENT_SUFFIXES = {".yaml", ".yml"}
IMAGE_LINE = re.compile(r"^\s*image:\s*[\"']?([^\"'\s]+)")


def changed_deployment_files(before: str, after: str, root: Path) -> list[Path]:
    result = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            before,
            after,
            "--",
            ":(glob)**/*.yaml",
            ":(glob)**/*.yml",
            ":(exclude).github/**",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return [root / name for name in result.stdout.splitlines() if (root / name).is_file()]


def all_deployment_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.suffix in DEPLOYMENT_SUFFIXES
        and ".github" not in path.parts
        and ".kics-exclude" not in path.parts
    )


def images_from_files(files: list[Path]) -> list[str]:
    images: set[str] = set()
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if match := IMAGE_LINE.match(line):
                images.add(match.group(1))
    return sorted(images)


def image_matrix(images: list[str], bucket_count: int = 16) -> dict[str, list[dict[str, str]]]:
    buckets: dict[int, list[str]] = {}
    for image in sorted(set(images)):
        bucket = int(hashlib.sha256(image.encode()).hexdigest()[:8], 16) % bucket_count
        buckets.setdefault(bucket, []).append(image)
    return {
        "include": [
            {"id": f"{bucket:02d}", "images": " ".join(buckets[bucket])}
            for bucket in sorted(buckets)
        ]
    }


def combine_sarif(documents: list[dict]) -> dict:
    if not documents:
        raise ValueError("at least one SARIF document is required")
    return {
        "version": "2.1.0",
        "$schema": documents[0].get("$schema"),
        "runs": [run for document in documents for run in document.get("runs", [])],
    }


def write_output(name: str, value: str) -> None:
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"{name}={value}\n")


def plan(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    if args.event == "workflow_dispatch" and args.scanners not in {"all", "trivy"}:
        files: list[Path] = []
    elif args.event in {"schedule", "workflow_dispatch"}:
        files = all_deployment_files(root)
    elif args.event == "pull_request":
        files = changed_deployment_files(args.base, args.head, root)
    elif args.before and set(args.before) != {"0"}:
        files = changed_deployment_files(args.before, "HEAD", root)
    else:
        files = all_deployment_files(root)

    images = images_from_files(files)
    matrix = json.dumps(image_matrix(images), separators=(",", ":"))
    write_output("count", str(len(images)))
    write_output("matrix", matrix)
    print(f"Planned {len(images)} image(s) across {len(json.loads(matrix)['include'])} job(s).")


def combine(args: argparse.Namespace) -> None:
    files = sorted(Path().glob(args.pattern))
    documents = [json.loads(path.read_text(encoding="utf-8")) for path in files]
    Path(args.output).write_text(
        json.dumps(combine_sarif(documents), separators=(",", ":")),
        encoding="utf-8",
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(required=True)

    plan_parser = commands.add_parser("plan")
    plan_parser.add_argument("--event", required=True)
    plan_parser.add_argument("--before", default="")
    plan_parser.add_argument("--base", default="")
    plan_parser.add_argument("--head", default="")
    plan_parser.add_argument("--scanners", default="all")
    plan_parser.add_argument("--root", default=".")
    plan_parser.set_defaults(func=plan)

    combine_parser = commands.add_parser("combine")
    combine_parser.add_argument("--pattern", required=True)
    combine_parser.add_argument("--output", required=True)
    combine_parser.set_defaults(func=combine)
    return root


if __name__ == "__main__":
    arguments = parser().parse_args()
    arguments.func(arguments)
