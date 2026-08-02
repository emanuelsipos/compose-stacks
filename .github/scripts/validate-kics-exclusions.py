#!/usr/bin/env python3
"""Validate committed KICS suppression metadata and affected paths."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXCLUDE_DIR = ROOT / ".kics-exclude"
SIMILARITY_ID = re.compile(r"^[a-f0-9]{64}$")


def slug(value: str) -> str:
    value = re.sub(r"[/ \\]", "-", value)
    return re.sub(r"[^A-Za-z0-9._-]", "", value)[:60]


def compose_paths() -> list[Path]:
    return sorted(
        path.relative_to(ROOT)
        for pattern in ("compose.yaml", "compose.yml")
        for path in ROOT.rglob(pattern)
        if ".git" not in path.parts
    )


def main() -> int:
    errors: list[str] = []
    paths = compose_paths()

    for exclusion in sorted(EXCLUDE_DIR.iterdir()):
        if exclusion.name == "README.md" or not exclusion.is_file():
            continue

        lines = exclusion.read_text(encoding="utf-8").splitlines()
        if not lines or not SIMILARITY_ID.fullmatch(lines[0]):
            errors.append(f"{exclusion.name}: missing or invalid similarity ID")
            continue

        if len(lines) >= 3:
            candidates = [Path(lines[2])]
        else:
            candidates = [
                path for path in paths if f"_{slug(path.as_posix())}_L" in exclusion.name
            ]

        if len(candidates) != 1:
            errors.append(
                f"{exclusion.name}: affected Compose path is missing or ambiguous"
            )
        elif not (ROOT / candidates[0]).is_file():
            errors.append(f"{exclusion.name}: {candidates[0]} does not exist")

    if errors:
        print("Invalid KICS exclusions:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"Validated {len(list(EXCLUDE_DIR.glob('HIGH_*')))} KICS exclusions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
