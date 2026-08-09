#!/usr/bin/env python3
"""Validate committed KICS suppression metadata and affected paths."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXCLUDE_DIR = ROOT / ".kics-exclude"
SIMILARITY_ID = re.compile(r"^[a-f0-9]{64}$")
QUERY_ID = re.compile(r"^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$")
FINGERPRINT = re.compile(r"^finding-v1:([a-f0-9]{64})$")


def compose_paths() -> list[Path]:
    return sorted(
        path.relative_to(ROOT)
        for pattern in ("*.yaml", "*.yml")
        for path in ROOT.rglob(pattern)
        if ".git" not in path.parts
        and ".github" not in path.parts
        and ".kics-exclude" not in path.parts
    )


def main() -> int:
    errors: list[str] = []
    paths = set(compose_paths())
    fingerprints: dict[str, str] = {}
    count = 0

    for exclusion in sorted(EXCLUDE_DIR.iterdir()):
        if exclusion.name == "README.md" or not exclusion.is_file():
            continue
        count += 1

        lines = exclusion.read_text(encoding="utf-8").splitlines()
        if len(lines) != 4:
            errors.append(f"{exclusion.name}: expected exactly four metadata lines")
            continue
        if not SIMILARITY_ID.fullmatch(lines[0]):
            errors.append(f"{exclusion.name}: invalid similarity ID")
        if not QUERY_ID.fullmatch(lines[1]):
            errors.append(f"{exclusion.name}: invalid query ID")
        path = Path(lines[2])
        if path.is_absolute() or ".." in path.parts or path not in paths:
            errors.append(f"{exclusion.name}: invalid or missing Compose path {path}")
        match = FINGERPRINT.fullmatch(lines[3])
        if not match:
            errors.append(f"{exclusion.name}: invalid finding fingerprint")
        elif previous := fingerprints.get(match.group(1)):
            errors.append(
                f"{exclusion.name}: duplicate finding fingerprint also in {previous}"
            )
        else:
            fingerprints[match.group(1)] = exclusion.name

    if errors:
        print("Invalid KICS exclusions:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"Validated {count} KICS exclusions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
