#!/usr/bin/env python3
"""Helpers used by the security scan workflow."""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import urllib.parse
import urllib.request
from pathlib import Path


DEPLOYMENT_SUFFIXES = {".yaml", ".yml"}
IMAGE_BUCKET_COUNT = 16
IMAGE_LINE = re.compile(r"^\s*image:\s*[\"']?([^\"'\s]+)")
PACKAGE_LINE = re.compile(r"^Package:\s*(.+)$", re.MULTILINE)
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
    "cs01/schemas/sarif-schema-2.1.0.json"
)
SIMILARITY_ID = re.compile(r"^[a-f0-9]{64}$")
KICS_QUERY_REF = re.compile(
    r"repository:\s*Checkmarx/kics\s*\n\s*ref:\s*[a-f0-9]{40}\s*#\s*v([^\s]+)"
)
KICS_QUERY_REF_COUNT = 2
KICS_VERSION = "2.1.20"
KICS_ARCHIVE_SHA256 = "8a5aa375ccfdc0ddd1114eddf1f9638ad7f6122e98d12a592207509dbe6d81f8"
KICS_ARCHIVE_URL = (
    f"https://github.com/Checkmarx/kics/releases/download/v{KICS_VERSION}/"
    f"kics_{KICS_VERSION}_linux_amd64.tar.gz"
)


def changed_deployment_files(before: str, after: str, root: Path) -> list[Path]:
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
            ":(glob)**/*.yaml",
            ":(glob)**/*.yml",
            ":(exclude).github/**",
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


def all_deployment_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.suffix in DEPLOYMENT_SUFFIXES
        and ".github" not in path.parts
        and ".kics-exclude" not in path.parts
    )


def kics_scan_path(event: str, base: str, head: str, root: Path) -> str | None:
    if event != "pull_request":
        return "."
    files = changed_deployment_files(base, head, root)
    relative_paths = [path.relative_to(root).as_posix() for path in files]
    if any("," in name or "\n" in name for name in relative_paths):
        raise SystemExit("KICS scan paths cannot contain commas or newlines")
    return ",".join(relative_paths) or None


def images_from_files(files: list[Path]) -> list[str]:
    images: set[str] = set()
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if match := IMAGE_LINE.match(line):
                images.add(match.group(1))
    return sorted(images)


def canonical_image_repository(image: str) -> str:
    reference = image.split("@", 1)[0]
    last_slash = reference.rfind("/")
    last_colon = reference.rfind(":")
    if last_colon > last_slash:
        reference = reference[:last_colon]

    parts = reference.split("/")
    first = parts[0]
    if len(parts) == 1:
        return f"docker.io/library/{reference}".lower()
    if "." not in first and ":" not in first and first != "localhost":
        return f"docker.io/{reference}".lower()
    return reference.lower()


def image_matrix(
    images: list[str],
    bucket_count: int = IMAGE_BUCKET_COUNT,
    include_empty: bool = False,
) -> dict[str, list[dict[str, str]]]:
    buckets: dict[int, list[str]] = {}
    for image in sorted(set(images)):
        repository = canonical_image_repository(image)
        bucket = (
            int(hashlib.sha256(repository.encode()).hexdigest()[:8], 16)
            % bucket_count
        )
        buckets.setdefault(bucket, []).append(image)
    bucket_ids = range(bucket_count) if include_empty else sorted(buckets)
    return {
        "include": [
            {"id": f"{bucket:02d}", "images": " ".join(buckets.get(bucket, []))}
            for bucket in bucket_ids
        ]
    }


def empty_sarif() -> dict:
    return {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trivy",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }


def normalize_image_sarif(document: dict, image: str) -> dict:
    normalized = copy.deepcopy(document)
    repository = canonical_image_repository(image)

    def normalize_uri(uri: str) -> tuple[str, str]:
        prefix = f"docker-image://{repository}/"
        if uri.startswith(prefix):
            return uri, urllib.parse.unquote(uri.removeprefix(prefix))
        target = uri.lstrip("/")
        return f"{prefix}container", target

    for run in normalized.get("runs", []):
        run["properties"] = {
            "imageRepository": repository,
            "imageReference": image,
        }
        artifacts = run.get("artifacts", [])
        artifact_targets: dict[int, str] = {}
        for index, artifact in enumerate(artifacts):
            location = artifact.get("location", {})
            if isinstance(location.get("uri"), str):
                location["uri"], artifact_targets[index] = normalize_uri(
                    location["uri"]
                )
                location.pop("uriBaseId", None)

        for result in run.get("results", []):
            properties = result.setdefault("properties", {})
            properties["imageRepository"] = repository
            properties["imageReference"] = image

            result_targets: list[str] = []

            def normalize_result_locations(value: object) -> None:
                if isinstance(value, dict):
                    artifact_location = value.get("artifactLocation")
                    if isinstance(artifact_location, dict):
                        artifact_index = artifact_location.get("index")
                        if isinstance(artifact_location.get("uri"), str):
                            artifact_location["uri"], target = normalize_uri(
                                artifact_location["uri"]
                            )
                            artifact_location.pop("uriBaseId", None)
                            result_targets.append(target)
                        elif isinstance(artifact_index, int):
                            if target := artifact_targets.get(artifact_index):
                                result_targets.append(target)
                    for child in value.values():
                        normalize_result_locations(child)
                elif isinstance(value, list):
                    for child in value:
                        normalize_result_locations(child)

            normalize_result_locations(result)
            target = result_targets[0] if result_targets else ""
            if target:
                properties["imageTarget"] = target

            message = result.get("message", {}).get("text", "")
            package_match = PACKAGE_LINE.search(message)
            rule_id = result.get("ruleId")
            if package_match and rule_id:
                identity = "\0".join(
                    [
                        "trivy-container-v1",
                        repository,
                        rule_id,
                        package_match.group(1).strip(),
                    ]
                )
                result.setdefault("partialFingerprints", {})[
                    "primaryLocationLineHash"
                ] = hashlib.sha256(identity.encode()).hexdigest()

    return normalized


def combine_sarif(documents: list[dict]) -> dict:
    runs = [run for document in documents for run in document.get("runs", [])]
    if not runs:
        raise ValueError("at least one SARIF run is required")

    combined = copy.deepcopy(runs[0])
    driver = combined.setdefault("tool", {}).setdefault("driver", {})
    combined_rules: list[dict] = []
    rule_indices: dict[str, int] = {}
    combined_results: list[dict] = []
    combined_artifacts: list[dict] = []

    def remap_artifacts(value: object, offset: int) -> None:
        if isinstance(value, dict):
            artifact = value.get("artifactLocation")
            if isinstance(artifact, dict) and isinstance(artifact.get("index"), int):
                artifact["index"] += offset
            for child in value.values():
                remap_artifacts(child, offset)
        elif isinstance(value, list):
            for child in value:
                remap_artifacts(child, offset)

    for run in runs:
        local_rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        local_rule_indices: dict[int, int] = {}
        for local_index, rule in enumerate(local_rules):
            rule_key = rule.get("id") or json.dumps(rule, sort_keys=True)
            if rule_key not in rule_indices:
                rule_indices[rule_key] = len(combined_rules)
                combined_rules.append(copy.deepcopy(rule))
            local_rule_indices[local_index] = rule_indices[rule_key]

        artifact_offset = len(combined_artifacts)
        combined_artifacts.extend(copy.deepcopy(run.get("artifacts", [])))
        for result in copy.deepcopy(run.get("results", [])):
            local_rule_index = result.get("ruleIndex")
            if local_rule_index in local_rule_indices:
                result["ruleIndex"] = local_rule_indices[local_rule_index]
            elif result.get("ruleId") in rule_indices:
                result["ruleIndex"] = rule_indices[result["ruleId"]]
            remap_artifacts(result, artifact_offset)
            combined_results.append(result)

    driver["rules"] = combined_rules
    combined["results"] = combined_results
    combined.pop("properties", None)
    if combined_artifacts:
        combined["artifacts"] = combined_artifacts
    else:
        combined.pop("artifacts", None)

    return {
        "version": "2.1.0",
        "$schema": documents[0].get("$schema"),
        "runs": [combined],
    }


def combine_sarif_files(files: list[Path]) -> dict:
    documents = [json.loads(path.read_text(encoding="utf-8")) for path in files]
    return combine_sarif(documents) if documents else empty_sarif()


def exclusion_ids(root: Path, ref: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", ref, "--", ".kics-exclude/"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    exclusions: list[str] = []
    for name in result.stdout.splitlines():
        content = subprocess.run(
            ["git", "show", f"{ref}:{name}"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        similarity_id = content.splitlines()[0].strip()
        if SIMILARITY_ID.fullmatch(similarity_id):
            exclusions.append(similarity_id)
    return exclusions


def kics_command(args: argparse.Namespace, root: Path) -> list[str]:
    command = [
        str(Path(args.executable).resolve()),
        "scan",
        "-p",
        args.path,
        "--config",
        "kics-config.yaml",
        "--queries-path",
        args.queries,
        "--libraries-path",
        args.libraries,
        "--report-formats",
        args.formats,
        "-o",
        args.output,
        "-e",
        ".git,.cache,.github",
        "--ignore-on-exit",
        "all",
    ]
    if args.exclude_severities:
        command.extend(["--exclude-severities", args.exclude_severities])
    if args.exclude_results:
        command.extend(["--exclude-results", args.exclude_results])
    return command


def install_kics(args: argparse.Namespace) -> None:
    destination = Path(args.destination).resolve()
    with urllib.request.urlopen(KICS_ARCHIVE_URL) as response:
        archive = response.read()
    actual_digest = hashlib.sha256(archive).hexdigest()
    if actual_digest != KICS_ARCHIVE_SHA256:
        raise SystemExit(
            f"KICS archive SHA-256 mismatch: expected {KICS_ARCHIVE_SHA256}, "
            f"received {actual_digest}"
        )
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        source = package.extractfile("kics")
        if source is None:
            raise SystemExit("KICS archive does not contain the kics binary")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("wb") as binary:
            shutil.copyfileobj(source, binary)
    destination.chmod(0o755)
    print(f"Installed KICS {KICS_VERSION} at {destination}")


def verify_kics_pins(args: argparse.Namespace) -> None:
    workflow = Path(args.workflow)
    versions = KICS_QUERY_REF.findall(workflow.read_text(encoding="utf-8"))
    if len(versions) != KICS_QUERY_REF_COUNT:
        raise SystemExit(
            f"Expected {KICS_QUERY_REF_COUNT} pinned Checkmarx/kics checkouts in "
            f"{workflow}, found {len(versions)}"
        )
    mismatches = [version for version in versions if version != KICS_VERSION]
    if mismatches:
        raise SystemExit(
            f"KICS query version(s) {', '.join(mismatches)} do not match "
            f"the scanner version {KICS_VERSION}"
        )
    print(f"Validated {len(versions)} KICS query pin(s) at v{KICS_VERSION}")


def write_output(name: str, value: str) -> None:
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"{name}={value}\n")


def kics_plan(args: argparse.Namespace) -> None:
    path = kics_scan_path(args.event, args.base, args.head, Path(args.root).resolve())
    write_output("skip", "false" if path else "true")
    if path:
        write_output("path", path)
        print(f"KICS will scan {path}")
    else:
        print("No changed deployment YAML; KICS scan will be skipped")


def image_scan_files(
    event: str,
    before: str,
    base: str,
    head: str,
    scanners: str,
    root: Path,
) -> tuple[list[Path], bool]:
    if event == "workflow_dispatch" and scanners not in {"all", "trivy"}:
        return [], False
    if event in {"schedule", "workflow_dispatch"}:
        return all_deployment_files(root), True
    if event == "pull_request":
        return changed_deployment_files(base, head, root), False
    if before and set(before) != {"0"}:
        return changed_deployment_files(before, "HEAD", root), False
    return all_deployment_files(root), True


def plan(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    files, full_inventory = image_scan_files(
        args.event,
        args.before,
        args.base,
        args.head,
        args.scanners,
        root,
    )
    images = images_from_files(files)
    matrix = json.dumps(
        image_matrix(images, include_empty=full_inventory),
        separators=(",", ":"),
    )
    write_output("count", str(len(images)))
    write_output("full_inventory", str(full_inventory).lower())
    write_output("matrix", matrix)
    scope = "full inventory" if full_inventory else "changed files"
    print(
        f"Planned {len(images)} image(s) from {scope} across "
        f"{len(json.loads(matrix)['include'])} job(s)."
    )


def combine(args: argparse.Namespace) -> None:
    files = sorted(Path().glob(args.pattern))
    Path(args.output).write_text(
        json.dumps(combine_sarif_files(files), separators=(",", ":")),
        encoding="utf-8",
    )


def normalize(args: argparse.Namespace) -> None:
    source = Path(args.input)
    document = json.loads(source.read_text(encoding="utf-8"))
    Path(args.output).write_text(
        json.dumps(
            normalize_image_sarif(document, args.image),
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


def exclusions(args: argparse.Namespace) -> None:
    values = exclusion_ids(Path(args.root).resolve(), args.ref)
    write_output("list", ",".join(values))
    print(f"Loaded {len(values)} exclusion(s) from {args.ref}")


def kics(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    Path(args.output).mkdir(parents=True, exist_ok=True)
    result = subprocess.run(kics_command(args, root), cwd=root, check=False)
    raise SystemExit(result.returncode)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(required=True)

    kics_plan_parser = commands.add_parser("kics-plan")
    kics_plan_parser.add_argument("--event", required=True)
    kics_plan_parser.add_argument("--base", default="")
    kics_plan_parser.add_argument("--head", default="")
    kics_plan_parser.add_argument("--root", default=".")
    kics_plan_parser.set_defaults(func=kics_plan)

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

    normalize_parser = commands.add_parser("normalize-image-sarif")
    normalize_parser.add_argument("--input", required=True)
    normalize_parser.add_argument("--output", required=True)
    normalize_parser.add_argument("--image", required=True)
    normalize_parser.set_defaults(func=normalize)

    exclusions_parser = commands.add_parser("exclusions")
    exclusions_parser.add_argument("--ref", default="origin/main")
    exclusions_parser.add_argument("--root", default=".")
    exclusions_parser.set_defaults(func=exclusions)

    kics_parser = commands.add_parser("kics")
    kics_parser.add_argument("--path", required=True)
    kics_parser.add_argument("--formats", required=True)
    kics_parser.add_argument("--output", required=True)
    kics_parser.add_argument("--queries", required=True)
    kics_parser.add_argument("--libraries", required=True)
    kics_parser.add_argument("--exclude-results", default="")
    kics_parser.add_argument("--exclude-severities", default="")
    kics_parser.add_argument("--executable", default="kics")
    kics_parser.add_argument("--root", default=".")
    kics_parser.set_defaults(func=kics)

    verify_parser = commands.add_parser("verify-kics-pins")
    verify_parser.add_argument(
        "--workflow", default=".github/workflows/security-scan.yml"
    )
    verify_parser.set_defaults(func=verify_kics_pins)

    install_parser = commands.add_parser("install-kics")
    install_parser.add_argument("--destination", required=True)
    install_parser.set_defaults(func=install_kics)
    return root


if __name__ == "__main__":
    arguments = parser().parse_args()
    arguments.func(arguments)
