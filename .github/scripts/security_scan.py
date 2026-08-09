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
from collections import Counter
from pathlib import Path


DEPLOYMENT_SUFFIXES = {".yaml", ".yml"}
KICS_CONTROL_PATHS = (
    ".kics-exclude/",
    "kics-config.yaml",
    ".github/scripts/security_scan.py",
    ".github/scripts/validate-kics-exclusions.py",
    ".github/workflows/security-scan.yml",
)
IMAGE_BUCKET_COUNT = 16
IMAGE_KEY = re.compile(r'''^\s*(?:image|"image"|'image')\s*:''')
IMAGE_LINE = re.compile(
    r'''^\s*(?:image|"image"|'image')\s*:\s*'''
    r'''(?P<quote>["']?)(?P<image>[^\s"'#]+)(?P=quote)\s*(?:#.*)?$'''
)
FLOW_IMAGE_KEY = re.compile(r'''(?:^|[{,])\s*(?:image|"image"|'image')\s*:''')
ESCAPED_MAPPING_KEY = re.compile(r'''(?:^|[{,])\s*"[^"]*\\[^"]*"\s*:''')
ESCAPED_MAPPING_KEY_START = re.compile(r'''(?:^|[{,])\s*"[^"]*\\''')
COMPLEX_MAPPING_KEY = re.compile(r"(?:^|[{,])\s*[?*!&]")
PACKAGE_LINE = re.compile(r"^Package:\s*(.+)$", re.MULTILINE)
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
    "cs01/schemas/sarif-schema-2.1.0.json"
)
KICS_FINGERPRINT = re.compile(r"^finding-v([12]):([a-f0-9]{64})$")
PINNED_IMAGE_REFERENCE = re.compile(r"^[^@\s]+@sha256:[a-f0-9]{64}$")
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


def kics_controls_changed(before: str, after: str, root: Path) -> bool:
    result = subprocess.run(
        ["git", "diff", "--quiet", before, after, "--", *KICS_CONTROL_PATHS],
        cwd=root,
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise subprocess.CalledProcessError(result.returncode, result.args)
    return result.returncode == 1


def kics_scan_path(event: str, base: str, head: str, root: Path) -> str | None:
    if event != "pull_request":
        return "."
    if kics_controls_changed(base, head, root):
        return "."
    files = changed_deployment_files(base, head, root)
    relative_paths = [path.relative_to(root).as_posix() for path in files]
    if any("," in name or "\r" in name or "\n" in name for name in relative_paths):
        raise SystemExit("KICS scan paths cannot contain commas or line breaks")
    return ",".join(relative_paths) or None


def images_from_files(files: list[Path]) -> list[str]:
    images: set[str] = set()
    for path in files:
        if path.is_symlink():
            raise ValueError(f"Deployment YAML cannot be a symlink: {path}")
        images.update(images_from_text(path.read_text(encoding="utf-8")))
    return sorted(images)


def images_from_git_ref(
    ref: str, root: Path, files: list[Path] | None = None
) -> list[str]:
    if files is not None and not files:
        return []
    images: set[str] = set()
    if files is None:
        result = subprocess.run(
            ["git", "ls-tree", "-r", "-z", "--name-only", ref],
            cwd=root,
            check=True,
            capture_output=True,
        )
        paths = [
            name.decode(errors="surrogateescape")
            for name in result.stdout.split(b"\0")
            if name
            and Path(name.decode(errors="surrogateescape")).suffix
            in DEPLOYMENT_SUFFIXES
            and ".github"
            not in Path(name.decode(errors="surrogateescape")).parts
            and ".kics-exclude"
            not in Path(name.decode(errors="surrogateescape")).parts
        ]
    else:
        paths = [path.relative_to(root).as_posix() for path in files]
    for path in paths:
        result = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
        images.update(images_from_text(result.stdout))
    return sorted(images)


def images_from_text(content: str) -> set[str]:
    images: set[str] = set()
    for line in content.splitlines():
        if (
            ESCAPED_MAPPING_KEY.search(line)
            or ESCAPED_MAPPING_KEY_START.search(line)
            or COMPLEX_MAPPING_KEY.search(line)
        ):
            raise ValueError(
                "Unsupported Compose mapping key syntax: " + line.strip()
            )
        if image := image_from_line(line):
            images.add(image)
        elif FLOW_IMAGE_KEY.search(line):
            raise ValueError(
                "Unsupported Compose image declaration (flow style): "
                + line.strip()
            )
    return images


def image_from_line(line: str) -> str | None:
    if not IMAGE_KEY.match(line):
        return None
    match = IMAGE_LINE.match(line)
    if not match:
        raise ValueError(f"Unsupported Compose image declaration: {line.strip()}")
    image = match.group("image")
    if image in {"|", "|-", "|+", ">", ">-", ">+"}:
        raise ValueError(f"Unsupported Compose image declaration: {line.strip()}")
    return image


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
    baseline_images: list[str] | None = None,
) -> dict[str, list[dict[str, str]]]:
    current_by_repository: dict[str, set[str]] = {}
    for image in images:
        current_by_repository.setdefault(canonical_image_repository(image), set()).add(
            image
        )
    ambiguous_current = sorted(
        repository
        for repository, references in current_by_repository.items()
        if len(references) > 1
    )
    if ambiguous_current:
        raise ValueError(
            "Ambiguous current image reference(s) for repository: "
            + ", ".join(ambiguous_current)
        )
    for references in current_by_repository.values():
        validate_pinned_image(next(iter(references)))

    baseline_by_repository: dict[str, set[str]] = {}
    for image in baseline_images or []:
        repository = canonical_image_repository(image)
        if repository in current_by_repository:
            baseline_by_repository.setdefault(repository, set()).add(image)
    ambiguous_baseline = sorted(
        repository
        for repository, references in baseline_by_repository.items()
        if len(references) > 1
    )
    if ambiguous_baseline:
        raise ValueError(
            "Ambiguous trusted-base image reference(s) for repository: "
            + ", ".join(ambiguous_baseline)
        )
    for references in baseline_by_repository.values():
        validate_pinned_image(next(iter(references)))

    buckets: dict[int, list[str]] = {}
    for image in sorted(set(images)):
        repository = canonical_image_repository(image)
        bucket = (
            int(hashlib.sha256(repository.encode()).hexdigest()[:8], 16)
            % bucket_count
        )
        buckets.setdefault(bucket, []).append(image)
    bucket_ids = range(bucket_count) if include_empty else sorted(buckets)
    entries: list[dict[str, str]] = []
    for bucket in bucket_ids:
        bucket_images = buckets.get(bucket, [])
        entry = {"id": f"{bucket:02d}", "images": " ".join(bucket_images)}
        if baseline_images is not None:
            entry["baseline_images"] = " ".join(
                next(iter(baseline_by_repository[repository]))
                for repository in sorted(
                    canonical_image_repository(image) for image in bucket_images
                )
                if repository in baseline_by_repository
            )
        entries.append(entry)
    return {"include": entries}


def kics_finding_identity(query_id: str, finding: dict) -> tuple[str, ...]:
    path = str(finding.get("file_name", "")).replace("\\", "/").removeprefix("./")
    return (
        query_id,
        path,
        str(finding.get("issue_type", "")),
        str(finding.get("search_key", "")),
        str(finding.get("expected_value", "")),
        str(finding.get("actual_value", "")),
        str(finding.get("line", 0)),
        str(finding.get("search_line", 0)),
    )


def kics_finding_content_identity(query_id: str, finding: dict) -> tuple[str, ...]:
    return kics_finding_identity(query_id, finding)[:-2]


def validate_pinned_image(image: str) -> None:
    if not PINNED_IMAGE_REFERENCE.fullmatch(image):
        raise ValueError(
            "Image reference must be pinned by @sha256:<64 lowercase hex>: "
            + image
        )


def kics_finding_fingerprint(query_id: str, finding: dict) -> str:
    identity = "\0".join(
        ["kics-finding-v2", *kics_finding_identity(query_id, finding)]
    )
    return hashlib.sha256(identity.encode()).hexdigest()


def kics_finding_v1_fingerprint(
    query_id: str, finding: dict, occurrence: int
) -> str:
    identity = "\0".join(
        [
            "kics-finding-v1",
            *kics_finding_content_identity(query_id, finding),
            str(occurrence),
        ]
    )
    return hashlib.sha256(identity.encode()).hexdigest()


def exclusion_records(root: Path, ref: str) -> list[dict[str, str]]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", ref, "--", ".kics-exclude/"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    records: list[dict[str, str]] = []
    for name in result.stdout.splitlines():
        if name.endswith("/README.md"):
            continue
        content = subprocess.run(
            ["git", "show", f"{ref}:{name}"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        lines = content.splitlines()
        version = ""
        fingerprint = ""
        if len(lines) == 4 and (
            match := KICS_FINGERPRINT.fullmatch(lines[3].strip())
        ):
            version, fingerprint = match.groups()
        records.append(
            {
                "name": Path(name).name,
                "similarity_id": lines[0].strip() if lines else "",
                "query_id": lines[1].strip() if len(lines) >= 2 else "",
                "file_name": lines[2].strip() if len(lines) >= 3 else "",
                "version": version,
                "fingerprint": fingerprint,
            }
        )
    return records


def exclusion_fingerprints(
    root: Path, ref: str, trusted_baseline: dict | None = None
) -> set[str]:
    records = exclusion_records(root, ref)
    fingerprints = {
        record["fingerprint"] for record in records if record["version"] == "2"
    }
    trusted_v1 = [record for record in records if record["version"] == "1"]
    if not trusted_v1:
        return fingerprints
    if trusted_baseline is None:
        raise ValueError(
            "Trusted-base KICS JSON is required to resolve finding-v1 records"
        )

    v1_to_v2: dict[str, list[str]] = {}
    for query in trusted_baseline.get("queries", []):
        query_id = str(query.get("query_id", ""))
        occurrences: Counter[tuple[str, ...]] = Counter()
        for finding in query.get("files", []):
            identity = kics_finding_content_identity(query_id, finding)
            occurrence = occurrences[identity]
            occurrences[identity] += 1
            v1 = kics_finding_v1_fingerprint(query_id, finding, occurrence)
            v1_to_v2.setdefault(v1, []).append(
                kics_finding_fingerprint(query_id, finding)
            )

    for record in trusted_v1:
        matches = v1_to_v2.get(record["fingerprint"], [])
        if len(matches) == 1:
            fingerprints.add(matches[0])
    return fingerprints


def trusted_exclusions_need_baseline(root: Path, ref: str) -> bool:
    return any(record["version"] == "1" for record in exclusion_records(root, ref))


def filter_kics_json(
    document: dict, fingerprints: set[str]
) -> tuple[
    dict,
    Counter[tuple[str, str, int, str]],
    Counter[tuple[str, str, int, str]],
]:
    filtered = copy.deepcopy(document)
    suppressed: Counter[tuple[str, str, int, str]] = Counter()
    findings: Counter[tuple[str, str, int, str]] = Counter()
    identity_counts = Counter(
        kics_finding_identity(query.get("query_id", ""), finding)
        for query in filtered.get("queries", [])
        for finding in query.get("files", [])
    )
    for query in filtered.get("queries", []):
        query_id = query.get("query_id", "")
        kept = []
        for finding in query.get("files", []):
            identity = kics_finding_identity(query_id, finding)
            sarif_key = (
                query_id,
                str(finding.get("file_name", ""))
                .replace("\\", "/")
                .removeprefix("./"),
                int(finding.get("line", 0)),
                str(finding.get("actual_value", "")),
            )
            findings[sarif_key] += 1
            if (
                identity_counts[identity] == 1
                and kics_finding_fingerprint(query_id, finding) in fingerprints
            ):
                suppressed[sarif_key] += 1
            else:
                kept.append(finding)
        query["files"] = kept
    return filtered, suppressed, findings


def filter_kics_sarif(
    document: dict,
    suppressed: Counter[tuple[str, str, int, str]],
    findings: Counter[tuple[str, str, int, str]],
) -> dict:
    filtered = copy.deepcopy(document)
    sarif_counts: Counter[tuple[str, str, int, str]] = Counter()
    for run in filtered.get("runs", []):
        for result in run.get("results", []):
            sarif_counts[kics_sarif_result_key(result)] += 1
    removable = {
        key
        for key, count in suppressed.items()
        if count == findings[key] == sarif_counts[key]
    }
    for run in filtered.get("runs", []):
        kept = []
        for result in run.get("results", []):
            if kics_sarif_result_key(result) not in removable:
                kept.append(result)
        run["results"] = kept
    return filtered


def kics_sarif_result_key(result: dict) -> tuple[str, str, int, str]:
    location = result.get("locations", [{}])[0].get("physicalLocation", {})
    path = (
        str(location.get("artifactLocation", {}).get("uri", ""))
        .replace("\\", "/")
        .removeprefix("./")
    )
    return (
        str(result.get("ruleId", "")),
        path,
        int(location.get("region", {}).get("startLine", 0)),
        str(result.get("message", {}).get("text", "")),
    )


def sarif_result_identity(result: dict) -> str:
    fingerprint = result.get("partialFingerprints", {}).get("primaryLocationLineHash")
    if isinstance(fingerprint, str) and fingerprint:
        return fingerprint
    properties = result.get("properties", {})
    identity = "\0".join(
        [
            "sarif-result-v1",
            str(properties.get("imageRepository", "")),
            str(result.get("ruleId", "")),
            str(result.get("message", {}).get("text", "")),
        ]
    )
    return hashlib.sha256(identity.encode()).hexdigest()


def sarif_difference(current: dict, baseline: dict) -> tuple[dict, int]:
    baseline_ids = {
        sarif_result_identity(result)
        for run in baseline.get("runs", [])
        for result in run.get("results", [])
    }
    difference = copy.deepcopy(current)
    count = 0
    for run in difference.get("runs", []):
        results = [
            result
            for result in run.get("results", [])
            if sarif_result_identity(result) not in baseline_ids
        ]
        run["results"] = results
        count += len(results)
    return difference, count


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
        prefix = f"container-images/{repository}/"
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
    if "\r" in value or "\n" in value:
        raise ValueError("GitHub Actions output values cannot contain line breaks")
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


def kics_exclusions_plan(args: argparse.Namespace) -> None:
    required = trusted_exclusions_need_baseline(
        Path(args.root).resolve(), args.ref
    )
    write_output("needs_baseline", str(required).lower())
    print(
        "Trusted-base KICS scan is "
        + ("required" if required else "not required")
        + " for reviewed exclusions"
    )


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
    baseline_images: list[str] | None = None
    if not full_inventory:
        baseline_ref = args.base if args.event == "pull_request" else args.before
        if baseline_ref and set(baseline_ref) != {"0"}:
            baseline_images = images_from_git_ref(baseline_ref, root)
        else:
            baseline_images = []
    matrix = json.dumps(
        image_matrix(
            images,
            include_empty=full_inventory,
            baseline_images=baseline_images,
        ),
        separators=(",", ":"),
    )
    write_output("count", str(len(images)))
    write_output("full_inventory", str(full_inventory).lower())
    write_output("gate_new", str(not full_inventory).lower())
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


def filter_kics(args: argparse.Namespace) -> None:
    trusted_baseline = (
        json.loads(Path(args.trusted_baseline_json).read_text(encoding="utf-8"))
        if args.trusted_baseline_json
        else None
    )
    fingerprints = exclusion_fingerprints(
        Path(args.root).resolve(), args.ref, trusted_baseline
    )
    json_document = json.loads(Path(args.json).read_text(encoding="utf-8"))
    sarif_document = json.loads(Path(args.sarif).read_text(encoding="utf-8"))
    filtered_json, suppressed, findings = filter_kics_json(
        json_document, fingerprints
    )
    filtered_sarif = filter_kics_sarif(sarif_document, suppressed, findings)
    Path(args.json_output).write_text(
        json.dumps(filtered_json, separators=(",", ":")), encoding="utf-8"
    )
    Path(args.sarif_output).write_text(
        json.dumps(filtered_sarif, separators=(",", ":")), encoding="utf-8"
    )
    print(
        f"Applied {len(fingerprints)} reviewed KICS fingerprint(s); "
        f"suppressed {sum(suppressed.values())} finding(s)"
    )


def diff_sarif(args: argparse.Namespace) -> None:
    current = json.loads(Path(args.current).read_text(encoding="utf-8"))
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    difference, count = sarif_difference(current, baseline)
    Path(args.output).write_text(
        json.dumps(difference, separators=(",", ":")), encoding="utf-8"
    )
    if "GITHUB_OUTPUT" in os.environ:
        write_output("count", str(count))
    print(f"Found {count} newly introduced image vulnerability result(s)")


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

    exclusions_plan_parser = commands.add_parser("kics-exclusions-plan")
    exclusions_plan_parser.add_argument("--ref", default="origin/main")
    exclusions_plan_parser.add_argument("--root", default=".")
    exclusions_plan_parser.set_defaults(func=kics_exclusions_plan)

    plan_parser = commands.add_parser("plan")
    plan_parser.add_argument("--event", required=True)
    plan_parser.add_argument("--before", default="")
    plan_parser.add_argument("--base", default="")
    plan_parser.add_argument("--head", default="")
    plan_parser.add_argument("--scanners", default="all")
    plan_parser.add_argument("--root", default=".")
    plan_parser.set_defaults(func=plan)

    filter_kics_parser = commands.add_parser("filter-kics")
    filter_kics_parser.add_argument("--json", required=True)
    filter_kics_parser.add_argument("--sarif", required=True)
    filter_kics_parser.add_argument("--json-output", required=True)
    filter_kics_parser.add_argument("--sarif-output", required=True)
    filter_kics_parser.add_argument("--ref", default="origin/main")
    filter_kics_parser.add_argument("--root", default=".")
    filter_kics_parser.add_argument("--trusted-baseline-json")
    filter_kics_parser.set_defaults(func=filter_kics)

    diff_parser = commands.add_parser("diff-sarif")
    diff_parser.add_argument("--current", required=True)
    diff_parser.add_argument("--baseline", required=True)
    diff_parser.add_argument("--output", required=True)
    diff_parser.set_defaults(func=diff_sarif)

    combine_parser = commands.add_parser("combine")
    combine_parser.add_argument("--pattern", required=True)
    combine_parser.add_argument("--output", required=True)
    combine_parser.set_defaults(func=combine)

    normalize_parser = commands.add_parser("normalize-image-sarif")
    normalize_parser.add_argument("--input", required=True)
    normalize_parser.add_argument("--output", required=True)
    normalize_parser.add_argument("--image", required=True)
    normalize_parser.set_defaults(func=normalize)

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
