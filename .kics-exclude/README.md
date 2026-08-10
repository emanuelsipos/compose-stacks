# .kics-exclude/

Each file in this directory suppresses one HIGH or CRITICAL KICS finding.
The rationale and compensating controls for each accepted risk class are
documented in [`SECURITY.md`](../SECURITY.md).

## File format

```
Filename: {SEVERITY}_{QuerySlug}_{FileSlug}_L{line}_{fingerprint8}
Contents:
  line 1: full KICS similarity_id (scanner metadata)
  line 2: KICS query_id
  line 3: affected file path
  line 4: finding-v3:<semantic finding SHA-256 fingerprint>
```

Where slugs replace `/`, `\`, and spaces with `-`, strip non-alphanumeric
characters (except `.`, `_`, `-`), and are truncated to 60 chars. The suffix is
the first 8 characters of the semantic finding fingerprint. Existing entries can
retain their original line and similarity-ID suffix because the filename is
descriptive only; enforcement reads line 4.

Example:
```
HIGH_Privileged-Containers-Enabled_jupiter-forgejo-compose.yaml_L41_69f30ea6
```

## How suppression works

The `misconfig` CI job reads reviewed fingerprints from `origin/main` and
filters raw KICS JSON and SARIF after scanning. A fingerprint includes the
query, repository-relative file path, issue type, KICS search key, expected
value, and actual value. It deliberately excludes line numbers and KICS
similarity IDs because both can change without changing the reviewed risk.
Unrelated edits that move a finding therefore keep its approval. Changing the
file, service/property path, rule, issue type, expected value, or actual value
requires reapproval. Deleting and later recreating identical risk semantics at
the same file and service/property path inherits the prior approval.

If a semantic identity occurs more than once in one scan, CI suppresses none
of that group and the PR manager refuses to generate suppression PRs for those
findings. Resolve the duplicate findings before reviewing a suppression.

CI verifies all four metadata fields, rejects duplicate fingerprints, and
requires every suppression to refer to an existing Compose file.

## Adding a suppression

1. Let the weekly "Security Scan" run. Manual dispatches are intentionally
   read-only and do not open suppression PRs.
2. The "Generate Fix PRs" job opens one PR per unsuppressed HIGH/CRITICAL
   finding. Each PR adds one file to this directory.
3. Confirm that its rationale and compensating controls are covered by
   `SECURITY.md`; update the risk register if they are not.
4. Merge the PR to permanently suppress it.

To reopen a dismissed (closed-without-merge) suppression PR, rerun the PR
manager locally against trusted `main` with
`--reopen <fingerprint-prefix>` (comma-separated, minimum 8 chars each).

## Removing a suppression

Delete the relevant file from this directory and merge. The finding will
reappear in the next scan.

## What NOT to do

Do **not** use `# kics-scan ignore-line` inline comments — inline suppression
is silently broken in KICS v2.1.x and has no effect.
