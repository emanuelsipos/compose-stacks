# .kics-exclude/

Each file in this directory suppresses one HIGH or CRITICAL KICS finding.
The rationale and compensating controls for each accepted risk class are
documented in [`SECURITY.md`](../SECURITY.md).

## File format

```
Filename: {SEVERITY}_{QuerySlug}_{FileSlug}_L{line}_{sim8}
Contents:
  line 1: full KICS similarity_id
  line 2: KICS query_id (newer entries)
  line 3: affected file path (newer entries)
```

Where slugs replace `/`, `\`, and spaces with `-`, strip non-alphanumeric
characters (except `.`, `_`, `-`), and are truncated to 60 chars. The `{sim8}`
suffix is the first 8 characters of the similarity_id for uniqueness.

Example:
```
HIGH_Privileged-Containers-Enabled_jupiter-forgejo-compose.yaml_L43_e7818330
```

## How suppression works

The `misconfig` CI job reads all files in this directory from `origin/main`
and passes their similarity_ids to KICS via `--exclude-results`. It also
matches on the `{SEVERITY}_{QuerySlug}_{FileSlug}_` prefix so suppression
remains stable if line numbers shift when a file is edited after a suppression
was merged. This fallback is intentionally scoped to a severity, rule, and
Compose file. A new occurrence of the same rule in an already accepted file is
therefore covered by the existing suppression and must be reviewed when that
file changes.

CI also verifies that each suppression contains a valid similarity ID and
still refers to an existing Compose file.

## Adding a suppression

1. Let the weekly "Security Scan" run, or trigger it manually (Actions tab →
   Security Scan → workflow_dispatch).
2. The "Generate Fix PRs" job opens one PR per unsuppressed HIGH/CRITICAL
   finding. Each PR adds one file to this directory.
3. Confirm that its rationale and compensating controls are covered by
   `SECURITY.md`; update the risk register if they are not.
4. Merge the PR to permanently suppress it.

To reopen a dismissed (closed-without-merge) suppression PR, trigger the
Security Scan workflow with `reopen_findings=<sim8prefix>` (comma-separated,
minimum 8 chars each; e.g. `fe37c69c,87a31c47`).

## Removing a suppression

Delete the relevant file from this directory and merge. The finding will
reappear in the next scan.

## What NOT to do

Do **not** use `# kics-scan ignore-line` inline comments — inline suppression
is silently broken in KICS v2.1.x and has no effect.
