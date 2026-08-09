# Compose Stacks

Docker Compose definitions for services running across a small self-hosted environment. Stacks are grouped by host, with reusable services and defaults kept separately.

## Layout

- `_common/base.yaml` contains shared restart, logging, security, database, and cache defaults.
- `common/` contains reusable stacks.
- `aegis/`, `jupiter/`, and `sage/` contain host-specific deployments.
- `komodo/` contains the deployment control plane.

These files reflect a real deployment and are not intended to be used unchanged. Host paths, device mappings, network addresses, and environment variables must be adapted first. Komodo supplies each stack's environment at deployment time; deployment `.env` files are not stored in this repository.

## Resource overrides

All services inheriting the shared defaults receive a `PIDS_LIMIT` of 512 unless the deployment overrides it. The Docker-in-Docker GitHub runner instead uses `${RUNNER_PIDS_LIMIT:-2048}` to accommodate build process trees. Higher-risk or heavier services have an individual `${SERVICE_MEM_LIMIT:-default}` memory ceiling. Set the relevant `*_MEM_LIMIT` deployment variable (for example, `PLEX_MEM_LIMIT=6g`) to size that service for its workload; do not remove the limit globally.

Images are pinned and updated by Renovate. CI runs Compose linting, secret detection, misconfiguration checks, and vulnerability scans. Scanner results are published to GitHub code scanning; reviewed KICS exceptions and their compensating controls are documented in [`SECURITY.md`](SECURITY.md).

Run `pre-commit install` to apply dclint fixes before each local commit. CI also opens an autofix PR when a push to `main` introduces a fixable lint issue.

## Automation boundaries

- Renovate updates pinned GitHub Actions, scanner tools, pre-commit packages, and container images. Major image updates remain manual unless a package-specific rule explicitly allows them.
- A moving image channel is retained only when the publisher does not provide a suitable versioned equivalent. The digest remains pinned, so each commit is reproducible and Renovate can review digest changes.
- Deployment is intentionally not performed by this repository's workflows. Initial host paths, devices, networks, secrets, and environment values remain deployment-time responsibilities.
- The Bazarr, Plex, and Tautulli Git updater mounts must contain checkouts before use and be writable by `PUID:PGID`. Their containers become unhealthy when no checkout is found or a repository has not completed a successful fast-forward update within two hours.

## License

[MIT](LICENSE)
