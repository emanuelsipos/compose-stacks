# Compose Stacks

Docker Compose definitions for services running across a small self-hosted environment. Stacks are grouped by host, with reusable services and defaults kept separately.

## Layout

- `_common/base.yaml` contains shared restart, logging, security, database, and cache defaults.
- `common/` contains reusable stacks.
- `aegis/`, `jupiter/`, and `sage/` contain host-specific deployments.
- `komodo/` contains the deployment control plane.

These files reflect a real deployment and are not intended to be used unchanged. Host paths, device mappings, network addresses, and environment variables must be adapted first. Komodo supplies each stack's environment at deployment time; `.env` files are not stored in this repository.

Images are pinned and updated by Renovate. CI runs Compose linting, secret detection, misconfiguration checks, and vulnerability scans. Scanner results are published to GitHub code scanning; reviewed KICS exceptions are recorded in `.kics-exclude/`.

## License

[MIT](LICENSE)
