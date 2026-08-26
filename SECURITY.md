# Security

Secrets and deployment-specific values are supplied by Komodo and are not stored in this repository. Images and GitHub Actions are pinned, Renovate maintains those pins, and CI scans changes with Gitleaks, Checkov, KICS, and Trivy.

KICS and Checkov block new HIGH or CRITICAL misconfigurations. Trivy's
filesystem scan also blocks HIGH or CRITICAL dependency findings. Container
image scans compare changed digest references with the trusted base revision
and block only newly introduced HIGH or CRITICAL vulnerability identities;
scanner errors also fail the workflow. Pushes and pull requests scan images
from changed deployment YAML, including shared files and fragments, for
immediate feedback. Weekly and manual scans cover every image when Trivy is
selected and publish complete category snapshots to GitHub code scanning;
partial scans never replace those authoritative results.

## Accepted risks

KICS suppressions are limited to reviewed HIGH or CRITICAL findings in
`.kics-exclude/`. They fall into four deployment requirements.
Approvals are bound to the finding's rule, Compose file, service/property path,
issue type, expected value, and actual value rather than scanner line numbers.
Unrelated edits can move an approved finding without invalidating it; any change
to those risk semantics requires review, and duplicate identities fail closed.

### Docker socket access

Affected stacks use either the read-only socket mount in `_common/base.yaml`, a dedicated socket proxy on an internal network, or—in the case of Wolf—direct Docker access required to create gaming containers.

Compensating controls:

- socket-proxy API permissions are explicitly allow-listed per stack;
- proxy networks are internal and are not published to the host;
- images are digest-pinned and updated by Renovate;
- services are not exposed to untrusted users;
- Wolf runs on a dedicated host and is treated as host-equivalent code.

Accepted paths: `_common/base.yaml`, `aegis/addy`, `jupiter/fileflows`, `jupiter/pangolin`, `jupiter/qbittorrent`, `jupiter/wolf`, and `sage/pangolin`.

### Privileged CI containers

The GitHub runner and Forgejo Docker-in-Docker service require a privileged container to start an isolated Docker daemon.

Compensating controls:

- GitHub runners are ephemeral and have a temporary in-memory work directory;
- public-repository workflows use GitHub-hosted runners, not these deployment runners;
- the Forgejo daemon is reachable only through an internal network using mutual TLS;
- neither runner is used as a path into production infrastructure.

Accepted paths: `common/github-runner` and `jupiter/forgejo`.

### FileFlows privilege inheritance

FileFlows explicitly sets `no-new-privileges:false` because its worker processes require the vendor image's normal privilege behavior. It reaches Docker only through a restricted socket proxy and its image is digest-pinned.

Accepted path: `jupiter/fileflows`.

### Host directory mounts

Backup, media, hardware-integration, and observability services require access to host data that KICS classifies as sensitive. These mounts are part of the service's purpose rather than generic host access.

Compensating controls:

- read-only mounts are used where the application permits them;
- containers inherit `no-new-privileges:true` unless explicitly documented above;
- images are digest-pinned;
- services are scoped to trusted hosts and networks;
- backup and media paths are separated from application configuration.

Accepted paths: `_common/base.yaml`, `aegis/addy`, `aegis/filebrowser`, `common/rustic`, `jupiter/fileflows`, `jupiter/frigate`, `jupiter/home-assistant`, `jupiter/immich`, `jupiter/pangolin`, `jupiter/qbittorrent`, `jupiter/rustic`, `jupiter/suwayomi`, `jupiter/wolf`, `jupiter/zigbee2mqtt`, and `sage/pangolin`.

## Reporting

If you find a security issue, open a private security advisory on GitHub. Do not include credentials, private infrastructure details, or exploit data in a public issue.
