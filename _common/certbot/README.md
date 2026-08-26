# Certbot Consumer Reloads

Certbot remains the certificate manager. Consumers mount Certbot's normal
`live/` and `archive/` directories read-only under one certificate root, so the
relative symlinks in `live/` continue to resolve into `archive/`. There are no
certificate copies, runtime generations, markers, fingerprints, Docker socket
mounts, TLS probes, or custom certificate lifecycle files.

## Compose Convention

Active stacks use the Compose service key `certbot` and an explicit, globally
unique `<stack>_certbot` container name. Komodo addresses one-shot jobs by Docker
container name, so generated Compose names are not stable enough for this
automation contract. These utility containers are singletons and are never
scaled.

Each Certbot block keeps the pinned image, container name, volumes, optional
deploy-hook environment, folded `certonly` command, explicit `restart: "no"`,
and shared defaults in that order. Domain and email inputs use Compose required
variable guards. Stack-specific commands, mounts, GIDs, and webhook secrets stay
inline; a shared Compose extension would obscure more configuration than it
would remove.

## Flow

1. A stopped one-shot Certbot container owns its ACME account, renewal, `live/`,
   and `archive/` state. `komodo/actions/run-one-shot-container.ts` starts and
   attaches that container, waits up to `timeout_seconds` (default `900`), and
   requires a final `exited` status with exit code `0`.
2. Certbot runs `komodo-deploy-hook.py` only after initial issuance or a renewal.
   The hook validates the lineage and its resolved archive targets, makes the
   minimum direct-file permission changes, then sends one HTTPS,
   GitLab-compatible private Komodo Action or Procedure webhook with
   `X-Gitlab-Token` and ref `refs/heads/main`, matching the generated webhook URL
   ending in `/main`.
3. A single-consumer receiver invokes `komodo/actions/reload-container.ts`. It
   sends `HUP` by default, confirms the container remains running one second
   later, and restarts only when the signal fails or leaves it stopped. Consumers
   without a reliable reload signal use explicit `mode: "restart"`. A
   multi-consumer stack can target a Procedure that runs one reload Action per
   consumer and succeeds only when every execution succeeds. These receivers
   perform no TLS or certificate verification.

The hook requires `RENEWED_LINEAGE`, numeric `CERT_CONSUMER_GID`,
`KOMODO_WEBHOOK_URL`, and `KOMODO_WEBHOOK_SECRET_FILE`. It changes only the
 `live/` root, `archive/` root, renewed lineage, and resolved archive lineage
 directories to running-owner:`CERT_CONSUMER_GID` with mode `0710`. The resolved
 full chain is mode `0644`; the current resolved private key is mode `0640`.
 Historical private keys in that lineage are reset to root-owned mode `0600`.
 The webhook
secret must be a nonempty regular, non-symlink file without group or other
permissions. Redirects are rejected so the token cannot be forwarded.

## Consumer Mapping

Mount the two Certbot directories side by side, for example:

| Host source | Consumer target |
| --- | --- |
| `/opt/docker/<consumer>/letsencrypt/certs/live/` | `/service/certs/live/` |
| `/opt/docker/<consumer>/letsencrypt/certs/archive/` | `/service/certs/archive/` |

Configure the consumer with its `live/<lineage>/fullchain.pem` and
`live/<lineage>/privkey.pem` paths. For future applications, create one mapping
per certificate resource: a stopped Certbot container, a private webhook secret,
and either a reload Action for one consumer or a reload Procedure for multiple
consumers. No shared certificate runtime is required.

## Scheduling And Bootstrap

Migrate the existing `run-certbot` Procedure only after the first stack is
validated. Its final form is a parallel stage that invokes
`run-one-shot-container.ts` once per stack with that stack's `server`,
`container`, and optional timeout arguments.

For initial issuance, create the Certbot container and private reload webhook,
mount both certificate directories into the consumer, issue the certificate,
then enable or reload the consumer's TLS listener after the files exist. This
avoids starting a TLS consumer against missing `live/` paths.

Certbot records deploy-hook failure in its logs but does not necessarily return
that failure as the Certbot command's exit status. The one-shot Action captures
attached output in a private temporary file and fails when this hook reports an
error. The hook makes no retries to avoid repeated reload alerts; monitor the
private Action webhook separately as the authoritative reload result. Keep the
certificate tree root-owned and writable only by root so its validated paths
cannot be replaced during the hook.
