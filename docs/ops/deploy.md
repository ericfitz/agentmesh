# Deploying agentmesh server

All settings are in `configuration.md`; admin commands are in `admin-bootstrap.md`.

## 1. One host over SQLite

A server needs a certificate authority before it starts: a root certificate it trusts, an intermediate key with a certificate that the root signed, and a name for the installation (see "The certificates" below and `signing-keys.md`, "A first start", which gives the four commands). With those in place:

```sh
agentmesh server -listen 127.0.0.1:8420 -sqlite /var/lib/agentmesh/agentmesh.db \
  -set root_certificate_file=/etc/agentmesh/root.pem \
  -set intermediate_key_file=/etc/agentmesh/intermediate.key \
  -set installation_name=example-prod
```

There is no default port: `listen` is required, and the server exits 2 with `listen is required` without it. The same goes for the trust settings: without `root_certificate_file`, `installation_name` or one of `intermediate_key_file` and `intermediate_key_uri` the server exits 2 and names the missing setting. On a loopback address (or a `unix:<path>` socket, created mode 0600; on Windows it gets an owner-only ACL) registration defaults to `open` (Decision 20): an agent claims any free name with an unauthenticated `register`. Any other address defaults to `enrollment` (Decision 58, 72); `-registration open|enrollment` overrides either default.

On start the server prints `agentmesh server listening on ...` with the engine, registration mode, issuer and the thumbprint and expiry of the leaf certificate it just made. SIGINT or SIGTERM starts a shutdown that gives in-flight requests up to 60 seconds; a clean shutdown exits 0.

The SQLite file is created with mode 0600. An existing file readable or writable by group or others is refused: `agentmesh server` and `agentmesh server admin` exit non-zero with an error that names the path and mode; fix it with `chmod 600`. (Local mode, which has no certificates, only warns.) The file runs in WAL mode, so `-wal` and `-shm` files sit next to it.

Set `issuer` on every server that is not local. When it is unset the issuer is `http://<bound address>`, so a server bound to `0.0.0.0` tells clients `http://0.0.0.0:<port>`, and the server prints a notice saying so. Behind a TLS proxy set it to the public `https` URL (no path, no trailing slash).

## 2. The Docker image

```sh
make docker-image          # docker build -t agentmesh:local .
docker build --build-arg VERSION=2.0.0 -t agentmesh:2.0.0 .
```

`make docker-image` builds with `VERSION=dev`; give a release build its version with `--build-arg VERSION=...` and use the tag as the version (the value is what `agentmesh version` and `server_version` in `GET /v1/discover` report). The image is a static binary on a Chainguard `static` base (built with Chainguard `go`), entrypoint `/agentmesh server`, runs as `nonroot` (uid and gid 65532), declares `VOLUME /data` (owned by 65532) and has no shell.

```sh
docker run -d --name agentmesh --user "$(id -u):$(id -g)" -p 127.0.0.1:8420:8420 -v "$PWD/data:/data" -v "$PWD/ca:/ca:ro" \
  -e AGENTMESH_SERVER_LISTEN=0.0.0.0:8420 \
  -e AGENTMESH_SERVER_SQLITE=/data/agentmesh.db \
  -e AGENTMESH_SERVER_ISSUER=https://agentmesh.example.com \
  -e AGENTMESH_SERVER_ROOT_CERTIFICATE_FILE=/ca/root.pem \
  -e AGENTMESH_SERVER_INTERMEDIATE_KEY_FILE=/ca/intermediate.key \
  -e AGENTMESH_SERVER_INSTALLATION_NAME=example-prod \
  agentmesh:local
```

A container listens on `0.0.0.0`, which is not local, so registration defaults to `enrollment`; the `-registration` flag, passed as the container command, is the override (`agentmesh:local -registration open`). The intermediate key file is mode 0600 and the server refuses a key file other accounts can read, so the container's user must be the file's owner: this example runs the container as the user that made `ca/` (`--user`, as `deploy/docker-compose.yml` does with `AGENTMESH_UID` and `AGENTMESH_GID`), and then that user must be able to write `data/`. Without `--user` the container runs as uid 65532: give the key file to it (`chown 65532:65532 ca/intermediate.key`); a named volume takes the ownership of `/data`, and a bind-mounted data directory must be writable by uid 65532 (`chown 65532:65532 <dir>`). The CA files are only read, so they can be mounted read-only (`:ro`, as above). The container exits 2 with a message when no store, no `listen` or no trust setting is configured.

`docker stop` waits 10 seconds by default before killing; pass `--time 60` (compose: `stop_grace_period: 60s`) to leave the full drain.

### The certificates

The server signs its bearer tokens with a leaf certificate: an Ed25519 key that each server process makes in memory at start and renews at W/2 (`leaf_validity_hours`, default 168 hours). The leaf is signed by the installation's intermediate key, which the root certificate vouches for. The database holds only certificates and revocation lists, no private key, so a backup holds none either (`backup.md`). `signing-keys.md` explains the hierarchy, the commands and the failure states; what a deployment needs is:

- **The root.** `ca init` makes a root, `root.pem` and `root.key`; the root's directory stays offline and only `root.pem` goes to the servers (`root_certificate_file`; every replica needs the same content). With your own CA, see "A root from an outside CA" in `signing-keys.md`.
- **The intermediate key, once per installation, shared by every replica.** Either a PEM file (`intermediate_key_file`: PKCS#8, mode 0600 or owner-only), delivered to every replica as a mounted secret, or a key in a key service (`intermediate_key_uri`). `server admin ca csr` creates the file when it is missing and prints the signing request; `ca sign` (or your CA) issues the certificate; `server admin ca install` stores it in the database, where every replica finds it. Run the four commands from the first start once, before the first server starts (`signing-keys.md`, "A first start"; `deploy/docker-compose.yml` has the same steps for the compose stack).
- **The name.** `installation_name` is the intermediate certificate's subject common name; every replica uses the same name, and each installation under one root needs a name of its own.
- **Renewing the intermediate certificate before it expires.** The root tool's certificates last 365 days. Health is `degraded` once fewer than 30 days remain (`health.md`). Renew with `ca csr`, `ca sign` and `ca install` for the same key; no restart is needed.
- An external key needs a binary built with the backend's tag: `-tags awskms` for AWS KMS, `-tags gcpkms` for Google Cloud KMS, `-tags azurekms` for Azure Key Vault, `-tags hashivault` for HashiCorp Vault transit or OpenBao (`signing-keys.md`); the Docker image of this repository is built with all four tags (`ARG BUILD_TAGS` in its `Dockerfile`, `awskms,gcpkms,azurekms,hashivault`), so every backend works there without a rebuild; the release archives (the brew, scoop and winget installs) carry none, so build from source with `-tags` for a binary that needs one.
- The server refuses to start (exit 2, naming `agentmesh server admin ca csr` and `ca install`) when the database holds no intermediate certificate for the configured key that the pinned root signed and that carries this installation's name; when that certificate has expired or its key is revoked; and when the root has expired. It exits 1 when a key service does not answer while the first leaf is signed.
- Every start issues a fresh leaf, and the previous process's leaf stays valid until it expires or is revoked. Replicas start independently and each has a leaf of its own; a bearer one replica mints is accepted by the others through the leaf's row and the shared intermediate. Each replica reloads the trust material at least every 30 seconds.
- Forced renewal and revocation (`signing-keys.md`): `agentmesh signing-keys rotate` or `agentmesh server admin signing-key rotate` revokes every unexpired leaf, and `ca revoke` with `ca install-crl` revokes an intermediate.

## 3. Postgres and two replicas

`deploy/docker-compose.yml` runs Chainguard Postgres 18 (`cgr.dev/chainguard/postgres`, pinned by digest) and two replicas of the image, `agentmesh-a` (127.0.0.1:8420) and `agentmesh-b` (127.0.0.1:8421).

```sh
cp deploy/example.env deploy/.env      # deploy/.env is git-ignored; set POSTGRES_PASSWORD and AGENTMESH_ISSUER
docker compose -f deploy/docker-compose.yml up -d
```

Both replicas start with `registration enrollment`, each printing its own leaf thumbprint, and `GET /v1/discover` answers on both ports.

What replicas must share:

- the database: it holds the data, the intermediate certificates, the leaf certificates and CRLs and the single-use record of client assertions, so a token endpoint on any replica refuses an assertion another replica accepted;
- `issuer`: identical on every replica;
- the trust settings: the same root certificate (the same content, not the same path), the same `installation_name` and the same intermediate key (the same file delivered to every replica, or the same key service key). Nothing else is shared: each replica makes its own leaf;
- `postgres_budget_mib`, `idle_window_hours` and `cleanup_free_percent`, which must be equal on every replica: the replica that holds the maintenance lock runs the budget backstop with its own values, so a replica with a smaller budget would delete what the others keep, and every replica reports the tier from its own `cleanup_free_percent` (`configuration.md`, "Retention and the budget backstop");
- the Slack bridge settings, when it is used: the files named by `slack_app_token_file` and `slack_bot_token_file` must exist on every replica (any replica may serve a `bridges` call or archive a bridge), and `slack_archive_after_done_hours`, `slack_max_message_chars`, `slack_canvas_enabled` and `slack_canvas_coalesce_seconds` should match (only the lock holder publishes the scope canvas). One replica at a time runs the Socket Mode connection, under the `slack-bridge` lock; if its host vanishes without closing the database connection, Postgres can keep that lock (and a `bridges create` lock) until the server notices the dead connection, so the TCP keepalive settings below bound the wait. See [slack-bridge.md](slack-bridge.md).

They need no session affinity: any replica serves any request.

Postgres requirements and sizing: Postgres 12 or later (the size columns the budget measure sums are generated columns). The budget bounds the logical size of the data, not the disk: deleted rows leave dead tuples until autovacuum reclaims them, and autovacuum reuses that space rather than returning it to the filesystem, so the disk stays near its high-water mark. Size the disk from `storage.disk_ratio` in `GET /v1/health` (administrator tier; `disk_bytes` divided by `bytes`), multiplying the budget by the ratio you observe with headroom beyond it.

Per replica:

- **Rate limits.** The send buckets (`send_messages_per_second`, `send_kib_per_second`) are per process, so N replicas each grant an identity the full rate. A refused send answers 429 `rate_limited` with a `Retry-After` header in whole seconds (at least 1), taken from the bucket's wait.
- **Wake-ups.** Each replica holds one extra Postgres connection that `LISTEN`s, so a send on one replica wakes long-polls on the others. The wake is a hint only: if the connection drops, the replica reconnects with backoff and a lost hint costs latency, never a message. The server starts without it.
- **Maintenance** runs on one replica at a time. The holder keeps the lock across ticks and releases it at shutdown. A holder that is silently partitioned keeps the lock until the server ends its session, which pauses maintenance on every replica: cleanup is delayed, and no new tick starts on two replicas at once. The lock is checked when a tick starts, so a tick already running when its holder loses the lock finishes the job in hand (the tick stops starting jobs half an interval in) and can overlap the next holder's first tick; every job is idempotent, so the overlap repeats work and loses nothing. To bound the pause, set TCP keepalives on the Postgres server side, `tcp_keepalives_idle = 60`, `tcp_keepalives_interval = 10` and `tcp_keepalives_count = 3`, in `postgresql.conf` (or the managed service's parameter group), or per connection in the DSN:

  ```
  postgres://USER:PASSWORD@HOST:5432/agentmesh?options=-c%20tcp_keepalives_idle%3D60%20-c%20tcp_keepalives_interval%3D10%20-c%20tcp_keepalives_count%3D3
  ```

  pgx passes `options` to the server at session start. Checked against the compose Postgres with `psql` on that DSN: `SHOW tcp_keepalives_idle`, `..._interval` and `..._count` printed `60`, `10` and `3`, against `0` on a default connection; the server accepted the same DSN (`server admin -postgres ... enrollment list` exited 0).

### Postgres requirements

Create the database with a UTF-8 ctype. The `postgres` image's default is `en_US.utf8`. The server's start refuses any other with a `schema_meta is invalid` error that names the ctype (text-search normalization needs a UTF-8 character classification). On a managed service check it with:

```sql
SELECT datctype, pg_encoding_to_char(encoding), datlocprovider FROM pg_database WHERE datname = current_database();
```

(`SHOW lc_ctype` is not available on Postgres 17.) The compose database printed `en_US.utf8 | UTF8 | c`. With an ICU or builtin locale provider the encoding must be UTF8.

### Behind a reverse proxy

A watch (long-poll) holds a request open for up to `watch_max_seconds` (default 50). The proxy must pass it without buffering and its read timeout (nginx `proxy_read_timeout`) must exceed that value. Set `issuer` to the public URL.

## 4. Two servers over one SQLite file

Do not. Two server processes over one SQLite file both start and serve, and a token minted by one verifies on the other, but wake-ups are in process: a long-poll on one server is not woken by a send handled by the other, and it ends at its timeout. Use Postgres for more than one server.

## 5. Health

Two probes, with different jobs:

- Liveness: `GET /v1/discover` is unauthenticated (Decision 43), never touches the store and returns 200 while the process serves, with a JSON body including `api_versions`, `capabilities` (`health`, `long_poll`), `protocol_version` and `server_version`. A database outage never fails it, so it never restarts a replica for one.
- Readiness: `GET /v1/health` is 200 when the store answers (`status` `ok` or `degraded`) and a 503 problem with `code` `unavailable` when it does not. Without a bearer it returns only `status`, `tier`, `version`, `protocol_version` and `now`; a bearer adds more, by tier (an identity, then an administrator).

A probe must send no `Authorization` header: a stale or invalid bearer gets a 401, not the probe tier.

```sh
curl -fsS http://127.0.0.1:8420/v1/discover
curl -fsS http://127.0.0.1:8420/v1/health
```

The image has no shell or `curl`, so probe from the host or the orchestrator, not from inside the container. The document, its tiers and the 503 are described in [health.md](health.md).
