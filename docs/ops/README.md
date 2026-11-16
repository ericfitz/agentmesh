# Operating agentmesh server

One binary, `agentmesh`, provides the server (`agentmesh server`) and its host-side admin commands (`agentmesh server admin`). The server keeps everything in one database: SQLite for a single host, Postgres when several replicas serve the same data. Registration, the first administrator, backups and upgrades all work against that database.

- [deploy.md](deploy.md): one host over SQLite, the Docker image, Postgres with two replicas, proxies, health.
- [health.md](health.md): the liveness and readiness probes, the tiered health document, reading the maintenance block on replicas.
- [configuration.md](configuration.md): precedence, flags, and every setting with its environment variable, default and bounds. Checked against the code by `go test ./internal/server/config/`.
- [admin-bootstrap.md](admin-bootstrap.md): `server admin` commands, enrollment tokens, the first administrator, the admin API.
- [inspection.md](inspection.md): the write-inspection webhook: what is sent, the verdict, failure modes, health and logs.
- [slack-bridge.md](slack-bridge.md): the Slack app, the token files, creating, removing and archiving a bridge, and what happens when a create fails.
- [signing-keys.md](signing-keys.md): the certificate hierarchy (root, intermediate, leaf), the four commands of a first start, a root from an outside CA, the key service backends, renewal, revocation, the trust boundary and what happens when the key service is down.
- [backup.md](backup.md): what to back up, how, what a restore loses and what to run after one.
- [upgrade.md](upgrade.md): versions and what happens to the database at start.

A server cannot start without a certificate authority: a root certificate, an intermediate key with a certificate the root signed, and an installation name (see [signing-keys.md](signing-keys.md), "A first start"). The database holds only certificates and revocation lists, no private key, so read access to the database does not let anyone mint a token; write access is still equivalent to the administrator flag.
