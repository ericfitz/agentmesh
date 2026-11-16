# Backup and restore

## What to back up

- The database. It holds all data and the public trust material: the intermediate certificates, the leaf certificates and the CRLs (the `trust_material` rows). It holds no private key: a backup of the database cannot mint a token.
- The configuration file, if you use one, and the values of any `AGENTMESH_SERVER_*` variables, the three trust settings among them.
- What the database does not hold, kept separately: the root certificate file (`root_certificate_file`), the intermediate key (the file named by `intermediate_key_file`, or the key in the key service) and the root's own directory, where the root tool keeps `root.key` and `state.json` (offline). Losing the intermediate key means a new key, a new request and a new certificate (`signing-keys.md`, "Renewing the intermediate certificate, and changing its key"); losing the root's directory means a new root, which every client must accept (`install.md`).

The intermediate key file is a secret as the database credential is: keep its copy as protected as the original (mode 0600). The database backup is still protected like the database itself (see `deploy.md`), because whoever can write it is an administrator.

## SQLite

Stop the server, or use SQLite's online backup. The file is in WAL mode, so copying the database file alone while the server runs is not a consistent backup (committed data can still be in the `-wal` file).

```sh
sqlite3 /var/lib/agentmesh/agentmesh.db ".backup /backups/agentmesh.db"
chmod 600 /backups/agentmesh.db
```

`.backup` writes the copy with the process's umask (mode 0644 under a default umask), so set the mode yourself; a backup that others can read or write is refused, like a database that others can read or write, when `agentmesh server` or `agentmesh server admin` opens it. The copy opens as a database: `agentmesh server admin -sqlite /backups/agentmesh.db enrollment list` exited 0.

## Postgres

```sh
pg_dump --schema=public "$DSN" > agentmesh.sql
```

`--schema` names the schema the DSN's `search_path` selects. Against the compose database the tables are in `public`. Check `\dt` if your role or DSN sets another search path. Restrict the dump's mode (`umask 077` before running).

## Restore

1. Stop every server that uses the database.
2. Restore the database: for SQLite put the file at the configured path (mode 0600); for Postgres create an empty database with a UTF-8 ctype (see `deploy.md`) and load the dump.
3. Restore the configuration file.
4. Put the root certificate file and the intermediate key where the trust settings name them (they are not in the database).
5. Start the servers.
6. Rebuild what the backup lacks ("The trust material after a restore" below).

Do not start a server, or run `ca install`, on the empty database before the restore: it would create the schema (and the certificate) first, and the restore would then collide with them.

## What a restore loses

- Everything written after the backup.
- Sessions opened after the backup are gone. The sessions in the backup have lapsed by the time of the restore; each can be resumed for `session_retention_hours` (default 72) after its lease ended.
- Client assertions that were presented between the backup and the restore are accepted once more, because the restored replay record does not have them. That window is bounded by the assertion lifetime (at most 5 minutes) plus 60 seconds of leeway after each assertion's expiry.
- Leaf certificates issued after the backup: their rows are gone. A bearer signed by such a leaf is refused as an unknown key; the client re-mints on the 401. Every process makes a new leaf when it starts.
- Intermediate certificates installed after the backup: install them again (`ca install`; the certificate file is the root's output, not the database's). Until then a leaf under one of them fails the chain check.
- Nothing else: bearers signed by a leaf whose row is in the backup verify against the restored trust material and stay valid until they expire, unless the restored CRLs list them.

## The trust material after a restore

A restore puts back the CRLs and the trust number of the backup (Decision 27). The trust number is a time in Unix milliseconds, so the restored one is earlier than any number issued since the backup. A client that saw a later change differs from the server's number and receives the bundle: it refuses an older CRL once, with a line in its log (`<data dir>/logs/`), keeps the revocations it has already seen and records the server's number. The next change to the trust material raises the number above every value issued before the restore. The next leaf CRL a server builds has a higher number than any issued before, because CRL numbers are times too, so clients accept it. It lists what the restored CRL lists and what the building process has seen; a leaf revoked after the backup and seen by no running server process is missing from it, and only the clients that saw its revocation still refuse it. Therefore, after a restore:

1. Install the latest root CRL again, from the root's directory: `agentmesh server admin ... ca install-crl root.crl`. The restored root CRL is the backup's, and an installed one must have a higher number than the stored one, which the latest has (the command says `unchanged` when it is already the stored one).
2. If a forced renewal or `signing-key revoke` was run after the backup was taken, run one again: `agentmesh signing-keys rotate`, or the host command `agentmesh server admin ... signing-key rotate` (or `signing-key revoke` for the one leaf that you know). It revokes whatever leaves are unexpired at that moment and gives clients a new CRL.

Restoring the same backup a second time is the same case again. A running server keeps in memory the highest CRL number it has verified for each CRL and writes its newer copy back when the stored one is older (`trust material rollback written back` in its log), and it does the same for a leaf CRL whose row has gone: a leaf CRL row that you delete from the database of a running installation is written back by the running server, at its next reload (at most about 30 seconds). Do not delete a CRL row expecting it to stay gone; a restart is the only thing that makes a server forget it, and a client never forgets.
