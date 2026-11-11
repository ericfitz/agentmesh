> **Superseded (Eric, 2026-11-11): this design was abandoned and none of it is to be implemented.** It is kept only as a record. See "Server key file design abandoned (2026-11-11)" in `docs/adr/0012-signing-key-rotation-and-key-providers.md` and the design that replaces it, `docs/adr/0019-certificate-hierarchy-and-signed-messages.md`.

# Server key file: row MACs and sealed signing keys (design spec)

## 1. Status

- Second draft, 2026-11-10. The first draft is commit `bf97d4a`; this one folds in Eric's 21 decisions of 2026-11-10 on that draft's open questions and on the security review (`.local/design/2026-11-10-server-key-file-review-decisions.md`, `.local/design/2026-11-10-server-key-file-security-review.md`).
- **The design is Eric's and is frozen.** Its sources, in order of authority:
  1. the 21 review decisions (2026-11-10), which win wherever they differ from the two below;
  2. decisions 1 to 11 of the ADR 0012 "Server key file addendum (2026-11-10)";
  3. the four design sections Eric approved on 2026-11-10 (`.local/design/2026-11-10-server-key-file-approved-sections.md`).
- This spec transcribes them to an implementable level. It makes no design decision: where the sources give only a name it adds a plan ruling, and where they are silent it adds an open question.
- Labels used below:
  - **(Eric 2026-11-10, review decision N)**: decision N of the 21 review decisions.
  - **(Eric 2026-11-10, decision N)**: decision N of the ADR 0012 "Server key file addendum (2026-11-10)".
  - **(Eric 2026-11-10, section N)**: approved section N (1 threat model and configurations, 2 key file and key lifecycle, 3 covered tables and the row check, 4 components, errors and testing).
  - **(plan ruling)**: a choice of this spec. Eric may overrule each one.
  - **(Open question N)**: section 11 holds the finding, the options and a recommendation. Where the body needs a value to be readable it states the recommended one with this mark.
- What the review decisions changed in the earlier sources: decision 4's five message fields (review decision 8); decision 5's "a non-current key without an epoch row is valid" as the only form of retirement, and decision 6's file format (review decisions 2 and 7); approved section 2's "Turning on for an existing database" (review decision 3); approved section 3's covered columns for `enrollment_tokens`, `bridges`, `signing_keys` and `channel_acl` (review decisions 1, 6, 16 and 10).
- Section 11 holds 5 open questions, all raised by the review decisions. The 15 open questions of the first draft are answered by review decisions 2, 3, 4, 5, 8 to 16 and 21.
- Pre-release rule (CLAUDE.md, Eric 2026-10-25): the schema changes in place in `0001_initial.sql` on both engines, with no migration, converter or compatibility path. Local and test databases are recreated.

## 2. Problem and scope

### The attacker

Threat 2 and SD1 of `docs/security/threat-model-server.md`: someone with database access but not the server host (Eric 2026-11-10, section 1). Examples: a leaked backup, a reporting or other-tenant role on a shared Postgres, a compromised database administrator or database role, a SQL injection in another application on the same database. The attacker may also hold an ordinary agent credential or reach the public API, registration included (security review).

Today such a writer takes full control. `Keyring.LoadKeys` trusts the public key of every `signing_keys` row (`internal/core/signingkeys/keyring.go:39-65`), and the same writer can set `identities.is_admin`, add an `identity_keys` row for any agent, bind an email in `human_bindings`, edit `access_refs`, grant itself a `channel_acl` row or insert a message with `sender_kind = 'human'`, which every agent treats as an operator instruction. A reader takes the plaintext PEM of the store provider's signing key and mints any bearer.

Not in scope (Eric 2026-11-10, section 1): nation-state actors, compromise of the server host or the server process (P04), and denial of service by deleting rows.

### Goal

One optional server key file, outside the database, that puts a MAC on every protected row and seals the store provider's private signing keys (Eric 2026-11-10, decision 1). With it:

- a database reader reads content, bindings and emails but cannot mint a bearer;
- a database writer cannot add or alter identities, login keys, bindings, the administrator and user lists, ACLs, signing keys or messages, and cannot take over an identity by deleting its rows and registering again (Eric 2026-11-10, review decision 1); deleting rows is denial of service only.

### Vocabulary

- **Server key file**: the JSON file named by `server_key_file`.
- **File key**: one 32-byte key in the file, named by its **key id**. **Current key**: the file key that `current` names; it seals every new row. **Retired key**: a file key the file's `retired` list names.
- **Database id**: the random id `keygen` writes into a new key file and database creation records.
- **Covered table**: a table whose rows carry `mac` and `mac_key`. **Security row**: a row of any covered table except `messages`.
- **Sealed database**: a database created with a key file. **Unsigned row**: a row whose `mac_key` is the empty string.
- **Epoch row**: a row of `integrity_epochs`, `(key id, max seq)`: the highest message seq a retired key is valid for.
- **Configuration 1, "Local"**, is a server without a key file. It is not local mode. Local mode (a local profile running the core in process over a SQLite file: `agentmesh mcp`, `agentmesh tui`, the client commands) never has a key file and stays outside the threat model.

### Out of scope

- A cloud secret-store source for the key file: file only (Eric 2026-11-10, decision 1).
- Column encryption of content (Eric 2026-11-10, section 1).
- Turning the key file on for an existing database, or off for a sealed one (Eric 2026-11-10, review decision 3 and decision 7).
- URL references in key rows (Eric 2026-11-10, decision 10).
- The Slack email-to-human trust, threat 4 (Eric 2026-11-10, decision 11).
- The tables and columns section 4.16 lists as not covered.
- A mechanism that prevents a replica from running with a retired current key: section 10.
- A command that deletes failing rows: the log names each one and `docs/ops/server-key.md` gives the SQL (plan ruling).
- Data migration (pre-release rule).

## 3. What exists today

Checked against the tree at `bf97d4a`.

- **Schema.** Both `0001_initial.sql` files create the same 30 tables (SQLite adds the FTS5 table `messages_fts`); `schema_meta` is created by the Store's bootstrap (`internal/store/sqlstore/migrate.go:110`), outside `0001`. No table has a MAC column. The step ends by seeding the reserved `slack-bridge` identity with plain SQL (`sqlite/schema/0001_initial.sql:282-284`). `channels.id`, `channel_acl.id` and `bridges.id` are assigned by the database (`AUTOINCREMENT` on SQLite; `GENERATED ALWAYS AS IDENTITY` and `BIGSERIAL` on Postgres). `channel_acl` has no unique constraint on `(channel_id, identity)`, and its `id` is used only by `ORDER BY id` in `ACL` (`internal/store/sqlstore/acl.go:84`); the Store contract documents "insertion order" (`internal/store/channels.go:77`). No SQLite table is `STRICT`.
- **Ids on the wire.** Channel ids and bridge ids never leave the server: `api/openapi.yaml` and the `internal/bus` types name channels and bridges by channel name.
- **Store contract.** `store.Store` is `Tx`, `Append`, `Read`, `SchemaVersion`, `Close`, `Locks` and `Space` (`internal/store/store.go:14-40`). `sqlstore.Options` holds `Migrations`, `TxAttempts`, `Now` and `Logger` (`internal/store/sqlstore/dialect.go:65-73`). Every SQL statement of the product is under `internal/store`: the repositories in `internal/store/sqlstore`, plus a few statements in the engine packages (the FTS condition `messages_fts MATCH` in `sqlite/sqlite.go:265`, the `size_bytes` sum over `sqlstore.MeasuredTables` in `postgres/space.go:21`, the locks and the schema probes). Covered table names also appear as bare string literals: `MeasuredTables` (`sqlstore/eviction.go:21-25`), `resetDataTables` (`sqlstore/meta.go:18-21`) and the `sumBytes("channel_acl", ...)` call of `ChannelBytes`.
- **Locks.** `Store.TryLock` works for any name: SQLite inserts the `leases` row on demand and the lease lapses at `until` (`internal/store/sqlstore/lock.go:33-41`); Postgres holds a session advisory lock. A running server holds the `maintenance` lock, renewed on every tick with a term of twice the interval (`internal/core/maintenance/service.go:140`).
- **Appends.** `Store.Append` serializes appends (SQLite's immediate transaction; `LOCK TABLE seq_counter IN EXCLUSIVE MODE` on Postgres, `internal/store/postgres/postgres.go:229-232`). `AppendMessage` takes its seq from `seq_counter` and maps only a foreign-key violation (`internal/store/sqlstore/messages.go:161-170`), so a primary-key collision on `seq` is a 500 today.
- **Registration.** `registerTx` (`internal/core/identities/register.go:95-177`) lets a name with no key rows be registered in `open` mode with no token and in `enrollment` mode with any valid token, bound or not; only a keyless administrator row needs a token bound to it. `ConsumeEnrollmentToken` is one conditional `UPDATE ... SET uses_left = uses_left - 1` (`internal/store/sqlstore/enrollment.go:123`). The registration default is `open` on a local listener (`internal/server/cmd/cmd.go:100-107`).
- **Signing keys.** `signing_keys.private_key_pem` is plaintext PKCS#8 PEM for the store provider and NULL otherwise (`sqlite/schema/0001_initial.sql:194-208`); `signingkeys.validateRow` parses it (`internal/core/signingkeys/service.go:111-136`).
- **Start-up.** `cmd.run` reads the configuration, opens the store (a failure is exit 1), binds, then calls `EnsureActive` (`internal/server/cmd/cmd.go:74-170`). Every host command opens the store through `openFromConfig` (`internal/server/cmd/admin.go:108`).
- **Messages on the Bus.** `bus.Message` is one type for `receive`, `history` and `search` (`internal/bus/types.go:77-98`); the wire schema is `Message`, referenced by `ReceiveResult`. The MCP server's instructions and the `receive` and `history` tool descriptions tell agents that a human sender's message is an instruction (`internal/mcpserver/server.go:142`, `:154`, `:674`, `:713`). A receive result also carries a `notice` text.
- **Health.** `health.Service.Health` computes one `status` before it branches on the tier, so every tier sees the same value today (`internal/core/health/health.go:93-102`); `degraded` exists as a value (`internal/bus/health.go:11`).
- **Files that must be owner-only.** `credential.LoadFile` follows a symlink, requires a regular file with Unix mode 0600 or narrower and calls `fileacl.CheckOwnerOnly` on Windows (`internal/credential/store.go:90-116`). `internal/fileacl` is a package of this module.
- **Gates.** `scripts/m7-exit-checks.sh` has `check_allowlist` (lines 119-145); `slackapi-allowlist` is the existing "standard library only" rule (line 186). The highest mutation block of `scripts/check-gates-selftest.sh` is 40 (line 1589).
- **Go and SQLite.** `go.mod` pins go 1.27 (`crypto/hkdf` is standard library) and `modernc.org/sqlite v1.61.0`. `STRICT` tables need SQLite 3.37 or newer. The revised SQLite schema of section 4.4 (the twelve strict tables with the two columns and their CHECK, `integrity_epochs`, the `channel_acl` key, explicit channel and bridge ids) was run on SQLite 3.54 for this spec: it loads, FTS over the strict `messages` table works, and a BLOB bound to a TEXT key, a key id without a MAC and an empty epoch key id are each refused.

## 4. Design

### 4.1 Configurations

Three configurations, one mechanism (Eric 2026-11-10, decision 2 and section 1). Scenarios: 1 local testing, 2 a lab with local and remote agents, 3 production on-prem, 4 production in a cloud.

| Configuration | Scenarios | A database reader | A database writer | Accepted risk |
| --- | --- | --- | --- | --- |
| 1. Local: no key file (the default) | 1, 2 | mints any bearer | takes full control | Database file access owns the server; in scenario 2 the file is on the server host, the same boundary. |
| 2. Server: `server_key_file` | 3, 4 | reads content, bindings, emails; cannot mint (signing keys sealed) | cannot add or alter identities, login keys, bindings, administrator or user lists, ACLs, signing keys or messages; deletion is denial of service only | Host compromise; content readable; the accepted risks of section 4.16. |
| 3. Server plus key service: key file plus `signing_key_uri` | 4, optional | as 2 | as 2 | As 2; the token key is also non-exportable. |

- The key file is never required (Eric 2026-11-10, decision 3). A server whose listener is not local (`ClassifyListen`, `internal/server/cmd/listen.go:25`) and that has no key file logs one start-up warning: `server_key_file is not set and the listener is not loopback: anyone who can write the database controls this server (docs/ops/server-key.md)` (wording: plan ruling). The health document's administrator tier reports `integrity.mode: off`.
- A configuration is chosen when the database is created and never changes: "turning on key signing must happen at database creation time, before any rows are added" (Eric 2026-11-10, review decision 3), and turning it off is unsupported (Eric 2026-11-10, decision 7).
- Configurations 2 and 3 also change three behaviors outside the Store: registration needs a token bound to the name (section 4.12), delivery marks stale messages (section 4.13), and integrity failures degrade the administrator's health status (section 4.14). Configuration 1 and local mode behave as today.
- In configuration 3 the key service holds the token key, so there is no private key to seal; the key file still MACs every covered row, `signing_keys` included (Eric 2026-11-10, section 2).

### 4.2 The server key file

Setting `server_key_file` (`AGENTMESH_SERVER_SERVER_KEY_FILE`, `-set server_key_file=PATH`), empty by default (Eric 2026-11-10, section 2). There is no environment-variable source for the key itself.

Format (Eric 2026-11-10, decision 6, extended by review decisions 2 and 7):

```json
{"version":1,"database":"3f9c1e0b7a2d4c5e8f6a9b0c1d2e3f40","current":"k2","keys":{"k1":"<base64 of 32 bytes>","k2":"<base64 of 32 bytes>"},"retired":["k1"]}
```

- `database` is the database id: 16 bytes from `crypto/rand`, written as 32 lowercase hexadecimal characters by the `keygen` that creates the file, and never changed afterwards (Eric 2026-11-10, review decision 7; the size and form are plan rulings).
- `retired` lists the retired key ids (Eric 2026-11-10, review decision 2). It may be absent or empty. Only `resign` and `rotate` add to it.
- `version` stays 1 (pre-release rule). It selects every algorithm of sections 4.3, 4.6 and 4.8; nothing in the database selects one (Eric 2026-11-10, decision 9).
- The file is read once, at start; a changed file takes effect at the next start (Eric 2026-11-10, section 2).
- The file is never edited by hand: every change is made by a command of section 4.15 (Eric 2026-11-10, review decision 12).

The start, and every host command that needs the file, refuses it with exit 2 and a message naming the setting and the reason. Refusals named by Eric (2026-11-10, section 2): a mode that is not owner-only, an unknown `version`, a missing `current`, a duplicate key id, a key that is not 32 bytes. The complete list (the additions are plan rulings, following "reject unrecognized inputs by default"):

1. The path cannot be opened, or after following symbolic links is not a regular file.
2. The file is not owner-only: on Unix any of the mode bits `0o077` is set on the opened file; on Windows `fileacl.CheckOwnerOnly` refuses it. Symbolic links are followed, so a mounted secret works.
3. The file is larger than 65536 bytes.
4. The content is not one JSON object, has trailing data, or has a member other than `version`, `database`, `current`, `keys` and `retired`.
5. `version` is absent or not the number 1.
6. `database` is absent or not 32 lowercase hexadecimal characters.
7. `keys` is absent, empty or not an object of strings.
8. A key id appears twice in `keys`. The decoder reads the object token by token, because `encoding/json` keeps the last of two equal member names silently.
9. A key id is not 1 to 32 characters of `a` to `z`, `0` to `9`, `-` and `_`.
10. A key value is not standard base64 with padding (RFC 4648 section 4), or does not decode to exactly 32 bytes.
11. Two key ids hold the same 32 bytes.
12. `current` is absent, empty or names no member of `keys`.
13. `retired` is present and is not an array of strings, names a key id that is not in `keys`, names one twice, or names the current key.

No message ever contains key material.

### 4.3 Derived keys

The raw file key is never used directly (Eric 2026-11-10, section 2). Each file key yields two subkeys with HKDF-SHA256 (RFC 5869; `crypto/hkdf.Key`); the database id is in the info (Eric 2026-11-10, review decision 7):

| Subkey | Use | IKM | Salt | Info (ASCII) | Length |
| --- | --- | --- | --- | --- | --- |
| `mac` | HMAC-SHA256 over rows | the 32-byte file key | none (HKDF's default of 32 zero bytes) | `agentmesh/server-key/v1/mac/` followed by the database id | 32 bytes |
| `seal` | AES-256-GCM over `signing_keys.private_key_pem` | the 32-byte file key | none | `agentmesh/server-key/v1/seal/` followed by the database id | 32 bytes |

The info strings and the absent salt are plan rulings. Because the id is in the derivation, a row sealed for one database never verifies in a database with another id, even under the same file keys. The key id is bound in the MAC input (section 4.6) and in the AAD (section 4.8).

### 4.4 Schema

Both `0001_initial.sql` files change in place (Eric 2026-11-10, section 4).

- **MAC columns** (Eric 2026-11-10, decision 9). The eleven existing covered tables (`identities`, `identity_keys`, `human_bindings`, `access_refs`, `channels`, `channel_acl`, `signing_keys`, `enrollment_tokens`, `slack_users`, `bridges`, `messages`) each gain:
  - `mac`: `BLOB NOT NULL DEFAULT x''` on SQLite, `BYTEA NOT NULL DEFAULT ''::bytea` on Postgres; the 32 bytes of the HMAC, or empty;
  - `mac_key`: `TEXT NOT NULL DEFAULT ''`; the key id, or empty;
  - `CHECK ((mac_key = '') = (length(mac) = 0))` (`octet_length` on Postgres).
  The column types and the CHECK are plan rulings.
- **`integrity_epochs`** (Eric 2026-11-10, decisions 5 and 8), created with the two columns, so twelve tables carry them:

  ```sql
  CREATE TABLE integrity_epochs (
    key_id TEXT PRIMARY KEY CHECK (key_id <> ''),
    max_seq INTEGER NOT NULL CHECK (max_seq >= 0),
    created_at INTEGER NOT NULL,
    mac BLOB NOT NULL,
    mac_key TEXT NOT NULL CHECK (mac_key <> '')
  ) STRICT;
  ```

  (`BIGINT` and `BYTEA` on Postgres, without `STRICT`; `created_at` is a plan ruling, shown by `integrity status` and not covered.)
- **`STRICT`** (Eric 2026-11-10, review decision 17). On SQLite the twelve covered tables are declared `STRICT`, so a column holds only its declared storage class. The existing column types (`INTEGER`, `TEXT`, `BLOB`) are all valid in a strict table.
- **Channel and bridge ids** (Eric 2026-11-10, review decision 4). `channels.id` becomes `INTEGER PRIMARY KEY` (SQLite) and `BIGINT PRIMARY KEY` (Postgres); `bridges.id` likewise. No database sequence assigns them: the server picks each id at random (section 4.10).
- **`channel_acl`** (Eric 2026-11-10, review decision 10). The surrogate `id` column goes; the table gets `PRIMARY KEY (channel_id, identity)`; the index `channel_acl_channel_identity` goes, because the key replaces it.
- **Database id.** `schema_meta` gains `integrity_database TEXT NOT NULL DEFAULT ''`: the database id of the key file the database was created with, or empty (Eric 2026-11-10, review decision 7 says creation records it; the place is a plan ruling). It is the mark of a sealed database.
- `CREATE INDEX messages_mac_key ON messages (mac_key);` (Eric 2026-11-10, section 3). It serves `resign`'s search for the highest message under a key and the counts of `integrity status`.
- `signing_keys.private_key_pem` keeps its name and its CHECK; in a sealed database it holds the sealed form of section 4.8, not PEM.
- The generated `size_bytes` columns do not change (plan ruling). `Meta.ResetData` and `Meta.ResetRegistry` never touch `integrity_epochs` or `schema_meta.integrity_database`.

**Creation.** When the Store is opened with a key file and this open creates the schema, then in the same transaction as the schema step it records the file's database id in `schema_meta.integrity_database` and seals the seeded `slack-bridge` row. The seal is computed from constants (`name` `slack-bridge`, `is_admin` false, `kind` `agent`, `scope` absent), not read back from the row (plan ruling). Nothing else in the database is ever sealed after the fact: there is no adoption of unsigned rows and no unsigned epoch (Eric 2026-11-10, review decision 3).

### 4.5 Covered tables and columns

Eric 2026-11-10, decision 8 and section 3, as changed by review decisions 1, 6, 8, 9, 10 and 16. The column order below is the MAC field order (plan ruling). Every name was checked against both schema files; the engines use the same names and differ only in types.

| Table | Primary key | Covered columns, in MAC order | Not covered |
| --- | --- | --- | --- |
| `identities` | `name` | `name`, `is_admin`, `kind`, `scope` | `tags_acked_seq`, `created_at` |
| `identity_keys` | `identity`, `kid` | `identity`, `kid`, `algorithm`, `public_key` | `created_at` |
| `human_bindings` | `identity` | `identity`, `issuer`, `claim_type`, `value`, `provider_subject` | `created_at` |
| `access_refs` | `ref_list`, `ref_kind`, `issuer`, `value` | `ref_list`, `ref_kind`, `issuer`, `value`, `created_at` ("all") | none |
| `channels` | `id` | `id`, `name`, `kind`, `scope` | `creator`, `created_seq`, `evicted_before_seq`, `created_at`, `last_read_at`, `size_bytes` |
| `channel_acl` | `channel_id`, `identity` (review decision 10) | `channel_id`, `identity`, `can_read`, `can_write`, `can_admin` | `size_bytes` |
| `signing_keys` | `kid` | `kid`, `state`, `provider`, `provider_ref`, `algorithm`, `public_key`, `private_key_pem` as stored (sealed), `retired_at`, `remove_after` (review decision 16) | `created_at` |
| `enrollment_tokens` | `id` | `id`, `token_hash`, `identity`, `expires_at`, `uses_left` (review decision 1) | `created_at`, `size_bytes` |
| `slack_users` | `identity` | `identity`, `team_id`, `user_id` | `created_at` |
| `bridges` | `id` | `id`, `channel_id`, `scope`, `slack_channel_id`, `state`, `cursor_ts` (review decision 6) | `channel_name`, `slack_name`, `created_at`, `archived_at` |
| `messages` | `seq` | `seq`, `channel_id`, `sender`, `sender_kind`, `session_id`, `created_at`, `type`, `subject`, SHA-256 of `content`, SHA-256 of `metadata`, `reply_to`, `memory_id`, `revision`, `tombstone` (the fourteen fields, review decision 8), then the message's tags, sorted (review decision 9) | `tombstone_at`, `size_bytes`, the Postgres `fts_subject` and `fts_content` |
| `integrity_epochs` | `key_id` | `key_id`, `max_seq` | `created_at` |

`message_tags` has no MAC columns: its rows are covered through the `messages` MAC (Eric 2026-11-10, review decision 9). A tag row planted on, or removed from, a genuine message makes that message fail, which equals deleting it.

Every other table is not covered; section 4.16 lists each with its risk.

### 4.6 MAC input

HMAC-SHA256 under the key's `mac` subkey, all 32 bytes stored (Eric 2026-11-10, section 3). The input is the table name, the key id and the covered columns, each length-prefixed (Eric 2026-11-10, section 3 and decision 9), with a present-or-absent byte for every nullable column (Eric 2026-11-10, review decision 17). The exact bytes are a plan ruling:

```text
input    = lp(table) || lp(key_id) || u16(n) || field_1 || ... || field_n
lp(b)    = u32(len(b)) || b                      u16, u32: big-endian
field    = value                                  a NOT NULL column
         | 0x00                                   a nullable column that is NULL
         | 0x01 || value                          a nullable column that holds a value
value    = 0x01 || lp(UTF-8 bytes)                text
         | 0x02 || lp(bytes)                      bytes
         | 0x03 || i64                            integer: 8 bytes, two's complement, big-endian
         | 0x04 || (0x00 | 0x01)                  boolean
         | 0x05 || u32(k) || lp(t_1) .. lp(t_k)   text list (the message tags only)
```

Rules:

- `table` is the table's name as in the schema, ASCII. `n` is the number of fields. The fields are the covered columns in the order of section 4.5; whether a field is nullable is fixed by its column, so the encoding is unambiguous.
- The nullable covered columns, each read as NULL or a value and never coalesced: `identities.scope`, `channels.scope`, `messages.reply_to`, `messages.metadata`, `messages.memory_id`, `messages.revision`, `signing_keys.private_key_pem`. The verify helpers select `scope` without the `COALESCE` that `identityCols` uses today, so NULL and the empty string stay distinct. Every other covered column is `NOT NULL`; `enrollment_tokens.identity` is the empty string for an unbound token and is encoded as that text.
- The values are Go values after the scan, so the engines agree: `is_admin`, `can_read`, `can_write`, `can_admin` and `tombstone` are booleans; every integer column is an `int64`; `public_key` is bytes; everything else is text. With `STRICT` tables and the existing `CHECK (... IN (0, 1))` constraints, one stored value has one Go value.
- The `content` field is the bytes type holding SHA-256 over the stored `content` text. The `metadata` field is absent when the column is NULL, otherwise SHA-256 over the stored `metadata` text exactly as the column holds it (never a re-marshaled map).
- The tags field is the message's tags in ascending byte order.
- A value outside these types is a programming error and fails the seal.

Known-answer vectors (computed for this spec; the unit tests hold them). File key: the 32 bytes `00` to `1f` (base64 `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=`), key id `k1`, database id `000102030405060708090a0b0c0d0e0f`:

- `mac` subkey: `92ee7a96ffd7b3a02bd44def09964b6c663300570bc564fc74fa967369dc5767`
- `seal` subkey: `4c143e9458f5aa6a5de6a1358907b82266e2a18121032750fc77f88c32283be0`
- `identities` row `name` `alice`, `is_admin` false, `kind` `agent`, `scope` NULL: input (45 bytes) `0000000a6964656e746974696573000000026b3100040100000005616c696365040001000000056167656e7400`, MAC `3c21ebc94107c00031c0ba0ddb7f99cb1b957ba3f19d9da84f681eafe7584512`
- the same row with `scope` `proj`: input (54 bytes) `0000000a6964656e746974696573000000026b3100040100000005616c696365040001000000056167656e7401010000000470726f6a`, MAC `de4609bae9949789821ae21984713689a95b38895ad4c00575d5cccccfaefb59`

### 4.7 Which key is valid for which row

Eric 2026-11-10, decision 5 and section 2, as changed by review decisions 2 and 3: `current` only chooses the key for new rows; retirement lives in the key file; a retired key never verifies a security row; a retired key verifies a message only up to its epoch row's seq, and with no epoch row it fails closed; the database cannot un-retire a key; an unsigned row never verifies. Bounded by seq, not time, because delivery follows seq and a forger can backdate a timestamp.

A row with key id K, checked on a server whose key file has keys F, current key C and retired list R:

| Case | Condition | Result | Logged reason |
| --- | --- | --- | --- |
| Unsigned | K is empty | fails, in every covered table | `unsigned` |
| Unknown | K not in F | fails | `unknown key` |
| Bad MAC | K in F, MAC does not verify | fails | `bad MAC` |
| Current | K = C, MAC verifies | valid | |
| Retired in the file | K in R, MAC verifies | a security row fails; a `messages` row is valid only when a counted epoch row (K, S) exists and its seq is at most S | `retired key` |
| Not retired, no epoch row | K in F, not C, not in R, MAC verifies, no counted epoch row for K | valid for every row (mixed replicas during a roll) | |
| Not retired in this file, epoch row exists | K in F, not C, not in R, MAC verifies, counted epoch row (K, S) | as "Retired in the file": `resign` has run and this server has not yet received the file that lists K | `retired key` |

An epoch row is a security row. It counts when its `mac_key` names a file key that the file does not list as retired and its MAC verifies under that key; otherwise it is a failing row (section 4.11). The two-level rule of the first draft is dropped (Eric 2026-11-10, review decision 2).

Consequences, stated so the tests and the operator guide can hold them:

- Once a server runs with a file that lists K as retired, nothing in the database makes K valid for a security row again, and deleting K's epoch row only makes K's messages fail.
- Between `resign` and the delivery of the file that lists K, K's retirement on each server rests on the epoch row alone. A writer who deletes that row in this window makes K fully valid again on servers that still have the old file. The window closes with the last restart of the roll.
- A counted epoch row whose `key_id` is the server's own current key means the server's file is out of date: section 4.10 item 8.

The Store reads `integrity_epochs` at most once per transaction, the first time that transaction meets a row whose `mac_key` is not C, and keeps the result for the transaction (plan ruling). A row under the current key needs no lookup; a retirement written by `resign` is seen by every replica's next transaction that meets an older row.

### 4.8 Sealing the store provider's private key

AES-256-GCM under the sealing key's `seal` subkey (Eric 2026-11-10, sections 2 and 4). The Store seals in `PutSigningKey` and opens in `ListSigningKeys` (Eric 2026-11-10, review decision 14), so `store.SigningKey.PrivateKeyPEM` stays plaintext at the Store contract and `internal/core/signingkeys` parses it as today.

- **Nonce**: 12 bytes from `crypto/rand`, new for every seal (plan ruling). A key seals one private key per rotation and per `resign`, so random nonces are far inside the bound.
- **AAD**: `lp("signing_keys") || lp(kid) || lp(key_id)`, the table, the row's `kid` and the sealing key id (Eric 2026-11-10, section 4; the framing is a plan ruling).
- **Plaintext**: the PKCS#8 PEM bytes the store provider produced.
- **Stored form**: standard base64 of `nonce || ciphertext || tag`, in `private_key_pem` (plan ruling).
- **Which key**: the row's `mac_key`. One write seals and MACs under the same key, the current one.
- **Sealed or plaintext is told by `mac_key`, never by the content** (plan ruling). With a key file an unsigned `signing_keys` row fails like any unsigned row, so the server never parses a plaintext PEM a writer planted, and no plaintext key a reader may already hold is ever taken into a sealed database (Eric 2026-11-10, review decision 3).
- A stored value that does not open (bad base64, shorter than 28 bytes, the tag fails) drops the row with the reason `sealed key does not open`.
- The MAC covers the stored, sealed text, so the MAC check needs no decryption.

### 4.9 The port and the leaf package

`store.Integrity` (Eric 2026-11-10, decision 8 and section 3: `Seal`, `Verify`, `SealSecret`, `OpenSecret`), passed at open as `sqlstore.Options.Integrity`; nil is configuration 1: columns left empty, no check. Signatures (plan ruling; built-in types only, so the leaf implements the port without importing `internal/store`):

```go
// package store
type Integrity interface {
	// Database is the key file's database id.
	Database() string
	// Current is the key id that Seal and SealSecret use.
	Current() string
	// Retired reports whether the file lists keyID as retired.
	Retired(keyID string) bool
	// Seal returns the MAC of the row under the current key. Each field is a
	// string, []byte, int64, bool or []string, or, for a nullable column,
	// nil or a pointer to one of those.
	Seal(table string, fields ...any) (mac []byte, keyID string, err error)
	// Verify recomputes the MAC under keyID. known is false when the file
	// has no such key; ok is false when the MAC differs.
	Verify(table, keyID string, mac []byte, fields ...any) (known, ok bool, err error)
	// SealSecret seals under the current key; rowID is the row's kid.
	SealSecret(table, rowID string, plaintext []byte) (sealed string, err error)
	// OpenSecret opens what keyID sealed.
	OpenSecret(table, rowID, keyID, sealed string) (plaintext []byte, err error)
}
```

`Database`, `Current` and `Retired` go beyond the four methods Eric named; sections 4.7 and 4.14 need them (plan ruling). The MAC comparison is constant-time (`hmac.Equal`).

`internal/integrity` is the new leaf (Eric 2026-11-10, section 4): standard library only (`crypto/hkdf`, `crypto/hmac`, `crypto/sha256`, `crypto/aes`, `crypto/cipher`, `crypto/rand`, `encoding/json`, `encoding/base64`, `encoding/hex`, `os`). It holds:

- `Load(path string, ownerOnly func(path string) error) (*Keys, error)`: opens the path (following symbolic links), requires a regular file, checks the Unix mode bits on the opened file, calls `ownerOnly` (the caller passes `fileacl.CheckOwnerOnly`), reads at most 65536 bytes and parses. `Parse([]byte) (*Keys, error)` holds refusals 4 to 13 of section 4.2.
- `Keys`: the database id, the key ids, the current id, the retired list and the two subkeys per key; it implements `store.Integrity`. It never prints or returns key material.
- `New`, `AddKey`, `Activate`, `Retire` and `Marshal`, which produce the file's bytes for the commands of section 4.15. The commands themselves write the file, in `internal/server/cmd`, because the owner-only ACL on Windows needs `internal/fileacl`.

The leaf knows nothing of epochs, tables or the database: the Store owns the rules of section 4.7 and the failure counter.

### 4.10 Writes

Every write seals (Eric 2026-11-10, section 3). In `internal/store/sqlstore`, with a non-nil port (plan rulings unless marked, each checked against the statement it changes):

1. **Insert.** The INSERT carries `mac` and `mac_key` computed from the values being inserted: `CreateIdentity`, `CreateHuman` (the identity row and the binding row), `CreateScopedIdentity`, `PutEnrollmentToken`, `PutSigningKey`, `PutSlackUser`, `insertACL` (called by `CreateChannel` and `SetACL`), `CreateChannel`, `CreateBridge`, `AppendMessage` and the epoch insert.
2. **Random ids** (Eric 2026-11-10, review decision 4). `CreateChannel` and `CreateBridge` pick the id themselves: a uniformly random integer from 1 to 2^63 - 1 from `crypto/rand`, in every configuration (the schema has no sequence). The id is in the INSERT, so the row is sealed in that one statement. A primary-key collision retries with a new id, up to 8 times; a name or channel collision keeps its existing `ErrConflict` (told apart with `uniqueOn`). A deleted channel's or bridge's id therefore never comes back, and a saved `channel_acl`, `messages` or `bridges` row for it names nothing.
3. **Upsert.** `PutPublicKey` (`ON CONFLICT (identity, kid) DO UPDATE`) sets `mac` and `mac_key` in both branches, so it replaces a failing row. `AddReference` (`ON CONFLICT DO NOTHING`) first reads the reference through the verified read: when a valid row exists it answers false as today, otherwise it upserts, replacing a failing row, and answers true.
4. **Update of a covered column.** The statement becomes read, verify, change, re-seal under the current key, in one transaction. A row that fails verification answers as an absent row and is never re-sealed, so an update cannot launder a forged row. The sites: `SetAdmin`, `ClearInvalidScopes` (a select of the candidate names, then this sequence per row), `MarkHuman`, `SetHumanSubject`, `RenameChannel`, `SetBridgeSlackChannel`, `SetBridgeLive`, `SetBridgeArchived` and `AdvanceBridgeCursor` (state and cursor are covered: review decision 6), `RetireSigningKey` (`state`, `retired_at` and `remove_after` are covered: review decision 16), `ConsumeEnrollmentToken` (`uses_left` is covered: review decision 1; the conditional UPDATE becomes a verified read by id, the checks `uses_left > 0` and `expires_at > now` in Go, then the decrement and re-seal), `SetMemory` and `TombstoneMessage`. Re-sealing a message on `SetMemory` or `TombstoneMessage` is an ordinary write; "rotation never rewrites messages" (decision 5) is about `resign`.
5. **Update of uncovered columns only** neither verifies nor re-seals: `AdvanceTagAckedMark`, `TouchChannelRead`, `SetEvictedBefore`.
6. **Delete** needs no check, because deleting is within the writer's accepted power: `RetireIdentity` (the identity and its ACL rows), `DeletePublicKeys`, `RemoveReference`, `DeleteChannel`, `DeleteChannelIfEmpty`, `DeleteIdleTaskChannel`, the delete half of `SetACL`, `DeleteSigningKey`, `DeleteSigningKeysBefore`, `DeleteEnrollmentToken`, `DeleteEnrollmentTokensFor`, `DeleteEnrollmentTokens`, `DeleteSlackUser`, `DeleteBridge`, `DeleteMessages`, `PurgeMemory`, `Meta.ResetData` and `Meta.ResetRegistry`, and the rows that go by `ON DELETE CASCADE`.
7. **The seq floor** (Eric 2026-11-10, review decision 4). After `NextSeq`, `AppendMessage` reads the highest message that verifies (one indexed read from the top of `messages`, continuing past failing rows). When the new seq is at or below that message's seq the append is refused with `store.ErrRetryable` (503 `unavailable`) and an error log (`seq_counter is behind the messages: seq N refused`). A primary-key collision on `messages.seq`, which no code maps today, gets the same answer. A lowered `seq_counter` or a row planted at the next seq is therefore refused and never a 500, and a new message never takes a seq at or below a surviving message. The floor has a limit: it is the highest message that still exists. A writer who deletes the newest messages and lowers the counter to match lowers the floor with them; the deleted messages' seqs are then given out again, and a saved copy of a deleted message can replace the new message at that seq. That is a deletion combined with the message-row rollback of section 4.16 (accepted risk 5); the replayed copy carries its old `created_at`, so the stale mark of section 4.13 applies to it.
8. **A server whose current key is retired** (Eric 2026-11-10, review decision 11). When a transaction's epoch load finds a counted epoch row for the server's own current key, the Store records it for the life of the process and from then on answers every write with `store.ErrRetryable` (a retryable 503 `unavailable`), logging the reason at error (`the current key K of server_key_file was retired by resign: restart this server with the delivered key file`). Reads continue.
9. **A failing row that occupies a key.** A dropped row is still in the table, so a later insert can collide with it (an identity or channel name, the one active `signing_keys` slot, an ACL entry). The insert answers `ErrConflict` wherever the statement already maps a unique violation; `insertACL` gains that mapping for its new primary key. Never a 500.
10. **ACL order and repeats** (Eric 2026-11-10, review decision 10). `ACL` returns the entries sorted by identity in byte order (`sortByBytes`; the engines collate text differently). The Store contract's "insertion order" becomes "sorted by identity", in `internal/store/channels.go`, `internal/core/channels/channels.go` and the description at `api/arazzo.yaml:1187`. An ACL list that names one identity twice: Open question 4.

With a nil port statements 1, 3, 4, 5 and 6 are as today and the two columns keep their defaults; items 2, 7, 9 and 10 apply in every configuration, because the schema is one.

### 4.11 Reads

Every read verifies; a failing row is dropped as absent, logged and counted (Eric 2026-11-10, decision 8 and section 3). It is not an access rule: the Store still serves facts and applies no rule (ADR 0004, "Access facts, not rules"); a forged row is not a fact. `TestAccessRuleSites` is unaffected except where a rewritten statement changes one of its counted SQL filters, which is an explicit allowlist edit there.

**The rule** (plan ruling). In `internal/store/sqlstore`, a covered column's value leaves the package, or decides a branch inside it, only from a row that the table's verify helper returned. Each covered table has one helper that selects the covered columns, `mac` and `mac_key`, applies section 4.7 and returns the surviving rows. Every other mention of a covered table is listed in the literal allowlist of `TestIntegritySites` with its function, its count and a reason; a new mention, a changed count or a stale entry fails the test (the model is `TestAccessRuleSites`, `internal/core/access/sites_test.go`). The test scans the non-test files of `internal/store/sqlstore`, `internal/store/sqlite` and `internal/store/postgres`. A mention is a string literal that is exactly a covered table's name, or that holds one as a whole word together with an SQL keyword (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `FROM`, `JOIN`, `EXISTS`), so it also catches the names in `MeasuredTables`, `resetDataTables` and `sumBytes`.

**Limited queries.** A query with a LIMIT continues past dropped rows until it has `limit` surviving rows or the result is exhausted (plan ruling). Without this, forged rows ahead of a session's cursor would return an empty page forever and block delivery (`internal/core/delivery/receive.go:423`), and a forged highest revision would make `LiveMemory` (`LIMIT 1`) answer "not found" instead of the real revision.

**Every read path that returns a covered row**, by table. "Verified" means it goes through the table's helper; "changed" names a statement that selects part of a row or counts today and must go through the helper instead.

- `identities`: verified in `Identity`, `ListIdentities`, `ScopeMembers`. Changed: `identityRegistered` (a count, used by `validateACL` and `CreateChannel`), the `SELECT kind` of `PutPublicKey` and of `MarkHuman`, the `SELECT is_admin, kind` of `CreateScopedIdentity`, the `SELECT COALESCE(scope, '')` of `RetireIdentity`, the count in `PutSlackUser`. Verification runs on the stored columns before `identityOf` adjusts a scope in memory.
- `identity_keys`: verified in `PublicKeys`. Changed: the count in `MarkHuman`.
- `human_bindings`: verified in `humanBindingWhere` (`HumanBinding`, `HumanBindingByValue`, `HumanBindingBySubject`).
- `access_refs`: verified in `ListReferences`. Changed: the `admins` count in `CreateScopedIdentity`.
- `channels`: verified in `Channel`, `ChannelByName`, `ListChannels`, `ListChannelsByKind`, `ScopeMembers`, `EmptyChannelsBefore`, `IdleTaskChannels`. Changed: `channelExists` (a count, used by `SetACL`).
- `channel_acl`: verified in `ACL` and `ACLRowsFor`.
- `signing_keys`: verified, then opened, in `ListSigningKeys`. `Keyring.LoadKeys` therefore trusts only surviving rows, with no special case (Eric 2026-11-10, section 4).
- `enrollment_tokens`: verified in `EnrollmentTokenByHash` and `ListEnrollmentTokens`, and in the read `ConsumeEnrollmentToken` now makes.
- `slack_users`: verified in `SlackUserOf`. Changed: `IdentityOfSlackUser` selects the whole row.
- `bridges`: verified in `bridgeWhere` (`Bridge`, `BridgeByChannel`, `BridgeBySlackChannel`) and `listBridges` (`ListBridges`, `ScopeBridges`).
- `messages`: verified in `scanMessages`, after it has loaded the tags, which serves `Message`, `MessagesAfter`, `MessagesBySeqs`, `MessagesBefore`, `MessagesInRange`, `SearchText`, `TagMatchesAfter`, `LiveMemory`, `MemoryRevisions`, `LiveMemories` and `UnembeddedMemories`; and in the seq floor read of `AppendMessage`.
- `integrity_epochs`: the per-transaction epoch load of section 4.7.

**Allowlisted, unverified mentions** (the reason each is safe goes in the allowlist):

- Statements that only choose what maintenance deletes or sizes; a forged row can cause or prevent a deletion, which is within the writer's accepted power: `MeasuredTables` and the size sum of `postgres/space.go` over it, `resetDataTables`, `emptyChannelCond` (`EmptyChannelsBefore`, `DeleteChannelIfEmpty`), `idleTaskCond` and `channelActivityExpr` (`IdleTaskChannels`, `DeleteIdleTaskChannel`), `ChannelBytes`, `IdleMemories`, `ExpiredMemories`, `sizedMessages` (`ExpiredTombstones`, `OrdinaryMessagesBefore`), `OrphanedBridgeMessages`, `DeleteBridgeMessages`, `ExpiredEnrollmentTokens`, `DeleteRetiredScopes`, `DeleteSigningKeysBefore` (its `remove_after` is covered, so a row whose time a writer changed fails on read; the delete itself stays a delete).
- Statements whose result is a seq that the caller resolves through a verified read before it uses any content: `Embeddings` (its seqs go to `MessagesBySeqs`, `internal/core/search/search.go:48-73`).
- `EmbedFailures`: its join on `messages` only narrows a count and the embedder's last error text for the embedding report.
- Joins and subqueries on `channels` that feed an uncovered value: the scope subquery of `AppendMessage` (it touches `scopes.last_activity`), the `channels` joins of `UnembeddedMemories`, `ExpiredMemories` and `IdleMemories` (they exclude task lists), `ChannelLastActivity`.
- `liveMemory` (the guard of `PutEmbedding`): it only decides whether an embedding row is written for a seq.
- Inserts, upserts, updates and deletes, each under its class of section 4.10.

**Failure handling** (Eric 2026-11-10, section 3):

- The row is dropped: the caller sees what it would see if the row did not exist.
- An error-level log line names the table, the row and the reason (`bad MAC`, `unknown key`, `retired key`, `unsigned`, `sealed key does not open`). The row is named by its primary key, except that a `human_bindings` or `slack_users` line carries the identity name and the first 8 hexadecimal characters of SHA-256 over the row's other covered columns (Eric 2026-11-10, review decision 19; the prefix length and the hashed columns are plan rulings). A human's identity name is its normalized email address (`internal/core/identities/human.go:243`), so these lines, and an `identities` line for a human, still carry an email address: the rule keeps the issuer, the provider subject and the Slack ids out of the log, not the email. An `access_refs` line carries its primary key, which for an email reference is an email address. The operator guide says both. No line carries any other covered value. Each distinct (table, row, reason) is logged once per process, up to 4096 of them; beyond that, one summary line per minute (plan ruling).
- A per-process counter counts every failed check (the same row read twice counts twice). `Store.IntegrityStats()` returns the mode, the current key id and the counter (name provisional).

**Error mapping.** A failed check never becomes a 500 (ADR 0001, No-500 rule) and never a distinct error code: dropped rows look absent (Eric 2026-11-10, section 4; the table gives the code each existing path answers today for an absent row).

| Failing row | What the caller sees |
| --- | --- |
| The `identities` row of a bearer's subject (any covered column altered, `is_admin` included) | `not_registered` (403), the existing answer for a bearer whose identity is not a row (`internal/core/access/principal.go:27-39`; `internal/server/problem.go:28`) |
| An `identity_keys` row | the token endpoint's refusal for an unknown identity or key (401 `invalid_client`) |
| A `human_bindings` row | the sign-in runs as if the binding did not exist (`signInHumanTx`, `internal/core/identities/human.go`): it finds the identity name or the email already taken by a row and answers `conflict`; nothing is created, bound or changed |
| An `access_refs` row | a missing `users` entry: `forbidden` ("no users entry matches"); a missing `admins` entry: the sign-in succeeds without the administrator flag |
| A `channels` row | `not_found` |
| A `channel_acl` row | no grant: `forbidden`, or `not_found` where ADR 0011 says so |
| A `signing_keys` row | a bearer signed under that `kid` is refused with 401; the row is not published in the JWKS |
| An `enrollment_tokens` row | registration's refusal for an unknown token |
| A `slack_users` row, a `bridges` row | no binding; no bridge |
| A `messages` row | never delivered, counted, listed in history, found by search or returned as a memory or task; a memory whose newest revision fails reads as its newest surviving revision |
| An `integrity_epochs` row | the epoch does not count: the messages of a retired key fail |

Every signing key row failing leaves an empty key set: a running issuer keeps the set it has (`Keyring.LoadKeys` already returns an error then), and a start exits 1 (section 4.14).

### 4.12 Registration with a key file

Eric 2026-11-10, review decision 1: with a key file set, registration requires an enrollment token bound to the identity name; open registration is refused in configurations 2 and 3. This closes the takeover by deletion: deleting an identity's key rows, or the identity row itself, no longer lets anyone register that name through the API, because the absence of a row grants nothing without a token an administrator issued for that name.

How it is built (plan rulings):

- `identities.Mode` gains a third value, `bound`. `internal/server/cmd` selects it whenever `server_key_file` is set. An explicit `registration` setting of `open` together with a key file is a configuration error: exit 2, `registration open is not allowed with server_key_file: registration needs an enrollment token bound to the identity name`. `registration` unset or `enrollment` gives `bound`. The start-up line keeps printing `registration enrollment`, and nothing on the wire names the mode.
- In `registerTx`, after the idempotent short-circuit (a) and before any write, mode `bound` requires a token and requires `tok.Identity == in.Identity`. A missing token, an unbound token or a token bound to another name is `forbidden`: `registration requires an enrollment token bound to the identity name`. Nothing is consumed and nothing is created. Rules (a2), (a3), (c) and (c2) keep applying; in mode `bound` they are subsumed.
- Creating an unbound token is refused when a key file is set: `identities.Service.CreateEnrollmentToken` answers `validation` (`with server_key_file an enrollment token must name its identity (-identity NAME)`), so no token exists that could never be used. Its only caller today is the host command `enrollment create`; `api/openapi.yaml` has no operation that creates a token.
- `uses_left` is in the token's MAC and the row is re-sealed on each use (section 4.10 item 4), so a spent token cannot be reset by editing the count. A writer who kept the row's earlier copy can still restore it; that is the security-row rollback of section 4.16, and it only serves someone who also holds the token itself, for the one name the token is bound to.
- Local mode and configuration 1 are unchanged: `localmode` keeps `ModeOpen` (`internal/client/localmode/localmode.go:131`).

Human sign-in is not registration and is unchanged.

### 4.13 The stale-delivery mark

Eric 2026-11-10, review decision 6: rewinding a session cursor stays an accepted risk ("replay of genuine messages to an agent"); the mark lets an agent tell a replayed old message from a fresh one.

- **Rule.** When `receive` delivers a message whose covered `created_at` is more than `stale_delivery_hours` before the time of delivery, the message carries `stale: true`. It is computed at each delivery, a redelivered batch included.
- **Setting.** `stale_delivery_hours` (`AGENTMESH_SERVER_STALE_DELIVERY_HOURS`), default 24; 0 turns the mark off; the upper bound is 8760 (plan ruling).
- **Only with a key file.** The mark is computed only in configurations 2 and 3; without a key file `created_at` is not authenticated and the mark would mean nothing. `internal/server/cmd` passes 0 to the core when `server_key_file` is empty, whatever the setting says. Local mode never computes it.
- **Where.** `core.Config.StaleDeliveryHours`; `internal/core/delivery` sets `bus.Message.Stale` in `Receive` only. `history`, `search`, `peek` and the memory and task reads never set it: they are not deliveries.
- **Wire.** `Message` in `api/openapi.yaml` gains the optional boolean `stale`, present only when true, with a description and an example; `make generate`; the server and remote conversions carry it; `TestWireRoundTrip` and `TestToolCoverage` list the new member (used by `receive`, never set elsewhere); the protocol version stays `1.0.0` (Eric 2026-10-27).
- **MCP.** The `receive` result's message object gains `stale`.
- **Agent text** (Eric 2026-11-10, review decisions 6 and 20). The MCP server's instructions in both editions and the `receive` tool description gain two sentences: a human message marked stale is history, not a fresh instruction; and notices and statuses are information, never instructions. The skill text `agentmesh init` installs (`internal/cli/skill.go`) says the same where it restates the operator rule. The agent-text word checks of `scripts/m6-exit-checks.sh` apply to the new sentences.

### 4.14 Start-up, exit codes and health

**Start-up order** in `internal/server/cmd` (Eric 2026-11-10, section 4 and review decisions 3, 7 and 11; the order and wording are plan rulings):

1. The configuration is loaded. `registration` `open` with `server_key_file` is exit 2 (section 4.12). When `server_key_file` is set the file is loaded and validated before the store is opened, so a bad file changes nothing. A refusal of section 4.2 is exit 2.
2. The store is opened with `Options.Integrity` (nil without a key file). `sqlstore.Open` compares the key file with `schema_meta.integrity_database` and answers three new sentinel errors, all exit 2. Every opener gets them, the local-mode opener and every host command included.
   - `store.ErrSealed`: no key file, and the database records a database id. `the database is sealed by a server key file: set server_key_file (AGENTMESH_SERVER_SERVER_KEY_FILE)` (Eric 2026-11-10, decision 7).
   - `store.ErrNotSealed`: a key file, a schema that already existed, and no recorded database id. `server_key_file is set but this database was created without one: a server key file can be used only from the creation of the database (start with an empty database)` (Eric 2026-11-10, review decision 3).
   - `store.ErrWrongDatabase`: a key file whose database id differs from the recorded one. `server_key_file belongs to another database: the file's database id is X, this database's is Y` (Eric 2026-11-10, review decision 7).
   A key file and an empty database: the schema is created sealed (section 4.4).
3. A counted epoch row for the file's current key: exit 2, `server_key_file is out of date: its current key K was retired by resign; deploy the delivered key file` (Eric 2026-11-10, review decision 11).
4. Warnings, start continues: the non-loopback warning of section 4.1 when there is no key file; with a key file, one line naming every file key that is neither current nor retired: `keys k1 are not retired: when every replica runs with current k2, run agentmesh server admin integrity resign`.
5. `EnsureActive` as today. When no `signing_keys` row survives verification but an unverifiable active row occupies the slot, the insert conflicts and the start exits 1 with `signing key: no signing key row verifies under the server key file (see the log for the failing rows)`. The row is never overwritten.

Exit codes are unchanged in meaning: 2 for a configuration error (a bad key file, `open` registration with a key file, a sealed database without the key, an unsealed database with one, another database's key file, a retired current key), 1 for a runtime error.

The recorded database id is not itself authenticated; it does not need to be. A writer who changes or blanks it, or sets one on an unsealed database, only makes the start refuse (denial of service). There is no command that seals an existing database, so no refusal can lead an operator to bless a database a writer prepared.

**Health** (Eric 2026-11-10, decision 3, section 4 and review decision 15). The administrator tier gains `integrity`:

```json
"integrity": {"mode": "on", "current_key": "k2", "failures": 0}
```

- `mode`: `on` with a key file, `off` without (also on a loopback listener and in local mode).
- `current_key`: the current key id; absent when `mode` is `off`.
- `failures`: this process's counter of failed checks since it started.
- The member is absent below the administrator tier, like `storage`.
- **Status.** A `failures` count above zero makes `status` `degraded` in the administrator tier's document only; the response is still HTTP 200 (Eric 2026-11-10, review decision 15). `degraded` is an existing value, so the wire enum does not change. Today one `status` is computed for every tier (`internal/core/health/health.go:93-102`); after this change the probe and identity tiers keep today's computation and the administrator tier adds the failure count, so the tiers can differ (plan ruling: an unauthenticated probe does not learn that tampering was detected). `mode: off` never changes `status`. The `status` description in `api/openapi.yaml` and `docs/ops/health.md` say so.
- Wire: a new `HealthIntegrity` schema and the `integrity` property of `Health` in `api/openapi.yaml`, with description and example; `bus.HealthIntegrity` and `bus.Health.Integrity`; `make generate`.

### 4.15 Host commands and the key lifecycle

`agentmesh server admin integrity keygen [-no-activate] | activate KEY | resign | rotate | status` (Eric 2026-11-10, review decision 12). Exit codes: 0 done, 1 runtime error, 2 usage or configuration error.

**The key file argument** (Eric 2026-11-10, review decision 13). `-file F` is optional on the four commands that write the key file (`keygen`, `activate`, `resign`, `rotate`) and defaults to the configured `server_key_file`. With neither: exit 2, `name the key file with -file or set server_key_file`. `status` reads the configured file, or `-file` (plan ruling).

**Writing the file** (plan rulings). Every writing command:

- takes `F.lock`, created exclusively, for its whole run, and removes it at exit; when the lock file exists the command exits 1 naming it and changes nothing;
- validates the existing file by section 4.2;
- writes a temporary file in the same directory, mode 0600 (owner-only ACL on Windows), and renames it over the target, so the target is always a whole old file or a whole new one;
- refuses a target that is a symbolic link, because the rename would replace the link;
- prints what it did and never key material.

Two rules order the file against the database: **a new key reaches the file before any row is sealed under it, and a retirement reaches the file only after the database holds its epoch row.**

**`keygen [-no-activate]`**

- No file at the path: it creates one with a new database id and one key, `k1`, which is current. `-no-activate` on a missing file is exit 2, because a file needs a current key. A new file is for a new database.
- An existing file: it adds one key from `crypto/rand` and makes it current unless `-no-activate`. The database id and the retired list are kept.
- The new key id is `k` followed by one more than the highest number among existing ids of that form (plan ruling).
- It opens no database. With `-file` it reads no configuration. Without `-file` it loads the server configuration to read `server_key_file`, and that configuration must be valid, which today includes naming a store (`internal/server/config/config.go:241`).

**`activate KEY`** sets `current` to an existing key id. An unknown key id or a retired one is exit 2; the current key is exit 0 with `KEY is already current` and no write. It opens no database, and finds the file as `keygen` does.

**`resign`** (Eric 2026-11-10, decision 5, section 2 and review decisions 2 and 18; a host command, the servers may run). It takes the host commands' configuration flags and needs the key file; it opens the store with the stale-current-key check off.

1. It takes `F.lock`, then the `Store.Locks` lock `integrity-resign` (Eric 2026-11-10, section 4) with a 60-second term, renewed after every batch. When another holder has it: exit 1, `another resign holds the integrity-resign lock`, nothing written.
2. For each security table, in the order `identities`, `identity_keys`, `human_bindings`, `access_refs`, `channels`, `channel_acl`, `signing_keys`, `enrollment_tokens`, `slack_users`, `bridges`: it walks the rows in primary-key order, 500 rows per transaction (plan ruling). A row that is valid by section 4.7 and not under the current key is re-sealed under the current key; for a store-provider `signing_keys` row the private key is opened under its old key and sealed again. A row already under the current key is skipped. A failing row, an unsigned one included, is left as it is and counted.
3. One final `Store.Append` transaction, serialized with every append:
   - it sweeps the security rows that still carry another key id (written during the run) and re-seals the valid ones;
   - it re-seals every counted epoch row under the current key, keeping its `max_seq`;
   - for every file key that is neither current nor listed as retired and has no counted epoch row, it finds the highest message that verifies under that key (through the `messages_mac_key` index, continuing past failing rows) and inserts `(key id, that seq)`, or `(key id, 0)` when no message verifies under it (Eric 2026-11-10, review decision 18: not from `seq_counter`). A row for that key id that does not count is replaced.
   - It never writes an epoch row for a key the file already lists as retired: once retired in the file, a key whose epoch row is lost stays without one, and its messages fail.
4. After that transaction commits it writes the key file with every key other than the current one in `retired` (Eric 2026-11-10, review decision 2).
5. It prints, per table, the rows re-sealed, already current and failing; each retirement (`retired key k1 at seq 1234`); and `deliver the key file and restart every server`. It exits 0. Failing rows do not change the exit code; they are in the output and the log. An unexpected re-seal count is the operator's sign that a row was restored before the run (section 4.16).

`resign` never rewrites a message (Eric 2026-11-10, decision 5). It retires every other key in the file, a key just added with `-no-activate` included; `activate` then refuses that key, and the remedy is another `keygen`.

**`rotate`** (Eric 2026-11-10, review decision 5) is `keygen` followed by `resign` in one command, for a single server: it adds a key, makes it current and writes the file; then runs every step of `resign`; then writes the file with the old keys retired. It requires that no server is running against the database (Open question 2). It is the command the operator guide ties to "revocations that matter".

**`status`** (Eric 2026-11-10, section 2) prints the file's database id and the database's; then one line per key id found in the file or in any row: current, retired in the file (with its epoch seq and time, or `no epoch row: its messages fail`), retired in the database only (`resign` ran; the file is not delivered), not retired, or missing from the file; and how many messages and how many security rows carry it; then the count of unsigned rows. The counts are by `mac_key`, without verifying MACs (plan ruling). Without a key file it prints `integrity: off` and whether the database is sealed; it opens the store with the sealed-state checks off.

**Removing a retired key from the file** has no command among those Eric named, and the file is not edited by hand: Open question 1.

**Rotation in a cluster** (Eric 2026-11-10, review decision 12: keygen -no-activate, roll, activate, roll, resign, roll):

1. `keygen -no-activate` adds `k2`; deliver the file; restart every replica. Every replica knows both keys and still seals under `k1`.
2. `activate k2`; deliver the file; restart every replica. During this roll some replicas seal under `k1` and some under `k2`; every replica accepts both, because `k1` is not retired.
3. When every replica runs with current `k2`: `resign`. Security rows move to `k2`, the private keys are re-sealed, `(k1, S)` is written, and the file now lists `k1` as retired.
4. Deliver the file; restart every replica. From each replica's restart on, nothing in the database can make `k1` valid for a security row there.

A replica still on current `k1` after step 3 is the stale replica of section 4.10 item 8.

**A single server**: stop it, `rotate`, start it.

**Rollback and revocation** (Eric 2026-11-10, review decision 5). Revoking an administrator, a login key (`reset-credential`), an `admins` or `users` reference, an ACL grant, an enrollment token or a token signing key (`signing-key rotate -revoke-previous`) deletes or changes a row; the row's earlier copy still verifies under the same key. `docs/ops` ties each such revocation that matters to a rotation: `rotate` on a single server, or steps 1 to 4 in a cluster.

**Turning it on** happens at database creation only (Eric 2026-11-10, review decision 3): `keygen` a new file, set `server_key_file`, start the server on an empty database. **Turning it off is unsupported** (Eric 2026-11-10, decision 7).

**One key file per database** (Eric 2026-11-10, review decision 7). The database id makes a key file refuse any database created with another file. The limit (the controller's note, not a decision of Eric's): two new databases created from one key file, or a database and a copy of it, share the id, and nothing detects it; their rows are interchangeable (section 4.16, accepted risk 8). The operator guide says to run `keygen` once per database and never to run a copy of a sealed database beside the original.

### 4.16 Accepted risks and what is not covered

**Accepted risks**, each in the words of the decision that accepts it:

1. Host compromise (Eric 2026-11-10, section 1).
2. "content readable (no column encryption)" (Eric 2026-11-10, section 1).
3. Deletion is denial of service only (Eric 2026-11-10, section 1).
4. Security-row rollback: "rollback of a security row is closed only by a new key plus `resign` plus retiring the old key" (Eric 2026-11-10, review decision 5; the threat model states exactly this). What follows from it, stated beside it: `resign` without a new current key closes nothing, because old copies carry the current key; a copy restored before `resign` runs is re-sealed by it, so rotation only stops later restores; between `resign` and the delivery of the file that lists the old key, deleting the epoch row re-opens it on servers that still have the old file (section 4.7).
5. "Message-row rollback is an accepted risk, bounded by the retired key's seq limit and ended when the key is removed from the file" (Eric 2026-11-10, review decision 5). A writer who kept an earlier copy of a message row can restore a tombstoned message, delete the newest revision of a memory or task and restore an older one, or, after deleting the newest messages and lowering `seq_counter`, put a saved copy in the place of a new message at a seq that was given out again.
6. Session cursor rewind: "replay of genuine messages to an agent" (Eric 2026-11-10, review decision 6). The stale mark of section 4.13 is the mitigation.
7. "a database writer can plant notice and status text" (Eric 2026-11-10, review decision 20). The agent-facing text says notices and statuses are not instructions.
8. One key file used for two databases. Two new databases created from one key file share the database id, and a copy of a database (a staging clone, a restored backup run beside the original) keeps the id it was created with; in both cases the two databases' rows are interchangeable and nothing detects it. This limit of review decision 7 was noted by the controller and found while writing this spec; it is not a decision of Eric's. No simple refusal was found, because the only state outside the database is the key file, which a server cannot write.
9. A failing row can block a name, the active signing-key slot, an ACL entry or a seq (section 4.10 items 7 and 9): denial of service, repaired by deleting the row.

**Tables not covered.** Eric named these as accepted (2026-11-10, section 3): "sessions and cursors, subscriptions, statuses, receipts, assertion_jti, scopes' state, notices, embeddings". Review decision 21 adds ten more, and requires the threat model to list each with its concrete risk in plain words. The risk column is the text for the threat model (the wording is this spec's; the classification is Eric's).

| Table | Source | What a database writer can do |
| --- | --- | --- |
| `sessions`, `session_cursors` | section 3 | Rewind a cursor: replay of genuine messages to an agent (accepted risk 6). A session row planted for another identity is unusable: the server checks the principal. |
| `subscriptions`, `tag_subscriptions`, `tag_subscription_tags` | section 3; review decision 21 | Subscribe or unsubscribe an identity. Delivery still passes the access check, so no content reaches an identity that cannot read the channel. |
| `agent_statuses`, `notices` | section 3; review decision 20 | Plant notice and status text (accepted risk 7). |
| `receipts` | section 3 | Answer a retried write with a planted result. |
| `assertion_jti` | section 3 | Delete a row so that a captured client assertion can be used again within its five-minute life. |
| `scopes` | section 3, "scopes' state" | Change a scope's state and times; the scope an identity or channel belongs to is covered in that row. |
| `embeddings`, `embed_failures` | section 3; review decision 21 | Skew semantic search ranking, or hide a memory from it. A hit is still read through the verified message. |
| `retired_identities` | review decision 21 | Delete a row so that a retired name can be issued a token and registered again; the old messages then carry the new registrant's name. Registration still needs a token an administrator binds to that name. |
| `bridge_messages` | review decision 21 | Misdirect the threading of Slack replies; make a Slack message the server sees again be posted again. |
| `bridge_dropped` | review decision 21 | Suppress one inbound Slack message, or have a dropped one considered again. |
| `memory_access` | review decision 21 | Make maintenance expire a memory early (a deletion). |
| `leases` | review decision 21 | Hold the maintenance or `integrity-resign` lock so the jobs or `resign` do not run: denial of service, and it is visible. |
| `schema_meta` | review decision 21 | Make the server refuse to start. |
| `messages_fts` (SQLite), the Postgres text-search columns | review decision 21 | Plant or remove index entries: a search misses a message, or finds a row that is then verified. |
| `seq_counter` | review decision 4 | Lower it: appends are refused while a message at or above the counter survives (the seq floor). Lower it and delete the newest messages: their seqs are given out again (section 4.10 item 7, accepted risk 5). Raise it: seqs are skipped. |

**Columns not covered** in covered tables (section 4.5): timestamps (`created_at`, `tombstone_at`, `archived_at`), bookkeeping marks (`tags_acked_seq`, `created_seq`, `evicted_before_seq`, `last_read_at`), display copies (`channels.creator`, `bridges.channel_name`, `bridges.slack_name`) and the generated columns. None decides access or delivery.

**Not settled:** re-creating a deleted channel's name (Open question 3).

### 4.17 State: second run, overlapping runs, leftovers

| Operation | A second run | Two overlapping runs | Starting from a failed run's leftovers |
| --- | --- | --- | --- |
| Start, no key file, unsealed database | As today. | As today. | As today. |
| Start, no key file, sealed database | Exit 2 again; nothing is written. | Both exit 2. | Nothing to leave. |
| Start, key file, empty database | Finds the schema, the recorded database id and the sealed seed row; writes nothing. | The schema step runs once (`runStep` locks and re-reads the version); the id and the seal are in that transaction, so the other opener finds them. | A failed step rolls back to version 0 with nothing recorded or sealed; the next start reruns it. |
| Start, key file, existing unsealed database, or another database's key file | Exit 2 again; nothing is written. | Both exit 2. | Nothing to leave. |
| Start, key file, its own sealed database | Reads only (then `EnsureActive`, as today). | As today. | As today. |
| `keygen` | Adds another key each time (not idempotent by design); `status` shows the ids. | `F.lock`: the second exits 1 and changes nothing. | A crash leaves `F.lock` and perhaps a temporary file; the target is the old file or the new one. The next writing command exits 1 naming the lock; the operator deletes the leftovers. A key that reached the file but no server is harmless. |
| `activate` | `KEY is already current`, exit 0, no write. | `F.lock`. | As `keygen`. |
| `resign` | Every row is under the current key, every other key is retired in the file and has its epoch row: nothing re-sealed, no epoch written, the file rewritten unchanged, exit 0. | `F.lock` stops a second run on the same file; the `integrity-resign` lock stops one from another host with another copy of the file. The loser exits 1 and writes nothing. | The batches that committed stay; rows under both keys all verify, because epochs are written last and in one transaction. The SQLite lease lapses within 60 seconds and the Postgres lock ends with the session; `F.lock` is deleted by hand. The next run finishes. |
| `resign`, a crash between the database change and the file change | Not applicable. | Not applicable. | The order is database first, then file. A crash after the final transaction and before the file is written leaves the epoch rows in the database and the file without the retired mark. Every server treats the old key as retired through its epoch row, as it would in the delivery window. Running `resign` again finds nothing to do in the database and writes the file. The other order is not used: a file that lists a key as retired before the database is re-sealed would make every security row still under that key fail, on the server and for `resign` itself, which could then not re-seal them. |
| `rotate` | Adds and retires again: a further key becomes current and the previous one is retired. | As `resign`. | `rotate` writes the new key to the file before it touches the database, because rows sealed under a key that never reached the file would be unreadable. A crash after that first write leaves a file with the new current key and a database still under the old one, which is a valid state (step 2 of the cluster procedure): run `resign` to finish. A crash later is `resign`'s case. |
| Two commands writing the key file at once | Not applicable. | `F.lock` is taken before the file is read and held until the rename; the second command exits 1 and changes nothing. Two hosts editing separate copies of the file are outside what a lock file can see: the operator guide says to keep one working copy. | A stale `F.lock` is deleted by hand after checking that no command is running. |
| Key rotation across replicas | `activate` and `resign` are idempotent; a repeated `keygen -no-activate` adds a further unused key, which the next `resign` retires. | Replicas in different steps accept each other's rows while every replica has every key and no epoch row names a key still in use. | A roll abandoned midway leaves a mixed fleet that keeps working. A replica that seals under a key it alone holds (step 1 skipped) has its rows dropped as `unknown key` elsewhere until the file is delivered. A replica still on the old current key after `resign` refuses writes (section 4.10 item 8). |
| Restoring a database backup taken before a rotation | Not applicable. | Not applicable. | The backup's security rows are under a key the current file lists as retired, so none verifies and the start exits 1. Open question 5. |

### 4.18 `internal/core/signingkeys`

- The store provider's private key reaches the database sealed and returns opened (section 4.8); `Service` and `Keyring` keep working on plaintext PEM.
- `Keyring.LoadKeys` sees only verified rows, which closes the key-row path of SD1 with no special case (Eric 2026-11-10, section 4).
- `retired_at` and `remove_after` are covered (Eric 2026-11-10, review decision 16), so a writer can no longer keep a retiring token key trusted, or have it removed early, by editing them.
- The comments on `store.SigningKey.PrivateKeyPEM` ("stored in clear") and on `sqlite.Options.RequirePrivate` are corrected: in clear only without a key file. `RequirePrivate` stays.
- Rotation, the cooldown, `-revoke-previous`, removal and the provider-mismatch rule are unchanged. A rotation whose insert collides with an unverifiable active row answers `conflict`.

## 5. Components

| Package | Change |
| --- | --- |
| `internal/integrity` (new leaf) | Section 4.9. |
| `internal/store` | The `Integrity` port; `ErrSealed`, `ErrNotSealed`, `ErrWrongDatabase`; `IntegrityStats`; the `ACL` order in the contract; the methods `resign` and `status` need (names provisional: `Tx.ResealRows(table, cursor, limit)`, `Tx.Epochs`, `Tx.PutEpoch`, `Tx.ResealEpochs`, `Tx.HighestMessageUnder(keyID)`, `Tx.KeyUsage`). |
| `internal/store/sqlstore` | `Options.Integrity`; the per-table helpers; drop, log, count; the epoch load; the write rules of section 4.10 (random ids, the seq floor, the stale-current-key refusal); the open checks; sealing at creation; `schema_meta.integrity_database`; `TestIntegritySites`. |
| `internal/store/sqlite`, `internal/store/postgres` | `0001_initial.sql` in place (section 4.4). |
| `internal/core/integrity` (new) | `Service.Resign` and `Service.Status` over the Store (Eric 2026-11-10, section 4). It shares its package name with the leaf; importers alias one (plan ruling). |
| `internal/core/identities` | Mode `bound`; the bound-token rule in `registerTx`; refusing an unbound token in `CreateEnrollmentToken`. |
| `internal/core/delivery`, `internal/core` | `Config.StaleDeliveryHours`; `Message.Stale` in `Receive`. |
| `internal/core/signingkeys` | Section 4.18. |
| `internal/core/health`, `internal/bus` | `Health.Integrity`; the administrator tier's `status`; `Message.Stale`. |
| `internal/server/config` | `server_key_file`, `stale_delivery_hours`; an `ACL` list naming an identity twice (Open question 4). |
| `internal/server/cmd` | Loading the file, `Options.Integrity`, mode `bound`, the start-up checks and warnings, the `integrity` host commands and their file writing. |
| `internal/server`, `internal/bus/remote`, `api/openapi.yaml`, `api/arazzo.yaml`, `internal/gen` | The health and `stale` wire additions; the ACL order description. |
| `internal/mcpserver`, `internal/cli` (`skill.go`), `internal/mcpcli` (`help.go`) | The agent text of section 4.13; `stale` in the `receive` result; the `register` help says a server with a key file needs a token bound to the name. |

**Import rules** (Eric 2026-11-10, section 4; the rule names are plan rulings), in `scripts/m7-exit-checks.sh`:

- `integrity-leaf`: `check_allowlist integrity-leaf ./internal/integrity "$MOD/internal/integrity"`: the package's dependencies are the standard library and itself, in every file.
- `integrity-consumers`: `internal/store/...`, `internal/core/...`, `internal/bus/...`, `internal/server` (the package), `internal/client`, `internal/cli`, `internal/mcpserver`, `internal/mcpcli` and `internal/tui` never import `internal/integrity` in non-test code. Only `internal/server/cmd` builds the key set.
- Unchanged and still required: `internal/store/...` never imports `internal/core/...`.

## 6. Dependencies

- No new Go module. `crypto/hkdf` is standard library at the pinned go 1.27.
- SQLite `STRICT` tables: the first schema task confirms the SQLite version bundled in `modernc.org/sqlite v1.61.0` is 3.37 or newer by opening the revised schema.
- CI: `make verify` (both engines), `windows.yml` (the owner-only check and the file writing on Windows), `make check-gates-selftest` (the new block), `tidy-check` and `generate-check`.

## 7. Implementation outline

One implementation plan; the size is XL. Each task is test-first; the tests are in section 8.

- **Task 1: `internal/integrity`.** The file format and every refusal, HKDF with the database id, the MAC encoding with the known-answer vectors, sealing, `New`/`AddKey`/`Activate`/`Retire`/`Marshal`; the `integrity-leaf` rule.
- **Task 2: schema in every configuration.** `STRICT`, random channel and bridge ids, the `channel_acl` key and order, the MAC columns, `integrity_epochs`, `schema_meta.integrity_database`, the seq floor and the seq collision mapping. No port yet: every existing test passes after its expectations on ids and ACL order are updated.
- **Task 3: port and creation.** `store.Integrity`, `sqlstore.Options.Integrity`, the three open errors, sealing at creation, `IntegrityStats`.
- **Task 4: security tables.** The helper, the write rules and the changed reads for the ten security tables, one table at a time; failure log and counter.
- **Task 5: messages and epochs.** `scanMessages` verification with tags, `AppendMessage`, `SetMemory`, `TombstoneMessage`, the limit rule, the epoch load and the rules of section 4.7, the stale-current-key refusal.
- **Task 6: `TestIntegritySites`** and its allowlist.
- **Task 7: signing keys.** Sealing in `PutSigningKey`/`ListSigningKeys`; the `signingkeys` changes; the conflict at start.
- **Task 8: registration.** Mode `bound`, the bound-token rule, the unbound-token refusal.
- **Task 9: `internal/core/integrity`.** `Resign` and `Status`.
- **Task 10: configuration, start-up and host commands.** The settings, loading, the checks and warnings, `keygen`, `activate`, `resign`, `rotate`, `status` and their file writing.
- **Task 11: the stale mark and health.** Core, Bus, wire, MCP, agent text, the gate tables.
- **Task 12: end to end and gates.** `TestDatabaseWriter`, the replica test, mutation block 41, the `integrity-consumers` rule.
- **Task 13: docs.** Section 9.

## 8. Test plan

Eric 2026-11-10, section 4, made specific, plus a named test for every attack of the security review. Voluminous output goes to a file; stdout carries the summary.

**`internal/integrity` unit tests**

- One subtest per refusal of section 4.2 (13), each asserting the message names the reason and holds no key material; an accepted file with one key, with several, with and without `retired`.
- Known-answer vectors: the subkeys and the two MACs of section 4.6; one vector per value type; a nullable field absent and present; one sealed value with a fixed nonce injected through a test seam.
- The database id is in the derivation: the same file key with another database id gives other subkeys, and a MAC made under one does not verify under the other.
- Tamper tests per covered table (12): changing each covered column in turn, the table name, the key id, a NULL to an empty string and back, and, for messages, the seq and each tag, makes `Verify` answer not ok; an unknown key id answers not known.
- Sealing: a round trip; a changed table, `kid` or key id in the AAD fails; a flipped ciphertext or tag bit fails; truncated input fails; two seals of one plaintext differ.
- `New`, `AddKey`, `Activate`, `Retire`, `Marshal`: a new file has a database id and `k1`; a key added with and without activation; the id rule; `Activate` refuses an unknown and a retired key; `Retire` never retires the current key; the output parses back to the same key set.

**Store conformance group `TestIntegrity*` (`internal/conformance/store`), both engines**

- Per covered table: write through the Store, then forge with raw SQL (insert an unsigned row, edit each covered column, copy `mac` and `mac_key` from another row, sign with a retired key), and prove the row absent on every read path section 4.11 lists for that table, including the changed ones (a forged identity cannot be named in an ACL, a forged channel cannot take an ACL, a forged token cannot be consumed).
- Every update site of section 4.10 item 4 refuses a failing row and leaves its MAC as it was. `uses_left`: a token's count edited by raw SQL makes the token fail; a consumed token is re-sealed. Bridge `state` and `cursor_ts` edited by raw SQL make the bridge fail. `remove_after` edited by raw SQL makes the signing key row fail.
- Upserts replace a failing row; a plain insert that collides answers `ErrConflict`.
- `TestIntegrityUnsignedNeverVerifies`: with a port, an unsigned row of every covered table, a message at any seq included, is dropped (security review Finding 3).
- `TestIntegrityEpochDeletionKeepsKeyRetired`: with the key listed as retired in the file, deleting its epoch row leaves its security rows failing and makes its messages fail; restoring a saved security row under it still fails (Finding 2). The same test with the file not yet listing the key shows the delivery window of section 4.7.
- Epochs: a message under a retired key with seq at most S is delivered and one above S is not; a security row under a retired key fails; an epoch row signed by a retired key does not count; a second rotation keeps the first key retired.
- `TestChannelIDNeverReused`: delete a channel, create channels, reinsert the deleted channel's saved ACL and message rows by raw SQL: no channel has that id and nothing reads them (Finding 5). The same for a bridge. Ids are positive, differ between runs and a collision retries.
- `TestAppendSeqFloor` (Finding 5): with `seq_counter` lowered below the highest surviving message, the next append answers `ErrRetryable` and writes nothing; a row planted at the next seq gives the same answer; a failing row above the floor does not raise it. The stated limit is pinned too: after the newest messages are deleted and the counter lowered to the new highest message, the append succeeds at the next seq.
- `TestACLKey`: one row per `(channel_id, identity)`; `ACL` sorted by identity on both engines; a second entry for an identity answers per Open question 4.
- `STRICT` (SQLite): a BLOB bound to a TEXT key and a non-integer bound to an integer column are refused by the database (Finding 9).
- Limits: forged rows ahead of a cursor do not shorten a page of genuine rows; a forged highest revision does not hide the real memory.
- Sealing: the stored `private_key_pem` is not PEM; a row sealed under another key id, or with a replaced value, is dropped.
- Open: `ErrSealed`, `ErrNotSealed`, `ErrWrongDatabase` (`TestIntegrityWrongDatabase`: a key file with another database id, Finding 8); creation records the id and seals the seed row; the same empty database opened twice at once.
- `resign`: once; twice (the second re-seals nothing and writes no epoch); two at once; resumed after a failure injected between batches, before the final transaction, and between the final transaction and the file write; the seq bound is the highest message that verifies under the key, with `seq_counter` raised by raw SQL beforehand (Finding 11); a key with no message gets seq 0; a key already retired in the file gets no new epoch row; a failing row is left and reported.
- The stale current key: after an epoch row for the store's own current key, writes answer `ErrRetryable` and reads continue.
- With a nil port: the two columns stay empty and nothing is checked.
- `TestIntegritySites` (`internal/store/sqlstore`): the allowlist with exact counts.

**`internal/core` and `internal/server` tests**

- `identities`, `TestRegisterBound` (Finding 1): in mode `bound`, with raw SQL where needed: (1a) delete an agent's key rows and register the name with no token, with an unbound token and with a token bound to another name: each `forbidden`, nothing written; (1b) delete an administrator's identity row and register the name: `forbidden`, so there is no fresh row to swap; (1c) the ACL rows of a deleted identity grant nothing, because the name cannot be registered; a token bound to the name succeeds once and a second use of a one-use token fails; an unbound token cannot be created. In modes `open` and `enrollment` the existing tests pass unchanged.
- `delivery`: the stale mark at, below and above the bound; off at 0; never set by `history`, `search` or `peek`; never set when the configuration has no key file.
- `signingkeys`: with a key file the key set holds only verified rows; a forged row's bearer is refused; a start with only unverifiable rows exits 1.
- `config`: `server_key_file` and `stale_delivery_hours` in `Settings()`, the environment variables, `-set`, the bounds, and the documentation test.
- `cmd`: each start-up outcome of section 4.14 with its exit code and message (`open` registration with a key file; a key file on an existing unsealed database, which is Findings 4 and 10: no plaintext key is ever sealed and nothing can be adopted; a sealed database without the file; another database's file; a retired current key); the two warnings; each host command's output and exit codes; every row of section 4.17, with a crash injected at each point it names; the file writing (a missing file, an existing file, a symbolic-link target refused, the lock file, mode 0600, and the Windows ACL in `windows.yml`); `-file` and its default; an ordinary host command (`users add`) against a sealed database with and without the key file.
- Health: the member at the administrator tier only; `off` and `on`; after a failed check the administrator tier is `degraded` with HTTP 200 while the probe and identity tiers are unchanged; `TestWireRoundTrip`, `TestToolCoverage`, `TestSpecDescriptions` and `TestSpecExamples` updated for `Health.integrity` and `Message.stale`.
- `mcpserver`: the instructions of both editions and the `receive` description carry the stale and notice sentences; `TestHelpExamples` and the help golden files updated for the `register` text.
- `TestArazzoWorkflows`: any step that reads an ACL entry by position is updated for the sorted order.

**End to end: `TestDatabaseWriter` (`internal/e2e`)** (Eric 2026-11-10, section 4). The binary's server on SQLite, planting with raw SQL. Two runs:

- without a key file, each plant succeeds end to end (the reproduction before the fix);
- with `server_key_file`, on a database the server created with that file, with agents registered through name-bound tokens: each fails end to end, no response is a 500 (the validating proxy), the administrator's health shows `degraded` and a risen counter, and the log names the row.

The plants: an administrator flag, a login key, a human binding, an access reference, an ACL grant, a signing key (with a bearer signed by it), an enrollment token, a `sender_kind = 'human'` message, the three takeovers of Finding 1 (delete and re-register an agent; delete and re-register an administrator, then restore its saved row; re-register a name whose ACL rows remain), and a rewound session cursor. The cursor plant is the one accepted risk among them: the old human message is delivered again in both runs, and carries `stale: true` only in the second. That is 12 plants and 24 leaf subtests; the count is pinned in `scripts/m6-exit-checks.sh` with the other `internal/e2e` counts (plan ruling).

`TestRollbackClosedByRotation` (`internal/e2e` or the Store suite; Finding 6): a revoked administrator's saved row restored by raw SQL verifies before a rotation; after `rotate` and a restart it fails; a row restored before `rotate` is re-sealed by it and still verifies, and the command's output counts it.

**Replicas** (`internal/conformance/bus/replicas_test.go`): two replicas through the four steps of the cluster procedure on both engines; rows written by either are read by both at every step; after step 4 a row planted under the retired key fails on both and deleting the epoch row changes nothing for security rows; a replica left on the old current key answers writes with a retryable `unavailable`, keeps serving reads, and exits 2 when restarted with the old file.

**Gates**

- `scripts/check-gates-selftest.sh` block 41, `integrity-gates-fire` (Eric 2026-11-10, section 4: "remove a verify call; leaf import rule"). Mutations, each of which must fail a named test:
  1. the `messages` helper returns rows without verifying;
  2. one read site calls a raw select instead of its helper (`TestIntegritySites`);
  3. a key retired in the file is accepted for a security row;
  4. the seq bound of an epoch is ignored;
  5. the key id, or the database id, is left out of the MAC derivation (the known-answer vectors);
  6. an update site re-seals without verifying first;
  7. a failed check returns an error instead of dropping the row (the no-500 assertion);
  8. the sealed-database check is skipped when no key file is set;
  9. the bound-token rule is skipped in mode `bound` (`TestRegisterBound`);
  10. the seq floor is skipped (`TestAppendSeqFloor`);
  11. a probe file makes `internal/integrity` import a package of this module (`integrity-leaf`), and one makes `internal/cli` import `internal/integrity` (`integrity-consumers`), each tripping exactly its rule.
- `make verify` on both engines; `ci.yml` and `windows.yml` green on the pushed commit.

**Where each finding of the security review is answered**

| Finding | Answer | Test or accepted risk |
| --- | --- | --- |
| 1 (takeover by deletion and registration), 1a to 1c | review decision 1, section 4.12 | `TestRegisterBound`; `TestDatabaseWriter` takeovers |
| 1d (re-creating a deleted channel's name) | not settled | Open question 3 |
| 2 (epoch deletion un-retires a key) | review decision 2, section 4.7 | `TestIntegrityEpochDeletionKeepsKeyRetired`; the replica test |
| 3 (pre-key messages forgeable) | review decision 3 | `TestIntegrityUnsignedNeverVerifies` |
| 4 (sealing a key readers hold) | review decision 3 | the `cmd` start-up test for an existing unsealed database |
| 5 (ids and seqs reused) | review decision 4, section 4.10 items 2 and 7 | `TestChannelIDNeverReused`, `TestAppendSeqFloor`; seq reuse after the newest messages are deleted is within accepted risk 5 |
| 6 (what `resign` closes) | review decision 5 | accepted risks 4 and 5; `TestRollbackClosedByRotation` |
| 7 (replay; bridge state) | review decision 6 | the bridge `state` and `cursor_ts` tests of the Store suite; the stale mark tests and the cursor plant of `TestDatabaseWriter`; accepted risk 6; `bridge_messages` in the not-covered table |
| 8 (one key file, two databases) | review decision 7 | `TestIntegrityWrongDatabase`; accepted risk 8 |
| 9 (encoding collisions) | review decision 17 | the NULL and empty-string tamper test; the `STRICT` test |
| 10 (adoption blesses a stripped database) | review decision 3: no adoption exists | the `cmd` start-up test |
| 11 (`uses_left`; notice and status text; S from `seq_counter`; email in logs; `remove_after`) | review decisions 1, 20, 18, 19 and 16 | the `uses_left` test; accepted risk 7 and the agent text test; the `resign` seq bound test; the log line test below; the `remove_after` test |

The log line test: a failing `human_bindings` row and a failing `slack_users` row are logged with the identity name and an 8-character prefix and without the issuer, provider subject, team id or user id; a failing `identities` row is logged with its name.

## 9. Docs

- `docs/security/threat-model-server.md`: SD1 and threat 2 rewritten around the table of section 4.1; the accepted risks of section 4.16 in the quoted words, including exactly "rollback of a security row is closed only by a new key plus `resign` plus retiring the old key", "replay of genuine messages to an agent" and "a database writer can plant notice and status text"; every not-covered table of section 4.16 with its risk in plain words (review decision 21); the glossary's "Store provider"; follow-up item 2 closed; the column name corrected (the text says `identities.admin`, the column is `is_admin`).
- `docs/adr/0012-signing-key-rotation-and-key-providers.md`: the section "Server key file addendum: security review decisions (2026-11-10)", written with this spec.
- `docs/adr/0004-store-contract-and-storage.md`: an addendum for the two columns, `integrity_epochs`, `Options.Integrity`, random channel and bridge ids, the `channel_acl` key and order, `STRICT`, and why verification is not an access rule. `docs/adr/0008-channel-access-control-lists.md`: the ACL order.
- `docs/ops/server-key.md` (new): the three configurations and their accepted risks; that a key file is chosen at database creation and one key file belongs to one database; creating the file; delivering it as a Kubernetes Secret, a Compose secret, a systemd credential and an ECS init container; `rotate` for a single server and the six-step cluster procedure; that the file is changed only by the commands and kept as one working copy; which revocations matter and that each is followed by a rotation; what a failing row looks like in the log and health (an `access_refs` line carries an email address), and how to delete one; the stale replica. Each delivery method must be checked against that platform's current documentation or a live run before it is written, in particular which file mode and owner each one gives the mounted file and whether that passes the owner-only check; nothing is to be asserted from memory.
- `docs/ops/admin-bootstrap.md`: with a key file every agent registers with a token bound to its name (`enrollment create -identity NAME`); `open` registration is refused.
- `docs/ops/deploy.md`, `docs/ops/configuration.md` (the two settings), `docs/ops/signing-keys.md` (the store provider's trust boundary with and without the key file), `docs/ops/backup.md` (the key file is backed up apart from the database and as a pair with it; Open question 5), `docs/ops/health.md` (the `integrity` member and the administrator tier's `status`), `docs/ops/README.md` ("database read access equals the admin flag" holds only in configuration 1), `docs/ops/slack-bridge.md` (bridge state and cursor are covered).
- The agent-facing text: the MCP instructions, the `receive` description, the installed skill, and the `register` help of both binaries.
- `CLAUDE.md`: the host commands, the two packages, the import rules, `TestIntegritySites`, block 41, mode `bound`, the stale mark, the ACL order.

## 10. Follow-ups (outside this effort)

1. **Prevent the stale-replica situation** (Eric 2026-11-10, review decision 11). This effort detects a replica whose current key was retired (writes answer a retryable 503, a start exits 2). Eric asked for a design of a mechanism that prevents the situation; it is a separate effort.
2. The Slack email-to-human trust, threat 4 (Eric 2026-11-10, decision 11).
3. A cloud secret-store source for the key file (Eric 2026-11-10, decision 1: a later issue if asked).

## 11. Open questions for Eric

Each is raised by the review decisions and settled by none of the sources.

**Open question 1: how a retired key leaves the file.**
Found: review decision 5 ends message-row rollback "when the key is removed from the file", and approved section 2 says removing a retired key that no message carries is always safe. Review decision 12 lists the commands (`keygen`, `activate`, `resign`, `rotate`, `status`) and forbids editing the file by hand. None of the five removes a key.
Options: A. A sixth command, `integrity remove KEY`: it refuses a key that is not retired; it reads the database and refuses while messages still carry the key unless `-drop-messages` is given (for a key believed leaked); it writes the file like the other commands. B. `resign` drops every retired key that no message carries. It needs no new command, but it cannot remove a leaked key whose messages remain. C. Allow a hand edit for this one case.
Recommendation: A.

**Open question 2: `rotate` and a running server.**
Found: review decision 5 says `rotate` does `keygen` plus `resign` for a single server. A server reads the key file once, at start. If `rotate` runs while the server runs, the server does not know the new key: every row `resign` re-seals becomes an `unknown key` row for it, and it goes on sealing under a key that is now retired, until it is restarted.
Options: A. `rotate` requires that no server is running and checks it by taking the `maintenance` lock, which a running server holds; when it cannot, it exits 1 (`a server is running against this database: stop it, or use the cluster procedure`). After a server crash on SQLite the lease can hold `rotate` off for up to twice the maintenance interval. B. Document "stop the server first" without a check. C. Have a running server re-read the key file (a new mechanism; it contradicts "read once at start").
Recommendation: A.

**Open question 3: re-creating a deleted channel's name (security review Finding 1d).**
Found: random channel ids stop saved rows from landing on a new channel, and name-bound tokens stop identity takeover; neither stops this: a writer deletes a restricted channel's row, an agent the attacker controls creates a channel of the same name with its own ACL, and other agents that send to the name deliver into it. The review notes that decision 1's option does not close it. It needs a registered agent that may create channels.
Options: A. Accept and list it; the operator guide recommends restricting `channel_creation` on a server with a key file. B. With a key file, only administrators create channels (a behavior change for agents). C. Keep a covered record of deleted channel names that blocks re-creation; a writer can delete those rows too, so it does not close it.
Recommendation: A.

**Open question 4: an ACL list that names one identity twice.**
Found: `channel_acl` gets `PRIMARY KEY (channel_id, identity)` (review decision 10). Today nothing refuses a list with two entries for one identity: `store.ValidateEntry` checks each entry alone, `ValidateDefaultACL` checks duplicate permissions only (`internal/server/config/acl.go:42-60`), and the access check has a test for duplicate rows (`internal/core/access/decide_test.go:438`). With the new key the second insert collides.
Options: A. Refuse it: `SetACL` and `CreateChannel` answer `ErrInvalid` (`validation`: `ACL names identity X twice`) and `default_acl` with a repeated identity is a start-up error. B. Merge the entries by union before the insert.
Recommendation: A: one entry per identity is what the key now says, and a silent merge would hide a client mistake.

**Open question 5: a database backup older than the last rotation.**
Found: with retirement in the key file (review decision 2), a backup taken before a rotation holds its security rows under a key the current file lists as retired. Restored against the current file, none verifies and the server exits 1. That is the rule working: restoring an old database is a rollback of every security row. The only way to read such a backup is the key file as it was when the backup was taken.
Options: A. Document it: the key file is backed up with the database, as a pair, at every rotation; a restore uses the pair and is followed by a rotation. B. Add a command that un-retires a key in the file for a restore (it weakens review decision 2: retirement would be reversible by whoever holds the file, which is the operator anyway). C. Neither: an older backup is unreadable by design.
Recommendation: A. It needs no mechanism, and the file's holder is already trusted.
