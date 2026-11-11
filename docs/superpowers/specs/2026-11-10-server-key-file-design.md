# Server key file: row MACs and sealed signing keys (design spec)

## 1. Status

- Draft of 2026-11-10, written by an agent from `main` at `9a6588c` plus the uncommitted "Server key file addendum (2026-11-10)" of `docs/adr/0012-signing-key-rotation-and-key-providers.md`.
- **The design is Eric's and is frozen.** Eric approved four design sections on 2026-11-10 (`.local/design/2026-11-10-server-key-file-approved-sections.md`) and decisions 1 to 11 of the ADR 0012 server key file addendum. This spec transcribes them to an implementable level. It makes no design decision: where the inputs give only a name it adds a plan ruling, and where they are silent or disagree it adds an open question.
- Labels used below:
  - **(Eric 2026-11-10, decision N)**: decision N of the ADR 0012 "Server key file addendum (2026-11-10)".
  - **(Eric 2026-11-10, section N)**: approved section N of the 2026-11-10 design (1 threat model and configurations, 2 key file and key lifecycle, 3 covered tables and the row check, 4 components, errors and testing).
  - **(plan ruling)**: a choice of this spec where the inputs give only a name or no value. Eric may overrule each one.
  - **(Open question N)**: the inputs do not settle the point, or two inputs disagree. Section 10 holds the finding, the options and a recommendation. Where the body needs a value to be readable it states the recommended one with this mark.
- Section 10 holds 15 open questions. Nothing in the body resolves one silently.
- The addendum supersedes decisions 1, 3 and 6 of the ADR 0012 "Key set trust addendum (2026-11-09)" where they differ: there is no Kubernetes secret mode, no mounted directory of key files and no Kubernetes API provider (decision 1), and the three configurations of section 4.1 replace the three signing-key modes.
- Pre-release rule (CLAUDE.md, Eric 2026-10-25): the schema changes in place in `0001_initial.sql` on both engines, with no migration, converter or compatibility path. Local and test databases are recreated.

## 2. Problem and scope

### The attacker

Threat 2 and SD1 of `docs/security/threat-model-server.md`: someone with database access but not the server host (Eric 2026-11-10, section 1). Examples: a leaked backup, a reporting or other-tenant role on a shared Postgres, a compromised database administrator or database role, a SQL injection in another application on the same database.

Today such a writer takes full control. `Keyring.LoadKeys` trusts the public key of every `signing_keys` row (`internal/core/signingkeys/keyring.go:39-65`), and the same writer can set `identities.is_admin`, add an `identity_keys` row for any agent, bind an email in `human_bindings`, edit `access_refs`, grant itself a `channel_acl` row or insert a message with `sender_kind = 'human'`, which every agent treats as an operator instruction. A reader takes the plaintext PEM of the store provider's signing key and mints any bearer.

Not in scope (Eric 2026-11-10, section 1): nation-state actors, compromise of the server host or the server process (P04), and denial of service by deleting rows.

### Goal

One optional server key file, outside the database, that puts a MAC on every protected row and seals the store provider's private signing keys (Eric 2026-11-10, decision 1). With it:

- a database reader reads content, bindings and emails but cannot mint a bearer;
- a database writer cannot add or alter identities, login keys, bindings, the administrator and user lists, ACLs, signing keys or messages; deleting rows is denial of service only.

### Vocabulary

- **Server key file**: the JSON file named by `server_key_file`.
- **File key**: one 32-byte key in the file, named by its **key id**.
- **Current key**: the file key that `current` names; it seals every new row.
- **Covered table**: a table whose rows carry `mac` and `mac_key`. **Security row**: a row of any covered table except `messages`.
- **Sealed database**: a database whose rows carry MACs. **Unsigned row**: a row whose `mac_key` is the empty string.
- **Epoch row**: a row of `integrity_epochs`, `(key id, max seq)`, that retires a key.
- **Configuration 1, "Local"**, is a server without a key file. It is not local mode. Local mode (a local profile running the core in process over a SQLite file: `agentmesh mcp`, `agentmesh tui`, the client commands) never has a key file and stays outside the threat model.

### Out of scope

- A cloud secret-store source for the key file: file only (Eric 2026-11-10, decision 1); a later issue if asked.
- Column encryption of content: a reader still reads messages, memories, bindings and emails (Eric 2026-11-10, section 1).
- Turning the key file off again (Eric 2026-11-10, decision 7).
- URL references in key rows: `signing_keys` keeps `provider` and `provider_ref`, `identity_keys` keeps the public key inline (Eric 2026-11-10, decision 10).
- The Slack email-to-human trust, threat 4 (Eric 2026-11-10, decision 11).
- The tables and columns section 4.5 lists as not covered.
- A command that deletes failing rows: the log names each one and `docs/ops/server-key.md` gives the SQL (plan ruling).
- Data migration (pre-release rule).

## 3. What exists today

Checked against the tree at `9a6588c`.

- **Schema.** `internal/store/sqlite/schema/0001_initial.sql` and `internal/store/postgres/schema/0001_initial.sql` create the same 30 tables (SQLite adds the FTS5 table `messages_fts`); `schema_meta` is created by the Store's bootstrap, outside `0001`. No table has a MAC column. The step ends by seeding the reserved `slack-bridge` identity with plain SQL (`sqlite/schema/0001_initial.sql:282-284`).
- **Store contract.** `store.Store` is `Tx`, `Append`, `Read`, `SchemaVersion`, `Close`, `Locks` and `Space` (`internal/store/store.go:14-40`). `sqlstore.Options` holds `Migrations`, `TxAttempts`, `Now` and `Logger` (`internal/store/sqlstore/dialect.go:65-73`); `sqlite.Options` and `postgres.Options` embed it as `Store`. Every SQL statement of the product is under `internal/store`: the repositories in `internal/store/sqlstore`, plus a few statements in the engine packages (the FTS condition `messages_fts MATCH` in `sqlite/sqlite.go:265`, the `size_bytes` sum over `sqlstore.MeasuredTables` in `postgres/space.go:21`, the locks and the schema probes). The only other non-test file with SQL is the test helper `internal/storetest/storetest.go`. Covered table names also appear as bare string literals, not only after FROM or JOIN: `MeasuredTables` (`sqlstore/eviction.go:21-25`), `resetDataTables` (`sqlstore/meta.go:18-21`) and the `sumBytes("channel_acl", ...)` call of `ChannelBytes`.
- **Locks.** `Store.TryLock(name, owner, now, until)` works for any name: SQLite inserts the `leases` row on demand and the lease lapses at `until` (`internal/store/sqlstore/lock.go:33-41`); Postgres holds a session advisory lock on a pinned connection.
- **Appends.** `Store.Append` serializes appends: SQLite by its immediate transaction, Postgres by `LOCK TABLE seq_counter IN EXCLUSIVE MODE` (`internal/store/postgres/postgres.go:229-232`). `Tx.MaxSeq` reads `seq_counter`.
- **Signing keys.** `signing_keys.private_key_pem` is plaintext PKCS#8 PEM for the store provider and NULL otherwise (`sqlite/schema/0001_initial.sql:194-208`). `sqlstore.ListSigningKeys` returns every row; `signingkeys.validateRow` parses the PEM (`internal/core/signingkeys/service.go:111-136`).
- **Start-up.** `cmd.run` reads the configuration, opens the store (a failure is exit 1), binds, then calls `signingkeys.Service.EnsureActive` (`internal/server/cmd/cmd.go:74-170`). Every host command opens the store through `openFromConfig` (`internal/server/cmd/admin.go:108`); a configuration error is exit 2, any other error exit 1.
- **Health.** `health.Service.Health` builds the tiered document (`internal/core/health/health.go:44-151`); `bus.Health` has no integrity member (`internal/bus/health.go:66-78`); the wire schema is `Health` in `api/openapi.yaml`.
- **Files that must be owner-only.** `credential.LoadFile` follows a symlink, requires a regular file with Unix mode 0600 or narrower and calls `fileacl.CheckOwnerOnly` on Windows (`internal/credential/store.go:90-116`). `internal/fileacl` is a package of this module, not the standard library.
- **Import rule helpers.** `scripts/m7-exit-checks.sh` has `check_allowlist RULE PATTERN ALLOWED...` (every non-standard dependency must be in the list, lines 119-145) and `check_deps`; `slackapi-allowlist` is the existing "standard library only" rule (line 186). The highest mutation block of `scripts/check-gates-selftest.sh` is 40 (line 1589).
- **Go.** `go.mod` pins go 1.27, so `crypto/hkdf` is in the standard library.

## 4. Design

### 4.1 Configurations

Three configurations, one mechanism (Eric 2026-11-10, decision 2 and section 1). Scenarios: 1 local testing, 2 a lab with local and remote agents, 3 production on-prem, 4 production in a cloud.

| Configuration | Scenarios | A database reader | A database writer | Accepted risk |
| --- | --- | --- | --- | --- |
| 1. Local: no key file (the default) | 1, 2 | mints any bearer | takes full control | Database file access owns the server; in scenario 2 the file is on the server host, the same boundary. |
| 2. Server: `server_key_file` | 3, 4 | reads content, bindings, emails; cannot mint (signing keys sealed) | cannot add or alter identities, login keys, bindings, administrator or user lists, ACLs, signing keys or messages; deletion is denial of service only | Host compromise; content readable; the residual risks of section 4.14. |
| 3. Server plus key service: key file plus `signing_key_uri` | 4, optional | as 2 | as 2 | As 2; the token key is also non-exportable. |

- The key file is never required (Eric 2026-11-10, decision 3). A server whose listener is not local (`ClassifyListen`, `internal/server/cmd/listen.go:25`) and that has no key file logs one start-up warning: `server_key_file is not set and the listener is not loopback: anyone who can write the database controls this server (docs/ops/server-key.md)` (wording: plan ruling). The health document's administrator tier reports `integrity.mode: off` (section 4.12).
- In configuration 3 the key service holds the token key, so there is no private key to seal; the key file still MACs every covered row, `signing_keys` included (Eric 2026-11-10, section 2).
- The key-service backends stay as they are (Eric 2026-11-10, decision 2).

### 4.2 The server key file

Setting `server_key_file` (`AGENTMESH_SERVER_SERVER_KEY_FILE`, `-set server_key_file=PATH`), empty by default (Eric 2026-11-10, section 2). There is no environment-variable source for the key itself (ADR 0012 key set trust addendum, decision 5, unchanged).

Format (Eric 2026-11-10, decision 6):

```json
{"version":1,"current":"k2","keys":{"k1":"<base64 of 32 bytes>","k2":"<base64 of 32 bytes>"}}
```

The file is read once, at start; a changed file takes effect at the next start (Eric 2026-11-10, section 2). `version` selects every algorithm of sections 4.3, 4.6 and 4.8; nothing in the database selects one (Eric 2026-11-10, decision 9).

The start, and every host command that needs the file, refuses it with exit 2 and a message naming the setting and the reason. Refusals named by Eric (2026-11-10, section 2): a mode that is not owner-only, an unknown `version`, a missing `current`, a duplicate key id, a key that is not 32 bytes. The complete list (the additions are plan rulings, following "reject unrecognized inputs by default"):

1. The path cannot be opened, or after following symbolic links is not a regular file.
2. The file is not owner-only: on Unix any of the mode bits `0o077` is set on the opened file; on Windows `fileacl.CheckOwnerOnly` refuses it. Symbolic links are followed, so a mounted secret works (Eric 2026-11-10, section 2).
3. The file is larger than 65536 bytes (plan ruling).
4. The content is not one JSON object, has trailing data, or has a member other than `version`, `current` and `keys` (plan ruling).
5. `version` is absent or not the number 1.
6. `keys` is absent, empty or not an object of strings.
7. A key id appears twice in `keys`. The decoder reads the object token by token, because `encoding/json` keeps the last of two equal member names silently.
8. A key id is not 1 to 32 characters of `a` to `z`, `0` to `9`, `-` and `_` (plan ruling). The empty key id is reserved: it is what an unsigned row carries.
9. A key value is not standard base64 with padding (RFC 4648 section 4), or does not decode to exactly 32 bytes.
10. Two key ids hold the same 32 bytes (plan ruling).
11. `current` is absent, empty or names no member of `keys`.

No message ever contains key material.

### 4.3 Derived keys

The raw file key is never used directly (Eric 2026-11-10, section 2). Each file key yields two subkeys with HKDF-SHA256 (RFC 5869; `crypto/hkdf.Key`):

| Subkey | Use | IKM | Salt | Info (ASCII) | Length |
| --- | --- | --- | --- | --- | --- |
| `mac` | HMAC-SHA256 over rows | the 32-byte file key | none (HKDF's default of 32 zero bytes) | `agentmesh/server-key/v1/mac` | 32 bytes |
| `seal` | AES-256-GCM over `signing_keys.private_key_pem` | the 32-byte file key | none | `agentmesh/server-key/v1/seal` | 32 bytes |

The info strings and the absent salt are plan rulings. The key id is not part of the derivation: it is bound in the MAC input (section 4.6) and in the AAD (section 4.8).

### 4.4 Schema

Both `0001_initial.sql` files change in place (Eric 2026-11-10, section 4).

- The eleven existing covered tables (`identities`, `identity_keys`, `human_bindings`, `access_refs`, `channels`, `channel_acl`, `signing_keys`, `enrollment_tokens`, `slack_users`, `bridges`, `messages`) each gain two columns (Eric 2026-11-10, decision 9):
  - `mac`: `BLOB NOT NULL DEFAULT x''` on SQLite, `BYTEA NOT NULL DEFAULT ''::bytea` on Postgres; the 32 bytes of the HMAC, or empty;
  - `mac_key`: `TEXT NOT NULL DEFAULT ''`; the key id, or empty;
  - `CHECK ((mac_key = '') = (length(mac) = 0))` (`octet_length` on Postgres).
  The column types and the CHECK are plan rulings.
- A new table (Eric 2026-11-10, decisions 5 and 8). It is created with the two columns, so twelve tables carry them in all; "the eleven tables" of section 4 counts the existing ones.

  ```sql
  CREATE TABLE integrity_epochs (
    key_id TEXT PRIMARY KEY,
    max_seq INTEGER NOT NULL CHECK (max_seq >= 0),
    created_at INTEGER NOT NULL,
    mac BLOB NOT NULL,
    mac_key TEXT NOT NULL CHECK (mac_key <> '')
  );
  ```

  (`BIGINT` and `BYTEA` on Postgres; `created_at` is a plan ruling, shown by `integrity status` and not covered.) `key_id` is a file key id, or the empty string for the unsigned epoch.
- `CREATE INDEX messages_mac_key ON messages (mac_key);` (Eric 2026-11-10, section 3). It serves the per-key counts of `integrity status`.
- `signing_keys.private_key_pem` keeps its name and its CHECK; in a sealed database it holds the sealed form of section 4.8, not PEM.
- The generated `size_bytes` columns do not change (plan ruling): the budget estimate ignores the two columns.
- `Meta.ResetData` and `Meta.ResetRegistry` never touch `integrity_epochs`.

The seeded `slack-bridge` row is inserted by the schema step without a MAC. When the Store is opened with a key file and this open creates the schema, it seals that row from constants (`name` `slack-bridge`, `is_admin` false, `kind` `agent`, `scope` NULL) and inserts the unsigned epoch `('', 0)`, in the same transaction as the schema step (plan ruling; the epoch row is Open question 5). The seal is computed from the constants, not read back from the row.

### 4.5 Covered tables and columns

Eric 2026-11-10, decision 8 and section 3. The column order below is the MAC field order (plan ruling). Every name was checked against both schema files; the two engines use the same names and differ only in types (`INTEGER`/`BIGINT`, `INTEGER` 0 or 1/`BOOLEAN`, `BLOB`/`BYTEA`), which the encoding of section 4.6 removes.

| Table | Primary key | Covered columns, in MAC order | Not covered |
| --- | --- | --- | --- |
| `identities` | `name` | `name`, `is_admin`, `kind`, `scope` | `tags_acked_seq`, `created_at` |
| `identity_keys` | `identity`, `kid` | `identity`, `kid`, `algorithm`, `public_key` | `created_at` |
| `human_bindings` | `identity` | `identity`, `issuer`, `claim_type`, `value`, `provider_subject` | `created_at` |
| `access_refs` | `ref_list`, `ref_kind`, `issuer`, `value` | `ref_list`, `ref_kind`, `issuer`, `value`, `created_at` ("all") | none |
| `channels` | `id` | `id`, `name`, `kind`, `scope` | `creator`, `created_seq`, `evicted_before_seq`, `created_at`, `last_read_at`, `size_bytes` |
| `channel_acl` | `id` | `channel_id`, `identity`, `can_read`, `can_write`, `can_admin` | `id` (Open question 4), `size_bytes` |
| `signing_keys` | `kid` | `kid`, `state`, `provider`, `provider_ref`, `algorithm`, `public_key`, `private_key_pem` as stored (sealed) | `created_at`, `retired_at`, `remove_after` ("all but timestamps"; Open question 14) |
| `enrollment_tokens` | `id` | `id`, `token_hash`, `identity`, `expires_at` | `uses_left`, `created_at`, `size_bytes` |
| `slack_users` | `identity` | `identity`, `team_id`, `user_id` | `created_at` |
| `bridges` | `id` | `id`, `channel_id`, `scope`, `slack_channel_id` | `channel_name`, `slack_name`, `state`, `cursor_ts`, `created_at`, `archived_at` |
| `messages` | `seq` | `seq`, `channel_id`, `sender`, `sender_kind`, `session_id`, `created_at`, `type`, `subject`, SHA-256 of `content`, SHA-256 of `metadata`, `reply_to`, `memory_id`, `revision`, `tombstone`, then the tags (Open questions 1 and 2) | `tombstone_at`, `size_bytes`, the Postgres `fts_subject` and `fts_content` |
| `integrity_epochs` | `key_id` | `key_id`, `max_seq` | `created_at` |

Every other table is not covered. Eric named these as accepted (2026-11-10, section 3): "sessions and cursors, subscriptions, statuses, receipts, assertion_jti, scopes' state, notices, embeddings".

| Table | Class | Source |
| --- | --- | --- |
| `sessions`, `session_cursors` | not covered | section 3, "sessions and cursors" |
| `subscriptions` | not covered | section 3 |
| `agent_statuses` | not covered | section 3, "statuses" |
| `receipts` | not covered | section 3 |
| `assertion_jti` | not covered | section 3 |
| `scopes` | not covered | section 3, "scopes' state" (the whole row is state and timestamps; the scope name an identity or channel holds is covered in that row) |
| `notices` | not covered | section 3 |
| `embeddings` | not covered | section 3 |
| `message_tags` | covered through the `messages` MAC, no columns of its own | Open question 2 |
| `tag_subscriptions`, `tag_subscription_tags`, `embed_failures`, `memory_access`, `retired_identities`, `bridge_messages`, `bridge_dropped`, `seq_counter`, `leases`, `schema_meta`, `messages_fts` (SQLite) | not covered | in neither approved list: Open question 3 |

### 4.6 MAC input

HMAC-SHA256 under the key's `mac` subkey, all 32 bytes stored (Eric 2026-11-10, section 3). The input is the table name, the key id and the covered columns, each length-prefixed (Eric 2026-11-10, section 3 and decision 9). The exact bytes are a plan ruling:

```text
input = lp(table) || lp(key_id) || u16(n) || field_1 || ... || field_n
lp(b) = u32(len(b)) || b                      u16, u32: big-endian
field = 0x00                                   NULL
      | 0x01 || lp(UTF-8 bytes)                text
      | 0x02 || lp(bytes)                      bytes
      | 0x03 || i64                            integer: 8 bytes, two's complement, big-endian
      | 0x04 || (0x00 | 0x01)                  boolean
      | 0x05 || u32(k) || lp(t_1) .. lp(t_k)   text list (the message tags only)
```

Rules:

- `table` is the table's name as in the schema, ASCII. `n` is the number of fields. The fields are the covered columns in the order of section 4.5.
- The encoding is over Go values after the scan, so the engines agree: `is_admin`, `can_read`, `can_write`, `can_admin` and `tombstone` are booleans; every integer column is an `int64`; `public_key` is bytes; everything else is text.
- NULL is explicit. `identities.scope` and `channels.scope` are NULL in the database and the empty string in the Go row (`identityCols` coalesces): the empty string is encoded as NULL, which loses nothing because no scope has an empty name. `messages.reply_to`, `memory_id` and `revision` are NULL or an integer. `signing_keys.private_key_pem` is NULL or the stored text. `messages.metadata` is NULL or a value.
- The `content` field is the bytes type holding the 32 bytes of SHA-256 over the stored `content` text. The `metadata` field is NULL when the column is NULL, otherwise the 32 bytes of SHA-256 over the stored `metadata` text exactly as the column holds it (never a re-marshaled map).
- The tags field (Open question 2) is the message's tags in ascending byte order.
- A value outside these types is a programming error and fails the seal.

Known-answer vector (computed for this spec; the unit tests hold it). File key: the 32 bytes `00` to `1f` (base64 `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=`), key id `k1`:

- `mac` subkey: `c012cf6ac8e30127188ad9d09a246a762b59fc848997e4b1f161def63f76d447`
- `seal` subkey: `b555bffa5a7c08566da543db3a44b40dd2d6ec8af3fec662d3d246b7e098a839`
- `identities` row `name` `alice`, `is_admin` false, `kind` `agent`, `scope` NULL: input (45 bytes) `0000000a6964656e746974696573000000026b3100040100000005616c696365040001000000056167656e7400`
- MAC: `acf913ac720d20cd6a0d6db2793a1781dd0dc10453a73476d97430d7f273f485`

### 4.7 Which key is valid for which row

Eric 2026-11-10, decision 5 and section 2: `current` only chooses the key for new rows; a file key without an epoch row is valid for every row; a key with an epoch row is retired and is valid only for messages with seq at most S, never for a security row; a key id that is missing from the file fails. Bounded by seq, not time, because delivery follows seq and a forger can backdate a timestamp.

A row with key id K, checked on a server whose key file has keys F and current key C:

| Case | K | Result | Logged reason |
| --- | --- | --- | --- |
| Current | K = C, MAC verifies | valid | |
| No epoch | K in F, K is not C, MAC verifies, no counted epoch row for K | valid for every row (mixed replicas during a roll) | |
| Retired | K in F, MAC verifies, counted epoch row (K, S) | valid only for a `messages` row with seq at most S | `retired key` |
| Unknown | K not in F | fails | `unknown key` |
| Bad MAC | K in F, MAC does not verify | fails | `bad MAC` |
| Unsigned | K is empty | a `messages` row with an empty `mac` and seq at most S is valid when a counted epoch row `('', S)` exists; every other unsigned row fails | `unsigned` (Open question 5) |

Which epoch rows count (Open question 15; decision 5 says "signed by the current key" and is silent on a second rotation):

1. An epoch row is authentic when its `mac_key` names a file key and its MAC verifies under that key.
2. It counts when it is authentic and either its `mac_key` is C, or its `mac_key` is a file key that no C-signed authentic epoch row retires and is not the row's own `key_id`.
3. Any other epoch row is ignored and handled as a failing row (section 4.11).

Rule 2's second half keeps the keys retired by the previous current key retired between "activate the new key" and `resign`; without it every earlier retirement would lapse in that window. It has a limit, stated in Open question 15: in that window no epoch row is signed by C yet, so a retired key that has leaked can still sign an epoch row for another key id. A counted epoch row whose `key_id` is C means this server's file is out of date (section 4.10, Open question 9).

The Store reads `integrity_epochs` at most once per transaction, the first time that transaction meets a row whose `mac_key` is not C, and keeps the result for the transaction (plan ruling). A row under the current key needs no lookup, so the steady state costs nothing; a retirement written by `resign` is seen by every replica's next transaction with no signal between replicas.

### 4.8 Sealing the store provider's private key

AES-256-GCM under the sealing key's `seal` subkey (Eric 2026-11-10, sections 2 and 4).

- **Nonce**: 12 bytes from `crypto/rand`, new for every seal (plan ruling). A key seals one private key per rotation and per `resign`, so random nonces are far inside the bound.
- **AAD**: `lp("signing_keys") || lp(kid) || lp(key_id)`, the table, the row's `kid` and the sealing key id (Eric 2026-11-10, section 4; the `lp` framing is a plan ruling).
- **Plaintext**: the PKCS#8 PEM bytes the store provider produced.
- **Stored form**: standard base64 of `nonce || ciphertext || tag`, in `private_key_pem` (plan ruling).
- **Which key**: the row's `mac_key`. One write seals and MACs under the same key, the current one, so the row needs no second key id.
- **Sealed or plaintext is told by `mac_key`, never by the content** (plan ruling; the downgrade defense of decision 9 applied to the secret). A row with an empty `mac_key` holds plaintext PEM and exists only in configuration 1. With a key file an unsigned `signing_keys` row fails as a security row, so the server never parses a plaintext PEM a writer planted.
- A stored value that does not open (bad base64, shorter than 28 bytes, the tag fails) drops the row with the reason `sealed key does not open`.
- The MAC covers the stored, sealed text, so the MAC check needs no decryption.

The Store seals in `PutSigningKey` and opens in `ListSigningKeys` (Open question 12), so `store.SigningKey.PrivateKeyPEM` stays plaintext at the Store contract and `internal/core/signingkeys` keeps parsing it as today.

### 4.9 The port and the leaf package

`store.Integrity` (Eric 2026-11-10, decision 8 and section 3: `Seal`, `Verify`, `SealSecret`, `OpenSecret`), passed at open as `sqlstore.Options.Integrity`; nil is configuration 1: columns left empty, no check (Eric 2026-11-10, section 3). Signatures (plan ruling; they use only built-in types so the leaf implements the port without importing `internal/store`):

```go
// package store
type Integrity interface {
	// Current is the key id that Seal and SealSecret use.
	Current() string
	// Seal returns the MAC of the row under the current key. Each field is
	// nil, string, []byte, int64, bool or []string.
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

`Current` is a fifth method beyond the four Eric named; the rules of section 4.7 need the current key id (plan ruling). The MAC comparison is constant-time (`hmac.Equal`).

`internal/integrity` is the new leaf (Eric 2026-11-10, section 4): standard library only (`crypto/hkdf`, `crypto/hmac`, `crypto/sha256`, `crypto/aes`, `crypto/cipher`, `crypto/rand`, `encoding/json`, `encoding/base64`, `os`). It holds:

- `Load(path string, ownerOnly func(path string) error) (*Keys, error)`: opens the path (following symbolic links), requires a regular file, checks the Unix mode bits on the opened file, calls `ownerOnly` (the caller passes `fileacl.CheckOwnerOnly`, because `internal/fileacl` is not the standard library), reads at most 65536 bytes and parses. `Parse([]byte) (*Keys, error)` holds refusals 4 to 11 of section 4.2.
- `Keys`: the key ids, the current id and the two subkeys per key; it implements `store.Integrity`. It never prints or returns key material.
- `Generate`, `Activate` and `Marshal`, which produce the file's bytes for the `keygen` and `activate` commands (section 4.13). The commands themselves write the file, in `internal/server/cmd`, because the owner-only ACL on Windows needs `internal/fileacl`.

The leaf knows nothing of epochs, tables or the database: the Store owns the rules of section 4.7 and the failure counter.

### 4.10 Writes

Every write seals (Eric 2026-11-10, section 3). In `internal/store/sqlstore`, with a non-nil port (plan rulings, each checked against the statement it changes):

1. **Insert.** The INSERT carries `mac` and `mac_key` computed from the values being inserted: `CreateIdentity`, `CreateHuman` (the identity row and the binding row), `CreateScopedIdentity`, `PutEnrollmentToken`, `PutSigningKey`, `PutSlackUser`, `insertACL` (called by `CreateChannel` and `SetACL`), `AppendMessage` and the epoch insert. Where the database assigns a covered key (`channels.id` in `CreateChannel`, `bridges.id` in `CreateBridge`, both `RETURNING id`), the row is inserted and its MAC is written by an UPDATE in the same transaction. `channel_acl.id` is not covered, so `insertACL` seals in the INSERT.
2. **Upsert.** `PutPublicKey` (`ON CONFLICT (identity, kid) DO UPDATE`) sets `mac` and `mac_key` in both branches, so it replaces a failing row. `AddReference` (`ON CONFLICT DO NOTHING`) first reads the reference through the verified read: when a valid row exists it answers false as today, otherwise it upserts, replacing a failing row, and answers true.
3. **Update of a covered column.** The statement becomes read, verify, change, re-seal under the current key, in one transaction. A row that fails verification answers as an absent row (`ErrNotFound`, or the method's "no row" answer) and is never re-sealed, so an update cannot launder a forged row. The sites: `SetAdmin`, `ClearInvalidScopes` (it becomes a select of the candidate names followed by this sequence per row), `MarkHuman`, `SetHumanSubject`, `RenameChannel`, `SetBridgeSlackChannel`, `RetireSigningKey`, `SetMemory` and `TombstoneMessage`. Re-sealing a message on `SetMemory` or `TombstoneMessage` is an ordinary write; "rotation never rewrites messages" (decision 5) is about `resign`.
4. **Update of uncovered columns only** neither verifies nor re-seals: `AdvanceTagAckedMark`, `TouchChannelRead`, `SetEvictedBefore`, the `uses_left` decrement of `ConsumeEnrollmentToken`, `SetBridgeLive`, `SetBridgeArchived`, `AdvanceBridgeCursor`.
5. **Delete** needs no check, because deleting is within the writer's accepted power: `RetireIdentity` (the identity and its ACL rows), `DeletePublicKeys`, `RemoveReference`, `DeleteChannel`, `DeleteChannelIfEmpty`, `DeleteIdleTaskChannel`, the delete half of `SetACL`, `DeleteSigningKey`, `DeleteSigningKeysBefore`, `DeleteEnrollmentToken`, `DeleteEnrollmentTokensFor`, `DeleteEnrollmentTokens`, `DeleteSlackUser`, `DeleteBridge`, `DeleteMessages`, `PurgeMemory`, `Meta.ResetData` and `Meta.ResetRegistry`, and the rows that go by `ON DELETE CASCADE`.
6. **A failing row that occupies a key.** A dropped row is still in the table, so a later insert can collide with it (an identity or channel name, the one active `signing_keys` slot, a message seq). The insert answers `ErrConflict` wherever the statement already maps a unique violation. `AppendMessage` does not map one today: a primary-key violation on `messages.seq` becomes `store.ErrRetryable` (503 `unavailable`), with an error log naming the seq. Never a 500 (section 4.11).
7. **A server whose current key is retired.** When a transaction's epoch load finds a counted epoch row for the server's own current key, the Store records it and from then on refuses every write of a covered table with `store.ErrRetryable` (503 `unavailable`; "this server's key file is out of date: its current key K was retired"), logged at error. Reads continue. (Open question 9.)

With a nil port every statement is as today, and the two columns keep their defaults.

### 4.11 Reads

Every read verifies; a failing row is dropped as absent, logged and counted (Eric 2026-11-10, decision 8 and section 3). It is not an access rule: the Store still serves facts and applies no rule (ADR 0004, "Access facts, not rules"); a forged row is not a fact. `TestAccessRuleSites` is unaffected except where a rewritten statement changes one of its counted SQL filters, which is an explicit allowlist edit there.

**The rule** (plan ruling). In `internal/store/sqlstore`, a covered column's value leaves the package, or decides a branch inside it, only from a row that the table's verify helper returned. Each covered table has one helper that selects the covered columns, `mac` and `mac_key`, applies section 4.7 and returns the surviving rows. Every other mention of a covered table is listed in the literal allowlist of `TestIntegritySites` with its function, its count and a reason; a new mention, a changed count or a stale entry fails the test (the model is `TestAccessRuleSites`, `internal/core/access/sites_test.go`). The test scans the non-test files of `internal/store/sqlstore`, `internal/store/sqlite` and `internal/store/postgres`. A mention is a string literal that is exactly a covered table's name, or that holds one as a whole word together with an SQL keyword (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `FROM`, `JOIN`, `EXISTS`), so it also catches the names in `MeasuredTables`, `resetDataTables` and `sumBytes`.

**Limited queries.** A query with a LIMIT continues past dropped rows until it has `limit` surviving rows or the result is exhausted (plan ruling). Without this, forged rows ahead of a session's cursor would return an empty page forever and block delivery (`delivery.Receive` reads `MessagesAfter` with a count, `internal/core/delivery/receive.go:423`), and a forged highest revision would make `LiveMemory` (`LIMIT 1`) answer "not found" instead of the real revision.

**Every read path that returns a covered row**, by table. "Verified" means it goes through the table's helper; "changed" names a statement that selects part of a row or counts today and must go through the helper instead.

- `identities`: verified in `Identity`, `ListIdentities`, `ScopeMembers`. Changed: `identityRegistered` (a count, used by `validateACL` and `CreateChannel`), the `SELECT kind` of `PutPublicKey` and of `MarkHuman`, the `SELECT is_admin, kind` of `CreateScopedIdentity`, the `SELECT COALESCE(scope, '')` of `RetireIdentity`, the count in `PutSlackUser`. Verification runs on the stored columns before `identityOf` adjusts a scope in memory.
- `identity_keys`: verified in `PublicKeys`. Changed: the count in `MarkHuman`.
- `human_bindings`: verified in `humanBindingWhere` (`HumanBinding`, `HumanBindingByValue`, `HumanBindingBySubject`).
- `access_refs`: verified in `ListReferences`. Changed: the `admins` count in `CreateScopedIdentity`.
- `channels`: verified in `Channel`, `ChannelByName`, `ListChannels`, `ListChannelsByKind`, `ScopeMembers`, `EmptyChannelsBefore`, `IdleTaskChannels`. Changed: `channelExists` (a count, used by `SetACL`).
- `channel_acl`: verified in `ACL` and `ACLRowsFor`.
- `signing_keys`: verified, then opened, in `ListSigningKeys`. `Keyring.LoadKeys` therefore trusts only surviving rows, with no special case (Eric 2026-11-10, section 4).
- `enrollment_tokens`: verified in `EnrollmentTokenByHash` and `ListEnrollmentTokens`. Changed: the count in `ConsumeEnrollmentToken` becomes a verified read by id before the decrement.
- `slack_users`: verified in `SlackUserOf`. Changed: `IdentityOfSlackUser` selects the whole row.
- `bridges`: verified in `bridgeWhere` (`Bridge`, `BridgeByChannel`, `BridgeBySlackChannel`) and `listBridges` (`ListBridges`, `ScopeBridges`).
- `messages`: verified in `scanMessages`, after it has loaded the tags, which serves `Message`, `MessagesAfter`, `MessagesBySeqs`, `MessagesBefore`, `MessagesInRange`, `SearchText`, `TagMatchesAfter`, `LiveMemory`, `MemoryRevisions`, `LiveMemories` and `UnembeddedMemories`.
- `integrity_epochs`: the per-transaction epoch load of section 4.7.

**Allowlisted, unverified mentions** (the reason each is safe goes in the allowlist):

- Statements that only choose what maintenance deletes or sizes; a forged row can cause or prevent a deletion, which is within the writer's accepted power: `MeasuredTables` and the size sum of `postgres/space.go` over it, `resetDataTables`, `emptyChannelCond` (`EmptyChannelsBefore`, `DeleteChannelIfEmpty`), `idleTaskCond` and `channelActivityExpr` (`IdleTaskChannels`, `DeleteIdleTaskChannel`), `ChannelBytes`, `IdleMemories`, `ExpiredMemories`, `sizedMessages` (`ExpiredTombstones`, `OrdinaryMessagesBefore`), `OrphanedBridgeMessages`, `DeleteBridgeMessages`, `ExpiredEnrollmentTokens`, `DeleteRetiredScopes`, `DeleteSigningKeysBefore`.
- Statements whose result is a seq that the caller resolves through a verified read before it uses any content: `Embeddings` (its seqs go to `MessagesBySeqs`, `internal/core/search/search.go:48-73`).
- `EmbedFailures`: its join on `messages` only narrows a count and the embedder's last error text for the embedding report.
- Joins and subqueries on `channels` that feed an uncovered value: the scope subquery of `AppendMessage` (it touches `scopes.last_activity`), the `channels` joins of `UnembeddedMemories`, `ExpiredMemories` and `IdleMemories` (they exclude task lists), `ChannelLastActivity`.
- `liveMemory` (the guard of `PutEmbedding`): it only decides whether an embedding row is written for a seq.
- Inserts, upserts, updates and deletes, each under its class of section 4.10.

**Failure handling** (Eric 2026-11-10, section 3):

- The row is dropped: the caller sees what it would see if the row did not exist.
- An error-level log line names the table, the primary key and the reason (`bad MAC`, `unknown key`, `retired key`, `unsigned`, `sealed key does not open`, `epoch not counted`). It never contains a covered value other than the primary key. Each distinct (table, primary key, reason) is logged once per process, up to 4096 of them; beyond that, one summary line per minute (plan ruling).
- A per-process counter counts every failed check (the same row read twice counts twice). `Store.IntegrityStats()` returns the mode, the current key id and the counter (name provisional).

**Error mapping.** A failed check never becomes a 500 (ADR 0001, No-500 rule) and never a distinct error code: dropped rows look absent (Eric 2026-11-10, section 4, which names `not_found`, 401 and `forbidden`; the table gives the code each existing path answers today for an absent row).

| Failing row | What the caller sees |
| --- | --- |
| The `identities` row of a bearer's subject (any covered column altered, `is_admin` included) | `not_registered` (403), the existing answer for a bearer whose identity is not a row (`access.Resolve`, `internal/core/access/principal.go:27-39`; `internal/server/problem.go:28`) |
| An `identity_keys` row | the token endpoint's refusal for an unknown identity or key (401 `invalid_client`) |
| A `human_bindings` row | the sign-in runs as if the binding did not exist (`signInHumanTx`, `internal/core/identities/human.go`): it finds the identity name or the email already taken by a row and answers `conflict`; nothing is created, bound or changed. The exchange answers through `oauthFromBus`. |
| An `access_refs` row | a missing `users` entry: `forbidden` ("no users entry matches"); a missing `admins` entry: the sign-in succeeds without the administrator flag |
| A `channels` row | `not_found` |
| A `channel_acl` row | no grant: `forbidden`, or `not_found` where ADR 0011 says so |
| A `signing_keys` row | a bearer signed under that `kid` is refused with 401; the row is not published in the JWKS |
| An `enrollment_tokens` row | registration's refusal for an unknown token |
| A `slack_users` row, a `bridges` row | no binding; no bridge |
| A `messages` row | never delivered, counted, listed in history, found by search or returned as a memory or task; a memory whose newest revision fails reads as its newest surviving revision |
| An `integrity_epochs` row | the epoch is ignored |

Every signing key row failing leaves an empty key set: a running issuer keeps the set it has (`Keyring.LoadKeys` already returns an error then), and a start exits 1 (section 4.12).

### 4.12 Start-up, exit codes and health

**Start-up order** in `internal/server/cmd` (Eric 2026-11-10, section 4; the order and wording are plan rulings):

1. The configuration is loaded. When `server_key_file` is set the file is loaded and validated before the store is opened, so a bad file changes nothing. A refusal of section 4.2 is exit 2.
2. The store is opened with `Options.Integrity` (nil without a key file). `sqlstore.Open` answers two new sentinel errors, both exit 2:
   - `store.ErrSealed`: no key file, and `integrity_epochs` has a row. Message: `the database is sealed by a server key file: set server_key_file (AGENTMESH_SERVER_SERVER_KEY_FILE)` (Eric 2026-11-10, section 4 and decision 7). Every opener gets it, the local-mode opener included.
   - `store.ErrNotSealed`: a key file, the schema already existed, no counted unsigned epoch row, and at least one unsigned `identities` row. Message: `server_key_file is set but this database was never sealed: stop every server and run agentmesh server admin integrity resign -adopt-unsigned once. If this database was sealed before, do not adopt: its rows were altered` (Open question 5).
3. A counted epoch row for the file's current key: exit 2, `the current key K of server_key_file was retired by resign: deploy the file whose current key is the new one, or, if K was added with -no-activate and resign ran before it was activated, generate another key` (Open question 9).
4. Warnings, start continues: the non-loopback warning of section 4.1 when there is no key file; with a key file, one line naming every file key that is neither current nor retired: `keys k1 are not retired: when every replica runs with current k2, run agentmesh server admin integrity resign`.
5. `EnsureActive` as today. When no `signing_keys` row survives verification but an unverifiable active row occupies the slot, the insert conflicts and the start exits 1 with `signing key: no signing key row verifies under the server key file (see the log for the failing rows)`. The row is never overwritten.

Exit codes are unchanged in meaning: 2 for a configuration error (a bad key file, a sealed database without the key, an unsealed database with one, a retired current key), 1 for a runtime error.

Every host command (`agentmesh server admin ...`) opens the store the same way, so steps 1 and 2 apply to each: `users add` against a sealed database seals the row it writes, and without the key file it exits 2 and writes nothing. `integrity resign` and `integrity status` open the store with the two sealed-state checks off, because reporting and repairing that state is their job.

**Health** (Eric 2026-11-10, decision 3 and section 4). The administrator tier gains `integrity`:

```json
"integrity": {"mode": "on", "current_key": "k2", "failures": 0}
```

- `mode`: `on` with a key file, `off` without (also on a loopback listener and in local mode).
- `current_key`: the current key id; absent when `mode` is `off`.
- `failures`: this process's counter of failed checks since it started.
- The member is absent below the administrator tier, like `storage`.
- `status` does not change on `mode: off` or on `failures` above zero (Open question 13).
- Wire: a new `HealthIntegrity` schema and the `integrity` property of `Health` in `api/openapi.yaml`, with description and example; `bus.HealthIntegrity` and `bus.Health.Integrity`; `make generate`. The protocol version stays `1.0.0` (Eric 2026-10-27).

### 4.13 Host commands and the key lifecycle

`agentmesh server admin integrity keygen [-file F] [-no-activate] | resign | status` (Eric 2026-11-10, sections 2 and 4), plus `activate` (Open question 10). `resign` and `status` take the host commands' configuration flags (`-config`, `-sqlite`, `-postgres`, `-set`); `keygen` and `activate` open no database. Exit codes: 0 done, 1 runtime error, 2 usage or configuration error.

**`integrity keygen [-file F] [-no-activate]`**

- `-file` names the key file; without it the configured `server_key_file` is used, and with neither the command exits 2 (Open question 11).
- No file at the path: it creates one, mode 0600 (owner-only ACL on Windows), holding one new key that is current. `-no-activate` on a missing file is exit 2, because a file needs a current key.
- An existing file: it validates it by section 4.2, adds one new key from `crypto/rand`, and makes it current unless `-no-activate`.
- The new key id is `k` followed by one more than the highest number among existing ids of that form, starting at `k1` (plan ruling).
- It writes a temporary file in the same directory and renames it over the target; it refuses a target that is a symbolic link, because the rename would replace the link (plan ruling).
- While it works it holds `F.lock`, created exclusively and removed at exit; when the lock file exists it exits 1 naming it and changes nothing (plan ruling).
- It prints one line, for example `added key k2 to /etc/agentmesh/server.key (current: k2)`, and never key material.

**`integrity activate [-file F] KEY`** (Open question 10): sets `current` to an existing key id, with the same file handling as `keygen`.

**`integrity resign [-adopt-unsigned]`** (Eric 2026-11-10, decision 5 and section 2; a host command, the servers may run). It needs `server_key_file`; without it, exit 2.

1. It takes the `Store.Locks` lock `integrity-resign` (Eric 2026-11-10, section 4) with a 60-second term, renewed after every batch (plan ruling). When another holder has it: exit 1, `another resign holds the integrity-resign lock`, nothing written.
2. With `-adopt-unsigned` it refuses (exit 1) when a counted unsigned epoch row exists: the database was adopted, or created sealed, before.
3. For each security table, in the order `identities`, `identity_keys`, `human_bindings`, `access_refs`, `channels`, `channel_acl`, `signing_keys`, `enrollment_tokens`, `slack_users`, `bridges`: it walks the rows in primary-key order, 500 rows per transaction (plan ruling). A row that is valid by section 4.7 and not under the current key is re-sealed under the current key; for a store-provider `signing_keys` row the private key is opened under its old key and sealed again. A row already under the current key is skipped. A failing row is left as it is and counted. An unsigned row is sealed only with `-adopt-unsigned` (then a plaintext private key is sealed for the first time).
4. One final `Store.Append` transaction, so that it is serialized with every append:
   - it sweeps the security rows that still carry another key id (written during the run) and re-seals the valid ones;
   - it reads S, the highest seq (`Tx.MaxSeq`);
   - it re-seals every counted epoch row under the current key, keeping its `max_seq`;
   - for every file key other than the current one that has no counted epoch row, it inserts `(key id, S)`, replacing a row for that key id that does not count;
   - with `-adopt-unsigned` it inserts `('', S)`.
   The epoch is keyed by key id and the first write wins (Eric 2026-11-10, section 4): a later run never raises a retired key's S.
5. It prints, per table, the rows re-sealed, already current and failing, then each retirement (`retired key k1 at seq 1234`), and exits 0. Failing rows do not change the exit code; they are in the output and the log.

`resign` never rewrites a message (Eric 2026-11-10, decision 5).

**`integrity status`** (Eric 2026-11-10, section 2) prints one line per key id found in the file or in any row: whether it is current, retired (with its seq and the time), not retired, or missing from the file, and how many messages and how many security rows carry it; then the unsigned counts. The counts are by `mac_key` (the `messages_mac_key` index), without verifying MACs (plan ruling). Without a key file it prints `integrity: off` and whether the database is sealed, and opens the database without the `ErrSealed` check.

**Rotation in a cluster** (Eric 2026-11-10, section 2: add, roll, activate, roll, then `resign`):

1. `keygen -no-activate` adds `k2`; deliver the file; restart every replica. Every replica now knows both keys and still seals under `k1`.
2. `activate k2`; deliver the file; restart every replica. During this roll some replicas seal under `k1` and some under `k2`; every replica accepts both, because `k1` has no epoch row.
3. When every replica runs with current `k2`: `resign`. Security rows move to `k2`, the private keys are re-sealed, and `(k1, S)` retires `k1`.
4. When `status` shows no message under `k1`, `k1` may be removed from the file. Removing a retired key that no message carries is always safe (Eric 2026-11-10, section 2). A key removed earlier turns its remaining messages into `unknown key` rows.

A single server may do steps 1 and 2 as one `keygen` and one restart.

`resign` retires every file key except the current one, so it must not run between steps 1 and 2: it would retire the key that was just added. A start with that key as current then exits 2 (section 4.12 step 3) and the remedy is another `keygen`. `resign` prints every key it retires.

**Turning it on for an existing database** (Eric 2026-11-10, section 2; the flag is Open question 5): stop every server, create the key file, run `resign -adopt-unsigned`, set `server_key_file`, start. The unsigned epoch `('', S)` lets the messages that existed before the key still deliver and refuses every later unsigned message (Open question 6). A database created with the key file configured is sealed from its first transaction and needs no `resign`.

**Turning it off is unsupported** (Eric 2026-11-10, decision 7): a sealed database needs the key; a start without it is exit 2 naming `server_key_file`.

### 4.14 Residual risks to record in the threat model

Approved as accepted by Eric (2026-11-10, section 1): host compromise; content readable (no column encryption); rollback of security rows, closed by `resign` ("until it runs a revoked row's old copy still verifies"); the uncovered tables of section 3.

Consequences of the approved coverage that the threat model text must state plainly (each follows from sections 4.5 and 4.7; they are listed here, not decided here):

1. A deleted or revoked security row's old copy verifies until a new key is made current and `resign` runs. `resign` without a new key closes nothing.
2. Rotation limits future forgery; it does not find rows that were forged with a leaked key before `resign` re-sealed them.
3. Rewinding `session_cursors` replays genuine old messages, operator instructions included.
4. `bridges.state` and `bridges.cursor_ts` are not covered: a writer can make an archived bridge live or replay Slack history into its channel.
5. `enrollment_tokens.uses_left` is not covered: a spent token becomes usable again for someone who holds it.
6. `receipts.result` is not covered: a retried write can be answered with a planted result.
7. A failing row can block a name, the active signing-key slot or a seq (section 4.10 item 6): denial of service, repaired by deleting the row.
8. `seq_counter` is not covered, and an epoch's S is read from it (Open question 3).
9. The points of Open questions 3, 6, 7, 8, 14 and 15.

### 4.15 State: second run, overlapping runs, leftovers

| Operation | A second run | Two overlapping runs | Starting from a failed run's leftovers |
| --- | --- | --- | --- |
| Start, no key file, unsealed database | As today. | As today. | As today. |
| Start, no key file, sealed database | Exit 2 again; nothing is written. | Both exit 2. | Nothing to leave. |
| Start, key file, empty database | Finds the schema, the sealed seed row and `('', 0)`; writes nothing. | The schema step runs once (`runStep` locks and re-reads the version); the seal is in that transaction, so the other opener finds it done. | A failed step rolls back to version 0 with nothing sealed; the next start reruns it. |
| Start, key file, existing unsealed database | Exit 2 again; nothing is written. | Both exit 2. | Nothing to leave. |
| Start, key file, sealed database | Reads only (then `EnsureActive`, as today). | As today. | As today. |
| `keygen` | Adds another key each time (it is not idempotent by design); `status` shows the ids. | The command creates `F.lock` exclusively and removes it at exit; the second run exits 1 naming the lock file and changes nothing. | A crash leaves `F.lock` and perhaps a `F.tmp-*` file; the target is the old file or the new one, never a partial one (rename). The next run exits 1 naming the lock; the operator deletes both leftovers. |
| `activate` | `k2 is already current`, exit 0, file unchanged. | As `keygen`. | As `keygen`. |
| `resign` | Every row is already under the current key and every other key has its epoch: zero rows re-sealed, no epoch written, exit 0. | The lock serializes them: the second exits 1 and writes nothing. | The batches that committed stay; the database holds rows under both keys, all valid, because epochs are written last and in one transaction. The SQLite lease lapses within 60 seconds and the Postgres lock ends with the session; the next run finishes. A crash after the final transaction left a finished run. |
| `resign -adopt-unsigned` | Exit 1: the unsigned epoch exists. | As `resign`. | The unsigned epoch is written last, so a rerun continues: sealed rows are skipped, the rest are adopted. |
| Key rotation across replicas | `activate` and `resign` are idempotent. A repeated `keygen -no-activate` adds a further unused key, which the next `resign` retires like any other non-current key. `resign` before the added key is activated retires that key (section 4.13). | Replicas in different steps accept each other's rows while every replica has every key and no epoch names a key still in use. | A roll abandoned midway leaves a mixed fleet that keeps working. A replica that seals under a key it alone holds (step 1 skipped) has its rows dropped as `unknown key` elsewhere until the file is delivered. A replica still on the old current key after `resign`: Open question 9. |
| Removing a key from the file | Not applicable. | Replicas with and without the key disagree only about rows under it. | Putting the key back restores those rows. |

### 4.16 `internal/core/signingkeys`

- The store provider's private key reaches the database sealed and returns opened (section 4.8); `Service` and `Keyring` keep working on plaintext PEM.
- `Keyring.LoadKeys` sees only verified rows, which closes the key-row path of SD1 with no special case (Eric 2026-11-10, section 4).
- The comment on `store.SigningKey.PrivateKeyPEM` ("stored in clear") and on `sqlite.Options.RequirePrivate` are corrected: in clear only without a key file. `RequirePrivate` stays.
- Rotation, the cooldown, `-revoke-previous`, removal and the provider-mismatch rule are unchanged. A rotation whose insert collides with an unverifiable active row answers `conflict` (section 4.10 item 6).

## 5. Components

| Package | Change |
| --- | --- |
| `internal/integrity` (new leaf) | Section 4.9: load and validate the key file, the subkeys, `Seal`/`Verify` over the encoding of section 4.6, `SealSecret`/`OpenSecret`, key generation and the file's serialized form. |
| `internal/store` | The `Integrity` port; `ErrSealed`, `ErrNotSealed`; `IntegrityStats`; the epoch and re-seal methods `resign` and `status` need (names provisional: `Tx.ResealRows(table, cursor, limit, adopt)`, `Tx.Epochs`, `Tx.PutEpoch`, `Tx.ResealEpochs`, `Tx.KeyUsage`). |
| `internal/store/sqlstore` | `Options.Integrity`; the per-table seal and verify helpers; drop, log, count; the epoch load; the write rules of section 4.10; the open checks of section 4.12; sealing the seed row; `TestIntegritySites`. |
| `internal/store/sqlite`, `internal/store/postgres` | `0001_initial.sql` in place (section 4.4). Both `Options` already embed `sqlstore.Options`. |
| `internal/core/integrity` (new) | `Service.Resign` and `Service.Status` over the Store, called by the host commands (Eric 2026-11-10, section 4). It shares its package name with the leaf; importers alias one (plan ruling). |
| `internal/core/signingkeys` | Section 4.16. |
| `internal/core/health`, `internal/bus` | The `integrity` member (section 4.12). |
| `internal/server/config` | `server_key_file`. |
| `internal/server/cmd` | Loading the file (it passes `fileacl.CheckOwnerOnly`), `Options.Integrity`, the start-up checks and warnings, the `integrity` host commands. |
| `internal/server`, `internal/bus/remote`, `api/openapi.yaml`, `internal/gen` | The health wire addition. |

**Import rules** (Eric 2026-11-10, section 4: a leaf rule in the gate scripts; the rule names are plan rulings), in `scripts/m7-exit-checks.sh`:

- `integrity-leaf`: `check_allowlist integrity-leaf ./internal/integrity "$MOD/internal/integrity"`: the package's dependencies are the standard library and itself, in every file.
- `integrity-consumers`: `internal/store/...`, `internal/core/...`, `internal/bus/...`, `internal/server` (the package), `internal/client`, `internal/cli`, `internal/mcpserver`, `internal/mcpcli` and `internal/tui` never import `internal/integrity` in non-test code. Only `internal/server/cmd` builds the key set; everything else sees the `store.Integrity` port.
- Unchanged and still required: `internal/store/...` never imports `internal/core/...` (the port lives in `internal/store`).

## 6. Dependencies

- No new Go module. `crypto/hkdf` is standard library at the pinned go 1.27.
- No new external service.
- CI: `make verify` (both engines), `windows.yml` (the owner-only check and the file writing on Windows), `make check-gates-selftest` (the new block), `tidy-check` and `generate-check` (the health schema).

## 7. Implementation outline

One implementation plan. Each task is test-first; the tests are in section 8.

- **Task 1: `internal/integrity`.** Key file parsing and every refusal, HKDF, the MAC encoding with the known-answer vector, sealing, `Generate`/`Activate`/`Marshal`; the `integrity-leaf` rule.
- **Task 2: schema and port.** Both `0001_initial.sql` files; `store.Integrity`; `sqlstore.Options.Integrity`; the new errors and `IntegrityStats`. With a nil port every existing test passes unchanged.
- **Task 3: security tables.** The helper, the write rules and the changed reads for the ten security tables, one table at a time; sealing the seed row; failure log and counter.
- **Task 4: messages and epochs.** `scanMessages` verification with tags, `AppendMessage`, `SetMemory`, `TombstoneMessage`, the limit rule, `integrity_epochs`, the per-transaction epoch load and the rules of section 4.7; the seq collision mapping.
- **Task 5: `TestIntegritySites`** and its allowlist.
- **Task 6: signing keys.** Sealing in `PutSigningKey`/`ListSigningKeys`; the `signingkeys` changes; the conflict at start.
- **Task 7: `internal/core/integrity`.** `Resign` and `Status` with the lock, the batches and the final transaction.
- **Task 8: configuration and start-up.** `server_key_file`, loading, the open checks, the warnings, the exit codes.
- **Task 9: host commands.** `keygen`, `activate`, `resign`, `status`.
- **Task 10: health.** The Bus member, the wire schema, `make generate`, the server and remote conversions and their gate tables.
- **Task 11: end to end and gates.** `TestDatabaseWriter`, the replica test, mutation block 41, the `integrity-consumers` rule.
- **Task 12: docs.** Section 9.

## 8. Test plan

Eric 2026-11-10, section 4, made specific. Voluminous output goes to a file; stdout carries the summary.

**`internal/integrity` unit tests**

- One subtest per refusal of section 4.2 (11), each asserting the message names the reason and holds no key material; an accepted file with one key and with several.
- Known-answer vectors: the subkeys and the MAC of section 4.6; one vector per field type; one sealed value with a fixed nonce injected through a test seam.
- Tamper tests per covered table (12): changing each covered column in turn, the table name, the key id and, for messages, the seq and each tag, makes `Verify` answer not ok; an unknown key id answers not known.
- Sealing: a round trip; a changed table, `kid` or key id in the AAD fails; a flipped ciphertext or tag bit fails; truncated input fails; two seals of one plaintext differ.
- `Generate`, `Activate` and `Marshal`: a new file, a key added with and without activation, the id rule, an unknown key refused by `Activate`, and the output parsing back to the same key set.

**Store conformance group `TestIntegrity*` (`internal/conformance/store`), both engines**

- Per covered table: write through the Store, then forge with raw SQL (insert an unsigned row, edit each covered column, copy `mac` and `mac_key` from another row, sign with a retired key), and prove the row absent on every read path section 4.11 lists for that table, including the changed ones (for example a forged identity cannot be named in an ACL, a forged channel cannot take an ACL, a forged token cannot be consumed).
- Every update site of section 4.10 item 3 refuses a failing row and leaves its MAC as it was.
- Upserts replace a failing row; a plain insert that collides answers `ErrConflict`; a seq collision answers `ErrRetryable`.
- Limits: forged rows ahead of a cursor do not shorten a page of genuine rows; a forged highest revision does not hide the real memory.
- Message epochs: a message under a retired key with seq at most S is delivered and one above S is not; the unsigned epoch likewise; a security row under a retired key fails; an epoch row that does not count is ignored; a second rotation keeps the first key retired before and after `resign`.
- Sealing: the stored `private_key_pem` is not PEM; a row sealed under another key id, or with a replaced value, is dropped.
- Open: `ErrSealed`, `ErrNotSealed`, the sealed seed row on a fresh database, the same database opened twice at once.
- `resign`: once; twice (the second re-seals nothing and writes no epoch); two at once (one is refused by the lock); resumed after a failure injected between batches and before the final transaction; `-adopt-unsigned` once, twice, and resumed; a failing row is left and reported.
- With a nil port: the columns stay empty and nothing is checked.
- `TestIntegritySites` (`internal/store/sqlstore`): the allowlist with exact counts.

**`internal/core` and `internal/server` tests**

- `signingkeys`: with a key file the key set holds only verified rows; a forged row's bearer is refused; a start with only unverifiable rows exits 1.
- `config`: `server_key_file` in `Settings()`, the environment variable, `-set`, and the documentation test.
- `cmd`: each start-up outcome of section 4.12 with its exit code and message; the non-loopback warning present and absent; the unretired-keys warning; each host command's output, exit codes and the rows of section 4.15; the key file writing of `keygen` and `activate` (a missing file, an existing file, a symbolic-link target refused, the lock file, mode 0600, and the Windows ACL in `windows.yml`); an ordinary host command (`users add`) against a sealed database with and without the key file.
- Health: the member at the administrator tier only, `off` and `on`, the counter after a failed check; `TestWireRoundTrip`, `TestToolCoverage`, `TestSpecDescriptions` and `TestSpecExamples` updated for the new member.

**End to end: `TestDatabaseWriter` (`internal/e2e`)** (Eric 2026-11-10, section 4). The binary's server on SQLite, planting with raw SQL: an administrator flag, a login key, a human binding, an access reference, an ACL grant, a signing key (with a bearer signed by it), an enrollment token, and a `sender_kind = 'human'` message. Two runs of the eight plants:

- without a key file, each plant succeeds end to end (the reproduction before the fix);
- with `server_key_file`, each fails end to end, no response is a 500 (the validating proxy), the health counter rises and the log names the row.

That is 16 leaf subtests; the count is pinned in `scripts/m6-exit-checks.sh` with the other `internal/e2e` counts (plan ruling).

**Replicas** (`internal/conformance/bus/replicas_test.go`): two replicas through the four rotation steps of section 4.13 on both engines; rows written by either are read by both at every step; after `resign` a row planted under the retired key fails on both; a replica left on the old current key refuses writes with `unavailable` (Open question 9).

**Gates**

- `scripts/check-gates-selftest.sh` block 41, `integrity-gates-fire` (Eric 2026-11-10, section 4: "remove a verify call; leaf import rule"). Mutations, each of which must fail a named test:
  1. the `messages` helper returns rows without verifying;
  2. one read site calls a raw select instead of its helper (`TestIntegritySites`);
  3. a retired key is accepted for a security row;
  4. the seq bound of an epoch is ignored;
  5. the key id is left out of the MAC input (the known-answer vector);
  6. an update site re-seals without verifying first;
  7. a failed check returns an error instead of dropping the row (the no-500 assertion);
  8. the sealed-database check is skipped when no key file is set;
  9. a probe file makes `internal/integrity` import a package of this module (`integrity-leaf`), and one makes `internal/cli` import `internal/integrity` (`integrity-consumers`), each tripping exactly its rule.
- `make verify` on both engines; `ci.yml` and `windows.yml` green on the pushed commit.

## 9. Docs

- `docs/security/threat-model-server.md`: SD1 and threat 2 rewritten around the table of section 4.1; the residual risks of section 4.14; the glossary's "Store provider"; follow-up item 2 closed; the column name corrected (the text says `identities.admin`, the column is `is_admin`).
- `docs/adr/0012-signing-key-rotation-and-key-providers.md`: the server key file addendum (committed with this work), pointing at this spec and recording Eric's answers to section 10.
- `docs/adr/0004-store-contract-and-storage.md`: an addendum for the two columns, `integrity_epochs`, `Options.Integrity` and why verification is not an access rule.
- `docs/ops/server-key.md` (new): the three configurations and their accepted risks; creating the file; delivering it as a Kubernetes Secret, a Compose secret, a systemd credential and an ECS init container; rotation in a cluster; turning it on for an existing database; removing a retired key; what a failing row looks like in the log and health, and how to delete one; that the key file must be backed up apart from the database. Each delivery method must be checked against that platform's current documentation or a live run before it is written, in particular which file mode and owner each one gives the mounted file and whether that passes the owner-only check; nothing is to be asserted from memory.
- `docs/ops/deploy.md`, `docs/ops/configuration.md` (the setting; the configuration docs test covers it), `docs/ops/signing-keys.md` (the store provider's trust boundary with and without the key file), `docs/ops/backup.md` (a sealed backup is useless without the key file; a restored backup's old rows), `docs/ops/health.md` (the `integrity` member), `docs/ops/README.md` ("database read access equals the admin flag" holds only in configuration 1).
- `CLAUDE.md`: the host commands, the two packages, the import rules, `TestIntegritySites`, block 41.

## 10. Open questions for Eric

Each is something the inputs do not settle, or a place where two inputs disagree.

**Open question 1: which message fields the MAC covers.**
Found: ADR decision 4 says "a MAC over channel, sender, sender_kind, seq and a content digest". Section 3's table lists more: also `session_id`, `created_at`, `type`, `subject`, a digest of `metadata`, `reply_to`, `memory_id`, `revision` and `tombstone`. The ADR ranks first among the inputs; the section is the more specific and a superset.
Options: A. Section 3's list. B. Decision 4's five fields only.
Recommendation: A, and reword decision 4 to "at least". `subject`, `type`, `reply_to`, `memory_id`, `revision` and `tombstone` all change what an agent reads or which revision of a memory or task is live. The cost is a re-seal in `SetMemory` and `TombstoneMessage`.

**Open question 2: message tags.**
Found: tags live in `message_tags`, which is in neither approved list. Tags are written only in `AppendMessage` and never changed. They are returned with every message and drive tag-subscription delivery (`TagMatchesAfter`) and tag filters.
Options: A. Add the sorted tags as the last field of the message MAC; no column on `message_tags`. B. Leave tags uncovered: a writer can add or remove tags on genuine messages.
Recommendation: A. It costs nothing at write time and one comparison at read time, because `scanMessages` already loads the tags. A tag row planted on, or removed from, a genuine message then makes that message fail, which equals deleting it.

**Open question 3: tables in neither approved list.**
Found: eleven tables are neither covered nor named as accepted. With what a writer gains from each:
- `retired_identities`: deleting a row makes a retired name registrable again, and old messages then appear to be the new registrant's. A MAC cannot detect a deletion, so covering it would not help.
- `bridge_messages`: a planted row misdirects Slack threading; deleting rows lets Slack history be posted again.
- `bridge_dropped`: a planted row suppresses one inbound Slack message.
- `tag_subscriptions`, `tag_subscription_tags`: the same class as `subscriptions`; delivery still passes the access check.
- `embed_failures`, `memory_access`: operational state; an old `accessed_at` makes maintenance expire a memory (deletion).
- `seq_counter`: lowering it makes appends collide (denial of service; section 4.10 item 6). `resign` takes S from it (`Tx.MaxSeq`), so raising it before `resign` raises S. That gains nothing without a key: it matters only to someone who also holds the key being retired, who keeps the power to forge messages in the skipped range; before `resign` that key was valid for everything anyway.
- `leases`, `schema_meta`: denial of service.
- `messages_fts` (SQLite) and the Postgres text-search columns: a planted index entry only surfaces a row that is then verified.
Options: A. All not covered, each added to the threat model's accepted list. B. Cover some.
Recommendation: A.

**Open question 4: `channel_acl` and "primary key included".**
Found: Section 3 says the MAC input includes the primary key, but its `channel_acl` row lists `channel_id`, `identity` and the three permissions; the primary key is the surrogate `id`, which no read returns (it only orders `ACL`).
Options: A. Keep the listed columns; `id` stays out. A writer can then duplicate or reorder valid ACL rows, which grants nothing new. B. Add `id` to the MAC (an insert then needs `RETURNING id` and a second statement per entry).
Recommendation: A.

**Open question 5: unsigned rows when a key file is configured.**
Found: Section 2 says to turn it on by "start with the file, run `resign`", and that `resign` writes `(none, max seq)` so that pre-key messages deliver and new unsigned messages are refused. It does not say how a server with a key file treats unsigned rows before that epoch exists. By analogy with "a key without an epoch row is valid for every row", unsigned rows would be valid until `resign`. Then a writer who deletes the unsigned epoch row makes every unsigned row valid again and can plant an administrator: that breaks "deletion is denial of service only". Separately, if a plain `resign` seals whatever unsigned rows it finds, a writer can plant one and wait for the operator's next routine `resign`.
Options: A. Strict, as written in the body: with a key file an unsigned security row never verifies; an unsigned message verifies only under a counted unsigned epoch; a database created with the key is sealed in its first transaction; an existing database is adopted once by `resign -adopt-unsigned` with the servers stopped; a start against an unadopted database is exit 2. B. Literal: unsigned rows are valid until the unsigned epoch exists, and `resign` seals them.
Recommendation: A. One residue remains under either option and belongs in the operator guide: a writer can strip a database until it looks never sealed, and an operator who then runs `-adopt-unsigned` blesses it. The exit message says so.

**Open question 6: messages that predate the key stay forgeable.**
Found: under the unsigned epoch `('', S)` any unsigned message with seq at most S verifies, so a writer can alter or insert such messages (a `sender_kind = 'human'` one included) and, by rewinding an uncovered session cursor, have one delivered. Section 1 does not list this.
Options: A. Accept and document; operators who care start from an empty database or wait for retention to evict the old messages. B. `resign -adopt-unsigned` also MACs every existing message once, and no unsigned epoch is written.
Recommendation: A, as approved, with the risk listed. B is a one-time rewrite of the largest table, but it removes the risk; it is the alternative if Eric does not accept the risk.

**Open question 7: deleting an epoch row un-retires its key.**
Found: decision 5 makes a non-current key valid for every row while it has no epoch row. A retired key stays in the file as long as messages carry it, and memories can live for a long time. A writer who deletes the key's epoch row returns it to "no epoch": old copies of revoked security rows under that key verify again, and if the key had leaked the writer has full control. Section 1's "rollback of security rows closed by `resign`" therefore holds only while the epoch row survives or after the key leaves the file. No rule inside the database can tell "never retired" from "epoch deleted".
Options: A. Accept and document: remove a retired key from the file as soon as `status` shows no message under it, and at once when a key is believed leaked (its remaining messages are then dropped). B. Add a way to re-seal messages under the current key so a key can leave the file without loss (it changes decision 5's "rotation never rewrites messages"). C. Record retirements in the key file (it changes decision 6's format and needs the file rewritten on every replica).
Recommendation: A now; B as a later issue if operators need to drop a leaked key without losing memories.

**Open question 8: rollback of message rows is never closed.**
Found: an earlier valid copy of a message row keeps verifying for as long as its key is in the file, and `resign` does not touch messages. A writer who kept copies can restore a tombstoned message, or delete the newest revision of a memory or task and restore an older one. Section 1 lists rollback only for security rows.
Options: A. Accept and list it. B. Close it (it needs a per-row version outside the row, a different design).
Recommendation: A.

**Open question 9: a replica left on the old current key after `resign`.**
Found: Section 2's roll assumes every replica runs with the new current key before `resign`. If one does not, its new messages are above S under a retired key and its new security rows are under a retired key: every replica drops them, and nothing tells the operator.
Options: A. Document the precondition only. B. Also detect it, as written in the body: a server that finds a counted epoch row for its own current key refuses writes of covered tables with 503 `unavailable` and logs the cause, and a start in that state is exit 2.
Recommendation: B. The check uses the epoch rows a transaction already loads.

**Open question 10: the "activate" step has no command.**
Found: Section 2's two-step roll is "add, roll, activate, roll", but the approved commands are `keygen`, `resign` and `status`; nothing sets `current` to an existing key.
Options: A. `integrity activate [-file F] KEY`. B. A flag on `keygen`. C. Edit the JSON by hand.
Recommendation: A. Removing a key stays a hand edit, documented.

**Open question 11: is `-file` required on `keygen`?**
Found: Section 2 writes `keygen -file F [-no-activate]`; Section 4 writes `keygen [-file F] [-no-activate]`.
Options: A. Optional; without it the configured `server_key_file` is used; neither is exit 2. B. Required.
Recommendation: A.

**Open question 12: where the private key is sealed.**
Found: Section 3 puts the check "in `internal/store/sqlstore` through port `store.Integrity` (`Seal`, `Verify`, `SealSecret`, `OpenSecret`) passed at open"; Section 4 lists "`internal/core/signingkeys`: store-provider private key through SealSecret/OpenSecret".
Options: A. `sqlstore` seals in `PutSigningKey` and opens in `ListSigningKeys`; the Store contract and `signingkeys` keep plaintext PEM; the sealing key id is the row's `mac_key`. B. `signingkeys` calls the port; the Store carries the sealed text, and the sealed form must name its own key id.
Recommendation: A: one place holds the key ids, and `resign` re-seals a key in the same step that re-signs its row.

**Open question 13: does integrity change the health `status`?**
Found: the sections give the member three shapes (Section 1 `integrity: off`, Section 3 `integrity: on|off` and a failure count, Section 4 `integrity: {mode, current_key, failures}`); the body uses Section 4's, which contains the others. None says whether `mode: off` on a non-loopback listener, or `failures` above zero, makes `status` `degraded`.
Options: A. No change to `status`; the administrator tier member and the log are the signal. B. `degraded` while `failures` is above zero. C. Also `degraded` for `off` on a non-loopback listener.
Recommendation: A. The counter never falls while the process runs, so one planted row would hold every replica at `degraded` and hide real degradation, and the probe tier would disclose it to unauthenticated callers. Configuration 1 is a supported configuration, so `off` is not a fault.

**Open question 14: the uncovered `signing_keys` timestamps.**
Found: "all but timestamps" leaves `created_at`, `retired_at` and `remove_after` uncovered. A writer can move `remove_after` forward so that a retiring key stays trusted and published, or back so that it is removed early; and can move the active key's `created_at` to defeat or prolong the rotation cooldown and the scheduled rotation. None of this mints a bearer without the private key, which is sealed or in a key service.
Options: A. Keep as approved and list the consequence. B. Cover `retired_at` and `remove_after` (both are written once, in `RetireSigningKey`, which re-seals the row anyway).
Recommendation: A as approved; B costs nothing extra if Eric prefers the retirement window to be tamper-proof.

**Open question 15: which epoch rows count after a second rotation.**
Found: decision 5 says an epoch row is "signed by the current key". After a second rotation (k1 retired under k2, then k3 made current) the row that retires k1 is signed by k2 until `resign` re-seals it. Read literally, k1's retirement lapses on every replica that runs with current k3 until `resign` finishes: old copies of revoked security rows under k1 verify again, and a leaked k1 is fully valid.
Options: A. Literal: only rows signed by the current key count; accept the window. B. As written in section 4.7: a row also counts when signed by a file key that the current key has not retired, and not by its own subject. Earlier retirements then hold through the window, with one limit: until `resign` there is no row signed by the current key, so a retired key that has leaked can still sign an epoch row for another key id; the one that matters is the unsigned epoch with a raised seq, which lets unsigned messages verify. C. B, except that the unsigned epoch counts only when signed by the current key; messages that predate the key are then unreadable between activation and `resign`.
Recommendation: B. It is never weaker than A. Its limit needs a leaked key that is still in the file, which Open question 7 already answers with "remove a leaked key from the file at once"; the rotation guide should say to run `resign` as soon as the roll completes.
