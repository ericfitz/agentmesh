# Certificate hierarchy for key storage and rotation (design spec 1 of 2)

## 1. Status

- Approved by Eric, 2026-11-11 (second draft plus Decision 21). The first draft is commit `d3f5b56`; the second folds in Eric's rulings of 2026-11-11 on that draft's open questions. Nothing here is built.
- This is spec 1 of 2. Spec 2, `docs/superpowers/specs/2026-11-11-signed-messages-design.md`, puts signed messages on top of this hierarchy. Spec 1 ships alone (Decision 13): it moves the server's signing keys out of the database and makes bearers verify by a certificate chain instead of by database rows.
- The record of decisions is ADR 0019 (`docs/adr/0019-certificate-hierarchy-and-signed-messages.md`).
- It replaces the abandoned server key file design (`docs/superpowers/specs/2026-11-10-server-key-file-design.md`; ADR 0012, "Server key file design abandoned (2026-11-11)").
- Labels used below:
  - **(Eric 2026-11-11, Decision N)**: one of Eric's twenty-one decisions of 2026-11-11, numbered as in ADR 0019. Decisions 16 to 20 are his rulings on the first draft's open questions, Decision 21 his ruling on the second draft's Open question 28.
  - **(plan ruling)**: a proposal made while writing the design. Eric approved the ones that come from the three design sections of 2026-11-11 as part of those sections. The others are not his decisions, and he may overrule any of them.
  - **Ruling N**: the plan ruling on what the first draft called Open question N. Section 11 lists them (3, 4, 6 to 13 and 24 here; 14 to 16, 18 to 22, 25 and 26 are in spec 2) with the alternative not taken. They are not Eric's decisions.
- Neither spec has an open question.
- Every statement about today's code was checked against the tree at commit `d3f5b56` and carries a `path:line` citation.

## 2. What this changes, in short

Today the server signs bearers with a key whose public half, and by default whose private half, is a database row. Whoever can write that table can add a key of their own and forge bearers; whoever can read it can, by default, take the private key.

After this spec:

- A root certificate authority (CA) sits outside the server. Its certificate is pinned in the server's configuration and on every client (Eric's outline). agentmesh ships a small tool to run one (Decision 9).
- Each installation holds one intermediate CA key, in a PEM file or a key service, with a certificate the root issued (Decisions 4 and 10).
- Each server process makes its own signing key in memory at start and has the intermediate issue a short-lived leaf certificate for it. The key is never written anywhere (Decision 4).
- Bearers are signed by the leaf and verified by the chain to the pinned root. No key and no trust decision about a key comes from the database.
- Revocation is by certificate revocation lists (CRLs), delivered to clients inside ordinary responses (Decisions 6 and 12).
- A client gets the root, the chain and the CRLs from the discover document and pins the root on first contact, over HTTPS by default (Decision 19).
- The `signing_keys` table, the in-database key provider and the two rotation maintenance jobs are removed.

What it does not change (Decision 15): the server still reads ACLs, the administrator flag, identity rows and login keys from the database and believes them. Write access to the database stays equal to being the application's administrator, replicas and restores included.

## 3. What exists today

1. The signing key set is the `signing_keys` table: one `active` row and any number of `retiring` rows, with a `provider` column and, for the `store` provider, the private key as plaintext PEM (`internal/store/sqlite/schema/0001_initial.sql:194-209`; `internal/store/postgres/schema/0001_initial.sql:193-208`; `internal/store/signing.go:8-25`).
2. `Keyring.LoadKeys` builds the issuer's key set from every row and trusts each row's public key (`internal/core/signingkeys/keyring.go:39-63`). This is threat 2 of the threat model.
3. The key provider port has `Next` (the key a rotation would install) and `Signer` (open a key for signing) (`internal/keyprovider/keyprovider.go:45-55`). `StoreProvider` generates an Ed25519 key and returns its PEM for the row (`keyprovider.go:66-87`). The four external backends sign in place and accept ECDSA P-256 only (`keyprovider.go:122`, `174-187`).
4. A signer signs a digest under a context (`keyprovider.go:39-42`); the token package adapts that to `crypto.Signer` for go-jose (`internal/auth/token/keyset.go:154-165`).
5. `Issuer.Mint` signs an `at+jwt` with a `kid` header that is the key's thumbprint (`internal/auth/token/issuer.go:312-313`) and already puts a kind claim, `agentmesh_kind`, in every bearer (`issuer.go:266-273`, `331-334`). `Issuer.Verify` looks the key up by `kid`, checks the type, signature and claims, and returns only the subject (`issuer.go:343-374`).
6. The issuer reloads its key set every 30 seconds and, at most once per 5 seconds, when a bearer names an unknown key (`internal/auth/token/keyset.go:19-22`; `issuer.go:182-226`).
7. The server start opens the provider, creates or adopts the active key and builds the issuer over the keyring (`internal/server/cmd/cmd.go:156-177`). In local mode there is no issuer and the token endpoint answers 503 (`internal/server/cmd/serve.go:48`).
8. Settings: `signing_key_uri`, `signing_key_rotation_hours` (default 720) and `signing_key_rotation_cooldown_seconds` (default 3600) (`internal/server/config/config.go:64-66`, `131-132`, `258-265`). The bearer lifetime ceiling is 86400 seconds (`config.go:21`).
9. The wire has `GET /v1/admin/signing-keys` and `POST /v1/admin/signing-keys/rotate` with a `revoke_previous` parameter (`api/openapi.yaml:2465-2541`; `internal/server/signing_keys.go:13-16`), and `GET /v1/auth/jwks` (`api/openapi.yaml:2292-2315`). The authorization server metadata requires `jwks_uri` (`api/openapi.yaml:3510`; `internal/server/discovery.go:61`), and the client's discovery reads it (`internal/credential/discover.go:23`).
10. `GET /v1/discover` is an open operation that never touches the store, which is why it is the liveness probe (`api/openapi.yaml:113-128`, line 125; `internal/server/discovery.go:81-126`). The client already has a call for it (`internal/client/probe.go:17-39`).
11. A server profile's `server` may be an `http` or `https` URL on any host (`internal/profile/config.go:132-153`). The profile's `oidc.issuer` is stricter: `https`, or `http` only for `127.0.0.1`, `::1` and `localhost` (`internal/profile/config.go:53-68`).
12. Registration answers `identity`, `kid`, `algorithm` and `created` (`api/openapi.yaml:5219-5241`). A human identity cannot register (`api/openapi.yaml:2333`); humans sign in through the token exchange (`internal/server/auth_exchange.go:60-152`). The credential directory treats every regular file in it as an identity (`internal/credential/store.go:44-60`).
13. A watch wakes only when a message is pending for the session (`internal/core/delivery/watch.go:98-123`). A hint with sequence number 0 makes watchers look again and nothing more (`internal/core/notify/doc.go:9-11`).
14. Write transactions run at the serializable isolation level (`internal/store/sqlstore/store.go:113`).
15. The MCP-only binary may link exactly 13 modules, and `github.com/go-jose/go-jose/v4` is one of them (`scripts/m10-exit-checks.sh:39-53`, line 41). `go list -deps ./cmd/agentmesh-mcponly` shows the binary already links go-jose and `crypto/x509`. So client-side verification may use go-jose; no allowlist change is needed.

## 4. Design

### 4.1 Two configurations (Eric 2026-11-11, Decision 7)

| Configuration | Trust material | Behavior |
| --- | --- | --- |
| Local mode (the in-process core over the user's SQLite file) | None | No CA, no leaf, no bearers (as today). Nothing in this spec applies. |
| Server mode (`agentmesh server`) | A pinned root, an installed intermediate, a leaf per process | Required to start. There is no server without them. |

There is no switch between the two beyond which program runs. Development and tests use the shipped root tool (section 4.3) to make a throwaway root (Decision 7).

### 4.2 Certificates

All certificates are X.509 version 3. None carries a DNS name, an IP address or a TLS key usage: the hierarchy is not used for TLS (Eric's outline).

| Certificate | Key | Issued by | Validity | Extensions |
| --- | --- | --- | --- | --- |
| Root | Any algorithm Go's `crypto/x509` verifies; the root tool makes ECDSA P-256 | Itself | Chosen by the CA; the root tool default is 3650 days | CA true; key usage certificate signing and CRL signing; subject key identifier |
| Intermediate | ECDSA P-256 | The root | Chosen by the CA; the root tool default is 365 days | CA true, path length 0 (critical); key usage certificate signing and CRL signing (critical); subject key identifier; authority key identifier |
| Leaf | Ed25519, made in memory by the server process | The intermediate | W, default 7 days (section 4.6) | CA false (critical); key usage digital signature (critical); subject and authority key identifiers; random 128-bit serial number |

Plan rulings:

1. The intermediate key is ECDSA P-256 in both storage forms, because the four key service backends accept only that (`internal/keyprovider/keyprovider.go:174-187`) and one algorithm at the CA level is simpler than two.
2. A certificate is named by its thumbprint: the SHA-256 of its DER encoding, base64url without padding. This is the value of the JWS header `x5t#S256`.
3. The intermediate must carry a subject key identifier and the CRL signing usage, because Go's `x509.CreateRevocationList` refuses an issuer without them (Go 1.27, `crypto/x509/x509.go`, `CreateRevocationList`).
4. A leaf's "not after" is never later than its intermediate certificate's "not after".

**The profile an outside CA must issue** (Decision 9) is the Intermediate row above, for the public key in the CSR that `ca csr` prints, signed with any algorithm Go's `crypto/x509` verifies, with no name constraints. The operator guide states it in these words and gives an `openssl` example.

### 4.3 The root tool (Eric 2026-11-11, Decision 9)

`agentmesh ca` is a small root CA for development, test fixtures and small production installations. It is part of the `agentmesh` binary only (not `agentmesh-mcponly`). It never contacts a server or a database. The command names are a plan ruling Eric approved.

- `agentmesh ca init -dir DIR [-name NAME] [-days N]` makes the root key and the self-signed root certificate. It writes `DIR/root.key` (PKCS#8 PEM, mode 0600), `DIR/root.pem` and `DIR/state.json` (issued certificates, revocations, the CRL number), and prints the path of `root.pem` and its thumbprint.
- `agentmesh ca sign -dir DIR [-days N] CSR_FILE` checks the CSR's own signature, issues an intermediate certificate with the profile of section 4.2, records it in `state.json` and prints the certificate as PEM.
- `agentmesh ca revoke -dir DIR CERT_FILE` marks an intermediate this root issued as revoked, raises the CRL number by one, writes `DIR/root.crl` and prints the CRL as PEM. The CRL lists every intermediate ever revoked.

The administrator keeps `DIR` offline (Decision 9). The package behind the tool (`internal/pki/rootca`, a plan ruling) is what test fixtures call in process.

State (repeat, overlap, failure):

| Command | Second run | Two runs at once | After a failed run |
| --- | --- | --- | --- |
| `ca init` | Refuses (exit 2) when `DIR` already holds a root; it never overwrites a key | One wins the exclusive create of `root.key`; the other refuses | A run that died before `root.pem` was written leaves `root.key` only; `init` refuses and names the file to remove |
| `ca sign` | Issues another certificate with a new serial number for the same CSR; both are valid until expiry or revocation | Serialized by a lock file in `DIR` | `state.json` is replaced atomically before the certificate is printed; a certificate recorded but never printed is listed by `state.json` and can be revoked |
| `ca revoke` | The certificate is already revoked: prints the current CRL, number unchanged | Serialized by the lock file | The CRL file and `state.json` are replaced atomically, state first; a rerun completes it |

Exit codes: 0 done, 2 usage or a refused input, 1 an I/O failure.

### 4.4 The intermediate (Eric 2026-11-11, Decisions 4 and 10)

One intermediate key per installation, shared by every replica (Decision 4). It lives in one of two places (Decision 10):

- **A PEM file** named by the setting `intermediate_key_file` (PKCS#8, mode 0600 or owner-only, checked like the credential files). The operator delivers the same file to every replica (a mounted secret, for example).
- **A key service**, named by the setting `intermediate_key_uri` with one of the four existing schemes (`awskms`, `gcpkms`, `azurekms`, `hashivault`). The service signs in place; the private key never reaches the server. The backends stay behind their build tags.

Exactly one of the two settings is set. The in-database provider is deleted, and there is no backend that fetches a key from a secrets manager (Decision 10).

The host commands (no listener, no credential; they take `-config`, `-sqlite`, `-postgres` and `-set` like the other `server admin` commands):

- `agentmesh server admin ca csr [-name NAME] [-out FILE]` prints a certificate signing request for the intermediate key.
  - File: when the key file does not exist, it creates the key (written through a temporary file and linked into place without replacing an existing file), then prints the CSR. When the file exists, it prints a CSR for that key; this is how a certificate is renewed.
  - Key service: the operator creates the key in the service first; the server never creates, deletes or schedules deletion of an external key, as today (`docs/ops/signing-keys.md`, "Trust boundary"). `ca csr` resolves the URI with `Provider.Next` and has the service sign the CSR (Ruling 9).
  - It writes nothing to the database.
- `agentmesh server admin ca install CERT_FILE` checks the certificate and stores it. The checks: it chains to the pinned root and is inside its validity period; CA true with path length 0; certificate signing and CRL signing usages; a subject key identifier; its public key is the configured intermediate key's; it is not on the stored root CRL. Each failure names the failed check and exits 2.
- `agentmesh server admin ca install-crl CRL_FILE` checks a root CRL (signed by the pinned root; a number above the stored root CRL's) and stores it.
- `agentmesh server admin ca status` prints the pinned root's thumbprint, each stored intermediate (thumbprint, validity, whether it matches the configured key, whether the root CRL lists it), the CRL numbers, the trust number (section 4.8) and the unexpired leaves.

**Renewal** of the intermediate certificate is `ca csr` and `ca install` again with the same key. Earlier intermediate certificates stay in the table, so history signed under an expired intermediate still verifies, and history under a revoked one does not (approved section 3). A running process picks the newest valid certificate for its key the next time it issues a leaf; no restart is needed.

**Changing the intermediate key** is: point the setting at the new key, `ca csr`, `ca install`, restart every replica. During the roll, replicas with the old key keep issuing leaves under the old certificate. Ruling 4 says how the old key's leaves are cut off.

**Where the pinned key reference lives** (Ruling 9): for a key service, `ca install` records the resolved reference (the exact key version) in the intermediate's row, and every process signs by that reference. A changed reference cannot make a wrong key trusted: every leaf a process issues is checked against the intermediate certificate before use (section 4.6), so a wrong reference only stops issuing.

### 4.5 The Store

One new table holds everything public (approved section 1): intermediate certificates, leaf certificates and CRLs. Every row is self-verifying: a certificate or CRL that does not check out against the pinned root is ignored and logged, never trusted. There is no file distribution to replicas.

`trust_material` (both engines; a plan ruling on names):

| Column | Meaning |
| --- | --- |
| `id` | Row id |
| `kind` | `intermediate`, `leaf`, `root_crl`, `leaf_crl` or `trust_number` |
| `thumbprint` | SHA-256 of `der`, base64url; unique per kind |
| `der` | The certificate or CRL, DER; empty for `trust_number` |
| `issuer_key` | The subject key identifier of the issuing key, hex: for a leaf and a leaf CRL, the intermediate key; empty otherwise |
| `not_after` | Extracted copy, Unix milliseconds, for listing and cleanup; 0 for CRLs |
| `number` | The CRL number for a CRL row; the trust number for the `trust_number` row; 0 otherwise |
| `key_ref` | Intermediate rows with a key service: the pinned key reference; empty otherwise |
| `created_at` | Unix milliseconds |

Rules:

- At most one `root_crl` row, one `leaf_crl` row per `issuer_key` (Ruling 4), and exactly one `trust_number` row (created with the schema, value 0).
- The Store serves these rows as facts and applies no rule to them, like every other table (ADR 0004 addendum "Access facts, not rules"). New `Tx` methods: `PutTrustCertificate`, `TrustCertificates(kind)`, `TrustCertificateByThumbprint`, `PutCRL` (replaces the row only when the new number is higher; otherwise `ErrConflict`), `CRLs`, `TrustNumber`, `BumpTrustNumber`, `ExpiredLeafCertificates(before, limit)` and `DeleteTrustCertificates(ids)`.
- Schema: changed in place in both `0001_initial.sql` files; the schema version stays 1; no migration; local data is recreated (the pre-release rule, CLAUDE.md, Eric 2026-10-25).
- The Store lock `trust` (`Store.Locks`, `internal/store/lock.go:11-21`) serializes every change to CRLs. A change and its trust number bump commit in one transaction (approved section 3).

Removed: the `signing_keys` table and index, `store.SigningKey`, `store.SigningProviders` and the five `SigningKeys` methods (`internal/store/signing.go:8-62`).

### 4.6 The leaf (Eric 2026-11-11, Decision 4; approved section 1)

Each server process holds one Ed25519 signing key, generated at start, kept in memory and never written anywhere. The same leaf signs bearers and, with spec 2, messages (Decision 4).

**Issuing a leaf** (at start and at each renewal):

1. Generate the key pair in memory.
2. Build the certificate (section 4.2) with "not before" = now minus 60 seconds (Ruling 13) and "not after" = now plus W, cut to the intermediate's "not after".
3. Have the intermediate key sign it: a local signature for the file, one sign call for a key service, bounded by the existing 30-second limit (`internal/core/signingkeys/service.go:27-30`).
4. Verify the new certificate against the intermediate certificate and the pinned root. A failure here means the configured key is not the certificate's key; it is logged and counts as a failed issue.
5. Insert the leaf's row.
6. Only then start signing with it.

A crash or failure between steps 3 and 6 leaves at most an unused certificate; a certificate whose row was never inserted is simply lost (approved section 3).

**Validity and renewal:**

- W is `leaf_validity_hours`, default 168 (7 days; Eric approved the default), from 2 to 720 (the bounds are a plan ruling).
- At W/2 the process issues its next leaf and signs with it from then on. The previous leaf stays valid for verification until it expires. So two leaves per process are valid at any time, as Eric's outline asks.
- When a renewal fails, the process retries after one eighth of the time left before the current leaf expires, never sooner than one minute. The retries therefore come more often toward the end.
- When the leaf has expired and no renewal has succeeded: every operation that needs a signature answers a retryable 503. That is the token endpoint (`temporarily_unavailable`, as for an unavailable signing key today: `internal/server/auth_handlers.go:125-128`, `internal/server/auth_exchange.go:138-140`) and, with spec 2, every write that appends a message. Other requests are served as long as their bearer verifies. Ruling 12 says what that means on a single server.
- A process never signs outside its leaf's validity period as its own clock sees it; if the clock is outside (a clock step), it treats the leaf as expired and issues a new one (Ruling 13).

**The port.** `internal/core/signingkeys` is rewritten as the leaf manager (the package name is kept; a plan ruling). It holds the current and previous leaf, runs the renewal timer, and is the issuer's `token.KeySource`: the signer is the current leaf's key, and the published set is every leaf it has verified.

### 4.7 Bearers

- A bearer is the same `at+jwt` as today, signed by the current leaf (EdDSA). Its header carries `x5t#S256`, the leaf certificate's thumbprint, and `kid` with the same value (set as extra headers the way `kid` is set today, `internal/auth/token/issuer.go:312-313`).
- A bearer's expiry is the earlier of now plus its lifetime and the leaf's "not after". The configuration is refused (exit 2) when `token_lifetime_seconds` or an issuer's human lifetime is more than W/2, so a bearer minted by a healthy process always gets its full lifetime (approved section 1: "Bearer lifetime capped at W/2").
- Verification, on any replica: read the thumbprint from the header; take the leaf from the process's verified set, or load its row by thumbprint (the existing single-flight reload for an unknown key, `issuer.go:198-226`); verify the chain leaf, intermediate, pinned root at the current time with the existing 60-second leeway (`issuer.go:27-28`); refuse a leaf on the leaf CRL or under an intermediate on the root CRL; then the checks of today (type, signature, issuer, audience, expiry, subject).
- A row is never trusted for what it claims. A leaf row that does not chain to the pinned root is the same as no row. This closes threat 2: inserting a key into the database no longer makes it trusted.
- Replicas: a bearer minted by one replica is accepted by another through the leaf's row and the shared intermediate. Each process reloads the trust material every 30 seconds (the existing `token.ReloadInterval`) and at once after a local change.

### 4.8 Revocation (Eric 2026-11-11, Decisions 5, 6, 12 and 16; approved section 1)

**Two kinds of CRL**, both standard X.509 CRLs with a CRL number:

- **The root CRL** lists revoked intermediates. The root tool (or an outside CA) issues it; `ca install-crl` stores it.
- **The leaf CRL** lists revoked leaves by serial number. The intermediate signs it; the server writes it. There is one per intermediate key, covering that key's leaves (Ruling 4).

**What revocation means** (Decision 5): a revoked leaf, or a leaf under a revoked intermediate, verifies nothing, whatever it signed and whenever. Expiry alone never invalidates history: with spec 2, a message verifies when its signed time is inside its leaf's validity period.

**Forced renewal.** The existing rotate operation becomes "issue a new leaf here and put every other unexpired leaf on the CRL" (approved section 1; Eric's outline: "a server API forces immediate renewal with revocation of the previous certificate"). It always revokes and is never refused for being too soon; `revoke_previous` and the cooldown are gone (Ruling 6). In the handling process:

1. Check the caller is an administrator and look for a receipt of the idempotency key, as today (`internal/core/signingkeys/api.go:76-103`).
2. Take the Store lock `trust`. If another process holds it, answer a retryable `unavailable`.
3. Reload the trust material.
4. Issue a new leaf (section 4.6, steps 1 to 4).
5. Build the next leaf CRL: every entry of the current one, plus every unexpired leaf row under this intermediate key except the new leaf; number = current + 1. Sign it with the intermediate key.
6. In one transaction: check the administrator again, count what each newly revoked leaf signed (below), store the receipt, insert the new leaf's row, replace the leaf CRL row, raise the trust number.
7. After the commit: sign with the new leaf, wake the watchers (section 4.9), release the lock.

Other replicas see their leaf on the CRL at their next reload and issue a new one at once (approved section 1). Until a replica reloads (at most 30 seconds, or sooner on a Postgres notification), it still signs bearers with a revoked leaf; the replica that revoked refuses them at once, and the others once they reload. This is the propagation delay of today's `revoke_previous` (ADR 0012, decision 4).

The host command `agentmesh server admin signing-key rotate` does the lock, the reload, the CRL and the transaction without a new leaf: it revokes every unexpired leaf under the configured key, and the running processes issue new ones as above.

**What a forced renewal costs, and the report** (Decision 16). By Decision 5, everything the revoked leaves signed stops verifying. With spec 2 that is every message, memory revision and task document those leaves signed, from every replica, for up to W. Eric accepted this. Both forms of the command report, for each leaf they revoke, how many messages, memory revisions and task documents it had signed, so the operator sees the cost. In spec 1 alone the three counts are always 0, because nothing but bearers is signed yet; spec 2 section 4.8 says how they are counted. Revoking an intermediate does the same to everything under it. There is no re-sign path (Eric's outline: "no signing of data in the database"); spec 2 section 4.7 says how content from a revoked period is written again.

**Entries and rows are kept** (Ruling 7): a revoked entry stays on the leaf CRL for the life of the intermediate key. Leaf rows are deleted once expired and, with spec 2, once no message refers to them.

**The list of leaves to revoke comes from the table** (Ruling 8): a database writer who removes a leaf's row first keeps that leaf off the CRL until it expires.

**Revoking an intermediate** is done with the root tool: `agentmesh ca revoke`, then `ca install-crl` on the server. A running process that finds its intermediate on the root CRL stops issuing and signing, logs it and reports it in the health document; a start in that state exits 2.

**Rollback inside a running server.** Each process remembers, in memory, the highest CRL number it has verified for each CRL. A stored CRL with a lower number is ignored and logged as a rollback, and the process writes its newer copy back. A restart forgets this (Decision 6: an accepted risk).

**The trust number** (Ruling 3). Decision 12 speaks of "the current CRL number", but there are at least two CRLs, each with its own number, and a new intermediate certificate changes neither. The wire therefore carries one **trust number**: a counter in the `trust_number` row that goes up by one in the same transaction as every change to a CRL or to the set of intermediates. It only tells a client that there is something to fetch. What a client enforces is the signed number inside each CRL: it refuses a CRL with a lower number than the one it holds for the same issuer (Decision 12).

### 4.9 Delivery to clients (Eric 2026-11-11, Decisions 6, 12 and 19)

There is no "next update" enforcement and no state in which a client fails closed because its CRL is old (Decision 6). CRLs carry a "next update" field only because the format expects one; it is set to the issuer's "not after" and nobody enforces it.

**The trust bundle** is one JSON object (schema `TrustBundle`, a plan ruling):

| Member | Content |
| --- | --- |
| `trust_number` | The trust number |
| `intermediates` | Every stored intermediate certificate, base64 DER |
| `root_crl` | The root CRL, base64 DER; absent when none is installed |
| `leaf_crls` | The leaf CRLs, base64 DER; empty when no leaf was ever revoked |
| `root` | The pinned root certificate, base64 DER; present only in the discover document |

**Where it rides:**

1. **The discover document** (Decision 19). `GET /v1/discover` carries `trust`, the whole bundle with `root`. This is the one place the root travels. Registration and token responses keep their current shapes. So that discover stays the liveness probe that never touches the store (section 3 item 10), the server answers from the process's in-memory, verified copy of the trust material, the one it reloads every 30 seconds; a plan ruling. In local mode the document has no `trust`.
2. **Session open and every receive** (Decision 12). The request carries the trust number the client holds (`trust_number`, optional, in `OpenSessionRequest` and `ReceiveRequest`). The response always carries the current `trust_number`; when the client's number is absent or lower, it also carries `trust`, the bundle without `root`.
3. **Watch** (the doorbell, Decision 12). `watch` takes the client's `trust_number`; the server wakes the watch at once when its own number is higher, with a count of 0 and the new number in the answer. This needs a change, because a watch wakes today only for a pending message (`internal/core/delivery/watch.go:98-123`). The trust transaction publishes a hint in its process and, on Postgres, a notification, so waiting sessions on every replica look again; a replica without notifications (SQLite) notices at its 30-second reload and publishes the hint then.

A client woken this way calls receive, which brings the bundle. `agentmesh wait` exits 0 for it as for a message; a parked session stays silent and catches up on its next receive.

**When a client calls discover** (Ruling 24, which follows from Decision 19). A process calls discover once when it opens the `Bus` of a server profile. That covers first contact, a client with no session (a one-shot `history`, `search` or `memories get` refreshes its CRLs this way), and a long-lived process at its start; after that a session's receives keep it current. The three hooks are the exception: they read no content and must answer within 500 ms, so they do not call discover. When discover cannot be reached and the client already holds a pin, it goes on with what it holds (Decision 6: no failing closed on old CRLs). With no pin it cannot go on.

**What the client does with a bundle:**

1. Root (discover only): with no pinned root for the profile, pin the one received (first contact). With a pinned root, a different `root` is an error: the client stops, names both thumbprints and names the flag `-accept-new-root` (section 4.10). It never replaces a pin silently.
2. Intermediates: keep each one that chains to the pinned root.
3. Root CRL: accept when signed by the pinned root and its number is not below the held one; refuse a lower number (Decision 12).
4. Leaf CRLs: accept each when signed by a kept intermediate that is not on the root CRL and its number is not below the held one for that issuer key; refuse a lower number.
5. Remember the trust number only after the above succeeded.

A refused CRL is written to the client log (`<data dir>/logs/`) with both numbers; spec 2 also shows it in the receive result.

### 4.10 The client: HTTPS, the pin and the trust store (Eric 2026-11-11, Decision 19)

**HTTPS is required by default for a server profile.** The first contact pins the root from whatever answers at the profile's `server` URL, so that connection has to be to the right server. Today any `http` URL is accepted (section 3 item 11). The new rule for the profile's `server`:

- `https`: accepted. The certificate is checked against the system's roots, as Go does by default; there is no option to skip that check.
- `http` on a loopback host (`127.0.0.1`, `::1`, `localhost`): accepted without the switch. This is a plan ruling by the coordinating agent, not Eric's decision, and he may overrule it; it matches the rule the profile's `oidc.issuer` already follows (`internal/profile/config.go:53-68`) and keeps tests and a server on the same host working.
- `http` on any other host: refused (exit 2, naming the switch) unless the override switch is on.

**The override switch** is named `insecure_http` (the name is a plan ruling made in this spec). It is for local testing (Decision 19). It has one meaning, "this profile may use `http` to a host that is not loopback", and three forms:

- the profile member `"insecure_http": true` in `config.json`;
- the flag `-insecure-http` on `agentmesh register` and `agentmesh-mcponly register`, which writes that member when it creates the profile;
- for the profile `agentmesh-mcponly` holds in memory when `-server` is not defined in `config.json`: the flag `-insecure-http` or the variable `AGENTMESH_INSECURE_HTTP=1`.

Every command that runs with the switch on logs one line saying the connection is not protected.

**The pin.** A client with no pinned root for its profile pins the root from discover on first contact and prints the thumbprint. A different root later is an error until the operator runs `register` or `login` (in `agentmesh-mcponly`: `register` or `check`) with `-accept-new-root`, which prints the old and new thumbprints and replaces the pin, the stored chain and the stored CRLs (Decision 19). Once a client pins a new root, history signed under the old root no longer verifies for it, so a root should live long; the root tool's default is ten years.

**The trust store.** Per profile, in a directory of its own (Decision 19):

`<config dir>/trust/<profile>/` (mode 0700; files 0600): `root.pem` (the pin), `intermediates.pem`, `root.crl`, `leaf-<issuer key>.crl`, and `state.json` (the trust number and the server URL the pin belongs to). Spec 2 adds `leaves.pem`, a cache of leaf certificates that verified.

- It is per profile, not per identity: the root belongs to the server. It is not in the credential directory, where every file counts as an identity (section 3 item 12).
- Every process of the profile shares it (the MCP server, `wait`, the hooks, one-shot commands, the TUI). Writes take a lock file in the directory and replace files atomically, as `internal/sessionstate` does (`internal/sessionstate/state.go:83-97`, `138`).
- A profile whose server URL differs from the one in `state.json` is the root-mismatch error.
- Package `internal/trust` (a plan ruling) holds it and imports the standard library, `internal/filelock` and `internal/pki` only.
- The plumbing sits under the `Bus`: `internal/client` wraps the remote `Bus` of a server profile in a layer that calls discover when it is built, sends the held trust number on session open, receive and watch, and stores each bundle that comes back. The consumers (`internal/cli`, `internal/mcpserver`, `internal/mcpcli`, `internal/tui`) do not change. Spec 2 adds verification to the same layer.

State: writing the same bundle twice changes nothing. Two processes writing at once are serialized by the lock; the later one re-reads and keeps the higher numbers. Two processes making first contact at once both pin; the second finds the first's pin, compares, and either agrees or reports the mismatch. A crash leaves the previous files (atomic replace).

### 4.11 Wire changes (`api/openapi.yaml`)

The protocol version stays `1.0.0` (CLAUDE.md, Eric 2026-10-27). The operation count stays 57 (8 open, 49 protected).

| Element | Change |
| --- | --- |
| `TrustBundle` | New schema (section 4.9) |
| `Discovery` | Gains `trust` (the bundle with `root`; present from a server, absent in local mode). The description of `discover` still says it never touches the store |
| `Registration`, `AccessToken` | Unchanged (Decision 19) |
| `OpenSessionRequest`, `ReceiveRequest` | Gain `trust_number` (optional integer, 0 to 2^53) |
| `Session`, `ReceiveResult` | Gain `trust_number` (present from a server) and `trust` (when the client is behind) |
| `watch` (a new query parameter) and `Wake` | Gain `trust_number` |
| `SigningKey` | Now describes a leaf certificate: `thumbprint`, `serial`, `issuer_thumbprint`, `not_before`, `not_after`, `state` (`current`, `previous`, `other`, `revoked`). The members `kid`, `provider`, `provider_ref`, `algorithm`, `created_at`, `retired_at`, `remove_after` go |
| `SigningKeyList` | The unexpired leaves, this process's current leaf first, plus `trust_number` |
| `rotateSigningKey` | Loses `revoke_previous` (Ruling 6). `SigningKeyRotation` becomes `current` (the new leaf), `revoked` (one entry per leaf revoked: `thumbprint`, `messages`, `memory_revisions`, `task_documents`; Decision 16) and `trust_number` |
| `jwks` and `JWK` | Kept (Ruling 10): one JWK per unexpired, unrevoked leaf the process has verified, with `kid` (the certificate thumbprint), `x5t#S256` and `x5c` (leaf, then intermediate) |

Local mode answers the two signing key operations with the non-retryable `unavailable` of today (`internal/server/signing_keys.go:26-40`), and its session and receive answers carry no `trust_number`.

### 4.12 Settings

Server (Ruling 11):

| Setting | Meaning | Default |
| --- | --- | --- |
| `root_certificate_file` | Path of the pinned root certificate (PEM, one certificate) | None; required |
| `intermediate_key_file` | Path of the intermediate key (PKCS#8 PEM, owner-only) | None; exactly one of this and the next |
| `intermediate_key_uri` | Key service URI of the intermediate key | None |
| `leaf_validity_hours` | W | 168; 2 to 720 |

Removed: `signing_key_uri`, `signing_key_rotation_hours`, `signing_key_rotation_cooldown_seconds`. Each setting is read from the file, then `AGENTMESH_SERVER_<NAME>`, then `-set`, like the others. An error message names a key service key by `keyprovider.KeyName`, never by its URI (`internal/keyprovider/keyprovider.go:151-168`).

Client: the profile member `insecure_http` (boolean, default false; section 4.10).

### 4.13 Commands

- New: `agentmesh ca init | sign | revoke` (section 4.3); `agentmesh server admin ca csr | install | install-crl | status` (section 4.4).
- Changed: `agentmesh server admin signing-key list | rotate` and the client's `agentmesh signing-keys list | rotate` keep their names; `rotate` loses `-revoke-previous` and prints the per-leaf counts; `list` prints leaves.
- `agentmesh register`, `login` and `login -human`, and `agentmesh-mcponly register` and `check`, take `-accept-new-root`. `agentmesh register` and every `agentmesh-mcponly` command take `-insecure-http` (section 4.10).
- Any command that makes first contact prints the pinned root's thumbprint once.

### 4.14 Health (approved section 3)

The administrator tier of `GET /v1/health` gains a `signing` object, built by `internal/core/health` from the answering process's leaf manager:

- the intermediate in use: thumbprint, "not after", days left;
- the current leaf: thumbprint, "not before", "not after", when the next renewal is due;
- the trust number and each CRL's number;
- the last renewal failure: when and a short message (redacted and capped by the backend, as today), cleared by the next success.

The status is `degraded` (still HTTP 200) when the intermediate expires within 30 days, when the last renewal failed, when the leaf has expired, or when the intermediate is on the root CRL. The probe and identity tiers show none of it.

### 4.15 Start-up and failure states

| State at start | Result |
| --- | --- |
| `root_certificate_file` unset, unreadable or not one CA certificate | Exit 2 |
| Neither or both of `intermediate_key_file` and `intermediate_key_uri` | Exit 2 |
| Key file missing, not owner-only or not an ECDSA P-256 key | Exit 2 |
| No stored intermediate certificate that matches the configured key and chains to the root | Exit 2; the message names `agentmesh server admin ca csr` and `ca install` |
| The matching intermediate has expired or is on the stored root CRL | Exit 2 |
| A backend scheme that is not in this build | Exit 2, with the build tag, as today (`internal/server/cmd/keyprovider.go:31-34`) |
| The key service does not answer while the first leaf is issued | Exit 1 |
| `token_lifetime_seconds` or a human lifetime above W/2 | Exit 2 |
| The store does not answer | As today |

| State while running | Result |
| --- | --- |
| Renewal fails | Retry schedule of section 4.6; health `degraded` |
| Leaf expired, no renewal | Retryable 503 on the token endpoint and on appends; health `degraded` |
| Own leaf found on the leaf CRL | Issue a new leaf at once |
| Intermediate found expired or on the root CRL | Stop issuing and signing; retryable 503 on the token endpoint and on appends; health `degraded`; an error log line every reload |
| A stored certificate or CRL fails verification | Ignored, logged with its thumbprint; never a 500 (the no-500 rule, ADR 0001 addendum) |

| Client state | Result |
| --- | --- |
| A server profile with an `http` URL that is not loopback and no `insecure_http` | Exit 2, naming the switch |
| No pin and discover cannot be reached | The command fails as it does today when the server cannot be reached |
| The root in discover differs from the pin | Exit 2, naming both thumbprints and `-accept-new-root` |
| A pin, and discover cannot be reached | The client goes on with the trust it holds |

### 4.16 Removed

- The `signing_keys` table and its Store methods (section 4.5).
- `keyprovider.StoreProvider` (`internal/keyprovider/keyprovider.go:63-118`). A new `FileProvider` (standard library only) opens the PEM file; `Provider.Next` and `Provider.Signer` keep their shapes.
- The key set rules of `internal/core/signingkeys`: `EnsureActive`, `PrepareRotation`, `ApplyRotation`, `RotatePrepared`, `Rotate`, `RotateDue`, `RemoveExpired`, `RemoveAfter`, `ErrCooldown`, `ErrRotateNoChange` and the row-trusting `Keyring` (`internal/core/signingkeys/service.go`, `schedule.go`, `keyring.go`).
- The maintenance jobs `signing key rotation` and `signing key removal`. One job replaces them, `expired leaf removal`: it deletes leaf rows whose "not after" is more than an hour past. Spec 2 narrows it to rows no message refers to.
- The three settings of section 4.12 and the `revoke_previous` parameter.
- The first-start line `adopted signing key ...` (`internal/server/cmd/cmd.go:174-177`); the start line names the leaf thumbprint and its expiry instead.

## 5. Repeat, overlap and failed runs

| Action | Second run | Two runs at once | After a failed run |
| --- | --- | --- | --- |
| `ca csr` | Prints a new CSR for the same key | Both print a CSR; when the key file is being created, one creates it and the other reads it | No partial key file (linked into place whole); nothing in the database |
| `ca install` | The same certificate again: no change, exit 0, trust number unchanged | Serialized by the `trust` lock; the second finds the row | One transaction: either the row and the bump, or nothing |
| `ca install-crl` | The same CRL again: no change, exit 0. A lower number: refused, exit 2 | Serialized by the `trust` lock | One transaction |
| Server start | Issues a fresh leaf every start; the previous process's leaf stays valid until it expires or is revoked | Replicas start independently; each has its own leaf | A start that failed before step 5 of section 4.6 left nothing; after it, an unused leaf row |
| Leaf renewal | Not repeated: the timer is set from the current leaf | One timer per process | Retry schedule; the current leaf keeps signing until it expires |
| Forced renewal (API) | Same idempotency key: the first answer, counts included, and nothing changes. No key: another renewal that also revokes the leaf the first one issued | Serialized by the `trust` lock; the loser answers a retryable `unavailable` and, retried, runs after the winner | Failed before the transaction: a lost, unused leaf. The transaction is atomic. The lock is a lease on SQLite and a connection-bound lock on Postgres, so a dead holder frees it |
| Forced renewal (host command) | Revokes whatever leaves are unexpired at that moment, including ones issued since the first run | Serialized by the `trust` lock | One transaction |
| Client first contact | The pin exists: compare, do not replace | The second process finds the first's pin | Nothing pinned until the root file is in place (atomic replace) |
| `-accept-new-root` | The new root is already the pin: no change | Lock file | Atomic replace of the pin, then the chain and CRLs; a rerun completes it |
| Client stores a bundle | No change | Lock file; higher numbers win | Atomic replace; the previous files stay |

## 6. Accepted risks

In plain words; ADR 0019 holds the same list.

1. Whoever can write the database can still act as the application's administrator: set the administrator flag, add a login key for any agent, edit ACLs, the `users` and `admins` lists and identity rows (Decision 15). This design does not try to stop that.
2. Whoever can write the database can hide a revocation from clients and server processes that have not seen it yet, by putting back an older CRL or a lower trust number. A restarted server process forgets what it had seen. The harm ends when the hidden leaf expires, at most W after it was issued (Decision 6).
3. Whoever can write the database can remove a leaf's row before a forced renewal, so that leaf is not put on the CRL. It still expires within W (Ruling 8).
4. A client pins the root from the first discover answer it gets (Decision 19). Over HTTPS the answer comes from whoever holds a certificate for the server's name that the system's roots accept. With `insecure_http` on a network that is not loopback, anyone on the path can supply a root of their own; the switch is for local testing.
5. Whoever holds the intermediate key file, or may ask the key service to sign with the intermediate key, can issue leaves and so mint bearers for any identity. The file needs the care the database credential gets today.
6. Whoever can read a server process's memory has its leaf key until the leaf expires or is revoked.
7. A bearer signed by a leaf that was just revoked is accepted by other replicas for up to 30 seconds.
8. A forced renewal makes everything the revoked leaves signed unverifiable (Decision 16).

## 7. Tests

- **Fixtures** build a throwaway root in process through `internal/pki/rootca`, issue an intermediate into a temporary key file and install it (approved section 3). One helper serves `internal/server`, `internal/server/cmd`, `internal/e2e`, the inproc Bus suite and `TestAuthEndToEnd`. `scripts/cats-harness.sh up` and `scripts/docker-smoke.sh` run the real commands (`ca init`, `ca csr`, `ca sign`, `ca install`). Every fixture server listens on loopback, so no test needs `insecure_http` except the ones that test it.
- **`internal/pki`**: the certificate profiles; chain verification (good chain, wrong root, expired intermediate at the checked time, path length, missing usages); CRL creation and checks (signature, numbers, a CRL from another issuer).
- **Root tool**: each row of the table in section 4.3, including the refusal to overwrite.
- **Host commands**: each check of `ca install` and `ca install-crl` fails with its own message and exit 2; the repeat rows of section 5.
- **Start-up**: each row of the first table in section 4.15 with its exit code.
- **Leaf manager on a fake clock**: renewal at W/2; the retry times after a failure (one eighth of the time left, one-minute floor); expiry leading to 503 on the token endpoint; recovery on the next success; the clock-outside-validity case.
- **Bearers**: a bearer from a leaf whose row is missing, altered, self-signed, under another root, expired or revoked is refused; a forged row is not trusted (the mutation that replaces threat 2's test); the expiry cap; the W/2 configuration check.
- **Replicas on both engines** (`TestReplicas*`): a bearer from one replica is accepted by the other; a forced renewal on one makes the other issue a new leaf and refuse the old bearer within the reload interval; two forced renewals at once.
- **Forced renewal report**: one `revoked` entry per leaf with the three counts (0 in this spec); the same key replays the same answer.
- **Discover**: carries the bundle with `root` from a server and none in local mode; answers 200 with the bundle while the store is closed, from the in-memory copy (a new test of what the operation's description promises, `api/openapi.yaml:125`).
- **In-band delivery**: session open and receive with a lower, equal and absent `trust_number`; a watch that wakes on a trust number change with no message.
- **Profile rule**: `https` accepted; `http` to `127.0.0.1`, `::1` and `localhost` accepted; `http` to another host refused with the switch named; accepted with each of the three forms of `insecure_http`; an unknown value of `AGENTMESH_INSECURE_HTTP` refused.
- **Client trust store**: first contact pins and prints; a different root is refused and nothing is overwritten; `-accept-new-root` replaces pin, chain and CRLs; a lower CRL number is refused and logged; two processes at first contact; two writers; a crash between files; discover unreachable with and without a pin; the hooks make no discover call.
- **Key service intermediate**: the existing fakes (`internal/keyprovider/kmsfake`) issue leaves and CRLs; the outage paths (exit 1 at start, retry while running); `make vet-tags`.
- **No 500**: a tampered `trust_material` row in each kind answers a declared status.

## 8. Gates

- `TestWireRoundTrip`: the new and changed schemas (`TrustBundle`, `Discovery`, `Session`, `ReceiveResult`, `Wake`, `SigningKey`, `SigningKeyList`, `SigningKeyRotation`) and their Bus types.
- `TestToolCoverage`: the new Bus input and result members (`trust_number`, `trust`) as `used` or `hidden` with a reason.
- `TestSpecBounds` and `core_bound_rows.txt`: the new request fields.
- `TestSpecDescriptions`, `TestSpecExamples`, `TestRequestExamples`: descriptions and examples for every new element; the three `spec_jwk_*` tests for the changed `JWK`.
- `TestStatusTable` and `TestOperationErrorTable`: the two signing key operations (no cooldown `conflict`).
- `api/arazzo.yaml` workflow `signing-key-rotation` and `TestArazzoWorkflows`: rotate without `revoke_previous`; the e2e fixture drops `signing_key_rotation_cooldown_seconds=1`.
- `TestHelpExamples` and `internal/mcpcli/help.go`: the help texts that show an `http` server keep a loopback one or show the switch.
- `scripts/m7-exit-checks.sh`: the `keyprovider-leaf` rule loses the store provider and gains `FileProvider`; a new rule `pki-leaf`: `internal/pki` and `internal/pki/rootca` import the standard library only (and `rootca` imports `internal/pki`); `internal/trust` imports the standard library, `internal/filelock` and `internal/pki` only.
- `scripts/m10-exit-checks.sh`: the module list of the MCP-only binary stays at 13; no change to the allowlist.
- `scripts/check-gates-selftest.sh`: one mutation per new import rule; one that makes bearer verification trust a row without checking its chain (it must fail the forged-row test); one that drops the loopback test from the profile rule (it must fail the profile tests).
- `make verify`, `ci.yml` and `windows.yml` green; the file mode check of the key file follows the existing owner-only rule on Windows (`internal/fileacl`).

## 9. Documents the plan updates

- `docs/ops/signing-keys.md` is rewritten when this spec is implemented, not before: the hierarchy, the outside-CA profile, the four backends as stores of the intermediate key, forced renewal and what it costs. Until then it describes the code as it is.
- Also with the implementation: `docs/ops/configuration.md`, `docs/ops/deploy.md`, `docs/ops/admin-bootstrap.md`, `docs/ops/backup.md` (the database holds no private key), `docs/ops/health.md`, `docs/ops/upgrade.md`, `docs/install.md` (HTTPS and the switch), `CLAUDE.md` (commands and design notes), the threat model (SD1, SD3, SD6 and threats 1, 2, 6 and 15 once built) and its TMI mirror.

## 10. What spec 2 adds to this

Spec 2 uses the leaf to sign every message, adds columns to `messages`, narrows the `expired leaf removal` job, fills the counts of the forced renewal report, and gives clients the verification step. It needs everything in sections 4.2 to 4.10.

## 11. Plan rulings on the points the first draft left open

None of these is Eric's decision. Each stands as the first draft's recommendation; Eric may overrule any of them. The numbers are the first draft's open question numbers. Numbers 1, 2 and 5 are missing because Eric decided them (Decisions 19 and 16).

**Ruling 3: one trust number.** The wire carries one unsigned trust number, raised with every change to a CRL or to the intermediates; clients enforce the signed number inside each CRL. Not taken: carrying each CRL's own number; or one installation-wide leaf CRL reissued on every change so that its number could serve, which fails when the only intermediate is the thing being revoked, because nothing can sign the reissue. It fits Decision 19: discover carries the same number in its bundle.

**Ruling 4: one leaf CRL per intermediate key.** Standard scope: a leaf CRL lists the leaves of the key that signs it. A forced renewal revokes the leaves under the acting process's key and reports any others as not covered. While two intermediate keys are in use (a key change in progress), the old key's leaves are cut off by revoking the old intermediate with the root tool, or expire within W. Not taken: one list for the installation signed by whichever key acts; a stolen old key could then sign a newer list that un-revokes leaves of the new key.

**Ruling 6: rotate always revokes.** `revoke_previous`, the cooldown and all three `signing_key_*` settings are removed; routine renewal is automatic at W/2. Not taken: keeping `revoke_previous` so that a plain rotate only makes every process renew; that does nothing W/2 does not already do.

**Ruling 7: entries stay, rows go when unused.** A revoked entry stays on the leaf CRL for the life of the intermediate key, because removing it would make that leaf's history verify again, against Decision 5. An entry is about 40 bytes. Leaf rows are deleted once expired and, with spec 2, once no message refers to them. Not taken: dropping an entry once the database holds nothing the leaf signed; the CRL would then depend on database contents.

**Ruling 8: the leaves to revoke are listed from the table.** A writer who removes a leaf's row first keeps it off the CRL until it expires; accepted (section 6 item 3). Not taken: a "revoked before" time in the CRL as a private extension, which needs no table but is not standard and races between replicas with different clocks.

**Ruling 9: a key service intermediate.** The operator creates the key; `ca csr` resolves the URI and has the service sign the CSR; `ca install` records the resolved reference in the intermediate's row; every leaf is checked against the intermediate certificate before use, which also covers `awskms`, the one backend that does not verify after signing (ADR 0012, controller ruling 3). Not taken: no stored reference, with every process resolving the URI at start; adding a key version in the service would then stop the server until `ca csr` and `ca install` were run again.

**Ruling 10: the JWKS endpoint stays.** `GET /v1/auth/jwks` and `jwks_uri` are kept and serve the live leaves as JWKs with `x5c`, so the operation counts stay 57, 8 and 49 and the required metadata member keeps a meaning. Not taken: removing both.

**Ruling 11: setting names.** `root_certificate_file`, `intermediate_key_file`, `intermediate_key_uri`, `leaf_validity_hours`. Not taken: keeping `signing_key_uri` for the key service URI; the name would describe the wrong key.

**Ruling 12: "reads continue" when the leaf has expired.** The approved section says that with an expired, unrenewed leaf "writes and token exchange answer a retryable 503; reads continue". Every bearer a process signed expires no later than its leaf (section 4.7). So on a single server no bearer is left to read with, and on several replicas reads continue only with bearers from the healthy ones. The rule is kept and the operator guide says this plainly: a single server whose renewals fail for W/2 stops serving authenticated requests until a renewal succeeds, with health `degraded` from the first failure. Not taken: judging a bearer by whether it was issued inside its leaf's validity period and dropping the expiry cap.

**Ruling 13: clock rules.** No rule compares one replica's clock with another's for messages: a process signs with its own leaf, issued by its own clock. A leaf's "not before" is set 60 seconds back (the existing leeway). A process does not sign when its own clock is outside its leaf's validity period; it issues a new leaf. A chain is checked at the signed time for a message and at the current time, with the 60-second leeway, for a bearer. A CRL's signer is checked at the CRL's "this update" time. Clients apply no leeway to a message's time. Not taken: a 60-second allowance on the client for messages; the signer guarantees the time is inside, so the verifier can be exact.

**Ruling 24 (stated in section 4.9; it follows from Decision 19): a process calls discover once when it opens the `Bus` of a server profile,** the hooks excepted. This is how a client with no session refreshes its CRLs.
