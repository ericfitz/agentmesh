# Certificate hierarchy for key storage and rotation (design spec 1 of 2)

## 1. Status

- Approved by Eric, 2026-11-11 (second draft plus Decision 21). The first draft is commit `d3f5b56`; the second folds in Eric's rulings of 2026-11-11 on that draft's open questions. Nothing here is built.
- Third revision, 2026-11-12: it folds in Eric's rulings on the security review of the two approved specs (ADR 0019, Decisions 22 to 35). The rulings are his. The text that carries them out was approved by him on 2026-11-12 (Decision 49); the plan rulings it needed (section 12) stay rulings he may overrule.
- Fourth revision, 2026-11-12: it folds in Eric's decisions of that day on four points the third revision left open (ADR 0019, Decisions 36 to 39): the identifier of the extended key usage, distinct installation names under one root, an expected installation name, and a time-based trust number. It also restates what spec 2 adds to this spec, because Eric reduced spec 2 to human messages (Decision 40). The decisions are his. The text that carries them out was approved by him on 2026-11-12 (Decision 49); the plan rulings it needed (section 13) stay rulings he may overrule.
- Approved by Eric, 2026-11-12 (ADR 0019, Decision 49): the text of the third and fourth revisions. The plan rulings of sections 12 and 13 stay rulings he may overrule. Decision 47 lets the work be built on a branch with a refused stand-in for the enterprise number (section 8), and Decision 48 settles which stored intermediate a process with a key service signs with.
- This is spec 1 of 2. Spec 2, `docs/superpowers/specs/2026-11-11-signed-messages-design.md`, puts signed human messages on top of this hierarchy. Spec 1 ships alone (Decision 13): it moves the server's signing keys out of the database and makes bearers verify by a certificate chain instead of by database rows.
- The record of decisions is ADR 0019 (`docs/adr/0019-certificate-hierarchy-and-signed-messages.md`).
- It replaces the abandoned server key file design (`docs/superpowers/specs/2026-11-10-server-key-file-design.md`; ADR 0012, "Server key file design abandoned (2026-11-11)").
- Labels used below:
  - **(Eric 2026-11-11, Decision N)**: one of Eric's twenty-one decisions of 2026-11-11, numbered as in ADR 0019. Decisions 16 to 20 are his rulings on the first draft's open questions, Decision 21 his ruling on the second draft's Open question 28.
  - **(Eric 2026-11-12, Decision N)**: one of his rulings on the security review, Decisions 22 to 35 in ADR 0019, or one of his later decisions of the same day, Decisions 36 to 46 (43 to 46 concern spec 2 only).
  - **(plan ruling)**: a proposal made while writing the design. Eric approved the ones that come from the three design sections of 2026-11-11 as part of those sections. The others are not his decisions, and he may overrule any of them.
  - **Ruling N**: for N up to 26, the plan ruling on what the first draft called Open question N. Section 11 lists them (3, 4, 6 to 13 and 24 here; 14 to 16, 18 to 22, 25 and 26 are in spec 2) with the alternative not taken. Rulings 30 to 36 (section 12 here; 37 to 41 are in spec 2) are the plan rulings made on 2026-11-12 for the details the review rulings did not give; they answer no open question. Rulings 42 to 45 (section 13 here; 46 to 54 are in spec 2) are the plan rulings made for Decisions 36 to 39. None of them is Eric's decision.
- This spec has no open question. Open question 29, the identifier of the extended key usage, is settled by Decision 36. The number that identifier needs is not assigned yet, and **this spec does not ship until it is** (section 4.2; Ruling 42). Spec 2 has none either.
- Every statement about today's code was checked against the tree at commit `d3f5b56` and carries a `path:line` citation. The citations added on 2026-11-12 were checked at commit `5e133d3`; nothing under `internal/`, `api/`, `scripts/` or `cmd/` changed between the two, or between `5e133d3` and `93bc9c4`, where the fourth revision was checked.

## 2. What this changes, in short

Today the server signs bearers with a key whose public half, and by default whose private half, is a database row. Whoever can write that table can add a key of their own and forge bearers; whoever can read it can, by default, take the private key.

After this spec:

- A root certificate authority (CA) sits outside the server. Its certificate is pinned in the server's configuration and on every client (Eric's outline). agentmesh ships a small tool to run one (Decision 9).
- Each installation holds one intermediate CA key, in a PEM file or a key service, with a certificate the root issued (Decisions 4 and 10). The certificate names the installation, and verifiers accept no other installation's (Decision 23).
- Each server process makes its own signing key in memory at start and has the intermediate issue a short-lived leaf certificate for it. The key is never written anywhere (Decision 4).
- Bearers are signed by the leaf and verified by the chain to the pinned root. No key and no trust decision about a key comes from the database.
- Revocation is by certificate revocation lists (CRLs), delivered to clients inside ordinary responses (Decisions 6 and 12).
- A client gets the root, the chain and the CRLs from the discover document and pins the root, with the installation's name, on first contact, over HTTPS by default (Decisions 19 and 23). A profile can name the root it expects and the installation it expects (Decisions 30 and 38).
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
| Intermediate | ECDSA P-256 | The root | Chosen by the CA; the root tool default is 365 days | CA true, path length 0 (critical); key usage certificate signing and CRL signing (critical); subject key identifier; authority key identifier; the agentmesh extended key usage (below) |
| Leaf | Ed25519, made in memory by the server process | The intermediate | W, default 7 days (section 4.6) | CA false (critical); key usage digital signature (critical); subject and authority key identifiers; random 128-bit serial number; the agentmesh extended key usage |

Plan rulings:

1. The intermediate key is ECDSA P-256 in both storage forms, because the four key service backends accept only that (`internal/keyprovider/keyprovider.go:174-187`) and one algorithm at the CA level is simpler than two.
2. A certificate is named by its thumbprint: the SHA-256 of its DER encoding, base64url without padding. This is the value of the JWS header `x5t#S256`.
3. The intermediate must carry a subject key identifier and the CRL signing usage, because Go's `x509.CreateRevocationList` refuses an issuer without them (Go 1.27, `crypto/x509/x509.go`, `CreateRevocationList`).
4. A leaf's "not after" is never later than its intermediate certificate's "not after".

**The installation name** (Eric 2026-11-12, Decision 23). Several installations can sit under one root (Eric's outline), and an outside CA's root may have issued CA certificates for other purposes. So that one installation does not accept another's certificates, bearers or messages, an intermediate certificate names its installation: its subject common name is the installation's name. The server knows its own name from the setting `installation_name` (section 4.12), `ca csr` puts that name in the request, a client pins the name together with the root on first contact (section 4.10), and both verifiers accept only an intermediate whose subject common name is that name (the chain check below). The name's form, the setting's name and how the client receives it are Ruling 30. The root's administrator gives each installation under one root a name of its own. The shipped root tool holds to that: `ca sign` refuses a name it has already issued to a different key unless it is told that this is the same installation (Eric 2026-11-12, Decision 37; section 4.3). agentmesh cannot check it for an outside CA; there it stays the operator's duty, and the operator guide says so.

**The agentmesh extended key usage** (Decision 23). The intermediate and the leaf carry one extended key usage that means "agentmesh signing", so a CA certificate the same root issued for another purpose is not an agentmesh intermediate. The root does not carry it. Go's chain verification asks for the server authentication usage unless told otherwise (Go 1.27, `crypto/x509/verify.go:623-625`), so the verifiers ask the library for any usage and check this one themselves, on the intermediate and on the leaf. The shape is Ruling 31. The identifier is `1.3.6.1.4.1.<PEN>.1.1`, where `<PEN>` is the Private Enterprise Number that IANA assigns to Trojan Unicorn Ventures, the publisher (Eric 2026-11-12, Decision 36; it settles Open question 29). The number is to be registered and is not assigned yet. This spec does not ship until it is: the constant is written once, from the assigned number, and no stand-in value is accepted in its place (Ruling 42).

**The chain check** is one function of `internal/pki` that both verifiers call: the server for a bearer (section 4.7) and, with spec 2, every client for a human message (spec 2 section 4.10). A chain is accepted only when all of these hold:

1. It has exactly three certificates: the leaf, one intermediate and the pinned root (Eric 2026-11-12, Decision 32).
2. Each signature verifies, and each of the three certificates is inside its validity period at the checked time: the current time for a bearer, the signed time for a message (Ruling 13; Ruling 36 for the root).
3. The intermediate has the profile of the table above, its subject common name is the installation name the verifier holds, and it carries the agentmesh extended key usage (Decision 23).
4. The leaf is CA false with the digital signature usage and carries the agentmesh extended key usage (Decisions 23 and 32).
5. The leaf's validity period, "not after" minus "not before", is no longer than 720 hours plus 60 seconds: the top of `leaf_validity_hours` plus the 60 seconds a leaf's start is set back (Eric 2026-11-12, Decision 25). A process that honors `leaf_validity_hours` never issues a longer one, so a longer one did not come from the leaf manager, and without this rule it would stay valid until the intermediate expires.

Revocation is checked beside the chain check (section 4.8).

**The profile an outside CA must issue** (Decision 9) is the Intermediate row above, with the installation name as the subject common name and with the agentmesh extended key usage, for the public key in the CSR that `ca csr` prints, signed with any algorithm Go's `crypto/x509` verifies, with no name constraints. Every certificate the CA issues for one key carries the same subject key identifier (Ruling 33). The operator guide states the profile in these words and gives an `openssl` example. It also says that revoking an intermediate means revoking every certificate issued for its key (Decision 26; section 4.8), and that each installation under the root gets a name of its own, which an outside CA's operator has to see to, because nothing checks it there (Decision 37).

### 4.3 The root tool (Eric 2026-11-11, Decision 9)

`agentmesh ca` is a small root CA for development, test fixtures and small production installations. It is part of the `agentmesh` binary only (not `agentmesh-mcponly`). It never contacts a server or a database. The command names are a plan ruling Eric approved.

- `agentmesh ca init -dir DIR [-name NAME] [-days N]` makes the root key and the self-signed root certificate. It writes `DIR/root.key` (PKCS#8 PEM, mode 0600), `DIR/root.pem` and `DIR/state.json` (issued certificates, revocations, the CRL number), and prints the path of `root.pem` and its thumbprint.
- `agentmesh ca sign -dir DIR [-days N] [-same-installation] CSR_FILE` checks the CSR's own signature, issues an intermediate certificate with the profile of section 4.2, records it in `state.json` and prints the certificate as PEM. The subject common name is the CSR's, which is the installation name (Decision 23); a CSR without one is refused. The subject key identifier is derived from the public key, so every certificate for one key carries the same one (Ruling 33). The command prints the name on stderr. When `state.json` already records that name for a different public key, it refuses (exit 2), writes nothing and names the flag `-same-installation`: a second installation under the root must not take the first one's name (Eric 2026-11-12, Decision 37). With `-same-installation` it issues the certificate; that is the case of one installation that changes its key (section 4.4). A CSR for the key the name is already recorded with needs no flag; that is a renewal. The details are Ruling 43.
- `agentmesh ca revoke -dir DIR CERT_FILE` marks as revoked the intermediate in `CERT_FILE` and every other certificate in `state.json` with the same public key, and names each certificate it revoked on stderr (Eric 2026-11-12, Decision 26). The new CRL's number is the time of issue in Unix milliseconds, or the previous number plus one when that is higher (Eric 2026-11-12, Decision 27; Ruling 34). It writes `DIR/root.crl` and prints the CRL as PEM. The CRL lists every intermediate ever revoked.

The administrator keeps `DIR` offline (Decision 9). The package behind the tool (`internal/pki/rootca`, a plan ruling) is what test fixtures call in process.

State (repeat, overlap, failure):

| Command | Second run | Two runs at once | After a failed run |
| --- | --- | --- | --- |
| `ca init` | Refuses (exit 2) when `DIR` already holds a root; it never overwrites a key | One wins the exclusive create of `root.key`; the other refuses | A run that died before `root.pem` was written leaves `root.key` only; `init` refuses and names the file to remove |
| `ca sign` | Issues another certificate with a new serial number for the same CSR; both are valid until they expire or the key is revoked. A CSR refused for its name (Decision 37) is refused again the same way | Serialized by a lock file in `DIR` | `state.json` is replaced atomically before the certificate is printed; a certificate recorded but never printed is listed by `state.json` and can be revoked |
| `ca revoke` | Every certificate of that key is already revoked: prints the current CRL, number unchanged | Serialized by the lock file | The CRL file and `state.json` are replaced atomically, state first; a rerun completes it |

Exit codes: 0 done, 2 usage or a refused input, 1 an I/O failure.

### 4.4 The intermediate (Eric 2026-11-11, Decisions 4 and 10)

One intermediate key per installation, shared by every replica (Decision 4). It lives in one of two places (Decision 10):

- **A PEM file** named by the setting `intermediate_key_file` (PKCS#8, mode 0600 or owner-only, checked like the credential files). The operator delivers the same file to every replica (a mounted secret, for example).
- **A key service**, named by the setting `intermediate_key_uri` with one of the four existing schemes (`awskms`, `gcpkms`, `azurekms`, `hashivault`). The service signs in place; the private key never reaches the server. The backends stay behind their build tags.

Exactly one of the two settings is set. The in-database provider is deleted, and there is no backend that fetches a key from a secrets manager (Decision 10).

The host commands (no listener, no credential; they take `-config`, `-sqlite`, `-postgres` and `-set` like the other `server admin` commands):

- `agentmesh server admin ca csr [-out FILE]` prints a certificate signing request for the intermediate key, with the setting `installation_name` as its subject common name (Decision 23). The earlier `-name` flag is gone: the setting is the one source of the name (Ruling 30).
  - File: when the key file does not exist, it creates the key (written through a temporary file and linked into place without replacing an existing file), then prints the CSR. When the file exists, it prints a CSR for that key; this is how a certificate is renewed.
  - Key service: the operator creates the key in the service first; the server never creates, deletes or schedules deletion of an external key, as today (`docs/ops/signing-keys.md`, "Trust boundary"). `ca csr` resolves the URI with `Provider.Next` and has the service sign the CSR (Ruling 9).
  - It writes nothing to the database.
- `agentmesh server admin ca install CERT_FILE` checks the certificate and stores it. The checks: it chains to the pinned root and is inside its validity period; CA true with path length 0; certificate signing and CRL signing usages; a subject key identifier; its public key is the configured intermediate key's; its subject common name is `installation_name` and it carries the agentmesh extended key usage (Decision 23); its subject key identifier is the one that the stored certificates of the same public key carry (Ruling 33); its key is not revoked by the stored root CRL (Decision 26). Each failure names the failed check and exits 2.
- `agentmesh server admin ca install-crl CRL_FILE` checks a root CRL (signed by the pinned root; a number above the stored root CRL's) and stores it.
- `agentmesh server admin ca status` prints the pinned root's thumbprint, the installation name, each stored intermediate (thumbprint, validity, whether it matches the configured key, whether the root CRL lists it), the CRL numbers, the trust number (section 4.8) and the unexpired leaves.

**Renewal** of the intermediate certificate is `ca csr` and `ca install` again with the same key. Earlier intermediate certificates stay in the table, so history signed under an expired intermediate still verifies, and history under a revoked one does not (approved section 3). Revocation is of the key: once any certificate of an intermediate key is on the root CRL, no certificate of that key verifies anything (Eric 2026-11-12, Decision 26; section 4.8). Intermediate rows are never deleted, the revoked and the expired included, because a CRL names a serial number and only the certificate says which key that is (Ruling 33). A running process picks the newest valid certificate for its key the next time it issues a leaf; no restart is needed.

**Changing the intermediate key** is: point the setting at the new key, `ca csr`, have the root sign the request (with the shipped tool: `ca sign -same-installation`, because the name is already recorded with the old key; Decision 37), `ca install`, restart every replica. During the roll, replicas with the old key keep issuing leaves under the old certificate. Ruling 4 says how the old key's leaves are cut off.

**Where the pinned key reference lives** (Ruling 9): for a key service, `ca install` records the resolved reference (the exact key version) in the intermediate's row, and every process signs by that reference. A changed reference cannot make a wrong key trusted: every leaf a process issues is checked against the intermediate certificate before use (section 4.6), so a wrong reference only stops issuing.

### 4.5 The Store

One new table holds everything public (approved section 1): intermediate certificates, leaf certificates and CRLs. Every row is self-verifying: a certificate or CRL that does not check out against the pinned root is ignored and logged, never trusted. An intermediate row that is not signed by the pinned root, names another installation or lacks the agentmesh extended key usage (rule 3 of the chain check, section 4.2) is ignored and logged the same way (Decision 23). An expired or revoked intermediate row is not ignored: it serves history, and it says which key a revoked serial number belongs to (section 4.4). There is no file distribution to replicas.

`trust_material` (both engines; a plan ruling on names):

| Column | Meaning |
| --- | --- |
| `id` | Row id |
| `kind` | `intermediate`, `leaf`, `root_crl`, `leaf_crl` or `trust_number` |
| `thumbprint` | SHA-256 of `der`, base64url; unique per kind |
| `der` | The certificate or CRL, DER; empty for `trust_number` |
| `issuer_key` | The subject key identifier of the issuing key, hex: for a leaf and a leaf CRL, the intermediate key; empty otherwise |
| `not_after` | Extracted copy, Unix milliseconds, for listing and cleanup; 0 for CRLs |
| `number` | The CRL number for a CRL row; the trust number for the `trust_number` row; 0 otherwise. A 64-bit integer on both engines (`BIGINT` on Postgres), because both numbers are times in Unix milliseconds (Decisions 27 and 39) |
| `key_ref` | Intermediate rows with a key service: the pinned key reference; empty otherwise |
| `created_at` | Unix milliseconds |

Rules:

- At most one `root_crl` row, one `leaf_crl` row per `issuer_key` (Ruling 4), and exactly one `trust_number` row (created with the schema, value 0).
- Intermediate rows are never deleted (section 4.4). Leaf rows are (section 4.8).
- The Store serves these rows as facts and applies no rule to them, like every other table (ADR 0004 addendum "Access facts, not rules"). New `Tx` methods: `PutTrustCertificate`, `TrustCertificates(kind)`, `TrustCertificateByThumbprint`, `PutCRL` (replaces the row only when the new number is higher; otherwise `ErrConflict`), `CRLs`, `TrustNumber`, `BumpTrustNumber(now)` (sets the number to the larger of `now` in Unix milliseconds and the stored number plus one, and returns it; Decision 39), `ExpiredLeafCertificates(before, limit)` and `DeleteTrustCertificates(ids)`.
- Schema: changed in place in both `0001_initial.sql` files; the schema version stays 1; no migration; local data is recreated (the pre-release rule, CLAUDE.md, Eric 2026-10-25).
- The Store lock `trust` (`Store.Locks`, `internal/store/lock.go:11-21`) serializes every change to CRLs. A change and its trust number bump commit in one transaction (approved section 3).

Removed: the `signing_keys` table and index, `store.SigningKey`, `store.SigningProviders` and the five `SigningKeys` methods (`internal/store/signing.go:8-62`).

### 4.6 The leaf (Eric 2026-11-11, Decision 4; approved section 1)

Each server process holds one Ed25519 signing key, generated at start, kept in memory and never written anywhere. The same leaf signs bearers and, with spec 2, human messages (Decisions 4 and 40).

**Issuing a leaf** (at start and at each renewal):

1. Generate the key pair in memory.
2. Build the certificate (section 4.2) with "not before" = now minus 60 seconds (Ruling 13) and "not after" = now plus W, cut to the intermediate's "not after".
3. Have the intermediate key sign it: a local signature for the file, one sign call for a key service, bounded by the existing 30-second limit (`internal/core/signingkeys/service.go:27-30`).
4. Verify the new certificate against the intermediate certificate and the pinned root with the chain check of section 4.2. A failure here means the configured key is not the certificate's key; it is logged and counts as a failed issue.
5. Insert the leaf's row.
6. Only then start signing with it.

A crash or failure between steps 3 and 6 leaves at most an unused certificate; a certificate whose row was never inserted is simply lost (approved section 3).

**Validity and renewal:**

- W is `leaf_validity_hours`, default 168 (7 days; Eric approved the default), from 2 to 720 (the bounds are a plan ruling).
- At W/2 the process issues its next leaf and signs with it from then on. The previous leaf stays valid for verification until it expires. So two leaves per process are valid at any time, as Eric's outline asks.
- When a renewal fails, the process retries after one eighth of the time left before the current leaf expires, never sooner than one minute. The retries therefore come more often toward the end.
- When the leaf has expired and no renewal has succeeded: every operation that needs a signature answers a retryable 503. That is the token endpoint (`temporarily_unavailable`, as for an unavailable signing key today: `internal/server/auth_handlers.go:125-128`, `internal/server/auth_exchange.go:138-140`) and, with spec 2, every append of a human message, the only appends that are signed (Decision 40). Other requests are served as long as their bearer verifies. Ruling 12 says what that means on a single server.
- A process never signs outside its leaf's validity period as its own clock sees it; if the clock is outside (a clock step), it treats the leaf as expired and issues a new one (Ruling 13).

**The port.** `internal/core/signingkeys` is rewritten as the leaf manager (the package name is kept; a plan ruling). It holds the current and previous leaf, runs the renewal timer, and is the issuer's `token.KeySource`: the signer is the current leaf's key, and the published set is every leaf it has verified.

### 4.7 Bearers

- A bearer is the same `at+jwt` as today, signed by the current leaf (EdDSA). Its header carries `x5t#S256`, the leaf certificate's thumbprint, and `kid` with the same value (set as extra headers the way `kid` is set today, `internal/auth/token/issuer.go:312-313`).
- A bearer's expiry is the earlier of now plus its lifetime and the leaf's "not after". The configuration is refused (exit 2) when `token_lifetime_seconds` or an issuer's human lifetime is more than W/2, so a bearer minted by a healthy process always gets its full lifetime (approved section 1: "Bearer lifetime capped at W/2").
- Verification, on any replica: read the thumbprint from the header; take the leaf from the process's verified set, or load its row by thumbprint (the existing single-flight reload for an unknown key, `issuer.go:198-226`); run the chain check of section 4.2 at the current time with the existing 60-second leeway (`issuer.go:27-28`), which accepts exactly leaf, intermediate, pinned root, an intermediate named for this installation, the agentmesh usage on both and a leaf lifetime within the ceiling (Decisions 23 and 25); refuse a leaf that is revoked or whose intermediate key is revoked (section 4.8; Decisions 26 and 27); then the checks of today (type, signature, issuer, audience, expiry, subject).
- A row is never trusted for what it claims. A leaf row that does not chain to the pinned root is the same as no row. Chaining to the root is not enough either: a leaf under another installation's intermediate, or under a CA certificate the root issued for another purpose, fails the chain check even when both rows are present (Decision 23). This closes threat 2: inserting a key into the database no longer makes it trusted.
- Replicas: a bearer minted by one replica is accepted by another through the leaf's row and the shared intermediate. Each process reloads the trust material every 30 seconds (the existing `token.ReloadInterval`) and at once after a local change.

### 4.8 Revocation (Eric 2026-11-11, Decisions 5, 6, 12 and 16; Eric 2026-11-12, Decisions 25, 26, 27, 39 and 40; approved section 1)

**Two kinds of CRL**, both standard X.509 CRLs with a CRL number:

- **The root CRL** lists revoked intermediates. The root tool (or an outside CA) issues it; `ca install-crl` stores it.
- **The leaf CRL** lists revoked leaves by serial number. The intermediate signs it; the server writes it. There is one per intermediate key, covering that key's leaves (Ruling 4).

**What revocation means** (Decision 5): a revoked leaf, or a leaf under a revoked intermediate, verifies nothing, whatever it signed and whenever. Expiry alone never invalidates history: with spec 2, a human message verifies when its signed time is inside its leaf's validity period.

**An intermediate is revoked by key** (Eric 2026-11-12, Decision 26). After one renewal an intermediate key has two certificates, and a leaf signed by that key chains through either. A root CRL lists serial numbers. So a verifier finds, among the intermediate certificates it holds, each one whose serial number is on the root CRL, and treats that certificate's key as revoked: every intermediate certificate with the same subject key identifier is revoked with it, whichever one the CRL lists. This also covers an outside CA whose operator revokes only one of a key's certificates. A listed serial number that matches no certificate the verifier holds tells it nothing about a key, which is why `ca revoke` and the outside-CA guide revoke every certificate of the key, and why no party drops an intermediate certificate (Ruling 33).

**Forced renewal.** The existing rotate operation becomes "issue a new leaf here and put every other unexpired leaf on the CRL" (approved section 1; Eric's outline: "a server API forces immediate renewal with revocation of the previous certificate"). It always revokes and is never refused for being too soon; `revoke_previous` and the cooldown are gone (Ruling 6). In the handling process:

1. Check the caller is an administrator and look for a receipt of the idempotency key, as today (`internal/core/signingkeys/api.go:76-103`). With spec 2 the caller's bearer must also carry the human claim (Eric 2026-11-12, Decisions 28, 41 and 42; spec 2 section 4.18); in this spec alone the administrator flag is the whole check.
2. Take the Store lock `trust`. If another process holds it, answer a retryable `unavailable`.
3. Reload the trust material.
4. Issue a new leaf (section 4.6, steps 1 to 4).
5. Build the next leaf CRL: every entry of the stored one, every revoked serial number this process holds for the key (the union, below), and every unexpired leaf row under this intermediate key except the new leaf. Its number is the time of issue in Unix milliseconds, or the stored number plus one when that is higher (Eric 2026-11-12, Decision 27; Ruling 34), so a number does not go back after a restore. Sign it with the intermediate key.
6. In one transaction: check the administrator again, count what each newly revoked leaf signed (below), store the receipt, insert the new leaf's row, replace the leaf CRL row, raise the trust number.
7. After the commit: sign with the new leaf, wake the watchers (section 4.9), release the lock.

Other replicas see their leaf on the CRL at their next reload and issue a new one at once (approved section 1). Until a replica reloads (at most 30 seconds, or sooner on a Postgres notification), it still signs bearers with a revoked leaf; the replica that revoked refuses them at once, and the others once they reload. This is the propagation delay of today's `revoke_previous` (ADR 0012, decision 4).

The host command `agentmesh server admin signing-key rotate` does the lock, the reload, the CRL and the transaction without a new leaf: it revokes every unexpired leaf under the configured key, and the running processes issue new ones as above.

**Revoking one leaf that has no row** (Eric 2026-11-12, Decision 25). A leaf certificate can exist without a row: one whose row was removed, or one that the intermediate key was made to sign outside the leaf manager. A forced renewal lists leaves from the table and misses it, and until now the only remedy was to revoke the intermediate, at the cost of all history. The host command `agentmesh server admin signing-key revoke -cert FILE | -serial S` puts one leaf on the leaf CRL of the configured intermediate key:

- Exactly one of the two flags is given. With `-cert` the certificate must be signed by the configured intermediate key (exit 2 otherwise) and its serial number is taken from it. With `-serial` (hexadecimal) the number is listed as given, because without the certificate nothing about it can be checked.
- It takes the `trust` lock, builds the next leaf CRL as step 5 above does, and stores it and raises the trust number in one transaction, like the host form of rotate. It issues no leaf.
- It prints one `revoked` entry with the count of Decision 16: that of the leaf's row when it has one, 0 when it has none.
- A process that finds its own leaf listed issues a new one, as after a forced renewal.

The details are Ruling 32.

**What a forced renewal costs, and the report** (Decision 16, as changed by Decision 40). By Decision 5, everything the revoked leaves signed stops verifying. In this spec alone that is bearers. With spec 2 it is also the human messages those leaves signed, from every replica, for up to W: clients drop them from then on (spec 2 sections 4.10 and 4.12). Eric accepted this. Nothing else is signed (Decision 40), so a forced renewal no longer makes a memory or a task uneditable, or unreadable through its tools; what it does to a revision that a human wrote is spec 2 section 7 item 2. Both forms of the command report, for each leaf they revoke, how many human messages it had signed, so the operator sees the cost. In spec 1 alone the count is always 0, because nothing but bearers is signed yet; spec 2 section 4.8 says how it is counted. Revoking an intermediate does the same to everything under it. There is no re-sign path (Eric's outline: "no signing of data in the database").

**Entries and rows are kept** (Ruling 7): a revoked entry stays on the leaf CRL for the life of the intermediate key. Leaf rows are deleted once expired and, with spec 2, once no message refers to them.

**The list of leaves to revoke comes from the table** (Ruling 8): a database writer who removes a leaf's row first keeps that leaf off the CRL until it expires. `signing-key revoke` lists such a leaf once its certificate or serial number is known (Decision 25).

**Revoking an intermediate** is done with the root tool: `agentmesh ca revoke`, which revokes every certificate of that key (Decision 26), then `ca install-crl` on the server. A running process that finds its intermediate key revoked stops issuing and signing, logs it and reports it in the health document; a start in that state exits 2.

**Rollback inside a running server.** Each process remembers, in memory, the highest CRL number it has verified for each CRL. A stored CRL with a lower number is ignored and logged as a rollback, and the process writes its newer copy back. A restart forgets this (Decision 6: an accepted risk).

**Revocations only accumulate** (Eric 2026-11-12, Decision 27). A CRL can lose entries: a restore from backup brings back an earlier leaf CRL, and the next one built on it would un-revoke whatever was revoked in between. So no verifier checks revocation against the latest CRL alone. Each keeps the union of the revoked serial numbers of every CRL it has accepted, per issuer key, and a serial number once in the union stays revoked.

- A client keeps the union in its trust store, so it survives restarts (section 4.10).
- A server process keeps it in memory. Every leaf CRL it builds lists the union it holds for that key together with the stored CRL's entries (step 5 above), which is how the union gets back into the database after a rollback. It cannot sign a root CRL, so its union of revoked intermediates lives in memory only, and a restart forgets it.

**The trust number** (Ruling 3; Eric 2026-11-12, Decision 39). Decision 12 speaks of "the current CRL number", but there are at least two CRLs, each with its own number, and a new intermediate certificate changes neither. The wire therefore carries one **trust number**, held in the `trust_number` row and raised in the same transaction as every change to a CRL or to the set of intermediates. Like a CRL number it is time-based (Decision 39): the new value is the larger of the time of the change in Unix milliseconds and the previous value plus one. It is a 64-bit integer (`BIGINT` on Postgres). Eric asked about 2038: that limit belongs to seconds in 32 bits, and milliseconds in 64 bits are not affected. The number only tells a client that there is something to fetch. What a client enforces is the signed number inside each CRL: it refuses a CRL with a lower number than the one it holds for the same issuer (Decision 12).

The server sends the bundle whenever the client's trust number differs from its own, lower or higher (Eric 2026-11-12, Decision 27; this changes Decision 12's "a client that reports an older number"). After a restore the server's number is behind its clients', and they still need what it holds.

**Why the trust number is a time** (Decision 39). A counter that a restore puts back counts up again through values it has already had. A client that took one of those values before the restore would then hold the server's number while the server holds other trust material, and "differs" would not see it. With a time-based number the first change after a restore raises it above every value issued before, as long as the server's clock has not gone back behind them, so the same number never stands for two states. The number still only goes up, which the append check of spec 2 relies on: a process whose held number is below the stored one is behind and must reload before it signs (spec 2 section 4.6). The details are Ruling 45.

### 4.9 Delivery to clients (Eric 2026-11-11, Decisions 6, 12 and 19; Eric 2026-11-12, Decisions 23, 27, 30, 33 and 38)

There is no "next update" enforcement and no state in which a client fails closed because its CRL is old (Decision 6). CRLs carry a "next update" field only because the format expects one; it is set to the issuer's "not after" and nobody enforces it.

**The trust bundle** is one JSON object (schema `TrustBundle`, a plan ruling):

| Member | Content |
| --- | --- |
| `trust_number` | The trust number |
| `intermediates` | Every stored intermediate certificate, the revoked and the expired included, base64 DER |
| `root_crl` | The root CRL, base64 DER; absent when none is installed |
| `leaf_crls` | The leaf CRLs, base64 DER; empty when no leaf was ever revoked |
| `root` | The pinned root certificate, base64 DER; present only in the discover document |
| `installation` | The installation name (section 4.2; Decision 23); present only in the discover document |

**Where it rides:**

1. **The discover document** (Decision 19). `GET /v1/discover` carries `trust`, the whole bundle with `root` and `installation`. This is the one place the root and the name travel. Registration and token responses keep their current shapes. So that discover stays the liveness probe that never touches the store (section 3 item 10), the server answers from the process's in-memory, verified copy of the trust material, the one it reloads every 30 seconds; a plan ruling. In local mode the document has no `trust`.
2. **Session open and every receive** (Decision 12). The request carries the trust number the client holds (`trust_number`, optional, in `OpenSessionRequest` and `ReceiveRequest`). The response always carries the current `trust_number`; when the client's number is absent or differs from the server's (Decision 27), it also carries `trust`, the bundle without `root` and `installation`.
3. **Watch** (the doorbell, Decision 12). `watch` takes the client's `trust_number`; the server wakes the watch at once when its own number differs from it (Decision 27), with a count of 0 and the server's number in the answer. This needs a change, because a watch wakes today only for a pending message (`internal/core/delivery/watch.go:98-123`). The trust transaction publishes a hint in its process and, on Postgres, a notification, so waiting sessions on every replica look again; a replica without notifications (SQLite) notices at its 30-second reload and publishes the hint then.

A client woken this way calls receive, which brings the bundle. `agentmesh wait` exits 0 for it as for a message; a parked session stays silent and catches up on its next receive.

**When a client calls discover** (Ruling 24, which follows from Decision 19). A process calls discover once when it opens the `Bus` of a server profile. That covers first contact, a client with no session (a one-shot `history`, `search` or `memories get` refreshes its CRLs this way), and a long-lived process at its start; after that a session's receives keep it current. The three hooks are the exception: they read no content and must answer within 500 ms, so they do not call discover. When discover cannot be reached and the client already holds a pin, it goes on with what it holds (Decision 6: no failing closed on old CRLs). With no pin it cannot go on.

**A discover answer without `trust` is an error for a server profile** (Eric 2026-11-12, Decision 33). The command fails and says the server sent no trust material, with or without a pin. This is not the unreachable case: a server that answers always has a bundle, so an answer without one is not from an agentmesh server in server mode.

**What the client does with a bundle:**

1. Root and installation name (discover only): with no pinned root for the profile, pin the root received together with `installation` (first contact). When the profile names an expected root (`root_thumbprint`, section 4.10), the received root's thumbprint must equal it, and when it names an expected installation (`installation`, section 4.10), the received name must equal it; otherwise the client stops and pins nothing (Decisions 30 and 38). With a pinned root, a different `root` or a different `installation` is an error: the client stops, names both thumbprints or both names, and names the flag `-accept-new-root` (section 4.10). It never replaces a pin silently.
2. Intermediates: keep each one that is signed by the pinned root and meets rule 3 of the chain check of section 4.2: the profile, the pinned installation name and the extended key usage (Decision 23). Its validity period and its revocation are not tested here, because an expired intermediate still serves history and a revoked one says which key is revoked. The client never drops one it has kept (Decision 26).
3. Root CRL: accept when signed by the pinned root and its number is not below the held one; refuse a lower number (Decision 12). Add its serial numbers to the kept revocations (Decision 27).
4. Leaf CRLs: accept each when signed by a kept intermediate whose key is not revoked and its number is not below the held one for that issuer key; refuse a lower number. Add its serial numbers to the kept revocations of that key.
5. Record the bundle's trust number in place of the held one, higher or lower, once the steps above have run (Decision 27). A CRL refused for a lower number does not prevent this: it is reported once, and the number only says whether there is something to fetch.

With spec 2 the client applies a bundle before it verifies the human messages of the same answer (Decision 33; spec 2 section 4.10).

A refused CRL is written to the client log (`<data dir>/logs/`) with both numbers; spec 2 also shows it in the receive result.

### 4.10 The client: HTTPS, the pin and the trust store (Eric 2026-11-11, Decision 19; Eric 2026-11-12, Decisions 23, 27, 30, 34 and 38)

**HTTPS is required by default for a server profile.** The first contact pins the root from whatever answers at the profile's `server` URL, so that connection has to be to the right server. Today any `http` URL is accepted (section 3 item 11). The new rule for the profile's `server`:

- `https`: accepted. The certificate is checked against the system's roots, as Go does by default; there is no option to skip that check.
- `http` on a loopback host (`127.0.0.1`, `::1`, `localhost`): accepted without the switch. This is a plan ruling by the coordinating agent, not Eric's decision, and he may overrule it; it matches the rule the profile's `oidc.issuer` already follows (`internal/profile/config.go:53-68`) and keeps tests and a server on the same host working.
- `http` on any other host: refused (exit 2, naming the switch) unless the override switch is on.

**The override switch** is named `insecure_http` (the name is a plan ruling made in this spec). It is for local testing (Decision 19). It has one meaning, "this profile may use `http` to a host that is not loopback", and three forms:

- the profile member `"insecure_http": true` in `config.json`;
- the flag `-insecure-http` on `agentmesh register` and `agentmesh-mcponly register`, which writes that member when it creates the profile;
- for the profile `agentmesh-mcponly` holds in memory when `-server` is not defined in `config.json`: the flag `-insecure-http` or the variable `AGENTMESH_INSECURE_HTTP=1`.

Every command that runs with the switch on logs one line saying the connection is not protected.

**The pin.** A client with no pinned root for its profile pins the root and the installation name from discover on first contact and prints the thumbprint and the name (Decisions 19 and 23). A different root or a different name later is an error until the operator runs `register` or `login` (in `agentmesh-mcponly`: `register` or `check`) with `-accept-new-root`, which prints the old and new thumbprints and names and replaces the pin, the stored chain, the stored CRLs and the kept revocations (Decision 19).

**The pin is the certificate** (Eric 2026-11-12, Decision 34). Any root renewal is a new root to every client, a renewal that keeps the key included: each client needs `-accept-new-root`. What happens to history then depends on the new certificate (Ruling 36):

- A new root with another key: history signed under the old root no longer verifies for a client that has pinned the new one.
- A root renewed with the same key and subject name: the earlier intermediates chain to the new certificate, so history still verifies where its signed time is inside the new certificate's validity period. A renewed certificate that starts no later than the old one keeps all history; one that starts later loses the history before its start.

When the root expires, bearers stop, because a bearer's chain is checked at the current time, and a server process stops issuing and signing as it does for an expired intermediate (section 4.15). Messages signed before the expiry keep verifying, because a message's chain is checked at its signed time. The way out is a new root and `-accept-new-root` on every client, so a root should live long: the root tool's default is ten years, and an outside CA's root may live far less.

**An expected root** (Eric 2026-11-12, Decision 30). First contact pins whatever root the answer carries. A client that keeps its configuration directory makes one first contact; a client that starts with an empty one every time (the MCP-only binary in a container or a CI job) makes one at every start. So a profile can name the root it expects by its thumbprint, the value `ca init` and `ca status` print. Like `insecure_http` it has three forms:

- the profile member `"root_thumbprint": "<thumbprint>"` in `config.json`;
- the flag `-root-thumbprint T` on `agentmesh register` and `agentmesh-mcponly register`, which writes that member when it creates the profile;
- for the profile `agentmesh-mcponly` holds in memory when `-server` is not defined in `config.json`: the flag `-root-thumbprint T` or the variable `AGENTMESH_ROOT_THUMBPRINT`.

When it is set, a root is pinned only when its thumbprint equals it, on first contact and with `-accept-new-root`, and a held pin that differs from it is the root-mismatch error. Discover stays the source of the certificate, so Decision 19 holds. It names the root only (Ruling 35); the installation has a setting of its own, next.

**An expected installation** (Eric 2026-11-12, Decision 38). An expected root does not say which installation under that root the client means: with nothing more, first contact pins the name of whichever installation answers. So a profile can also name the installation it expects. It is a separate setting beside `root_thumbprint`, optional like it, with the same three forms:

- the profile member `"installation": "<name>"` in `config.json`;
- the flag `-installation NAME` on `agentmesh register` and `agentmesh-mcponly register`, which writes that member when it creates the profile;
- for the profile `agentmesh-mcponly` holds in memory when `-server` is not defined in `config.json`: the flag `-installation NAME` or the variable `AGENTMESH_INSTALLATION`.

When it is set, the installation name in the first answer must equal it; otherwise the client stops and pins nothing. The same holds for the name `-accept-new-root` would pin. A held pin whose name differs from it is an error, as a held root that differs from `root_thumbprint` is. Either setting works without the other. The details are Ruling 44.

**The trust store.** Per profile, in a directory of its own (Decision 19):

`<config dir>/trust/<profile>/` (mode 0700; files 0600): `root.pem` (the pin), `intermediates.pem`, `root.crl`, `leaf-<issuer key>.crl`, `revoked.json` (the kept revocations, Decision 27; Ruling 34), and `state.json` (the trust number, the installation name and the server URL the pin belongs to). Spec 2 adds `leaves.pem`, a cache of leaf certificates that verified.

- It is per profile, not per identity: the root belongs to the server. It is not in the credential directory, where every file counts as an identity (section 3 item 12).
- Every process of the profile shares it (the MCP server, `wait`, the hooks, one-shot commands, the TUI). Writes take a lock file in the directory and replace files atomically, as `internal/sessionstate` does (`internal/sessionstate/state.go:83-97`, `138`).
- A profile whose server URL differs from the one in `state.json` is the root-mismatch error.
- Package `internal/trust` (a plan ruling) holds it and imports the standard library, `internal/filelock` and `internal/pki` only.
- The plumbing sits under the `Bus`: `internal/client` wraps the remote `Bus` of a server profile in a layer that calls discover when it is built, sends the held trust number on session open, receive and watch, and stores each bundle that comes back. The consumers (`internal/cli`, `internal/mcpserver`, `internal/mcpcli`, `internal/tui`) do not change. Spec 2 adds verification to the same layer.

State: writing the same bundle twice changes nothing. Two processes writing at once are serialized by the lock; the later one re-reads and keeps the higher CRL numbers, the union of the kept revocations and the trust number it received last. Two processes making first contact at once both pin; the second finds the first's pin, compares, and either agrees or reports the mismatch. A crash leaves the previous files (atomic replace).

### 4.11 Wire changes (`api/openapi.yaml`)

The protocol version stays `1.0.0` (CLAUDE.md, Eric 2026-10-27). The operation count stays 57 (8 open, 49 protected).

| Element | Change |
| --- | --- |
| `TrustBundle` | New schema (section 4.9) |
| `Discovery` | Gains `trust` (the bundle with `root` and `installation`; present from a server, absent in local mode). The description of `discover` still says it never touches the store |
| `Registration`, `AccessToken` | Unchanged (Decision 19) |
| `OpenSessionRequest`, `ReceiveRequest` | Gain `trust_number` (optional integer, 0 to 2^53) |
| `Session`, `ReceiveResult` | Gain `trust_number` (present from a server) and `trust` (when the client's number is absent or differs; Decision 27) |
| `watch` (a new query parameter) and `Wake` | Gain `trust_number` |
| `SigningKey` | Now describes a leaf certificate: `thumbprint`, `serial`, `issuer_thumbprint`, `not_before`, `not_after`, `state` (`current`, `previous`, `other`, `revoked`). The members `kid`, `provider`, `provider_ref`, `algorithm`, `created_at`, `retired_at`, `remove_after` go |
| `SigningKeyList` | The unexpired leaves, this process's current leaf first, plus `trust_number` |
| `rotateSigningKey` | Loses `revoke_previous` (Ruling 6). `SigningKeyRotation` becomes `current` (the new leaf), `revoked` (one entry per leaf revoked: `thumbprint` and `human_messages`; Decision 16 as changed by Decision 40) and `trust_number` |
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
| `installation_name` | The installation's name: the subject common name of its intermediate certificates (section 4.2; Decision 23, Ruling 30) | None; required; 1 to 64 characters |

Removed: `signing_key_uri`, `signing_key_rotation_hours`, `signing_key_rotation_cooldown_seconds`. Each setting is read from the file, then `AGENTMESH_SERVER_<NAME>`, then `-set`, like the others. An error message names a key service key by `keyprovider.KeyName`, never by its URI (`internal/keyprovider/keyprovider.go:151-168`).

Client: the profile members `insecure_http` (boolean, default false; section 4.10), `root_thumbprint` (a certificate thumbprint, default none; section 4.10; Decision 30) and `installation` (an installation name, default none; section 4.10; Decision 38).

### 4.13 Commands

- New: `agentmesh ca init | sign [-same-installation] | revoke` (section 4.3; Decision 37); `agentmesh server admin ca csr | install | install-crl | status` (section 4.4); `agentmesh server admin signing-key revoke -cert FILE | -serial S` (section 4.8; Decision 25).
- Changed: `agentmesh server admin signing-key list | rotate` and the client's `agentmesh signing-keys list | rotate` keep their names; `rotate` loses `-revoke-previous` and prints the per-leaf counts; `list` prints leaves.
- `agentmesh register`, `login` and `login -human`, and `agentmesh-mcponly register` and `check`, take `-accept-new-root`. `agentmesh register` and every `agentmesh-mcponly` command take `-insecure-http`, `-root-thumbprint` and `-installation` (section 4.10).
- Any command that makes first contact prints the pinned root's thumbprint and the installation name once.

### 4.14 Health (approved section 3)

The administrator tier of `GET /v1/health` gains a `signing` object, built by `internal/core/health` from the answering process's leaf manager:

- the installation name;
- the intermediate in use: thumbprint, "not after", days left;
- the current leaf: thumbprint, "not before", "not after", when the next renewal is due;
- the trust number and each CRL's number;
- the last renewal failure: when and a short message (redacted and capped by the backend, as today), cleared by the next success.

The status is `degraded` (still HTTP 200) when the intermediate expires within 30 days, when the last renewal failed, when the leaf has expired, when the intermediate's key is revoked, or when the root has expired. The probe and identity tiers show none of it.

### 4.15 Start-up and failure states

| State at start | Result |
| --- | --- |
| `root_certificate_file` unset, unreadable or not one CA certificate | Exit 2 |
| The pinned root has expired (Decision 34) | Exit 2 |
| `installation_name` unset or not a valid name (Ruling 30) | Exit 2 |
| Neither or both of `intermediate_key_file` and `intermediate_key_uri` | Exit 2 |
| Key file missing, not owner-only or not an ECDSA P-256 key | Exit 2 |
| No stored intermediate certificate that matches the configured key, is signed by the pinned root and meets rule 3 of the chain check of section 4.2 (`installation_name` and the extended key usage among it) | Exit 2; the message names `agentmesh server admin ca csr` and `ca install` |
| The matching intermediate has expired, or its key is revoked by the stored root CRL | Exit 2 |
| A backend scheme that is not in this build | Exit 2, with the build tag, as today (`internal/server/cmd/keyprovider.go:31-34`) |
| The key service does not answer while the first leaf is issued | Exit 1 |
| `token_lifetime_seconds` or a human lifetime above W/2 | Exit 2 |
| The store does not answer | As today |

| State while running | Result |
| --- | --- |
| Renewal fails | Retry schedule of section 4.6; health `degraded` |
| Leaf expired, no renewal | Retryable 503 on the token endpoint and, with spec 2, on appends of human messages; health `degraded` |
| Own leaf found on the leaf CRL | Issue a new leaf at once |
| Intermediate or root found expired, or the intermediate's key found revoked | Stop issuing and signing; retryable 503 on the token endpoint and, with spec 2, on appends of human messages; health `degraded`; an error log line every reload |
| A stored certificate or CRL fails verification | Ignored, logged with its thumbprint; never a 500 (the no-500 rule, ADR 0001 addendum) |

| Client state | Result |
| --- | --- |
| A server profile with an `http` URL that is not loopback and no `insecure_http` | Exit 2, naming the switch |
| No pin and discover cannot be reached | The command fails as it does today when the server cannot be reached |
| The root or the installation name in discover differs from the pin | Exit 2, naming both values and `-accept-new-root` |
| The root that would be pinned, or the held pin, does not match `root_thumbprint` | Exit 2, naming both thumbprints; nothing is pinned or replaced |
| The installation name that would be pinned, or the held one, does not match `installation` (Decision 38) | Exit 2, naming both names; nothing is pinned or replaced |
| A pin, and discover cannot be reached | The client goes on with the trust it holds |
| Discover answers without `trust` | The command fails and says so, with or without a pin (Decision 33) |

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
| `signing-key revoke` | The serial number is already listed: no change, exit 0, trust number unchanged | Serialized by the `trust` lock | One transaction |
| Client first contact | The pin exists: compare, do not replace | The second process finds the first's pin | Nothing pinned until the root file is in place (atomic replace) |
| `-accept-new-root` | The new root is already the pin: no change | Lock file | Atomic replace of the pin, then the chain and CRLs; a rerun completes it |
| Client stores a bundle | No change | Lock file; higher CRL numbers win and the kept revocations are merged | Atomic replace; the previous files stay |

**After a restore from backup** (Eric 2026-11-12, Decision 27). The stored CRLs and the trust number are the backup's.

- The stored trust number is a time earlier than any number issued since the backup, so it differs from the number of every client that saw a later change, and each such client gets the bundle (Decision 39). It refuses the older CRLs once, with a log line, keeps the revocations it has seen and records the server's trust number.
- The next change to the trust material raises the trust number above every value issued before the restore, so no client is left holding the server's number with other trust material behind it.
- The next leaf CRL the server builds has a higher number than any issued before, because numbers are times, so clients accept it. It lists what the stored CRL lists and what the building process has seen; a leaf revoked after the backup and seen by no running server process is missing from it, and only the clients that saw its revocation still refuse it.
- So the operator installs the latest root CRL again (`ca install-crl`) and, when a forced renewal was run after the backup was taken, runs one again. `docs/ops/backup.md` says so (section 9).
- A second restore of the same backup is the same case again.

## 6. Accepted risks

In plain words; ADR 0019 holds the same list, under Eric's general ruling of 2026-11-12 (Decision 22): a database writer is effectively an administrator of the agentmesh server, and the server is not defended against its administrator.

1. Whoever can write the database can still act as the application's administrator: set the administrator flag, add a login key for any agent, edit ACLs, the `users` and `admins` lists and identity rows (Decision 15). This design does not try to stop that.
2. Whoever can write the database can hide a revocation from clients and server processes that have not seen it yet, by putting back an older CRL. A restarted server process forgets what it had seen; a client does not (Decision 27). For bearers the harm ends when the hidden leaf expires, at most W after it was issued (Decision 6). With spec 2 it does not end there for human messages: to a party that has not seen the revocation, a human message the leaf signed with a time inside its validity period keeps verifying (Decision 5; spec 2 section 7 item 3).
3. Whoever can write the database can remove a leaf's row before a forced renewal, so that leaf is not put on the CRL. It still expires within W (Ruling 8), and `signing-key revoke` lists it once its certificate or serial number is known (Decision 25).
4. A client pins the root and the installation name from the first discover answer it gets (Decisions 19 and 23). Over HTTPS the answer comes from whoever holds a certificate for the server's name that the system's roots accept. With `insecure_http` on a network that is not loopback, anyone on the path can supply a root of their own; the switch is for local testing. A profile that names an expected root pins no other root, and one that names an expected installation pins no other installation's name (Decisions 30 and 38); without them, every start of a client that keeps no configuration directory is a first contact.
5. Whoever holds the intermediate key file, or may ask the key service to sign with the intermediate key, can issue leaves and so mint bearers for any identity. The file needs the care the database credential gets today. With the file form the key is also within reach of the server process itself: the process reads the file, so whoever can read that process's memory or act as its OS user has the intermediate key and not only a leaf key (Decision 35).
6. Whoever can read a server process's memory has its leaf key. It mints bearers until the leaf expires or is revoked. What it can do with human messages is spec 2 section 7 item 3.
7. A bearer signed by a leaf that was just revoked is accepted by other replicas for up to 30 seconds.
8. A forced renewal makes everything the revoked leaves signed unverifiable (Decision 16). With spec 2 that is their human messages and nothing else (Decision 40).
9. Any root renewal is a new root to every client, a renewal with the same key included: each client needs `-accept-new-root`. When the root expires, bearers stop until a new root is in place and every client has accepted it (Decision 34).
10. Under an outside CA nothing checks that two installations under one root have different names, and with the shipped tool `-same-installation` is the operator's word for it. Two installations that share a root and a name accept each other's bearers and, with spec 2, each other's human messages (Decisions 23 and 37).

## 7. Tests

- **Fixtures** build a throwaway root in process through `internal/pki/rootca`, issue an intermediate into a temporary key file and install it (approved section 3). One helper serves `internal/server`, `internal/server/cmd`, `internal/e2e`, the inproc Bus suite and `TestAuthEndToEnd`. `scripts/cats-harness.sh up` and `scripts/docker-smoke.sh` run the real commands (`ca init`, `ca csr`, `ca sign`, `ca install`). Every fixture server listens on loopback, so no test needs `insecure_http` except the ones that test it.
- **`internal/pki`**: the certificate profiles; chain verification (good chain, wrong root, expired intermediate at the checked time, path length, missing usages); the chain check of section 4.2, one case per rule: a chain of two and of four certificates, an intermediate with another installation's name, an intermediate without the agentmesh extended key usage, a leaf without it, a leaf that is CA true, a leaf valid one second longer than 720 hours plus 60 seconds and one valid exactly that long, a root that is expired or not yet valid at the checked time; CRL creation and checks (signature, numbers, a CRL from another issuer); CRL numbers that are times and never go back, with the clock set back; revocation by key: a leaf under either certificate of a key is refused when the root CRL lists one of them; the union: a serial number listed by an earlier CRL and missing from the current one is still revoked; the extended key usage constant is the full identifier of Decision 36 (Ruling 42).
- **Root tool**: each row of the table in section 4.3, including the refusal to overwrite; `ca sign` keeps the CSR's name, refuses a CSR without one and gives two certificates of one key the same subject key identifier; a CSR whose name `state.json` records for another key is refused with exit 2 and nothing written, is issued with `-same-installation`, and a CSR for the recorded key is issued without the flag, as is a new name (Decision 37); `ca revoke` revokes every certificate of the key and names them.
- **Host commands**: each check of `ca install` (the installation name, the extended key usage and the subject key identifier among them) and `ca install-crl` fails with its own message and exit 2; `ca csr` carries `installation_name`; `signing-key revoke` with `-cert` (a leaf of the configured key, a certificate of another key refused), with `-serial`, for a leaf with a row and without one, with both flags and with neither; the repeat rows of section 5.
- **Start-up**: each row of the first table in section 4.15 with its exit code.
- **Leaf manager on a fake clock**: renewal at W/2; the retry times after a failure (one eighth of the time left, one-minute floor); expiry leading to 503 on the token endpoint; recovery on the next success; the clock-outside-validity case.
- **Bearers**: a bearer from a leaf whose row is missing, altered, self-signed, under another root, expired or revoked is refused; a forged row is not trusted (the mutation that replaces threat 2's test); a bearer from a leaf under a second installation's intermediate (the same root, another name) is refused with both rows present, and so is one under a CA certificate without the agentmesh usage and one from a leaf whose lifetime is over the ceiling; the expiry cap; the W/2 configuration check.
- **Replicas on both engines** (`TestReplicas*`): a bearer from one replica is accepted by the other; a forced renewal on one makes the other issue a new leaf and refuse the old bearer within the reload interval; two forced renewals at once.
- **Forced renewal report**: one `revoked` entry per leaf with its count (0 in this spec); the same key replays the same answer.
- **Discover**: carries the bundle with `root` from a server and none in local mode; answers 200 with the bundle while the store is closed, from the in-memory copy (a new test of what the operation's description promises, `api/openapi.yaml:125`).
- **In-band delivery**: session open and receive with a lower, equal, higher and absent `trust_number`; a watch that wakes on a trust number change in either direction with no message.
- **Trust number** (Decision 39): each change sets it to the larger of the clock in Unix milliseconds and the stored value plus one; with the clock set back it still goes up by one; a value above 2^31 is stored and read back on both engines.
- **Restore and rollback** (Decision 27): with the stored leaf CRL and the trust number put back to earlier values, a client that holds the later ones still gets the bundle, refuses the older CRL once, keeps its revocations and records the server's number; the next forced renewal's CRL has a higher number than the client holds and is accepted; a leaf revoked before the rollback and missing from the new CRL is still refused by that client; a server process that saw the revocation puts it into the next CRL it builds; the trust number of the first change after the rollback is above every value issued before it (Decision 39).
- **Root expiry** on a fake clock (Decision 34): bearers are refused, the process stops issuing and signing, health is `degraded`, and a start exits 2.
- **Profile rule**: `https` accepted; `http` to `127.0.0.1`, `::1` and `localhost` accepted; `http` to another host refused with the switch named; accepted with each of the three forms of `insecure_http`; an unknown value of `AGENTMESH_INSECURE_HTTP` refused.
- **Client trust store**: first contact pins the root and the installation name and prints both; a different root is refused and nothing is overwritten; a different installation name under the same root is refused the same way; an intermediate with another name in a bundle is not kept; `root_thumbprint` in each of its three forms: a matching root is pinned, another is refused and nothing is pinned, `-accept-new-root` to a root that does not match is refused, a held pin that differs is an error; `installation` in each of its three forms: a matching name is pinned, another is refused and nothing is pinned, `-accept-new-root` to another name is refused, a held name that differs is an error, and each of the two settings works without the other (Decision 38); a discover answer without `trust` fails with and without a pin; `-accept-new-root` replaces pin, chain, CRLs and kept revocations; a lower CRL number is refused and logged; two processes at first contact; two writers; a crash between files; discover unreachable with and without a pin; the hooks make no discover call.
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
- The extended key usage identifier (Decision 36; Ruling 42): a test of `internal/pki` pins the constant as a literal and fails for a stand-in: an identifier that is not `1.3.6.1.4.1.<PEN>.1.1`, a number of 0, or 32473, the enterprise number reserved for documentation (RFC 5612). No commit that adds the constant is made before ADR 0019 records the assigned number.
- `scripts/check-gates-selftest.sh`: one mutation per new import rule; one that makes bearer verification trust a row without checking its chain (it must fail the forged-row test); one for each rule of the chain check that Decisions 23, 25 and 26 add (the installation name comparison, the extended key usage on the intermediate and on the leaf, the leaf lifetime ceiling, revocation by key), each of which must fail its `internal/pki` case; one that sends the bundle only to a client whose number is lower (it must fail the restore test); one that makes the trust number a counter again (it must fail the trust number test); one that drops the name refusal from `ca sign` (it must fail the root tool test); one that drops the `installation` comparison at first contact (it must fail the trust store test); one that drops the loopback test from the profile rule (it must fail the profile tests).
- `make verify`, `ci.yml` and `windows.yml` green; the file mode check of the key file follows the existing owner-only rule on Windows (`internal/fileacl`).

## 9. Documents the plan updates

- `docs/ops/signing-keys.md` is rewritten when this spec is implemented, not before: the hierarchy, the outside-CA profile, the four backends as stores of the intermediate key, forced renewal and what it costs. Until then it describes the code as it is. It must also say: that each installation under one root needs a name of its own (Decision 23); that an outside CA issues the name, the extended key usage and the same subject key identifier for every certificate of a key; that revoking an intermediate means revoking every certificate issued for its key (Decision 26); what `signing-key revoke` is for (Decision 25); that any root renewal, a same-key renewal included, needs `-accept-new-root` on every client, with what root expiry does (Decision 34); and that the shipped root tool refuses a name it has issued to another key, what `-same-installation` is for, and that an outside CA has no such check, so its operator keeps the names apart (Decision 37).
- Also with the implementation: `docs/ops/configuration.md`, `docs/ops/deploy.md`, `docs/ops/admin-bootstrap.md`, `docs/ops/backup.md` (the database holds no private key; a restore puts back the CRLs and the trust number of the backup, so after one the operator installs the latest root CRL again and, when a forced renewal was run after the backup was taken, runs one again: Decision 27), `docs/ops/health.md`, `docs/ops/upgrade.md`, `docs/install.md` (HTTPS and the switch; `root_thumbprint` and `installation`, above all for a client that keeps no configuration directory: Decisions 30 and 38), `CLAUDE.md` (commands and design notes), the threat model (SD1, SD3, SD6 and threats 1, 2, 6 and 15 once built) and its TMI mirror.

## 10. What spec 2 adds to this

Spec 2 uses the leaf to sign human messages and nothing else (Eric 2026-11-12, Decision 40, which reduced it from every message), adds two columns to `messages`, narrows the `expired leaf removal` job, fills the count of the forced renewal report, and gives clients the verification step for human messages. It needs everything in sections 4.2 to 4.10. It also makes the forced renewal's API form require the human claim (Decisions 28, 41 and 42) and adds three client rules for trust that lags behind (Decision 33).

## 11. Plan rulings on the points the first draft left open

None of these is Eric's decision. Each stands as the first draft's recommendation; Eric may overrule any of them. The numbers are the first draft's open question numbers. Numbers 1, 2 and 5 are missing because Eric decided them (Decisions 19 and 16).

**Ruling 3: one trust number.** The wire carries one unsigned trust number, raised with every change to a CRL or to the intermediates; clients enforce the signed number inside each CRL. Not taken: carrying each CRL's own number; or one installation-wide leaf CRL reissued on every change so that its number could serve, which fails when the only intermediate is the thing being revoked, because nothing can sign the reissue. It fits Decision 19: discover carries the same number in its bundle. **Changed by Decision 27**: the server sends the bundle when the two numbers differ, not only when the client's is lower. **Changed by Decision 39**: the number is time-based, like a CRL number, and no longer a counter that goes up by one (section 4.8; Ruling 45).

**Ruling 4: one leaf CRL per intermediate key.** Standard scope: a leaf CRL lists the leaves of the key that signs it. A forced renewal revokes the leaves under the acting process's key and reports any others as not covered. While two intermediate keys are in use (a key change in progress), the old key's leaves are cut off by revoking the old intermediate with the root tool, or expire within W. Not taken: one list for the installation signed by whichever key acts; a stolen old key could then sign a newer list that un-revokes leaves of the new key.

**Ruling 6: rotate always revokes.** `revoke_previous`, the cooldown and all three `signing_key_*` settings are removed; routine renewal is automatic at W/2. Not taken: keeping `revoke_previous` so that a plain rotate only makes every process renew; that does nothing W/2 does not already do.

**Ruling 7: entries stay, rows go when unused.** A revoked entry stays on the leaf CRL for the life of the intermediate key, because removing it would make that leaf's history verify again, against Decision 5. An entry is about 40 bytes. Leaf rows are deleted once expired and, with spec 2, once no message refers to them. Not taken: dropping an entry once the database holds nothing the leaf signed; the CRL would then depend on database contents.

**Ruling 8: the leaves to revoke are listed from the table.** A writer who removes a leaf's row first keeps it off the CRL until it expires; accepted (section 6 item 3). Decision 25 adds `signing-key revoke` for a leaf that has no row. Not taken: a "revoked before" time in the CRL as a private extension, which needs no table but is not standard and races between replicas with different clocks.

**Ruling 9: a key service intermediate.** The operator creates the key; `ca csr` resolves the URI and has the service sign the CSR; `ca install` records the resolved reference in the intermediate's row; every leaf is checked against the intermediate certificate before use, which also covers `awskms`, the one backend that does not verify after signing (ADR 0012, controller ruling 3). Not taken: no stored reference, with every process resolving the URI at start; adding a key version in the service would then stop the server until `ca csr` and `ca install` were run again.

**Ruling 10: the JWKS endpoint stays.** `GET /v1/auth/jwks` and `jwks_uri` are kept and serve the live leaves as JWKs with `x5c`, so the operation counts stay 57, 8 and 49 and the required metadata member keeps a meaning. Not taken: removing both.

**Ruling 11: setting names.** `root_certificate_file`, `intermediate_key_file`, `intermediate_key_uri`, `leaf_validity_hours`. Not taken: keeping `signing_key_uri` for the key service URI; the name would describe the wrong key.

**Ruling 12: "reads continue" when the leaf has expired.** The approved section says that with an expired, unrenewed leaf "writes and token exchange answer a retryable 503; reads continue". Every bearer a process signed expires no later than its leaf (section 4.7). So on a single server no bearer is left to read with, and on several replicas reads continue only with bearers from the healthy ones. The rule is kept and the operator guide says this plainly: a single server whose renewals fail for W/2 stops serving authenticated requests until a renewal succeeds, with health `degraded` from the first failure. Not taken: judging a bearer by whether it was issued inside its leaf's validity period and dropping the expiry cap.

**Ruling 13: clock rules.** No rule compares one replica's clock with another's for messages: a process signs with its own leaf, issued by its own clock. A leaf's "not before" is set 60 seconds back (the existing leeway). A process does not sign when its own clock is outside its leaf's validity period; it issues a new leaf. A chain is checked at the signed time for a message and at the current time, with the 60-second leeway, for a bearer. A CRL's signer is checked at the CRL's "this update" time. Clients apply no leeway to a message's time. Not taken: a 60-second allowance on the client for messages; the signer guarantees the time is inside, so the verifier can be exact. The two comparisons Decision 24 adds are between different clocks and do take the 60 seconds (spec 2, Ruling 37).

**Ruling 24 (stated in section 4.9; it follows from Decision 19): a process calls discover once when it opens the `Bus` of a server profile,** the hooks excepted. This is how a client with no session refreshes its CRLs.

## 12. Plan rulings made while folding in the security review (2026-11-12)

None of these is Eric's decision. Each fills in a detail that one of his rulings on the review needed and did not give, and he may overrule any of them. The numbers continue the series and answer no open question; 29 was an open question, which Decision 36 settled, and Rulings 37 to 41 are in spec 2. Three of them were changed by Eric's decisions of the same day; each says so.

**Ruling 30: the installation name** (for Decision 23). The server setting is `installation_name`: required in server mode, no default, 1 to 64 characters (the limit X.520 puts on a common name) of lowercase letters, digits, `.` and `-`, beginning with a letter or a digit. It is the one source of the name: `ca csr` puts it in the request as the subject common name and loses its `-name` flag, so the request and the server cannot disagree. A verifier compares the subject common name byte for byte and ignores any other subject attribute an outside CA adds. The client receives the name as `installation` in the discover document's trust bundle, pins it in `state.json` beside the root, and treats a different name later as it treats a different root: the same error, cleared by the same flag. **Changed by Decision 37**: this ruling had `ca sign` print a note and refuse nothing; `ca sign` now refuses a name that `state.json` records for another key unless `-same-installation` is given (Ruling 43). Under an outside CA, that the names differ stays the root administrator's care. Not taken: a default name, with which two installations under one root would be the same installation without anybody choosing it; a `-name` flag on `ca csr` checked against the setting.

**Ruling 31: the shape of the extended key usage** (for Decision 23). One usage, the same on the intermediate and the leaf, absent from the root. The extension need not be marked critical; the verifiers require the usage whether it is or not, and a certificate that carries only the "any" usage does not have it. They check it themselves: Go's verification is called with the "any" usage, because it asks for server authentication by default (`crypto/x509/verify.go:623-625`), and the intermediate and the leaf are then compared with one constant in `internal/pki`. Every arc of the identifier must be below 2^31, because Go's parser refuses a certificate that holds a larger one (`vendor/golang.org/x/crypto/cryptobyte/asn1.go:421-431`, `readBase128Int`). The value was Open question 29 and is settled by Decision 36: `1.3.6.1.4.1.<PEN>.1.1`, with the number pending (Ruling 42).

**Ruling 32: the leaf lifetime ceiling and `signing-key revoke`** (for Decision 25). The ceiling is a constant, 720 hours plus 60 seconds, and not the server's `leaf_validity_hours`: a client does not know that setting, and one rule serves both verifiers. It is measured as "not after" minus "not before". `signing-key revoke` always writes to the leaf CRL of the configured intermediate key; a leaf of another key is cut off by revoking that key (Ruling 4). The serial number is hexadecimal, as `signing-key list` prints it. With `-serial` nothing ties the number to a certificate: a wrong number revokes nothing or, at worst, one live leaf, whose process then issues a new one. The count is that of the leaf's row and 0 for a leaf with no row, because spec 2 counts by the row a human message refers to. Not taken: revoking by thumbprint alone, which a CRL cannot express.

**Ruling 33: revocation by key** (for Decision 26). Two intermediate certificates are of one key when their subject key identifiers are equal, which is how `trust_material.issuer_key` already names a key. For that to hold, the root tool derives the identifier from the public key, the outside-CA profile asks for the same identifier on every certificate of a key, and `ca install` refuses a certificate whose identifier differs from that of the stored certificates with the same public key. Intermediate certificates are never deleted from the table, never left out of the bundle and never dropped by a client, the revoked and the expired included: a CRL names a serial number, and only the certificate says which key that is. Not taken: comparing public keys in every verifier in place of the identifiers.

**Ruling 34: CRL numbers, the kept revocations and the trust number** (for Decision 27). A CRL that agentmesh issues, the server's leaf CRL or the root tool's root CRL, takes as its number the larger of the time of issue in Unix milliseconds and the previous number plus one. An outside CA numbers its root CRL as it likes; only "not lower" is asked of it. The trust number is compared for equality only between a client and the server, and a client records the one it received last. **Changed by Decision 39**: this ruling kept the trust number a counter that goes up by one; it is now time-based by the same rule as a CRL number (Ruling 45). The client's kept revocations are one file of the trust store, `revoked.json`: for each issuer key identifier the revoked leaf serial numbers, and for the root the revoked intermediate serial numbers. `-accept-new-root` clears it with the rest. A CRL refused for a lower number adds nothing to it. The alternative this ruling did not take, a time-based trust number, is what Eric chose (Decision 39): a counter that a restore puts back can come to equal a client's number again.

**Ruling 35: the expected root** (for Decision 30). The value is the thumbprint of section 4.2 plan ruling 2, as the tools print it. It is checked whenever a root would be pinned (first contact and `-accept-new-root`), and a held pin that differs from it is the root-mismatch error, so the setting and the pin cannot disagree unnoticed. It names the root only. **Changed by Decision 38**: this ruling left the installation name to the first answer, so a client with an expected root accepted the name of any installation under that root. The alternative it did not take, an expected installation name in forms of its own, is what Eric chose (Ruling 44).

**Ruling 36: the root's validity period is part of the chain check** (for Decision 34). The chain check tests every certificate of the chain at the checked time, the root included, as Go's `crypto/x509` does (`crypto/x509/verify.go:451-470`, `isValid`, called for each certificate of a candidate chain at line 764). The statements of section 4.10 follow from it: when the root expires bearers stop and messages signed before the expiry keep verifying; under a root renewed with the same key, history verifies where its signed time is inside the new certificate's validity period. A server process treats an expired root as it treats an expired intermediate. Not taken: leaving the root's own validity period unchecked, as a trust anchor's may be; bearers would then outlive the root, which is not what Eric ruled.

## 13. Plan rulings made while folding in Decisions 36 to 39 (2026-11-12)

None of these is Eric's decision. Each fills in a detail that one of his four decisions on this spec needed and did not give, and he may overrule any of them. The numbers continue the series; Rulings 46 to 54 are in spec 2.

**Ruling 42: the identifier and the wait for the number** (for Decision 36). Eric gave the identifier's form, `1.3.6.1.4.1.<PEN>.1.1`: under the publisher's number, arc `1` is agentmesh and `1.1` its signing usage. Every arc is below 2^31, as Ruling 31 requires. The value is one constant in `internal/pki` and one line of the outside-CA profile. No value stands in for it: a test pins the constant as a literal and refuses an identifier of another form, a number of 0, and 32473, the number reserved for documentation (RFC 5612). The chain check and its tests need the constant, and `make verify` must pass on `main`, so no implementation of this spec lands on `main` before IANA has assigned the number and ADR 0019 records it. The plan for this spec can be written before that. Not taken: building with a stand-in and replacing it later, which would put certificates with a wrong usage into every fixture and, if one release slipped out, into installations.

**Ruling 43: the name check of `ca sign`** (for Decision 37). The flag is `-same-installation`, the name Eric offered. `state.json` already records every certificate the tool issued; the check reads the subject common name and the subject key identifier of each. A name counts as taken by every certificate ever issued under it, the expired and the revoked included: expiry or revocation does not free a name, because clients that pinned it would accept a new installation under it as the old one. The comparison is byte for byte, as a verifier's is (Ruling 30). The refusal is exit 2, writes nothing, and names the recorded key's identifier and the flag. The flag is needed only when the name is recorded with another key; given for a new name or for the recorded key it changes nothing. Not taken: a prompt, which a script cannot answer; a separate command for a key change.

**Ruling 44: the expected installation** (for Decision 38). The value has the form of an installation name (Ruling 30); another form is refused when the profile is read (exit 2). It is compared byte for byte with the name in the discover bundle whenever a name would be pinned, which is first contact and `-accept-new-root`, and with the held pin whenever a command reads the pin. A mismatch is the error of the same kind as a root mismatch: exit 2, both names shown, nothing pinned or replaced. It is independent of `root_thumbprint`: a profile may set either, both or neither. Not taken: one setting that holds the thumbprint and the name together; Eric chose a separate one.

**Ruling 45: the time-based trust number** (for Decision 39). `Tx.BumpTrustNumber(now)` sets the stored number to the larger of `now` in Unix milliseconds and the stored number plus one, inside the transaction that makes the change and under the `trust` lock, so two changes never take the same number. The row starts at 0 with the schema, and the first change gives it a time. The host commands take `now` from the host's clock, a server process from its own; when the clock is behind the stored number, the number goes up by one. The wire bound of 0 to 2^53 (section 4.11) holds: a time in milliseconds stays below it for more than two hundred thousand years. A client and the server compare the number for equality (Decision 27). A server process compares the number it holds with the stored one by order (spec 2 section 4.6), which is why the number never goes down. Not taken: keeping the counter and adding a mark that a restore happened, which is a second mechanism for what the time already does.

## 14. Open questions

None in this spec. Open question 29, the identifier of the agentmesh extended key usage, is settled by Decision 36, option A: register a Private Enterprise Number with IANA for Trojan Unicorn Ventures and use `1.3.6.1.4.1.<PEN>.1.1`. Not taken: an arc the publisher already holds (B); there is none. What is still outstanding is not a question but the assignment itself: the number is pending, and this spec does not ship until it arrives (Ruling 42).
