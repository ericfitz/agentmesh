# ADR 0019: Certificate hierarchy and signed messages

Status: Decisions 1 to 15 below are Accepted (Eric, 2026-11-11, human-made). The plan rulings are proposals Eric may overrule. Open questions 1 to 27 await his rulings; until he rules, the two specs are written against the recommendation for each. Nothing is built.

The design is in two specs: `docs/superpowers/specs/2026-11-11-certificate-hierarchy-design.md` (spec 1, the hierarchy, shippable alone) and `docs/superpowers/specs/2026-11-11-signed-messages-design.md` (spec 2, signed messages, which depends on spec 1).

## Context

The server signs bearers with a key from the `signing_keys` table, and trusts the public key of every row of that table (`internal/core/signingkeys/keyring.go:39-63`). By default the private key is in the row as well (`internal/store/signing.go:17-19`). A message's `sender_kind` is copied from the sender's identity row (`internal/core/messaging/send.go:144`), and agents are told to treat a `human` message as an instruction from their operator (`internal/mcpserver/server.go:142`). So whoever can write the database can forge bearers and can write messages that steer every agent (threat 2 and SD1 of `docs/security/threat-model-server.md`).

Two earlier answers were recorded in ADR 0012 and are not being built: the key set trust addendum (2026-11-09) and the server key file design (2026-11-10), which Eric abandoned on 2026-11-11. In abandoning it he accepted that write access to the database is the same privilege as administering the application, and named two subjects for the replacement: key storage and rotation, and provenance for human-initiated messages. This ADR records his design for both.

Eric's outline of 2026-11-11, condensed: a root CA with a private key, which can be anything and is not used for TLS, with the root certificate pinned in the server's configuration and given to clients at registration. Each installation is an intermediate CA under the root: a "generate" step makes a private key (a file or a key service) and a certificate signing request, and the administrator returns the certificate. The signing key is a private key with a certificate the intermediate issued. CRLs for revocation, delivered in band. A validity window with two active certificates at all times, renewal at half the window, and failed renewals retried more often toward the end. A server API forces immediate renewal with revocation of the previous certificate. No signing of data in the database: the server signs the message before the insert and stores the signed blob, with fields still extracted into columns for filtering and search. The client validates before acting; an invalid signature is an error and the client does not act. No keys in the database and no dependence on database integrity: assurance moves to the server before the insert and to the client after receipt and before use.

## Decisions (Eric, 2026-11-11, human-made)

1. **Human assertion.** The server signs sender kind `human` only when the request's bearer carries a human claim, and only the OIDC browser sign-in exchange sets that claim. The identity row's kind is never consulted for it.
2. **Slack-origin humans.** The signed blob carries `origin=slack` with the Slack user id, the email Slack reported and the Slack timestamp. `origin=api` carries the sign-in claim (the signed-in email). Clients treat both as human and can show which.
3. **Replay.** The client keeps, outside the database (the session state file, `internal/sessionstate`), the highest acknowledged sequence number per channel; a delivery at or below it is marked `replayed`. A human message whose signed origin time (the Slack timestamp for Slack origin, else the server timestamp) is older than a bound at delivery is marked `stale`. The bound is a client setting, default 24 hours. Both marks mean "history, not an instruction".
4. **Leaf key.** In memory, one per server process, generated at start, never written anywhere; the intermediate issues its certificate. The same leaf signs bearers and messages. One intermediate per installation, shared by replicas.
5. **Old messages.** A message verifies when its signed server timestamp is inside the signing leaf's validity window, the chain reaches the pinned root, and neither the leaf nor the intermediate is on a CRL. Expiry alone never invalidates history. Revocation invalidates everything that certificate signed, whenever it was signed.
6. **CRL freshness: broadcast only.** No pull endpoint with next-update enforcement and no fail-closed state for a stale CRL. A database writer who suppresses or rolls back the stored CRL can hide a revocation from clients that have not seen it; this is an accepted risk, bounded by the leaf's lifetime.
7. **Two configurations only.** Local mode (the in-process core over the user's SQLite file): no CA, no signatures, clients verify nothing. Server mode: a pinned root and an intermediate are required to start; there is no unsigned server. Development and tests use the shipped root tool.
8. **Coverage.** Every message written through `core.Append` is signed: chat, memory revisions, task documents, notices. Agent statuses stay unsigned; clients are told a status is display text, never an instruction; the threat model lists "a database writer can plant status text".
9. **Root tooling.** agentmesh ships a small root CA tool, with the root key in a file the administrator keeps offline. It serves development, test fixtures and small production installations. It is standard X.509, so an outside CA can replace it; the documents state the certificate profile an outside CA must issue.
10. **Intermediate key storage.** A PEM file (mode 0600, named by a setting) or one of the four existing key service backends of `internal/keyprovider` (`awskms`, `gcpkms`, `azurekms`, `hashivault`), which sign in place. The in-database provider is deleted. No backend that fetches a key from a secrets manager.
11. **Envelope.** Each message is a compact JWS (EdDSA or ES256) whose payload is the message as JSON and whose header names the leaf by certificate thumbprint. Leaf certificates are stored once each in a public table; every response that carries messages also carries the certificates they reference. Clients act only on fields parsed from the verified payload.
12. **Broadcast.** No message row announces a CRL. Session open and every receive result carry the current CRL number; a client that reports an older number gets the CRLs and the chain in the same response. A forced renewal also rings the wake doorbell for every waiting session. Clients refuse a CRL with a lower number than the one they hold.
13. **Two specs and one ADR.** The hierarchy first, shippable alone; then signed messages on top.
14. **Clients verify every message** in server mode, not only human ones. This overrides "optional for agent messages" in the outline; Eric accepted it.
15. **Database write still equals application administrator** for what the server reads to decide: ACLs, the administrator flag, identity rows other than the human claim. Replicas and restores are included.

## Plan rulings Eric approved with the design sections (2026-11-11)

Each was proposed during the brainstorm and approved by Eric as part of a design section. They are not among the fifteen decisions, and he may overrule any of them.

Names:

1. The stale setting is `human_stale_hours` and applies to every session.
2. The root tool's commands are `agentmesh ca init | sign CSR | revoke CERT`.

Section 1, the hierarchy:

3. The server pins the root from a file named by a setting. The client receives it in the registration response and stores it beside its credential; a different root later is an error needing re-registration. (Open questions 1 and 2 revisit where it is stored and how it is replaced.)
4. `agentmesh server admin ca csr` makes the intermediate key and prints the request; `ca install CERT` checks the certificate against the pinned root (CA true, path length 0, certificate and CRL signing) and stores it; `ca install-crl` stores a root CRL; `ca status` reports.
5. The intermediate certificate, the leaf certificates and the CRLs are public and self-verifying and live in one database table. Nothing is distributed to replicas by file, and a tampered row fails verification.
6. Without a valid intermediate the server exits 2 and names the two commands.
7. The leaf is Ed25519 with a validity window W, default 7 days (Eric approved the default), settable. At W/2 the process issues its next leaf and signs with it; the previous one verifies until it expires. A failed renewal is retried after one eighth of the remaining time, never sooner than a minute. With an expired, unrenewed leaf, writes and the token exchange answer a retryable 503 and reads continue. A bearer's lifetime is capped at W/2.
8. The intermediate signs a numbered leaf CRL. The rotate operation becomes: issue a new leaf here and put every other live leaf on the CRL; other replicas see their leaf listed and issue a new one at once. The root tool revokes an intermediate and emits a root CRL.
9. Removed: the `signing_keys` table, the in-database key provider, and the rotation and removal maintenance jobs.

Section 2, signed messages:

10. `core.Append` signs with the in-memory leaf after the transaction assigns the sequence number, and stores the blob in a new `messages.signed` column. The payload holds the sequence number, channel id, channel name at signing, sender, sender kind, session, server timestamp, type, subject, content, reply-to, metadata, memory id, revision, tags and origin. The existing columns stay as extracted copies. Storage roughly doubles and counts against the budget.
11. The bearer gains a kind claim; `Append` takes the sender kind from the claim or from the bridge's Slack check. (The claim exists already, `internal/auth/token/issuer.go:266-273`; what is new is carrying it to the write, and an email claim. Spec 2 section 4.5.)
12. On the wire each message carries `signed`; responses with messages carry the referenced leaf certificates; session open and receive carry the CRL number and, for a client that is behind, the CRLs and the chain.
13. One shared client verification package serves the CLI, both MCP servers and the TUI, on server profiles only. It checks the chain to the pinned root, the CRLs, that the signed timestamp is inside the leaf's window, and that the signed sequence number and channel id match the delivery; then it discards the unsigned copy. A delivery under a channel name different from the signed one is flagged `renamed`.
14. On failure the content is withheld, the receive result lists `unverified` entries (channel, sequence number, reason), the cursor still advances, and the agent text says to report it to the operator. A tombstoned message has no blob and is never an instruction. (Open question 16: tombstoned rows keep their content today.)
15. The threat model states in plain words what is not covered: deletion and suppression of messages, agent status text, ACLs and the administrator flag, a rolled-back CRL.

Section 3, operations and tests:

16. Exit 2: no pinned root, no intermediate certificate, a certificate that does not chain or does not match the key, an intermediate that is expired or on the root CRL. Exit 1: the key service does not answer at start.
17. Intermediate renewal is `csr` and `install` again; earlier intermediates stay in the table, so history under an expired intermediate verifies and history under a revoked one does not.
18. The registration response carries the root, the chain and the CRLs (trust on first use over the registration connection); `agentmesh-mcponly register` likewise.
19. The health document's administrator tier reports the intermediate and leaf expiry, the CRL numbers and the last renewal failure, and warns from 30 days before the intermediate expires.
20. `ca install` and `ca install-crl` are idempotent; CRL updates run under a Store lock with the number raised in one transaction; a crash between issuing and using a leaf leaves an unused certificate.
21. The schema is changed in place in `0001_initial.sql`; no migration; local data is recreated (the pre-release rule).
22. Tests: fixtures build a throwaway root in process through the root tool's package; a client verification matrix; renewal and retry on a fake clock including expiry to 503; replicas on both engines; signed append in the Store and Bus conformance suites; the wire, tool coverage, bounds, example and Arazzo gates updated; a new import rule for the verification package with selftest mutations.
23. If go-jose were not among the 13 modules the MCP-only binary may link, verification would be written against the standard library alone; the allowlist is never extended. Finding: go-jose is on the list (`scripts/m10-exit-checks.sh:41`) and the binary links it today, so verification uses go-jose.

## Plan rulings made while writing the specs (not yet seen by Eric)

Each is marked "(plan ruling)" in the spec that holds it. The ones that change or add to what he approved are raised as open questions below; the rest are names and bounds:

- Package and table names: `internal/pki`, `internal/pki/rootca`, `internal/trust`, `internal/provenance`, the table `trust_material`, `keyprovider.FileProvider`; `internal/core/signingkeys` keeps its name as the leaf manager.
- The intermediate key is ECDSA P-256 in both storage forms. A certificate's thumbprint is the SHA-256 of its DER encoding, base64url, carried as `x5t#S256`.
- `leaf_validity_hours` is 2 to 720; `human_stale_hours` is 1 to 8760.
- A message blob has `typ` `agentmesh-msg+jws`, so a bearer and a message signed by the same leaf cannot stand in for each other.
- Every append reads the trust number in its transaction and fails with a retryable `unavailable` when the process is behind.
- `max_message_kib` keeps measuring the plain message; the storage budget and the receive cut count the blob.
- A failed message outside receive is returned as a placeholder with its reason.

## Consequences

1. No private key and no trusted public key is in the database. Reading the database or a backup no longer yields a signing key, and inserting a key row no longer yields a trusted key. Threat 2 is closed for bearers once spec 1 is built.
2. Server mode needs a CA before the first start: four commands with the shipped tool (`ca init`, `ca csr`, `ca sign`, `ca install`), or the same with an outside CA. Every server test fixture, `scripts/docker-smoke.sh` and `scripts/cats-harness.sh` gain that step.
3. The intermediate key becomes the installation's most valuable secret after the root key. In file form it is a file every replica reads.
4. A message's human status is a signed statement that rests on the sign-in or the Slack check, not on an identity row. A database writer can no longer write a message that agents take for an operator's instruction, short of also holding a leaf key.
5. Clients do real work on every read: a signature check and a chain check per message, with certificates cached. Message storage and message-bearing responses roughly double.
6. The wire, the Store contract, the schema, the settings and the host commands change in place, with no migration and no compatibility path (the pre-release rule of 2026-10-25). The protocol version stays `1.0.0`.
7. A forced renewal is an emergency tool: by Decision 5 it makes everything the revoked leaves signed unverifiable (Open question 5).
8. The verifying layer sits under the `Bus`, so `internal/tui`, `internal/mcpserver`, `internal/mcpcli` and `internal/cli` keep their import rules.

## Accepted risks, in plain words

1. Whoever can write the database can still act as the application's administrator: set the administrator flag, add a login key for any agent and obtain a genuine agent bearer, edit ACLs, identity rows and the `users` and `admins` lists. Replicas and restores are included (Decision 15).
2. Whoever can write the database can add an email to the `users` list; the person who signs in with that email at the provider is then a human to every agent. The signature says "signed in at the provider with this email", not "is an authorized operator" (Open question 27).
3. Whoever can write the database can delete, hide or delay messages, bring back an earlier signed revision of a memory or task, and plant agent status text and server notice text. None of these is signed.
4. Whoever can write the database can hide a revocation from clients and server processes that have not seen it, until the hidden leaf expires (Decision 6), and can keep a leaf off the CRL by removing its row before a forced renewal (Open question 8).
5. A session with no state file has no `replayed` marks. A human message younger than the stale bound can be delivered again, unmarked, to a new session or to a session resumed on another host.
6. A client pins the root from the first registration or token response it receives (trust on first use).
7. Whoever holds the intermediate key, or may ask the key service to sign with it, can mint bearers and sign messages for anyone. Whoever can read a server process's memory has its leaf key until that leaf expires or is revoked.
8. A bearer signed by a leaf that was just revoked is accepted by other replicas for up to 30 seconds.
9. A forced renewal or an intermediate revocation makes everything those certificates signed unverifiable, memories and tasks included. There is no re-sign path.

## What this supersedes

- **ADR 0012**, in these parts:
  - decision 1 where it makes the Store row the default provider, and decision 2 (the Store as the registry of keys): the in-database provider and the `signing_keys` registry are removed (Decision 10). The four key service backends, their URI schemes and decision 12 (build tags) stay; they now hold the intermediate key.
  - decisions 3, 5, 7, 8, 9, 10 and 11 (resolution at rotation, `remove_after`, `-revoke-previous`, the two states, the provider mismatch refusal, the cooldown, scheduled rotation) and the consequences and settled notes that follow from them (settings, the two maintenance jobs, stale-key visibility): replaced by leaf renewal and the CRLs of spec 1. Decision 6 (rotate now as a host command and an admin API operation, protocol `1.0.0`) stays, with the new meaning of rotate. Decision 4 (reload on an unknown key and every 30 seconds) stays as the reload rule for trust material.
  - the "Key set trust addendum (2026-11-09)": superseded whole. Its three modes, the tamper protection for tables and the Kubernetes secret providers are not built. Its decision 5 (no environment-variable key source) is kept in effect by Decision 10.
  - the "Server key file addendum" and its "security review decisions" (2026-11-10): already abandoned in ADR 0012; this ADR is the replacement that section announces.
  - "How the four backends work" and the controller rulings about the backends stay true of the backends.
- **ADR 0004**, "Signing keys addendum (Eric, 2026-10-27)": the `signing_keys` rows, the one-active index and the five methods are removed. The table `trust_material` and the two `messages` columns take their place (spec 1 section 4.5; spec 2 section 4.8).
- **ADR 0002**, where it says database read access is equivalent to the administrator flag because the signing key is a Store row (its Milestone 5 item 2 and its item 6, "Signing keys", `docs/adr/0002-authentication-and-credentials.md:197-199`, `281-287`): no private key is in the database.
- `docs/superpowers/specs/2026-11-10-server-key-file-design.md` and `docs/superpowers/specs/2026-10-27-signing-keys-design.md` (the rotation and provider design): kept as records.

ADR 0012 itself is left as written. `docs/adr/README.md` needs a row for this ADR, and ADR 0012's status line a pointer here, when Eric accepts the open questions.

## Open questions for Eric

Each is set out with options A, B and C and a recommendation in the spec named. They are numbered once across both specs.

Spec 1 (hierarchy), section 11:

1. How a client that never registers on this host gets the root, and where trust is stored.
2. How a pinned root is replaced.
3. What "the current CRL number" is when there are several CRLs.
4. What the leaf CRL covers while two intermediate keys are in use.
5. A forced renewal makes up to W of history unverifiable.
6. What becomes of `revoke_previous`, the cooldown and scheduled rotation.
7. Whether CRL entries and leaf rows can ever be removed.
8. The list of leaves to revoke comes from the database.
9. A key service intermediate: who creates the key and where its pinned reference lives.
10. Whether the JWKS endpoint stays.
11. Setting names.
12. "Reads continue" when the leaf has expired.
13. Clock rules.

Spec 2 (signed messages), section 11:

14. Sender kind and origin for writes that have no bearer.
15. The memory id and revision are not known when `Append` would sign.
16. Tombstones keep their content today.
17. Revisions built from a stored row.
18. Tasks on the wire.
19. What is on the wire beside the blob, and `display`.
20. Where the certificates ride when a response is a bare array.
21. Notices that are table rows, not messages.
22. Where the replay marks live.
23. Slack history ingested again.
24. How fresh the CRLs are for a read with no session.
25. What `renamed` means to an agent.
26. The inspection webhook.
27. Any human who can sign in is an operator to every agent.

## Alternatives not taken

- The server key file with row MACs and sealed keys (ADR 0012, 2026-11-10): abandoned by Eric on 2026-11-11.
- Confirming key rows with the key source alone (the first proposal of 2026-11-09): it closes one of several paths a database writer has.
- A CRL pull endpoint with next-update enforcement, and failing closed on a stale CRL: Eric chose broadcast only (Decision 6).
- Verifying only human messages: Eric chose every message (Decision 14).
- Signing agent statuses: left unsigned (Decision 8).
