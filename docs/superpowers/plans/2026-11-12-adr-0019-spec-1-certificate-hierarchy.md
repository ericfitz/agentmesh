# ADR 0019 Spec 1: Certificate Hierarchy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The server's signing keys leave the database: a root CA outside the server, one intermediate CA key per installation (a PEM file or a key service), an in-memory Ed25519 leaf per server process, bearers verified by a certificate chain to the pinned root, revocation by CRLs delivered in ordinary responses, and a client that pins the root and the installation name from the discover document. The `signing_keys` table, the in-database key provider and the two rotation jobs are removed.

**Architecture:** `internal/pki` (standard library only) holds the certificate profiles, the one chain check, CRLs and the kept revocations; `internal/pki/rootca` is the shipped root tool's package. `internal/core/signingkeys` is rewritten as two types: `Trust` (the rules over the stored trust material, which the host commands call) and `Manager` (the leaf, its renewal, the issuer's `token.KeySource` and the core's `TrustSource`). The Store gains one table of public material, `trust_material`. On the client, `internal/trust` is the per-profile trust store and `internal/client` wraps the remote `Bus` of a server profile in a layer that pins, sends the held trust number and stores each bundle. The work is staged expand-then-contract so that every commit passes `make verify`: the new parts are built beside the old key set, one task switches the server start, and the old parts are deleted afterwards (see "Transitional states").

**Tech Stack:** Go 1.27 (`CGO_ENABLED=0`), `crypto/x509` (certificates, CSRs, CRLs), go-jose v4 (already linked by both binaries), oapi-codegen output in `internal/gen` (never edited by hand), SQLite (`modernc.org/sqlite`) and Postgres (`pgx`) through `internal/store/sqlstore`, bash gate scripts (`set -euo pipefail`, shellcheck-clean).

**Spec:** `docs/superpowers/specs/2026-11-11-certificate-hierarchy-design.md` (spec 1, fourth revision; "section N" below means a section of it). Decisions and rulings: `docs/adr/0019-certificate-hierarchy-and-signed-messages.md` (Decisions 1 to 46; "Decision N" and "Ruling N" below are its numbers). Spec 2 (`docs/superpowers/specs/2026-11-11-signed-messages-design.md`) is read only for what this plan must leave room for; none of it is built here (Decision 13). Superseded and not built: `docs/superpowers/specs/2026-11-10-server-key-file-design.md` and the key file addenda of ADR 0012. Checked against the tree at `5b09d27`.

## Open questions for Eric

These are not decided by this plan. Question 1 blocks execution, not the plan; question 2 blocks Task 37 only; question 3 has a default the plan builds and blocks nothing; question 4 is about a status line.

1. **May the work be built on a branch with a stand-in enterprise number, behind a gate that refuses to land it?** Three texts say no stand-in: Decision 36 ("no placeholder value is accepted in the code in its place"), Ruling 42 ("no implementation of this spec lands on `main` before IANA has assigned the number", and "Not taken: building with a stand-in and replacing it later"), and section 8 ("No commit that adds the constant is made before ADR 0019 records the assigned number"). The dispatch for this plan asks for the opposite on one point: one named constant with a placeholder that a gate refuses to ship, so everything else can be built now. That instruction came from the coordinating agent and is not Eric's approval. The plan is written for it (Plan ruling 1), because the alternative needs no plan change beyond deleting Task 2 and folding Task 37 into Task 1:
   - **A (what the plan assumes):** build now on the branch `adr-0019-spec-1`, never on `main`. The constant holds 32473, the number RFC 5612 reserves for documentation, which section 8's own test refuses. No certificate is committed as a fixture (every test makes its own), so the later change is one constant. `make pen-check` fails while the stand-in is there; it runs in CI on `main` and joins `make verify` in Task 37. The branch merges only after Task 37.
   - **B:** hold all execution until the number is assigned. Nothing is built; the plan waits.
2. **The assigned Private Enterprise Number.** Task 37 needs the number IANA assigns to Trojan Unicorn Ventures, and ADR 0019 has to record it first (Ruling 42).
3. **Which stored intermediate does a process with a key service use after a key change inside that service?** The spec does not say. A process signs by the reference `ca install` pinned and does not resolve the URI at start (Ruling 9), and a pinned reference cannot always be traced back to the configured URI (`awskms` resolves an alias to a key identifier; `hashivault` pins `NAME/VERSION`, `internal/keyprovider/hashivault/hashivault.go:220`). The plan takes **A** (Plan ruling 12) and Task 17 builds it; it is one function to change:
   - **A:** the newest valid stored intermediate whose `key_ref` has the configured URI's scheme. A replica restarted with the old URI during a key change then moves to the new key at once, or exits 1 when its service account may not use that key.
   - **B:** resolve the URI at every start and match by public key, as the file form does. Adding a key version in the service then stops every start until `ca csr` and `ca install` are run again, which is the alternative Ruling 9 did not take.
   - **C:** record the configured URI's printable name beside the reference and match on it. That adds to the `trust_material` row section 4.5 fixes.
4. **Status lines of spec 1.** Its section 1 still says the text of the third and fourth revisions "have not been approved by him yet", while the dispatch calls the spec approved. Task 36 updates those lines only on Eric's word.

## Global Constraints

- **Frozen:** Eric's Decisions 1 to 46 (ADR 0019) and the spec's text. The spec's own plan rulings (Rulings 3 to 13, 24, 30 to 36, 42 to 45) are followed as written. Where the spec is silent this plan makes a numbered plan ruling below; none of them is Eric's and he may overrule any. A gap found during execution is reported as a design change, not guessed.
- **Pre-release rule (Eric, 2026-10-25):** schema, wire, settings and formats change in place. No migration, no shim, no compatibility path, no deprecation. The schema version stays 1 and the protocol version stays `1.0.0`; the operation count stays 57 (8 open, 49 protected).
- **Branch:** every task commits to `adr-0019-spec-1`. Nothing merges to `main` and nothing is pushed to `main` before Task 37 and Task 38 are done (Open question 1). This overrides the "work lands directly on `main`" line of `CLAUDE.md` for this plan only.
- **Closing a task:** each task ends with `go vet ./... && make fmt-check && make lint && make vet-cross` (the last one vets Windows, which no local test run covers), then `make verify` (needs Docker; a run that skips the Postgres suites is not a pass), and shows the last 15 lines of its output. A task that changes a file under `scripts/`, `.github/` or the `Makefile` also runs `make release-lint`. Then one commit in the `type(scope): subject (ADR 0019)` style, ending with the attribution lines the session reminder gives. No task pushes.
- **Checkpoints for CI and Windows.** `ci.yml` runs on pushes to `main` and on pull requests, `windows.yml` on pushes to `main`; this plan opens no pull request, so nothing on the branch reaches CI or a Windows runner by itself. Task 2 adds `workflow_dispatch` to `ci.yml` (`windows.yml` has it). After Tasks 11, 26 and 32 the controller stops and asks Eric: `Approve: push branch adr-0019-spec-1 to origin and run ci.yml and windows.yml on it`. A red job is fixed before the next task starts.
- **No committed certificates, keys or CRLs.** Every test and fixture makes its own through `internal/pki`, `internal/pki/rootca` or `internal/trusttest`. A PEM or DER file under `testdata/` is a review rejection (it would pin the stand-in identifier).
- **One chain check.** Only `pki.VerifyChain` (and its two halves, `pki.CheckChain` and `Verified.ValidAt`) decides whether a chain is accepted (section 4.2). No other code compares an installation name, an extended key usage or a leaf lifetime.
- **Rows are facts.** The Store applies no rule to `trust_material` (ADR 0004 addendum "Access facts, not rules"); a row that fails verification is ignored and logged with its thumbprint, never trusted and never a 500 (the no-500 rule).
- **Import rules to keep:** `internal/pki` and `internal/pki/rootca` import the standard library only (`rootca` also `internal/pki`); `internal/trust` imports the standard library, `internal/filelock` and `internal/pki` only; `internal/keyprovider` stays inside its allowlist; `internal/auth/token` imports the standard library, go-jose and `internal/auth/keys` only (Plan ruling 3); `internal/tui`, `internal/mcpserver`, `internal/mcpcli` and `internal/cli` keep their rules (the layer sits under the `Bus`); the MCP-only binary still links exactly 13 modules.
- **Never edit `internal/gen` by hand.** Every change to `api/openapi.yaml` is followed by `make generate` in the same task. `api/arazzo.yaml` `info.version` stays `1.0.0`.
- **The pre-commit hook** (`.githooks/pre-commit`) fuzzes the changed paths of a staged non-documentation `api/openapi.yaml` change through `scripts/cats-harness.sh`. Tasks 15 and 27 commit such changes. A finding no rule explains is fixed, or the controller adds a rule with its reason through the `cats:*` skills; `--no-verify` is not used.
- **Selftest anchors.** `scripts/check-gates-selftest.sh` block 14 anchors on the line `if err := tok.Claims(key.Public, &c); err != nil {` of `internal/auth/token/issuer.go`, block 15 on `if !p.Admin {` of `internal/core/access/decide.go`, and the m7 probes of block 22 on the `keyprovider-leaf` and `keyprovider-consumers` rule names. Those lines and names stay as they are; a task that must change one changes the selftest in the same commit. The selftest tests `HEAD` and is not part of `make verify`, so Task 35 runs it whole.
- **`TestAccessRuleSites`** (`internal/core/access/sites_test.go`) is not touched: no task reads `Admin`, `Creator`, `Owner`, `Scope` or a `Kind` outside `access`. The administrator check of the forced renewal stays `Core.RequireServerAdmin`.
- **Windows:** `windows.yml` must be green. File modes mean nothing there: an owner-only check goes through `internal/fileacl`, an atomic replace through a temporary file and `os.Rename`, a lock through `internal/filelock` (or, in `rootca`, an exclusively created lock file). Tests that assert a Unix mode sit in `_unix_test.go` files.
- **Shell:** gate scripts stay `set -euo pipefail` and shellcheck-clean, with the `deps_violation=<pkg> imports <imp>` output contract.
- American English everywhere.
- **Done gate:** `make verify`, `make check-gates-selftest`, `make pen-check`, `make vet-tags`, `make docker-smoke`, then `ci.yml` (every job) and `windows.yml` green on the pushed commit. Task 38 runs them and shows their output.

## Rulings made by this plan (Eric may overrule)

1. **The stand-in and its gate** (the default of Open question 1). `pki.PrivateEnterpriseNumber` is 32473 until Task 37. `scripts/pen-gate.sh` (`make pen-check`) exits 1 while the constant is 0 or 32473 or the identifier is not `1.3.6.1.4.1.<n>.1.1`; it has a selftest and a mutation. It runs as the CI job `pen-gate` only when the ref is `main`, so a run of the workflow on the branch is not red for the branch's whole life, and Task 37 adds it to `make verify`. Not taken: a Go test that fails on the stand-in from Task 1 (every task's `make verify` would be red); a release preflight (release tags are cut from `main`, where the CI job and, after Task 37, `make verify` fire).
2. **The chain is verified once and its validity period is cached.** `pki.VerifyChain` is `pki.CheckChain` followed by `Verified.ValidAt`: `CheckChain` checks the signatures, the profiles, the name, the usage and the lifetime ceiling, and returns `pki.Verified` with the period in which all three certificates are valid: the latest "not before" and the earliest "not after" of leaf, intermediate and root (Ruling 36 puts the root in it). The server verifies a leaf row once per reload cycle that first sees it, and the issuer tests `Verified.ValidAt(now, 60 s)` for every bearer; revocation is evaluated again at every reload. This is "the chain check at the current time" of section 4.7 without two ECDSA verifications per request. A `pki` test proves `VerifyChain(at)` succeeds exactly when `ValidAt(at)` holds. The tests that must still bite: root expiry on the fake clock (Task 19) and the forged-row mutation (Task 35).
3. **`internal/auth/token` does not import `internal/pki`.** `token.Key` carries the DER chain (leaf, then intermediate) and the validity period; the issuer needs nothing else. The package keeps its three-import rule.
4. **The subject key identifier** is the first 20 bytes of the SHA-256 of the key's DER `SubjectPublicKeyInfo` (`pki.SubjectKeyID`). `trust_material.issuer_key` and every map keyed by "issuer key" use its lowercase hexadecimal form. A serial number is written in lowercase hexadecimal without leading zeros.
5. **The root tool's lock** is the file `DIR/lock`, created with `O_CREATE|O_EXCL`, removed when the command ends. A command that finds it waits up to 10 seconds, then exits 1 naming the file ("remove it if no agentmesh ca command is running"). Section 8 pins `rootca` to the standard library, which rules out `internal/filelock` (it imports `golang.org/x/sys` on Windows).
6. **`state.json` of the root tool:** `{"version":1,"crl_number":N,"issued":[{"serial","thumbprint","name","key","der","not_after","revoked"}]}`, where `key` is the subject key identifier and `der` is base64.
7. **Store types and indexes** for `trust_material` are in Task 8. A CRL row is keyed by `(kind, issuer_key)`; a certificate row by `(kind, thumbprint)`.
8. **`ResetData` keeps `trust_material`,** as it keeps `signing_keys` today (`internal/store/meta.go:23`).
9. **The server-mode SQLite file mode check stays** (`internal/store/sqlite/sqlite.go:39,86,147`): whoever can write the file is the administrator (Decision 15). Its message no longer says the file holds the signing key; it says the file is the server's database.
10. **Required settings are checked at the start, not in `Validate`.** `config.Validate` checks the shape of the five new settings when they are set. `Config.RequireTrust()` is what makes them required; the server start and the `ca` and `signing-key` host commands call it. `users`, `admins`, `enrollment` and the other host commands run without trust settings, as they do today.
11. **`keyprovider.FileProvider` reads through a function it is given.** The owner-only check (Unix mode 0600 or narrower; `fileacl.CheckOwnerOnly` on Windows) lives in `internal/server/cmd`, because the `keyprovider-leaf` allowlist has no `internal/fileacl`.
12. **Which stored intermediate "matches the configured key":** for the file form, one whose public key is the file's key; for a key service, one whose `key_ref` is not empty and has the configured URI's scheme (Ruling 9: a process signs by the pinned reference and does not resolve the URI at start). Among those that are valid now, the one with the latest "not before" is used. The key service half is option A of Open question 3: it is a default, and what it does during a key change inside one service is stated there.
13. **The manager is driven by `Step`.** `Manager.Step(ctx)` does whatever is due (reload, renewal, retry) and returns when to call it next; `Manager.Run` loops over it with a real timer. The fake-clock tests call `Step`.
14. **A transitional adapter for the two signing key operations** (Task 15): the wire, the Bus types, the handlers, the remote client and the CLI take their final shape while the old key set still serves them: `internal/core/signingkeys/api.go` is reduced to an adapter that answers from the old rows in the new shape. Task 23 moves the server to the manager's forms and Task 24 deletes the file.
15. **In-band answers come from one in-memory snapshot.** Discover, session open, receive and watch read `TrustSource.Bundle()`, the manager's verified copy, never the Store; the trust number of an answer is the bundle's. On a hint that carries no message the manager reads the stored trust number (at most once a second) and reloads when it differs from the one it holds, which is how a Postgres notification reaches a replica "sooner" (section 4.8).
16. **The health document's wire shape.** Section 4.11 omits it; section 4.14 defines the content. Schema `HealthSigning`: `installation`, `intermediate` (`thumbprint`, `not_after`, `days_left`), `leaf` (`thumbprint`, `not_before`, `not_after`), `next_renewal_at`, `trust_number`, `root_crl_number`, `leaf_crl_number`, `last_failure_at`, `last_failure`, `stopped` (empty, `intermediate_expired`, `intermediate_revoked` or `root_expired`).
17. **Bus type names** are in Task 15 and Task 27; `bus.RevokedLeaf` is one `revoked` entry.
18. **The hooks do not call discover** through `client.Options.NoDiscover`, which `stop-hook` sets (the only hook that opens a `Bus`). The layer reads the held trust number from the trust store at each call, because every process of the profile shares it. The discover call at open is bounded by 10 seconds.
19. **Where the client says things.** The first-contact line, the `insecure_http` line and a refused CRL go to `Options.Notice` (standard error in the CLI; never standard output, which is JSON or the MCP protocol) and to `<data dir>/logs/trust.log`.
20. **Trust store files:** `state.json` is `{"trust_number":N,"installation":"...","server":"..."}`; `revoked.json` is `pki.Revocations` as JSON; the lock file is `.lock`. Reads take the lock too (a Windows rename fails while a reader holds the file).
21. **Output of the host commands** (one line per item, stable words first) is in Tasks 13 and 21.
22. **`make verify` gains `bash scripts/m7-exit-checks.sh --deps-only`** (38 seconds, no Docker), so the new import rules are in the done gate; CI already runs it.
23. **`TestAuthEndToEnd` keeps its 12 leaf names** (`scripts/m5-exit-checks.sh` pins the count); their bodies move to the hierarchy. The bearer matrix of section 7 is `TestBearerMatrix` in `internal/core/signingkeys`, and the forged-row mutation targets it.
24. **A forced renewal revokes the leaf that signed the caller's own bearer.** The answer is delivered; the caller's next request is a 401 and the CLI's transport refreshes once. Every test that holds a raw bearer exchanges again after a rotation: the Arazzo workflow ends with a token exchange, `TestRequestExamples` runs `rotateSigningKey` as its last row.
25. **Containers.** `scripts/docker-smoke.sh` bootstraps inside the image with the shipped tool (`ca init`, `server admin ca csr`, `ca sign`, `server admin ca install`) into the data volume; `deploy/docker-compose.yml` and `deploy/example.env` name the three settings and mount the root certificate and the key file.
26. **Two fixtures with one shape.** `internal/trusttest` is a non-test package (several packages' tests import it) that the m4 rule keeps out of both binaries, like `internal/respcheck`. It does not import `internal/server/cmd` (that package's tests import it). It does import `internal/core/signingkeys`, whose own tests are `package signingkeys` and so cannot import it (an import cycle): that package has a fixture of its own in `helpers_test.go`, with the same methods unexported (`newFixture`, `sibling`, `renew`, `revokeIntermediate`, `trust`, `install`, `manager`, `leaf`). Where Tasks 12 and 17 to 20 say `Fixture.X` about a test of `internal/core/signingkeys`, they mean that one.
27. **`TrustCertificateByThumbprint` takes the kind**, because a thumbprint is unique per kind (section 4.5).
28. **Leaves a forced renewal does not cover** (Ruling 4: those under another intermediate key) are named in a log line by the API form and on standard error, as `not-covered <thumbprint>`, by the host form. The wire answer has no member for them.
29. **A flag that disagrees with a defined profile** (`-insecure-http`, `-root-thumbprint`, `-installation` against a profile that `config.json` defines with another value) is exit 2, as `-server` is today (`internal/client/resolve_test.go:263`).

## Task sizes

Tasks 15, 22 and 23 are the widest (many files, mechanical edits, one commit each because the tree does not compile or the suites do not pass in between). The controller gives each of them a fresh implementer with nothing else in its context, and escalates effort before splitting: none of the three has a green intermediate state to split at.

## Transitional states

Each is introduced and removed by a named task. None survives Task 37.

| State | From | Until |
| --- | --- | --- |
| The stand-in enterprise number 32473 | Task 1 | Task 37 |
| `trust_material` beside `signing_keys` | Task 8 | Task 26 |
| The five new settings accepted but not required | Task 9 | Task 23 |
| `api.go` as an adapter: the old key set answers the two operations in the new shape | Task 15 | Task 23 (unused), Task 24 (deleted) |
| `token.Key` with an optional chain; `token.StaticKeys` | Task 16 | Task 25 |
| Host `signing-key` commands act on leaves while the server still signs with the key set | Task 21 | Task 23 |
| Fixtures pass trust settings to a server that does not need them yet | Task 22 | Task 23 |
| `signingkeys.Service`, `Keyring`, `StoreProvider` compiled but unused by the server; the three `signing_key_*` settings accepted and ignored | Task 23 | Task 24 |

## Left for spec 2 (build none of it)

- `trust_material.id` is stable for the life of a row: spec 2's `messages.leaf_id` refers to it.
- The forced renewal's transaction calls `countSigned(ctx, tx, leafID)`, which returns 0 here; spec 2 fills it. `bus.RevokedLeaf.HumanMessages` is always 0.
- The forced renewal checks the administrator flag only (`RequireServerAdmin`). The human-claim action of Decision 42 is spec 2's.
- `expired leaf removal` deletes every leaf row an hour past its "not after"; spec 2 narrows it.
- The manager exposes its current leaf (`Manager.Current()`) and the trust number it holds (`Bundle().TrustNumber`); spec 2's signer port and append check use them.
- The client layer is the type `trustBus` in `internal/client`; spec 2 adds verification there. The trust store gets no `leaves.pem` here.

## Review Focus

1. **A forced renewal revokes the caller's own bearer** (Plan ruling 24). A person runs `agentmesh signing-keys rotate` and then `agentmesh signing-keys list` in the same home and expects both to work. Test: Task 34, `TestRotateThenList` in `internal/e2e`.
2. **A crash-looping server leaves thousands of leaf rows** (one per start, each valid for W). A reload must not verify them all again every 30 seconds. Test: Task 19, `TestReloadVerifiesOnlyNewRows` (2,000 rows; the second reload makes no signature check, counted through a test hook).
3. **A renewal that fails at the Store, not at the key service** (step 5 of section 4.6, the insert). The retry schedule and `degraded` must apply, and the current leaf must keep signing. Test: Task 18, `TestRenewalStoreFailure`.
4. **PEM inputs as people produce them:** CRLF line endings, a DER file, two blocks in one file, trailing text. `ca sign`, `ca revoke`, `ca install`, `ca install-crl` and `root_certificate_file` accept CRLF and refuse the rest with exit 2 and a message that says what the file held. Tests: Task 1 (`TestParsePEM`), Tasks 6 and 13 (one command case each).
5. **A trust directory the client cannot write** (a read-only container file system) or one that another process is reading on Windows. First contact fails naming the directory, and never goes on without a pin. Tests: Task 11, `TestStoreUnwritable` and `TestConcurrentReadWrite` (the latter also runs under `windows.yml`).

## File map

New packages:

| Path | Responsibility |
| --- | --- |
| `internal/pki/` (`eku.go`, `names.go`, `profile.go`, `pem.go`, `chain.go`, `crl.go`, `revocations.go`) | The identifier, thumbprints, names, the three certificate profiles, PEM parsing, the chain check, CRLs, the kept revocations |
| `internal/pki/rootca/` (`rootca.go`, `state.go`, `lock.go`) | The root tool's rules: init, sign, revoke, `state.json` |
| `internal/trust/` (`store.go`, `pin.go`, `apply.go`) | The client's per-profile trust store |
| `internal/trusttest/` (`trusttest.go`) | The test fixture: a throwaway root, an intermediate key file, an installed intermediate, a manager |

New files in existing packages:

| Path | Responsibility |
| --- | --- |
| `internal/cli/ca.go` | `agentmesh ca init|sign|revoke` |
| `internal/keyprovider/file.go` | `FileProvider`, `CreateKeyFile` |
| `internal/store/trust.go`, `internal/store/sqlstore/trust.go`, `internal/conformance/store/trust_test.go` | The `trust_material` contract, its SQL and its suite |
| `internal/core/trust.go` | The `TrustSource` port |
| `internal/core/signingkeys/trust.go`, `material.go`, `install.go`, `revoke.go`, `manager.go`, `manager_api.go`, `renew.go`, `reload.go`, `status.go` | `Trust`, the verified view of the rows, install, revocation, the manager |
| `internal/server/cmd/trust.go`, `keyfile.go`, `ca.go` | Opening the root and the provider, the owner-only read, the `ca` host commands |
| `internal/server/trust.go` | Bundle and health converters |
| `internal/client/trust.go` | The layer under the `Bus` |
| `scripts/pen-gate.sh`, `scripts/pen-gate-selftest.sh` | The enterprise number gate and its selftest |

Rewritten or deleted: `internal/core/signingkeys/service.go`, `schedule.go`, `keyring.go`, `api.go` and their tests (Task 24); `internal/store/signing.go`, `internal/store/sqlstore/signing.go`, `internal/conformance/store/signing_test.go` (Task 26); `internal/server/cmd/keyprovider.go` becomes `trust.go` (Task 23).

---

## Phase A: foundations (additive; the server does not change)

### Task 1: `internal/pki`: the identifier, names, thumbprints and the three certificate profiles

**Files:**
- Create: `internal/pki/doc.go`, `eku.go`, `names.go`, `profile.go`, `pem.go`
- Test: `internal/pki/eku_test.go`, `names_test.go`, `profile_test.go`, `pem_test.go`
- Modify: `scripts/m7-exit-checks.sh` (new rule `pki-leaf`; the header comment lists it), `Makefile` (`verify` runs `bash scripts/m7-exit-checks.sh --deps-only` after the m4 line; Plan ruling 22)

**Interfaces (Produces):**

```go
package pki // standard library only

const PrivateEnterpriseNumber = 32473 // stand-in until Task 37 (Decision 36); scripts/pen-gate.sh refuses it
var ExtKeyUsageAgentmesh = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, PrivateEnterpriseNumber, 1, 1}

const MaxLeafLifetime = 720*time.Hour + 60*time.Second // Decision 25
const LeafBackdate = 60 * time.Second                  // Ruling 13

func Thumbprint(der []byte) string                     // SHA-256, base64url, no padding
func SubjectKeyID(pub crypto.PublicKey) ([]byte, error) // Plan ruling 4
func KeyID(ski []byte) string                          // lowercase hex
func SerialText(n *big.Int) string                     // lowercase hex, no leading zeros
func ValidInstallationName(name string) error          // Ruling 30
func HasAgentmeshUsage(c *x509.Certificate) bool       // the identifier is in UnknownExtKeyUsage; ExtKeyUsageAny does not count

func NewRoot(key crypto.Signer, commonName string, notBefore, notAfter time.Time) (*x509.Certificate, error)
func NewRequest(key crypto.Signer, installation string) ([]byte, error)      // DER CSR, subject CN = installation
func ParseRequest(der []byte) (*x509.CertificateRequest, error)              // checks the CSR's own signature; refuses an empty or invalid CN
func IssueIntermediate(root *x509.Certificate, rootKey crypto.Signer, csr *x509.CertificateRequest, notBefore, notAfter time.Time) (*x509.Certificate, error)
func IssueLeaf(intermediate *x509.Certificate, key crypto.Signer, pub ed25519.PublicKey, now time.Time, validity time.Duration) (*x509.Certificate, error)

func ParseCertificatePEM(b []byte) (*x509.Certificate, error)
func ParseRequestPEM(b []byte) (*x509.CertificateRequest, error)
func ParseCRLPEM(b []byte) (*x509.RevocationList, error)
func EncodePEM(blockType string, der []byte) []byte // "CERTIFICATE", "CERTIFICATE REQUEST", "X509 CRL"
```

Profiles (section 4.2, exact): root: CA true, key usage certificate signing and CRL signing, subject key identifier, no extended key usage. Intermediate: CA true, `MaxPathLen` 0 with `MaxPathLenZero` (basic constraints critical), key usage certificate signing and CRL signing (critical), subject and authority key identifiers, the agentmesh usage, subject CN copied from the CSR, key ECDSA P-256 (another key is an error). Leaf: CA false (critical), key usage digital signature (critical), both key identifiers, a random 128-bit serial number, the agentmesh usage, "not before" `now - LeafBackdate`, "not after" `now + validity` cut to the intermediate's "not after". No certificate carries a DNS name, an IP address or a TLS usage.

- [ ] **Step 1: Write the failing tests**

`TestExtKeyUsageShape`: the identifier has 9 arcs, begins `1.3.6.1.4.1`, ends `1.1`, arc 7 is `PrivateEnterpriseNumber`, every arc is below `1<<31`; a leaf made by `IssueLeaf` parses with `x509.ParseCertificate` and `HasAgentmeshUsage` is true; a certificate whose only usage is `x509.ExtKeyUsageAny` gives false. (The literal pin and the refusal of a stand-in are Task 37.)

`TestThumbprint`: `Thumbprint([]byte("abc")) == "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"`.

`TestValidInstallationName`: accepted `a`, `prod-1`, `eu.west-2`, `0lab` and 64 times `a`; refused the empty string, 65 times `a`, `Prod`, `-a`, `.a`, `a_b`, `a b`, `é`.

`TestRootProfile`, `TestIntermediateProfile`, `TestLeafProfile`: one assertion per item of the profile list above, on the parsed certificate; `TestIntermediateProfile` also refuses a CSR with an RSA key and one with a P-384 key.

`TestLeafNotAfterCut`: an intermediate that expires in 1 hour and a validity of 168 hours give a leaf whose "not after" equals the intermediate's.

`TestSubjectKeyID`: 20 bytes, equal to the first 20 bytes of `sha256.Sum256(x509.MarshalPKIXPublicKey(pub))`; two intermediates issued for one CSR key carry the same identifier and different serial numbers.

`TestParsePEM` (Review Focus 4): each of the three parsers accepts a block with LF and with CRLF line endings, and refuses, with an error that says what it found: DER bytes ("not PEM"), two blocks ("2 PEM blocks; want one"), a block of another type (the type named), trailing text after the block.

Run: `go test ./internal/pki/ 2>&1 | tail -20`. Expected: the package does not compile.

- [ ] **Step 2: Implement** the functions above. `x509.CreateCertificate` and `x509.CreateCertificateRequest` do the encoding; every template sets `SubjectKeyId` from `SubjectKeyID` and never leaves it to the library.

- [ ] **Step 3: The import rule.** In `scripts/m7-exit-checks.sh`, beside the `keyprovider-leaf` lines: `check_allowlist pki-leaf ./internal/pki "$MOD/internal/pki"`. Add `bash scripts/m7-exit-checks.sh --deps-only` to the `verify` target.

Run: `go test ./internal/pki/ && bash scripts/m7-exit-checks.sh --deps-only | tail -2`. Expected: `ok` and `deps_ok=1`.

- [ ] **Step 4: Close the task** (Global Constraints). Commit: `feat(pki): certificate profiles and the agentmesh extended key usage (ADR 0019)`; files `internal/pki scripts/m7-exit-checks.sh Makefile`.

---

### Task 2: The enterprise number gate

**Files:**
- Create: `scripts/pen-gate.sh`, `scripts/pen-gate-selftest.sh`
- Modify: `Makefile` (targets `pen-check` and `pen-selftest`, both in `.PHONY`), `.github/workflows/ci.yml` (job `pen-gate`; the trigger `workflow_dispatch:` beside `push` and `pull_request`, so the controller can run the workflow on the branch at a checkpoint)

**Interfaces (Produces):**
- `bash scripts/pen-gate.sh [--file F]`: reads `internal/pki/eku.go` (or `F`). It needs exactly one line `const PrivateEnterpriseNumber = <digits>`. Exit 0 and `pen-gate: ok <n>` when `n` is none of 0 and 32473 and is below 2147483648; otherwise exit 1 and one line `pen-gate: FAIL <reason>` on standard error, where the reason for 32473 is `32473 is the documentation number (RFC 5612); the assigned number is not in yet (ADR 0019, Decision 36)`. A missing file or a missing or repeated line is exit 1 with its own reason.
- `bash scripts/pen-gate-selftest.sh`: runs the gate on six files it writes under `mktemp -d` (0, 32473, 2147483648, no constant, the constant twice, 99999), checks each exit code and reason, removes the directory, and prints `pen-gate-selftest: 6 run, 6 passed` or the names that failed (exit 1).
- CI job `pen-gate`: step 1 `make pen-selftest` on every push; step 2 `make pen-check` with `if: github.ref == 'refs/heads/main'`.

- [ ] **Step 1: Write the selftest first**, run it, and see it fail because `scripts/pen-gate.sh` does not exist.

- [ ] **Step 2: Write the gate.** Run: `make pen-selftest`. Expected: `pen-gate-selftest: 6 run, 6 passed`. Run: `make pen-check; echo "exit=$?"`. Expected: the 32473 reason and `exit=2` from make (the gate's 1): this is the intended state until Task 37.

- [ ] **Step 3: Close the task** (`make release-lint` included: the scripts and the workflow changed). Commit: `build(gates): pen-check refuses the stand-in enterprise number (ADR 0019)`.

State (Definition of Done D): both scripts write nothing outside `mktemp -d`; a second run and two runs at once are independent; a killed selftest leaves one temporary directory.

---

### Task 3: `internal/pki`: the chain check

**Files:**
- Create: `internal/pki/chain.go`
- Test: `internal/pki/chain_test.go`, `internal/pki/fixture_test.go` (test helpers that build roots, intermediates and leaves with chosen faults)

**Interfaces (Produces):**

```go
type Verified struct {
	Leaf, Intermediate  *x509.Certificate
	NotBefore, NotAfter time.Time // the period in which leaf, intermediate and root are all valid
}
func (v Verified) ValidAt(at time.Time, leeway time.Duration) bool // NotBefore-leeway <= at <= NotAfter+leeway

// VerifyChain is the chain check of section 4.2. presented is what the verifier was
// given, leaf first, without the root.
func VerifyChain(presented []*x509.Certificate, root *x509.Certificate, installation string, at time.Time, leeway time.Duration) (Verified, error)

// CheckChain is VerifyChain without the time: steps 1 to 5 below. The server calls it once for a
// leaf row and then tests ValidAt for every bearer (Plan ruling 2).
func CheckChain(presented []*x509.Certificate, root *x509.Certificate, installation string) (Verified, error)

// CheckIntermediate is rule 3 without the time: signed by root, the profile, the name, the usage.
func CheckIntermediate(c, root *x509.Certificate, installation string) error

var ErrChainLength, ErrChainSignature, ErrChainTime, ErrIntermediateProfile,
	ErrInstallation, ErrExtKeyUsage, ErrLeafProfile, ErrLeafLifetime error
```

Every refusal wraps exactly one of the eight errors. The order of the checks, which the tests pin:

1. `len(presented) != 2`: `ErrChainLength` (with the root that is not three certificates; Decision 32).
2. `CheckIntermediate(presented[1], root, installation)`: `CheckSignatureFrom(root)` fails: `ErrChainSignature`; not CA, basic constraints invalid, path length not 0, a missing certificate-signing or CRL-signing usage, no subject key identifier, or a key that is not ECDSA P-256: `ErrIntermediateProfile`; `Subject.CommonName != installation` (byte for byte): `ErrInstallation`; `!HasAgentmeshUsage`: `ErrExtKeyUsage`.
3. The leaf: CA true, basic constraints invalid or no digital-signature usage: `ErrLeafProfile`; no agentmesh usage: `ErrExtKeyUsage`; `NotAfter.Sub(NotBefore) > MaxLeafLifetime`: `ErrLeafLifetime`.
4. The period: the latest "not before" and the earliest "not after" of the three; an empty period is `ErrChainTime`.
5. The library's own verification, for the signatures and the path rules: `leaf.Verify(x509.VerifyOptions{Roots: <root>, Intermediates: <intermediate>, CurrentTime: <the period's NotBefore>, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})`; a failure is `ErrChainSignature` (Ruling 31: the library is asked for any usage and the usage is checked in steps 2 and 3).
6. `VerifyChain` only: `!ValidAt(at, leeway)`: `ErrChainTime`.

- [ ] **Step 1: Write the failing tests**

`TestVerifyChain`, one subtest per rule, each asserting `errors.Is` against the named error: `good` (nil, and the period is the intersection); `two-certificates` and `four-certificates` (`presented` of length 1 and 3: `ErrChainLength`); `wrong-root` (`ErrChainSignature`); `leaf-signed-by-another-key` (`ErrChainSignature`); `intermediate-path-length-1`, `intermediate-not-ca`, `intermediate-without-crl-sign`, `intermediate-without-ski` (`ErrIntermediateProfile`); `other-installation` (the same root, CN `other`: `ErrInstallation`); `intermediate-without-usage` and `leaf-without-usage` (`ErrExtKeyUsage`); `leaf-any-usage-only` (`ErrExtKeyUsage`); `leaf-is-ca` and `leaf-without-digital-signature` (`ErrLeafProfile`); `leaf-lifetime-at-ceiling` (720 h + 60 s exactly: nil) and `leaf-lifetime-over` (one second more: `ErrLeafLifetime`); `intermediate-expired-at-time`, `root-expired-at-time`, `root-not-yet-valid` (`ErrChainTime`); `leeway` (a leaf expired 30 s ago passes with a leeway of 60 s and fails with 0).

`TestValidAtMatchesVerifyChain` (Plan ruling 2): for one good chain and each of 12 times around the six boundaries of the three validity periods (one second before and after each), `VerifyChain(..., at, 0) == nil` exactly when the `Verified` that `CheckChain` returns reports `ValidAt(at, 0)`; and `CheckChain` accepts a chain whose leaf starts 60 seconds before its intermediate does (a leaf issued in the first minute of a new intermediate).

`TestCheckIntermediateIgnoresTime`: an expired intermediate passes `CheckIntermediate` (an expired one still serves history, section 4.9 step 2).

Run: `go test ./internal/pki/ -run 'TestVerifyChain|TestValidAt|TestCheckIntermediate' 2>&1 | tail -20`. Expected: compile failure (`VerifyChain` undefined).

- [ ] **Step 2: Implement `chain.go`** in the order above. Four lines appear exactly once in the file, each on one line, because Task 35's mutations anchor on them: `if c.Subject.CommonName != installation {`, `if !HasAgentmeshUsage(c) {` (the intermediate), `if !HasAgentmeshUsage(leaf) {` and `if leaf.NotAfter.Sub(leaf.NotBefore) > MaxLeafLifetime {`.

- [ ] **Step 3: Run** `go test ./internal/pki/`. Expected: `ok`.

- [ ] **Step 4: Close the task.** Commit: `feat(pki): the chain check (ADR 0019 Decisions 23, 25, 32)`.

---

### Task 4: `internal/pki`: CRLs, time-based numbers, revocation by key and the kept revocations

**Files:**
- Create: `internal/pki/crl.go`, `internal/pki/revocations.go`
- Test: `internal/pki/crl_test.go`, `internal/pki/revocations_test.go`

**Interfaces (Produces):**

```go
func NextNumber(now time.Time, previous int64) int64 // max(now.UnixMilli(), previous+1): Decisions 27 and 39
func CreateCRL(issuer *x509.Certificate, key crypto.Signer, number int64, now time.Time, serials []*big.Int) ([]byte, error)
func ParseCRL(der []byte) (*x509.RevocationList, error) // refuses a CRL without a number
func CheckCRL(crl *x509.RevocationList, issuer *x509.Certificate) error // signature; issuer valid at crl.ThisUpdate (Ruling 13)
func CRLNumber(crl *x509.RevocationList) int64

// Revocations is the kept revocations (Decision 27): once a serial number is in, it stays.
type Revocations struct {
	Root   []string            `json:"root"`   // revoked intermediate serial numbers (SerialText), sorted
	Leaves map[string][]string `json:"leaves"` // issuer key (KeyID) -> revoked leaf serial numbers, sorted
}
func (r *Revocations) AddRoot(crl *x509.RevocationList)
func (r *Revocations) AddLeaves(issuerKey string, crl *x509.RevocationList)
func (r *Revocations) Merge(o Revocations)
// RevokedKeys is revocation by key (Decision 26): the KeyID of every certificate in intermediates
// whose serial number is in Root. A listed serial number that matches none of them adds nothing.
func (r Revocations) RevokedKeys(intermediates []*x509.Certificate) map[string]bool
// LeafRevoked: the leaf's serial number is kept for its issuer key (KeyID(leaf.AuthorityKeyId)), or that key is revoked.
func (r Revocations) LeafRevoked(leaf *x509.Certificate, intermediates []*x509.Certificate) bool
func (r Revocations) LeafSerials(issuerKey string) []*big.Int
```

`CreateCRL` sets "this update" to `now`, "next update" to the issuer's "not after" (nobody enforces it, section 4.9) and each entry's revocation time to `now`.

- [ ] **Step 1: Write the failing tests**

`TestNextNumber`: `(now=1000 ms, previous=5)` is 1000; `(1000, 1000)` is 1001; `(1000, 2000)` is 2001 (the clock set back); a value above `1<<31` comes back unchanged plus one.

`TestCreateAndCheckCRL`: a CRL the intermediate signs checks against it and lists the serial numbers given; `CheckCRL` refuses one signed by another intermediate, one whose issuer was expired at "this update", and `ParseCRL` refuses one without a number; the root signs a CRL too (the root tool's case).

`TestRevocationByKey`: one key with two intermediate certificates A and B (a renewal); a root CRL that lists A's serial number alone gives `RevokedKeys` the key, and a leaf chaining through B is `LeafRevoked`; a root CRL that lists a serial number matching no held certificate revokes nothing.

`TestUnion`: after `AddLeaves(k, crl1)` (serial numbers 1, 2) and `AddLeaves(k, crl2)` (serial number 3 only), 1, 2 and 3 are all revoked; `Merge` of two values is the union for every key; the JSON form round-trips and its lists are sorted without duplicates.

Run: `go test ./internal/pki/ -run 'TestNextNumber|TestCreateAndCheckCRL|TestRevocationByKey|TestUnion' 2>&1 | tail`. Expected: compile failure.

- [ ] **Step 2: Implement.** `x509.CreateRevocationList` needs the issuer's subject key identifier and CRL-signing usage (section 4.2, plan ruling 3), which Task 1's profiles give. `LeafRevoked` holds the line `if r.RevokedKeys(intermediates)[issuer] {` exactly once (Task 35 anchors on it).

- [ ] **Step 3: Run** `go test ./internal/pki/`. Expected: `ok`.

- [ ] **Step 4: Close the task.** Commit: `feat(pki): CRLs, time-based numbers and the kept revocations (ADR 0019 Decisions 26, 27)`.

---

### Task 5: `internal/pki/rootca`: the root tool's rules

**Files:**
- Create: `internal/pki/rootca/rootca.go`, `state.go`, `lock.go`
- Test: `internal/pki/rootca/rootca_test.go`, `internal/pki/rootca/mode_unix_test.go` (the 0600 assertion)
- Modify: `scripts/m7-exit-checks.sh` (`check_allowlist pki-leaf ./internal/pki/rootca "$MOD/internal/pki"`)

**Interfaces (Produces):**

```go
package rootca // standard library and internal/pki only

var ErrRefused = errors.New("rootca: refused") // a refused input: the command exits 2; any other error is exit 1

func Init(dir, name string, days int, now time.Time) (thumbprint string, err error)
func Root(dir string) (*x509.Certificate, error)
func Sign(dir string, csr *x509.CertificateRequest, days int, sameInstallation bool, now time.Time) (*x509.Certificate, error)
// Revoke marks cert's key revoked: cert and every other issued certificate with the same subject key identifier.
// revoked lists the thumbprints this call newly revoked (empty on a repeat).
func Revoke(dir string, cert *x509.Certificate, now time.Time) (crlDER []byte, revoked []string, err error)
```

Files in `dir`: `root.key` (PKCS#8 PEM, created with `O_CREATE|O_EXCL` at mode 0600), `root.pem`, `state.json` (Plan ruling 6), `root.crl`, `lock` (Plan ruling 5). The root key is ECDSA P-256. Defaults when `days` is 0: 3650 for `Init`, 365 for `Sign`. `state.json` and `root.crl` are replaced through a temporary file in `dir` and `os.Rename`, the state first.

- [ ] **Step 1: Write the failing tests** (every row of section 4.3's table, and Ruling 43)

`TestInit`: writes the three files; the certificate has the root profile and `days` of validity; the thumbprint returned is `pki.Thumbprint` of it. `TestInitRefusesExistingRoot`: a second `Init` is `ErrRefused` and `root.key` is byte for byte unchanged. `TestInitAfterDeadRun`: a directory holding `root.key` alone is `ErrRefused` with the file named in the message.

`TestSign`: the certificate passes `pki.CheckIntermediate` for the CSR's name; `state.json` records it; a CSR with a bad signature (`ParseRequest` fails upstream) and a call with a CSR whose CN is empty are `ErrRefused`. `TestSignTwice`: the same CSR twice gives two serial numbers and one subject key identifier (a renewal needs no flag). `TestSignNameTaken` (Decision 37): a CSR with a recorded name and another key is `ErrRefused`, the message names `-same-installation` and the recorded key's identifier, and `state.json` is byte for byte unchanged; with `sameInstallation` it is issued; the flag given for a new name, or for the recorded key, changes nothing; a name whose only certificate is revoked or expired is still taken.

`TestRevoke`: after two certificates for key K and one for key L, revoking one of K's lists both of K's thumbprints, the CRL lists both serial numbers and not L's, `root.crl` holds it, and the CRL number is `pki.NextNumber(now, previous)`; `TestRevokeTwice`: the second call returns the same CRL bytes, an empty `revoked` and an unchanged number; `TestRevokeClockBack`: a second, different revocation with `now` one hour earlier gets the previous number plus one; `TestRevokeUnknown`: a certificate the tool never issued is `ErrRefused`.

`TestLock`: with `dir/lock` present, a `Sign` whose wait is shortened to 50 ms through a package variable fails with a message naming the file and is not `ErrRefused`; after a normal `Sign` the file is gone. `TestConcurrentSign`: eight goroutines signing eight CSRs end with eight recorded certificates.

`mode_unix_test.go`: `root.key` has mode 0600.

Run: `go test ./internal/pki/rootca/ 2>&1 | tail`. Expected: compile failure.

- [ ] **Step 2: Implement.** One lock for the whole of `Sign` and of `Revoke`; `Init` relies on the exclusive create of `root.key`. The name refusal is the line `if taken && !sameInstallation {`, exactly once in `rootca.go` (Task 35 anchors on it).

- [ ] **Step 3: Run** `go test -race ./internal/pki/rootca/ && bash scripts/m7-exit-checks.sh --deps-only | tail -1`. Expected: `ok`, `deps_ok=1`.

- [ ] **Step 4: Close the task.** Commit: `feat(rootca): the root tool's package (ADR 0019 Decisions 9, 26, 37)`.

State (Definition of Done D): section 4.3's table, each row a test above. A killed run can leave `lock`; the next run says so after 10 seconds (Plan ruling 5).

---

### Task 6: `agentmesh ca init | sign | revoke`

**Files:**
- Create: `internal/cli/ca.go`
- Test: `internal/cli/ca_test.go`
- Modify: `internal/cli/cli.go` (`"ca": RunCA` in `commands`; the `Usage` text)

**Interfaces:**
- Consumes: Task 5's four functions, Task 1's PEM parsers.
- Produces: `func RunCA(ctx context.Context, args []string, environ []string, stdin io.Reader, stdout, stderr io.Writer) int`. Exit codes: 0 done; 2 usage or `rootca.ErrRefused` or an unparseable input file; 1 anything else.
  - `ca init -dir DIR [-name NAME] [-days N]`: standard output `root DIR/root.pem` and `thumbprint <t>`, one per line. `-name` defaults to `agentmesh root`.
  - `ca sign -dir DIR [-days N] [-same-installation] CSR_FILE`: the certificate as PEM on standard output; `installation <name>` on standard error.
  - `ca revoke -dir DIR CERT_FILE`: the CRL as PEM on standard output; one `revoked <thumbprint>` line per certificate on standard error.
  - `-dir` is required. The command opens no profile, no server and no database, and takes neither `-profile` nor `-identity`.

- [ ] **Step 1: Write the failing tests**: `TestCAInitSignRevoke` (the three commands in order in `t.TempDir()`; the printed certificate parses and passes `pki.CheckIntermediate`; the printed CRL lists it); `TestCASignRefusals` (a second key under a recorded name: exit 2 and `-same-installation` in standard error; with the flag: exit 0); `TestCAInputs` (Review Focus 4: a CRLF CSR file is accepted; a DER file and a file with two blocks are exit 2 with the parser's message); `TestCAUsage` (no subcommand, an unknown one, a missing `-dir`, a missing file argument: exit 2 with the usage line); `TestCAInitTwice` (exit 2).

Run: `go test ./internal/cli/ -run '^TestCA' 2>&1 | tail`. Expected: compile failure.

- [ ] **Step 2: Implement `ca.go`.**

- [ ] **Step 3: Run** `go test ./internal/cli/ -run '^TestCA' && bash scripts/m6-exit-checks.sh --deps-only | tail -1`. Expected: `ok`, `deps_ok=1` (`internal/cli` gains only `internal/pki` and `internal/pki/rootca`).

- [ ] **Step 4: Close the task.** Commit: `feat(cli): agentmesh ca init, sign and revoke (ADR 0019 Decision 9)`.

---

### Task 7: `keyprovider.FileProvider`

**Files:**
- Create: `internal/keyprovider/file.go`
- Test: `internal/keyprovider/file_test.go`
- Modify: `internal/keyprovider/keyprovider.go` (package comment only), `scripts/m7-exit-checks.sh` (the comment of `keyprovider-leaf` names the file provider)

**Interfaces (Produces):**

```go
const NameFile = "file"

// FileProvider holds the intermediate key in a PKCS#8 PEM file (Decision 10). Read returns the
// file's bytes after the caller's owner-only check (Plan ruling 11); a nil Read is an error on use.
type FileProvider struct {
	Path string
	Read func(path string) ([]byte, error)
}
func (p FileProvider) Name() string // NameFile
func (p FileProvider) Next(ctx context.Context) (Key, error)        // reads the file; Key{KID, ES256, Public}; Ref ""
func (p FileProvider) Signer(ctx context.Context, k Key) (Signer, error) // reads the file; refuses a key that is not k.KID

// CreateKeyFile generates an ECDSA P-256 key and writes it at path: a temporary file in the same
// directory at mode 0600, then os.Link to path, so an existing file is never replaced (fs.ErrExist).
func CreateKeyFile(path string) error
```

A file whose key is not ECDSA P-256 is an error that names the path and the key type found (`describe`). The `StoreProvider` stays until Task 24.

- [ ] **Step 1: Write the failing tests**: `TestFileProviderNextAndSign` (a signature made through `Signer(...).SignContext` over a SHA-256 digest verifies with the public key `Next` returned); `TestFileProviderRefuses` (an Ed25519 key, a P-384 key, an RSA key, an empty file, a nil `Read`, a `Read` that fails: each error names the path); `TestFileProviderKeyChanged` (`Signer` with the `Key` of another file's key is refused); `TestCreateKeyFile` (creates; a second call is `fs.ErrExist` and the file is unchanged; no temporary file is left in either case; eight goroutines racing end with one winner and seven `fs.ErrExist`).

Run: `go test ./internal/keyprovider/ -run 'TestFileProvider|TestCreateKeyFile' 2>&1 | tail`. Expected: compile failure.

- [ ] **Step 2: Implement.** **Step 3: Run** `go test -race ./internal/keyprovider/ && bash scripts/m7-exit-checks.sh --deps-only | tail -1`.

- [ ] **Step 4: Close the task.** Commit: `feat(keyprovider): the file provider for the intermediate key (ADR 0019 Decision 10)`.

---

### Task 8: The Store: `trust_material`

**Files:**
- Create: `internal/store/trust.go`, `internal/store/sqlstore/trust.go`, `internal/conformance/store/trust_test.go`
- Modify: `internal/store/store.go` (`Tx` embeds `TrustMaterial`), `internal/store/sqlite/schema/0001_initial.sql`, `internal/store/postgres/schema/0001_initial.sql`, `internal/store/meta.go` (the `ResetData` comment names `trust_material`), `internal/store/sqlstore/meta.go` if `ResetData` lists tables, `internal/conformance/store/reset_test.go`, `open_test.go:363` (the table list), `store_test.go` (the read-only method list)

**Interfaces (Produces):**

```go
const (
	TrustIntermediate = "intermediate"
	TrustLeaf         = "leaf"
	TrustRootCRL      = "root_crl"
	TrustLeafCRL      = "leaf_crl"
)

type TrustCertificate struct {
	ID         int64  // assigned by PutTrustCertificate; stable for the life of the row
	Kind       string // TrustIntermediate or TrustLeaf
	Thumbprint string
	DER        []byte
	IssuerKey  string // a leaf: the intermediate key's identifier; an intermediate: ""
	NotAfter   int64  // Unix milliseconds
	KeyRef     string // an intermediate with a key service: the pinned reference; else ""
	CreatedAt  int64
}

type TrustCRL struct {
	Kind       string // TrustRootCRL (IssuerKey "") or TrustLeafCRL
	Thumbprint string
	DER        []byte
	IssuerKey  string
	Number     int64
	CreatedAt  int64
}

type TrustMaterial interface {
	// ErrInvalid: a kind outside the two, an empty thumbprint or DER, NotAfter or CreatedAt <= 0, an
	// intermediate with an IssuerKey, a leaf without one or with a KeyRef. ErrConflict: (kind, thumbprint) exists.
	PutTrustCertificate(ctx context.Context, c TrustCertificate) (id int64, err error)
	TrustCertificates(ctx context.Context, kind string) ([]TrustCertificate, error) // by id ascending; empty non-nil
	TrustCertificateByThumbprint(ctx context.Context, kind, thumbprint string) (TrustCertificate, bool, error)
	// PutCRL inserts the row of (kind, issuer key) or replaces it when c.Number is higher than the
	// stored one; otherwise ErrConflict. ErrInvalid as above, and for Number <= 0.
	PutCRL(ctx context.Context, c TrustCRL) error
	CRLs(ctx context.Context) ([]TrustCRL, error) // the root CRL first, then leaf CRLs by issuer key
	TrustNumber(ctx context.Context) (int64, error)
	// BumpTrustNumber sets the number to the larger of now and the stored number plus one and
	// returns it (Decision 39). On Postgres it also sends the control notification in the transaction.
	BumpTrustNumber(ctx context.Context, now int64) (int64, error)
	ExpiredLeafCertificates(ctx context.Context, before int64, limit int) ([]TrustCertificate, error)
	// DeleteTrustCertificates deletes leaf rows by id and returns how many; an id of an intermediate
	// row is ErrInvalid and nothing is deleted (intermediate rows are never deleted, Ruling 33).
	DeleteTrustCertificates(ctx context.Context, ids []int64) (int, error)
}
```

Schema, in both `0001_initial.sql` files beside `signing_keys` (SQLite types shown; Postgres uses `BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY`, `BYTEA` and `BIGINT`, and its seed row writes the empty value as `'\x'`, because `x''` is a bit string there):

```sql
CREATE TABLE trust_material (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL CHECK (kind IN ('intermediate', 'leaf', 'root_crl', 'leaf_crl', 'trust_number')),
  thumbprint TEXT NOT NULL DEFAULT '',
  der BLOB NOT NULL,
  issuer_key TEXT NOT NULL DEFAULT '',
  not_after INTEGER NOT NULL DEFAULT 0,
  number INTEGER NOT NULL DEFAULT 0,
  key_ref TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX trust_material_certificate ON trust_material (kind, thumbprint) WHERE kind IN ('intermediate', 'leaf');
CREATE UNIQUE INDEX trust_material_single ON trust_material (kind, issuer_key) WHERE kind IN ('root_crl', 'leaf_crl', 'trust_number');
CREATE INDEX trust_material_leaf_expiry ON trust_material (not_after) WHERE kind = 'leaf';
INSERT INTO trust_material (kind, der, created_at) VALUES ('trust_number', x'', 0);
```

The schema version stays 1; no migration (the pre-release rule). The SQL filters on `kind` only, which `TestAccessRuleSites` does not watch.

- [ ] **Step 1: Write the failing suite** in `internal/conformance/store/trust_test.go` (it runs on both engines like its neighbors): `TestTrustCertificates` (put, list by kind in id order, by thumbprint, the duplicate `ErrConflict`, each `ErrInvalid` case, ids that grow); `TestPutCRL` (insert; a higher number replaces; an equal and a lower number are `ErrConflict` and leave the row; one row per issuer key; one root CRL); `TestTrustNumber` (a new store reads 0; `BumpTrustNumber(1000)` is 1000; `BumpTrustNumber(500)` is 1001, the clock set back; a value above `1<<31` such as 1767225600000 is stored and read back; two concurrent transactions never return the same number); `TestExpiredLeaves` (only leaves with `NotAfter < before`, at most `limit`, never an intermediate); `TestDeleteTrustCertificates` (deletes leaves; an intermediate id is `ErrInvalid` and nothing goes); `TestResetKeepsTrustMaterial` in `reset_test.go`. Add the six read methods to the stub check in `store_test.go` and `trust_material` to `open_test.go:363`.

Run: `go test -count=1 ./internal/conformance/store/ -run 'Trust|PutCRL|ExpiredLeaves' 2>&1 | tail`. Expected: compile failure.

- [ ] **Step 2: Implement** `sqlstore/trust.go` and the schema. `BumpTrustNumber` calls the dialect's `NotifyControl` (`internal/store/postgres/notify.go:71`), as `RegisterWatch` does, and computes the number in Go on the line `next := max(now, stored+1)`, exactly once in the file (Task 35 anchors on it).

- [ ] **Step 3: Run** `make test-conformance 2>&1 | tail -5` and `make check-gates 2>&1 | tail -8`. Expected: every suite `ok` on both engines; every check `ok`.

- [ ] **Step 4: Close the task.** Commit: `feat(store): the trust_material table and its methods (ADR 0019 section 4.5)`.

State (Definition of Done D): every method is one statement inside the caller's transaction; a rerun of a failed transaction repeats it whole; two bumps serialize on the row.

---

### Task 9: Server settings (accepted, not yet required)

**Files:**
- Modify: `internal/server/config/config.go`, `internal/server/config/config_test.go`, `docs/ops/configuration.md` (the five rows; a test of that file pins the settings list if one exists: run the package's tests)

**Interfaces (Produces):**

```go
// Config gains:
RootCertificateFile string `json:"root_certificate_file"`
IntermediateKeyFile string `json:"intermediate_key_file"`
IntermediateKeyURI  string `json:"intermediate_key_uri"`
LeafValidityHours   int    `json:"leaf_validity_hours"` // Default(): 168
InstallationName    string `json:"installation_name"`

// RequireTrust is nil when the trust settings a server needs are all there: root_certificate_file,
// installation_name, and exactly one of intermediate_key_file and intermediate_key_uri (Plan ruling 10).
func (c Config) RequireTrust() error
func (c Config) LeafValidity() time.Duration
```

`Validate` adds, for values that are set: `leaf_validity_hours` between 2 and 720; `installation_name` passes `pki.ValidInstallationName`; `intermediate_key_uri` passes `keyprovider.SchemeOf` with a scheme (the message names the key by `keyprovider.KeyName`, never the URI); both intermediate settings set at once is an error; `token_lifetime_seconds`, and each issuer's `human_token_lifetime_seconds` (900 when 0), must not exceed `leaf_validity_hours * 1800` (W/2 in seconds), with the message `token_lifetime_seconds 7200 is more than half of leaf_validity_hours 2 (3600 seconds)`. The three `signing_key_*` settings stay until Task 24.

- [ ] **Step 1: Write the failing tests**: `TestTrustSettingsDefaults` (168; the four strings empty); `TestTrustSettingsValidation` (hours 1 and 721 refused, 2 and 720 accepted; names `Prod` and 65 characters refused; a URI `ftp://x` refused; a URI with a credential in it never appears in the error text; both key settings refused); `TestLifetimeWithinHalfTheLeaf` (W 2 with a token lifetime of 3600 accepted and 3601 refused; W 2 with an issuer whose human lifetime is 0 accepted (900) and 3601 refused; the defaults accepted); `TestRequireTrust` (each of the four missing or doubled cases names its setting; the complete set is nil). `TestSettingsListsEveryJSONName` covers the five names.

Run: `go test ./internal/server/config/ 2>&1 | tail`. Expected: failures naming the new tests.

- [ ] **Step 2: Implement.** **Step 3: Run** `go test ./internal/server/...`. Expected: `ok`.

- [ ] **Step 4: Close the task.** Commit: `feat(config): the trust settings, validated when set (ADR 0019 section 4.12)`.

---

### Task 10: The client profile rule: HTTPS, `insecure_http`, `root_thumbprint`, `installation`

**Files:**
- Modify: `internal/profile/config.go` (`Profile` members, `validServer`), `internal/profile/config_test.go`
- Modify: `internal/client/options.go` (`Options.InsecureHTTP bool`, `Options.RootThumbprint`, `Options.Installation string`), `Resolve` in `internal/client/options.go:116` (the in-memory profile of an undefined `-server` takes them; a defined profile that disagrees is a `ResolveError`, Plan ruling 29), `internal/client/resolve_test.go`
- Modify: `internal/mcpcli/flags.go` (`commonFlags` registers `-insecure-http`, `-root-thumbprint T`, `-installation NAME`; `applyEnv` reads `AGENTMESH_INSECURE_HTTP`, `AGENTMESH_ROOT_THUMBPRINT`, `AGENTMESH_INSTALLATION`), `internal/mcpcli/register.go`, `internal/cli/register.go` (the three flags; `register` writes the members when it creates the profile), `internal/client/registration.go` (the created profile carries them), `internal/mcpcli/help.go` (the flags and variables; every example with an `http` server keeps a loopback host)
- Test: `internal/mcpcli/flags_test.go`, `internal/mcpcli/register_test.go`, `internal/cli/register_test.go`, and every test fixture that names a server `http://h:1`, `http://h:2` or `http://elsewhere:1` (`internal/client/resolve_test.go:249-264`, `internal/mcpcli/mcpcli_test.go:87-106`, `internal/mcpcli/config_test.go:25-32`, `internal/cli/register_test.go:133`): they become `https://h:1` and so on, unless the test is about the rule

**Interfaces (Produces):**

```go
// Profile gains (server mode only; in a local profile each is an error):
InsecureHTTP   bool   `json:"insecure_http,omitempty"`
RootThumbprint string `json:"root_thumbprint,omitempty"` // 43 base64url characters
Installation   string `json:"installation,omitempty"`    // pki.ValidInstallationName
```

The rule for `server` (section 4.10): `https` is accepted; `http` to the host `127.0.0.1`, `::1` or `localhost` is accepted; `http` to any other host is accepted only with `insecure_http`, and refused otherwise with `server "http://h:1" must use https (http is accepted for 127.0.0.1, ::1 and localhost, or with insecure_http: true, the flag -insecure-http, for local testing only)`. `AGENTMESH_INSECURE_HTTP` accepts `1` and the empty string; any other value is exit 2 naming the variable.

- [ ] **Step 1: Write the failing tests**

`internal/profile`: `TestServerURLRule`: `https://h` accepted; `http://127.0.0.1:1`, `http://[::1]:1`, `http://localhost:1` accepted without the switch; `http://h:1` and `http://127.0.0.2:1` refused with `insecure_http` in the message; both accepted with `InsecureHTTP: true`. `TestTrustMembers`: a thumbprint of 42 characters or with `+` refused; `Installation: "Prod"` refused; each of the three members in a local profile refused; all three round-trip through `Save` and `Load`.

`internal/client`: `TestInMemoryProfileTrustOptions`: an undefined `-server http://h:1` resolves only with `Options.InsecureHTTP`; `RootThumbprint` and `Installation` reach `Resolved.Profile`; a defined profile with another `root_thumbprint`, another `installation` or without `insecure_http` against the option is a `ResolveError` containing `disagrees`.

`internal/mcpcli`: `TestTrustFlagsAndEnv`: each of the three as a flag and as a variable reaches `client.Options`; the flag wins over the variable; `AGENTMESH_INSECURE_HTTP=true`, `=0` and `=yes` are exit 2. `TestRegisterWritesTrustMembers` (also in `internal/cli`): `register -server <loopback test server> -insecure-http -root-thumbprint <t> -installation prod` writes a profile with the three members; `register -server http://elsewhere:1` without the switch is exit 2 and names `-insecure-http`.

Run: `go test ./internal/profile/ ./internal/client/ ./internal/mcpcli/ ./internal/cli/ 2>&1 | tail -20`. Expected: the new tests fail; fixtures with `http://h:1` fail until changed.

- [ ] **Step 2: Implement**, then change the fixtures. `validServer` takes the profile, and the rule is the line `if !loopbackHost(u.Hostname()) && !p.InsecureHTTP {`, exactly once in `internal/profile/config.go` (Task 35 anchors on it); `loopbackHost` is a new unexported function of the package, and the `oidc.issuer` rule at `config.go:60-64` uses it too. `TestHelpExamples` (`internal/e2e`) must still pass: `go test ./internal/e2e/ -run TestHelpExamples`.

- [ ] **Step 3: Run** `go test ./internal/profile/ ./internal/client/... ./internal/mcpcli/ ./internal/cli/ && bash scripts/m6-exit-checks.sh --deps-only | tail -1 && bash scripts/m10-exit-checks.sh --deps-only | tail -1`. Expected: `ok` and both `deps_ok=1` (`internal/profile` gains `internal/pki`, which is standard library only).

- [ ] **Step 4: Close the task.** Commit: `feat(profile): https by default, insecure_http, root_thumbprint and installation (ADR 0019 Decisions 19, 30, 38)`.

---

### Task 11: `internal/trust`: the client's trust store

**Files:**
- Create: `internal/trust/store.go`, `pin.go`, `apply.go`
- Test: `internal/trust/store_test.go`, `pin_test.go`, `apply_test.go`, `mode_unix_test.go`
- Modify: `scripts/m7-exit-checks.sh` (rule `trust-leaf`: `check_allowlist trust-leaf ./internal/trust "$MOD/internal/trust" "$MOD/internal/filelock" "$MOD/internal/pki"`, plus `golang.org/x/sys` if the rule's Windows pass reports it through `internal/filelock`; the comment says why)

**Interfaces (Produces):**

```go
package trust // standard library, internal/filelock and internal/pki only

func Dir(configDir, profile string) string // <config dir>/trust/<profile>

type Store struct{ Dir string }

// Bundle is a trust bundle as received (section 4.9); every certificate and CRL is DER.
type Bundle struct {
	TrustNumber   int64
	Intermediates [][]byte
	RootCRL       []byte
	LeafCRLs      [][]byte
	Root          []byte // discover only
	Installation  string // discover only
}

// Expect is what the profile says: its server URL and the optional expected root and installation.
type Expect struct{ Server, RootThumbprint, Installation string }

type Pin struct {
	Root                             *x509.Certificate
	Thumbprint, Installation, Server string
}

// MismatchError is every "stop, pin nothing, replace nothing" case. What is one of
// "root", "installation", "server", "expected root", "expected installation".
type MismatchError struct{ What, Held, Got string }

type Accepted struct {
	First, Replaced bool
	Old, New        Pin
}

func (s Store) Pinned() (Pin, bool, error)
// Check compares a held pin with e: the server URL, then RootThumbprint and Installation when set.
func (s Store) Check(e Expect) error
// Accept takes the root and the name of a discover bundle. No pin: both must satisfy e, then they are
// pinned (First). The same pin: nothing. A different root or name: *MismatchError, unless acceptNew,
// which checks e and then replaces the pin and removes the stored chain, CRLs and kept revocations.
func (s Store) Accept(b Bundle, e Expect, acceptNew bool) (Accepted, error)

type RefusedCRL struct {
	IssuerKey string // "" for the root CRL
	Held, Got int64
}
type Report struct{ Refused []RefusedCRL }
// Apply is steps 2 to 5 of section 4.9 against the pin. It needs a pin (an error without one).
func (s Store) Apply(b Bundle) (Report, error)

func (s Store) TrustNumber() (n int64, ok bool, err error)
func (s Store) Intermediates() ([]*x509.Certificate, error)
func (s Store) Revocations() (pki.Revocations, error)
```

Files (Plan ruling 20): `root.pem`, `intermediates.pem`, `root.crl`, `leaf-<issuer key>.crl`, `revoked.json`, `state.json`, `.lock`; the directory 0700, files 0600. Every read and every write holds `filelock.Lock` on `.lock`; every write is a temporary file in the directory and `os.Rename`, the pin first.

`Apply`, exactly: (2) keep each bundle intermediate that passes `pki.CheckIntermediate(c, root, pinned name)`, added to the ones held and never dropped, with no test of its validity period or its revocation; (3) the root CRL passes `pki.CheckCRL(crl, root)` and its number is not below the held one: store it and `AddRoot`; a lower number is refused and reported; (4) each leaf CRL is signed by a kept intermediate whose key is not in `RevokedKeys`, and its number is not below the held one for that issuer key: store it and `AddLeaves`; a lower number is refused and reported; (5) record the bundle's trust number, higher or lower, a refused CRL notwithstanding. A CRL refused for its number adds nothing to the kept revocations (Ruling 34).

- [ ] **Step 1: Write the failing tests** (section 7, "Client trust store", at the store's level)

`TestFirstContactPins`; `TestDifferentRootRefused` (`MismatchError{What: "root"}` with both thumbprints; every file byte for byte unchanged); `TestDifferentInstallationRefused` (the same root, another name); `TestExpectedRoot` (a match pins; another root is `"expected root"` and the directory stays empty; `acceptNew` toward a root that does not match is refused; a held pin that differs fails `Check`); `TestExpectedInstallation` (the same four cases for the name); `TestExpectIndependent` (either setting works without the other); `TestServerChanged` (`Check` with another URL: `"server"`); `TestAcceptNewRoot` (replaces the pin; `intermediates.pem`, the CRL files and `revoked.json` are gone; a second run changes nothing).

`TestApplyKeepsIntermediates` (one with another installation's name is not kept; an expired one is kept; one already held and absent from the bundle stays); `TestApplyCRLNumbers` (equal and higher accepted; lower refused, reported with both numbers, the held file unchanged); `TestApplyUnion` (a serial number an earlier CRL listed and the current one lacks is still in `Revocations`); `TestApplyLeafCRLOfRevokedKey` (not accepted); `TestApplyRecordsTrustNumber` (a lower bundle number is recorded; also when a CRL was refused); `TestApplyTwice` (no file changes: compare modification-independent contents).

`TestTwoFirstContacts` (two goroutines `Accept` the same bundle: one `First`, the other neither `First` nor an error; with different roots the second gets the mismatch); `TestTwoWriters` (concurrent `Apply` of two bundles: the higher CRL numbers win and the kept revocations are the union); `TestCrashBetweenFiles` (a pin written and nothing else, as a killed first contact leaves it: `Apply` completes it); `TestStoreUnwritable` (Review Focus 5: a directory that cannot be created, made by putting a regular file where the directory should be, makes `Accept` fail with the path in the error and `Pinned` report no pin); `TestConcurrentReadWrite` (Review Focus 5: one goroutine applies 200 bundles while another calls `TrustNumber` and `Intermediates` in a loop; no error on any OS).

`mode_unix_test.go`: directory 0700, files 0600.

Run: `go test ./internal/trust/ 2>&1 | tail`. Expected: compile failure.

- [ ] **Step 2: Implement.** The expected-installation check in `Accept` is the line `if e.Installation != "" && b.Installation != e.Installation {`, exactly once in `pin.go` (Task 35 anchors on it). **Step 3: Run** `go test -race ./internal/trust/ && bash scripts/m7-exit-checks.sh --deps-only | tail -1`. Expected: `ok`, `deps_ok=1`.

- [ ] **Step 4: Close the task.** Commit: `feat(trust): the client's trust store (ADR 0019 Decisions 19, 23, 27, 30, 38)`.

State (Definition of Done D): section 5's last three rows, each a test above.

---

### Task 12: `signingkeys.Trust`: the verified view of the stored rows, and installing an intermediate and a root CRL

**Files:**
- Create: `internal/core/signingkeys/trust.go`, `material.go`, `install.go`
- Test: `internal/core/signingkeys/material_test.go`, `install_test.go`, `helpers_test.go` (new helpers go here: `service_test.go` is deleted in Task 24). `helpers_test.go` holds the package's own fixture (Plan ruling 26): `newFixture(t)` makes a throwaway root through `rootca`, an intermediate key file with `keyprovider.CreateKeyFile` and the signed intermediate, with the methods `sibling(name)`, `renew(days)`, `revokeIntermediate()`, `trust(c)` and `install(c)`; Tasks 17 and 19 add `manager(c)` and `leaf(c, now, validity)`

**Interfaces:**
- Consumes: Tasks 1, 3, 4 (`pki`), Task 7 (`keyprovider.FileProvider`), Task 8 (the `Tx` methods).
- Produces:

```go
// Trust is the rules over the stored trust material. The host commands and the manager call it; it
// checks no caller (they are trusted or have checked already).
type Trust struct {
	*core.Core
	Root         *x509.Certificate
	Installation string
	Provider     keyprovider.Provider // nil where nothing signs (list, status)
}

const LockName = "trust"            // the Store lock that serializes every change (section 4.5)
const SignTimeout = 30 * time.Second // bounds one use of the intermediate key (the value of NextTimeout today)

// CryptoSigner adapts a keyprovider.Signer to crypto.Signer under ctx, for x509.Create*.
func CryptoSigner(ctx context.Context, s keyprovider.Signer) crypto.Signer

// Memory is what one process remembers between loads (section 4.8): the highest number it has
// verified for each CRL with that CRL's bytes, the kept revocations, and the chains it has already
// verified. The zero value is ready; it is not safe for concurrent use.
type Memory struct{ /* unexported */ }

type Leaf struct {
	ID       int64
	Verified pki.Verified
	Revoked  bool
}

type Material struct {
	Number        int64                           // read in the same transaction as the rows
	Intermediates []*x509.Certificate             // every stored one that passes pki.CheckIntermediate, in row order
	KeyRefs       map[string]string               // intermediate thumbprint -> key_ref
	RootCRL       *x509.RevocationList            // nil: none
	LeafCRLs      map[string]*x509.RevocationList // by issuer key
	Leaves        []Leaf                          // every leaf row whose chain verifies, in row order
	Revoked       pki.Revocations                 // the union this process holds
	RevokedKeys   map[string]bool
	Rollback      []store.TrustCRL                // CRLs this process holds that are newer than the stored ones
}

// Load reads the rows in one Store.Read and verifies each against the pinned root. A row that does
// not verify is ignored and logged once with its kind and thumbprint; only a Store failure is an error.
func (t Trust) Load(ctx context.Context, mem *Memory) (Material, error)

var ErrCheck = errors.New("signingkeys: check failed") // a refused install; the host command exits 2

func (t Trust) InstallIntermediate(ctx context.Context, cert *x509.Certificate) (changed bool, err error)
func (t Trust) InstallRootCRL(ctx context.Context, crl *x509.RevocationList) (changed bool, err error)
```

`Load`, exactly: an intermediate row is kept when its `thumbprint` column is `pki.Thumbprint(der)` and `pki.CheckIntermediate` passes; expiry and revocation do not drop it. The root CRL must pass `pki.CheckCRL(crl, Root)`; a leaf CRL must pass it against a kept intermediate of its `issuer_key` whose key is not revoked. A CRL whose number is below the one in `mem` is ignored, logged as a rollback, and the newer one from `mem` goes into `Rollback`; otherwise `mem` takes its number and bytes and its serial numbers join the union. A leaf row is verified with `pki.CheckChain` (no time, so the result does not depend on the clock) against each kept intermediate certificate of its issuer key; the result with the latest `NotAfter` is kept. `mem` caches results by leaf thumbprint and intermediate thumbprint, so a later load verifies only pairs it has not seen. `Leaf.Revoked` is `Revoked.LeafRevoked`.

`InstallIntermediate`, the checks in order, each wrapping `ErrCheck` with its own text (section 4.4): `does not chain to the pinned root`; `is not valid now`; `is not a CA with path length 0`; `lacks the certificate signing or the CRL signing usage`; `has no subject key identifier`; `its public key is not the configured intermediate key` (`Provider.Next`, bounded by `SignTimeout`); `names installation %q, this server is %q`; `lacks the agentmesh extended key usage`; `its subject key identifier differs from the stored certificates of the same key` (Ruling 33); `its key is revoked by the stored root CRL` (Decision 26). Then, under the `trust` lock (`Store.TryLock(ctx, LockName, t.Owner, now, now+60 s)`; held elsewhere: a retryable `unavailable`), one transaction: the thumbprint is already stored: `changed` false and nothing else; otherwise `PutTrustCertificate` (with `KeyRef` the `Ref` that `Next` returned) and `BumpTrustNumber(now)`.

`InstallRootCRL`: `pki.CheckCRL(crl, Root)` or `ErrCheck` (`is not signed by the pinned root`); the same thumbprint as the stored root CRL: `changed` false; a number not above the stored one: `ErrCheck` (`number %d is not above the stored %d`); else, under the lock, one transaction with `PutCRL` and `BumpTrustNumber(now)`.

- [ ] **Step 1: Write the failing tests**

`TestLoadVerifiesRows`, one subtest per tampered row, each asserting the row is absent from `Material`, one log line names its thumbprint and `Load` returns no error: an intermediate signed by another root; one with another installation's name; one without the agentmesh usage; a `thumbprint` column that is not the DER's; garbage DER in each of the four kinds; a self-signed leaf; a leaf under an ignored intermediate; a leaf valid one second over the ceiling; a leaf CRL signed by another key. And kept: an expired intermediate; an expired leaf (in `Leaves`, its period in the past).

`TestLoadRevocationByKey` (two certificates of one key, the root CRL lists one: every leaf of the key has `Revoked` true); `TestLoadUnion` (a leaf revoked by an earlier load stays revoked when the stored CRL no longer lists it); `TestLoadRollback` (after a load that saw leaf CRL number 2000, the row is put back to number 1000: the entry stays revoked, `Rollback` holds the 2000 CRL, the log says `rollback`); `TestLoadCachesVerification` (a second `Load` over the same rows makes no call to `pki.CheckChain`, counted through a package-level test hook).

`TestInstallIntermediate`: one subtest per check above with its text and `errors.Is(err, ErrCheck)`; a good certificate adds the row and raises the trust number; the same certificate again: `changed` false, the number unchanged; two calls at once end with one row. `TestInstallIntermediateKeyService` (with `kmsfake`): the row's `key_ref` is the reference `Next` returned. `TestInstallRootCRL`: accepted; the same again unchanged; a lower number and another root's CRL refused.

Run: `go test ./internal/core/signingkeys/ -run 'TestLoad|TestInstall' 2>&1 | tail`. Expected: compile failure.

- [ ] **Step 2: Implement.** The chain of a leaf row is checked on this line, exactly once in `material.go` and on one line (Task 35's mutation anchors on it): `v, err := pki.CheckChain([]*x509.Certificate{leaf, im}, t.Root, t.Installation)`. **Step 3: Run** `go test -race ./internal/core/signingkeys/`. Expected: `ok` (the old tests of the package still pass; nothing of theirs changed).

- [ ] **Step 4: Close the task.** Commit: `feat(signingkeys): the verified view of trust_material and the two installs (ADR 0019 sections 4.4, 4.5)`.

State (Definition of Done D): section 5's rows for `ca install` and `ca install-crl`, each a test above.

---

### Task 13: Host commands `agentmesh server admin ca csr | install | install-crl | status`

**Files:**
- Create: `internal/server/cmd/trust.go`, `keyfile.go`, `ca.go`
- Test: `internal/server/cmd/ca_test.go`, `keyfile_unix_test.go`, `keyfile_windows_test.go`
- Modify: `internal/server/cmd/admin.go` (`case "ca"`; `adminSubcommands` gains `ca (csr, install, install-crl, status)`; `hostEnv` gains `Trust func(sign bool) (signingkeys.Trust, error)`)

**Interfaces:**
- Consumes: Task 9 (`Config.RequireTrust`), Task 12 (`Trust`), Task 7.
- Produces (package `cmd`):

```go
// readOwnerOnly reads a regular file that only its owner can read or write: Unix mode 0600 or
// narrower, fileacl.CheckOwnerOnly on Windows. The error names the path and the fix.
func readOwnerOnly(path string) ([]byte, error)
// openRoot reads root_certificate_file: one PEM certificate with the root profile of section 4.2.
func openRoot(cfg config.Config) (*x509.Certificate, error)
// openIntermediateProvider is the FileProvider of intermediate_key_file, or the backend of
// intermediate_key_uri from keyBackends (a scheme not in this build names its build tag, as today).
func openIntermediateProvider(cfg config.Config) (keyprovider.Provider, error)
```

Commands (each calls `cfg.RequireTrust()` first; a failed requirement, a failed check and an unparseable file are exit 2; a Store or key service failure is exit 1):

- `ca csr [-out FILE]`: with the file form and no key file, `keyprovider.CreateKeyFile`; then `Provider.Next`, `Provider.Signer`, `pki.NewRequest(CryptoSigner(...), cfg.InstallationName)`; the CSR as PEM on standard output or in `FILE`. It writes nothing to the database. With a key service it never creates a key.
- `ca install CERT_FILE`: prints `installed <thumbprint> installation <name> until <RFC 3339>` or `unchanged <thumbprint>`.
- `ca install-crl CRL_FILE`: prints `installed root-crl <number>` or `unchanged root-crl <number>`.
- `ca status`: one line per item, in this order: `root <thumbprint> until <RFC 3339>`; `installation <name>`; per stored intermediate `intermediate <thumbprint> <not before> <not after> key=<configured|other> revoked=<yes|no>`; `root-crl <number>` or `root-crl none`; per leaf CRL `leaf-crl <issuer key> <number>`; `trust-number <n>`; per unexpired leaf `leaf <thumbprint> serial <hex> until <RFC 3339>`. With the file form "configured" is decided without the key service; with a key service it follows Plan ruling 12.

- [ ] **Step 1: Write the failing tests** (through `RunAdmin` with `-sqlite` in `t.TempDir()` and `-set`; the root comes from `rootca` in process)

`TestCACsr` (the key file is created at mode 0600; a second run prints a CSR for the same public key; the CN is `installation_name`; `-out` writes the file; no `trust_material` row changes); `TestCACsrKeyService` (a `kmsfake` registered in `keyBackends` for the test: the CSR verifies under the fake's key, and the fake holds no new key); `TestCAInstall` (each check of Task 12 is exit 2 with its text on standard error; the good case prints `installed`; again prints `unchanged` with exit 0 and the same trust number); `TestCAInstallCRL` (installed; unchanged; a lower number exit 2); `TestCAStatus` (the lines above for a store with one intermediate, one root CRL and no leaf); `TestCARequiresTrustSettings` (without `installation_name`: exit 2 naming the setting; without both key settings: exit 2); `TestCAInputs` (Review Focus 4: a CRLF certificate file is accepted; a DER file and a file with two certificates are exit 2); `TestOpenRoot` (an unreadable file, two certificates, a certificate that is not a CA: each an error naming `root_certificate_file`).

`keyfile_unix_test.go`: mode 0644 and 0640 refused with `chmod 600` in the text; 0600 and 0400 read; a directory refused. `keyfile_windows_test.go`: an ACL that grants another account is refused (the helpers of `internal/fileacl/acltest`).

Run: `go test ./internal/server/cmd/ -run 'TestCA|TestOpenRoot|TestReadOwnerOnly' 2>&1 | tail`. Expected: compile failure.

- [ ] **Step 2: Implement.** `openKeyProvider` and the three old settings stay until Task 24.

- [ ] **Step 3: Run** `go test ./internal/server/cmd/ && GOOS=windows go vet ./internal/server/cmd/`. Expected: `ok` and no vet finding.

- [ ] **Step 4: Close the task.** Commit: `feat(server): the ca host commands (ADR 0019 section 4.4)`.

---

### Task 14: `internal/trusttest`: one fixture for every package's tests

**Files:**
- Create: `internal/trusttest/trusttest.go`, `internal/trusttest/trusttest_test.go`
- Modify: `scripts/m4-exit-checks.sh` (four lines beside `internal/respcheck`: neither `.` nor `./cmd/agentmesh-mcponly` imports `internal/trusttest`; the header comment)

**Interfaces:**
- Consumes: Tasks 5, 7, 12 (whose `helpers_test.go` fixture this one mirrors, exported, for every other package).
- Produces:

```go
package trusttest // test support; never linked into a binary (the m4 rule). It does not import internal/server/cmd.

type Fixture struct {
	Dir          string // t.TempDir(): the root tool's directory and the files below
	RootFile     string // root.pem
	KeyFile      string // the intermediate key, PKCS#8 PEM, mode 0600
	CertFile     string // the intermediate certificate, PEM
	Installation string // "test-installation"
	Root         *x509.Certificate
	Intermediate *x509.Certificate
}

func New(t testing.TB) *Fixture
// Sibling is another installation under the same root: its own key, key file and name.
func (f *Fixture) Sibling(t testing.TB, installation string) *Fixture
// Sets is the three settings as arguments: "-set", "root_certificate_file=...", "-set",
// "intermediate_key_file=...", "-set", "installation_name=...".
func (f *Fixture) Sets() []string
func (f *Fixture) Trust(c *core.Core) signingkeys.Trust // Root, Installation, a FileProvider that reads with os.ReadFile
func (f *Fixture) Install(t testing.TB, c *core.Core)   // Trust(c).InstallIntermediate(f.Intermediate); fatal on error
// Renew issues another certificate for the same key; RevokeIntermediate returns the root CRL that revokes the key.
func (f *Fixture) Renew(t testing.TB, days int) *x509.Certificate
func (f *Fixture) RevokeIntermediate(t testing.TB) *x509.RevocationList
```

Task 17 adds `(*Fixture).Manager`.

- [ ] **Step 1: Write the failing test** `TestFixture`: `New` gives a certificate that passes `pki.CheckIntermediate`; `Install` on a SQLite store leaves one intermediate row; `Sibling("other")` chains to the same root with another key; `Sets` has six elements.
- [ ] **Step 2: Implement.** **Step 3: Run** `go test ./internal/trusttest/ && bash scripts/m4-exit-checks.sh --deps-only | tail -1`. Expected: `ok`, `deps_ok=1`.
- [ ] **Step 4: Close the task.** Commit: `test(trusttest): the shared trust fixture (ADR 0019 section 7)`.

---

## Phase B: the leaf manager and the switch

### Task 15: The two signing key operations take their final wire shape (the old key set answers in it)

This is the expand step of Plan ruling 14: wire, Bus, handlers, remote client and CLI change once, now. Until Task 23 the old key set answers through `internal/core/signingkeys/api.go`, rewritten here as a thin adapter; Task 24 deletes it.

**Files:**
- Modify: `api/openapi.yaml` (`SigningKey` at 5282, `SigningKeyList` at 5326, `SigningKeyRotation` at 5354, a new `RevokedLeaf`, `rotateSigningKey` at 2495 loses `revoke_previous`; descriptions and examples for each), then `make generate`
- Modify: `internal/bus/signingkeys.go`, `internal/bus/admin.go:79-80`, `internal/server/signing_keys.go`, `internal/bus/remote/signingkeys.go`, `internal/bus/local/signingkeys.go`, `internal/cli/signingkeys.go` (`rotate` loses `-revoke-previous`), `internal/core/signingkeys/api.go`
- Modify (tests and gates): `internal/server/signing_keys_test.go`, `internal/server/convert_requests_test.go`, `internal/server/wire_roundtrip_test.go`, `internal/server/status_table_test.go`, `internal/bus/remote/signingkeys_test.go`, `internal/cli/signingkeys_test.go`, `internal/conformance/bus/auth_test.go` (subtest `signing-key-rotation`), `internal/conformance/bus/replicas_test.go` (`TestReplicasSigningKeyRotation`), `api/arazzo.yaml` (workflow `signing-key-rotation`), `internal/e2e/zz_examples_test.go`, `api/cats-false-positives.yaml` (any rule that names `revoke_previous` or the cooldown conflict)

**Interfaces (Produces):**

```go
// internal/bus
type SigningKey struct {
	Thumbprint, Serial, IssuerThumbprint, State string // State: one of the four below
	NotBefore, NotAfter                         int64  // Unix milliseconds
}
const (
	SigningKeyCurrent  = "current"  // the answering process's current leaf
	SigningKeyPrevious = "previous" // its previous leaf
	SigningKeyOther    = "other"    // another process's leaf
	SigningKeyRevoked  = "revoked"
)
type SigningKeyList struct {
	Keys        []SigningKey // the unexpired leaves, the current one first
	TrustNumber int64
}
type RotateSigningKeyInput struct{ IdempotencyKey string }
type RevokedLeaf struct {
	Thumbprint    string
	HumanMessages int64 // always 0 until spec 2
}
type SigningKeyRotation struct {
	Current     SigningKey
	Revoked     []RevokedLeaf
	TrustNumber int64
}
// bus.Admin and server.SigningKeys:
ListSigningKeys(ctx) (SigningKeyList, error)
RotateSigningKey(ctx, in RotateSigningKeyInput) (SigningKeyRotation, error)
```

Wire members (section 4.11): `SigningKey`: `thumbprint`, `serial`, `issuer_thumbprint`, `not_before`, `not_after`, `state`, all required; `SigningKeyList`: `keys`, `trust_number`; `SigningKeyRotation`: `current`, `revoked` (array of `RevokedLeaf`: `thumbprint`, `human_messages`), `trust_number`; integers 0 to 2^53. `serial` and `issuer_thumbprint` carry no `minLength` and no pattern: the adapter below answers them empty until Task 23, and `respcheck` validates every answer in between.

The adapter in `api.go` (old rows in the new shape, nothing more): a row becomes `SigningKey{Thumbprint: KID, State: current for active, previous for retiring, NotBefore: CreatedAt, NotAfter: RemoveAfter}` with `Serial` and `IssuerThumbprint` empty; `TrustNumber` is 0; `RotateSigningKey` always applies `RotateInput{RevokePrevious: true}` (Ruling 6: rotate always revokes) and reports the deleted key as the one `RevokedLeaf`. The receipt payload is the empty object. The cooldown no longer applies to the API form.

- [ ] **Step 1: Change the tests first.** Keep one test per behavior and delete the rest of the old API tests (the non-revoking rotation, the cooldown conflict, `revoke_previous` parsing): the list's shape; the rotation's shape; a replay with the same idempotency key returns the first answer; a non-administrator is refused; local mode answers the non-retryable `unavailable`. `TestWireRoundTrip` pairs the four schemas with the Bus types above. `TestOperationErrorTable`: `rotateSigningKey` keeps `conflict` (the receipt for another payload) and nothing about a cooldown. The Arazzo workflow rotates without `revoke_previous` and ends with a token exchange and a `listSigningKeys` (Plan ruling 24: the rotation revoked the key that signed the caller's bearer). `TestRequestExamples` runs `rotateSigningKey` as its last row. `TestAuthEndToEnd/signing-key-rotation` and `TestReplicasSigningKeyRotation` exchange again after rotating.

Run: `go test ./internal/server/ ./internal/bus/... ./internal/cli/ 2>&1 | tail -20`. Expected: compile failures in every listed package.

- [ ] **Step 2: Change the spec and regenerate**: `make generate && make spec-lint`. **Step 3: Implement** the Bus types, the converters, the client, the CLI and the adapter.

- [ ] **Step 4: Run** `make test 2>&1 | tail -15` (the e2e package included: `TestArazzoWorkflows`, `TestRequestExamples`) and `go test -count=1 ./internal/conformance/bus/ -run 'TestAuthEndToEnd|TestReplicasSigningKeyRotation' 2>&1 | tail -5`. Expected: all `ok`. Any e2e step that now meets a 401 after the rotation exchanges again; the fix is in the test, not in the server.

- [ ] **Step 5: Close the task.** Commit: `feat(api): the signing key operations describe leaves; rotate always revokes (ADR 0019 section 4.11, Ruling 6)`.

---

### Task 16: `token`: keys bound to a certificate

**Files:**
- Modify: `internal/auth/token/keyset.go`, `internal/auth/token/issuer.go`, `internal/server/auth_handlers.go:124-138`, `internal/server/auth_exchange.go` (the `expires_in` of both grants)
- Test: `internal/auth/token/certkey_test.go` (new; it makes its certificates with the standard library, so the package's imports do not grow), `internal/server/auth_test.go`

**Interfaces (Produces):**

```go
type Key struct {
	KID       string
	Algorithm keys.Algorithm
	Public    crypto.PublicKey
	// Chain is the certificate chain of a leaf key, DER, the leaf first, then the intermediate. nil: a
	// key without a certificate (StaticKeys; removed in Task 25).
	Chain [][]byte
	// NotBefore and NotAfter are the period in which the chain is valid (pki.Verified); zero: unbounded.
	NotBefore, NotAfter time.Time
}
```

Rules: `KeySet.validate`: with a chain, `KID` is the base64url SHA-256 of `Chain[0]` and the certificate's public key equals `Public`; without one, the rule of today. A set with a nil `Signer` may have a zero `Active`, and may then have no keys at all (a process that can sign nothing); `Mint` on it fails with `ErrSignerUnavailable` and `Verify` finds only the keys it lists. `Mint`: the header carries `kid` and, with a chain, `x5t#S256` with the same value (section 4.7); the expiry is the earlier of `now + lifetime` and `Active.NotAfter`; with the clock outside `[NotBefore, NotAfter]` it fails with `ErrSignerUnavailable` (a process never signs outside its leaf's validity period). `Verify`: after the lookup, a key whose period does not contain `now` with `Leeway` is `invalid("the signing certificate is not valid at this time")`. The line `if err := tok.Claims(key.Public, &c); err != nil {` stays exactly as it is (selftest block 14). `JWKS`: a key with a chain carries `x5c` (leaf, then intermediate) and `x5t#S256` (`jose.JSONWebKey.Certificates` and `CertificateThumbprintSHA256`). The token endpoint's `expires_in` is the minted expiry minus now, no longer `iss.Lifetime()`. The `Jwks` handler copies each key through `gen.JWK` (`internal/server/auth_handlers.go:141-159`), so the wire answer gains `x5c` and `x5t#S256` only when Task 27 adds them to the schema; nothing changes on the wire here.

- [ ] **Step 1: Write the failing tests**: `TestCertificateKeyValidate` (a `KID` that is not the thumbprint, and a `Public` that is not the certificate's, are refused); `TestSetWithoutSigner` (a nil signer with a zero `Active` and other keys, and with no keys: both valid; `Mint` fails with `ErrSignerUnavailable`; a bearer under a listed key verifies); `TestMintHeaderCarriesThumbprint`; `TestMintCapsExpiryAtLeaf` (lifetime 1 hour, leaf ends in 10 minutes: `exp` is the leaf's end); `TestMintOutsideValidity` (`ErrSignerUnavailable`); `TestVerifyChecksValidity` (a period that ended 61 seconds ago refuses, 59 seconds ago accepts; one that starts in 61 seconds refuses); `TestJWKSCarriesChain`; in `internal/server`: `TestTokenExpiresInFollowsTheCap`.

Run: `go test ./internal/auth/token/ -run 'TestCertificateKey|TestMint|TestVerifyChecks|TestJWKSCarries' 2>&1 | tail`. Expected: compile failure (`Chain` undefined).

- [ ] **Step 2: Implement.** **Step 3: Run** `go test ./internal/auth/... ./internal/server/ && bash scripts/m5-exit-checks.sh --deps-only | tail -1`. Expected: `ok`, `deps_ok=1`.

- [ ] **Step 4: Close the task.** Commit: `feat(token): keys bound to a certificate chain (ADR 0019 section 4.7)`.

---

### Task 17: The manager: issuing a leaf, the start, and the issuer's key source

**Files:**
- Create: `internal/core/signingkeys/manager.go`
- Test: `internal/core/signingkeys/manager_test.go`
- Modify: `internal/trusttest/trusttest.go` (`Manager`), `internal/core/signingkeys/helpers_test.go` (the in-package `manager`)

**Interfaces:**
- Consumes: Task 12 (`Trust`, `Memory`, `Material`, `CryptoSigner`), Task 16 (`token.Key` with a chain).
- Produces:

```go
type Options struct {
	Trust        Trust         // Provider is required
	LeafValidity time.Duration // W: 2 to 720 hours
	OnChange     func()        // runs after this process's leaf or its view of the trust material changed; nil is fine
}

var (
	ErrNoIntermediate      error // no stored intermediate matches the configured key; the text names `agentmesh server admin ca csr` and `ca install`
	ErrIntermediateExpired error
	ErrIntermediateRevoked error
	ErrRootExpired         error
)

// New loads the trust material, picks the intermediate (Plan ruling 12) and issues the first leaf.
// Its errors are one of the four above, a keyprovider.ErrUnavailable, or a Store failure.
func New(ctx context.Context, o Options) (*Manager, error)
func (m *Manager) SetOnChange(f func())
func (m *Manager) Current() (thumbprint string, notAfter time.Time) // "" when nothing can sign
func (m *Manager) LoadKeys(ctx context.Context) (token.KeySet, error) // token.KeySource: reload, then the set

// trusttest:
func (f *Fixture) Manager(t testing.TB, c *core.Core) *signingkeys.Manager // Install when no row; W 168 hours; fatal on error
```

Issuing a leaf (section 4.6, the six steps, in this order): generate an Ed25519 key in memory; `pki.IssueLeaf` with the intermediate signer under a context bounded by `SignTimeout`; `pki.VerifyChain` of the new leaf at the current time (a failure is logged as `the configured key is not the certificate's key` and is a failed issue); insert the row (`IssuerKey` is `pki.KeyID` of the intermediate's subject key identifier) in one transaction; only then make it the current leaf, the former current one becoming the previous. The private key is held in the `Manager` and nowhere else.

`LoadKeys`: `Keys` is every leaf of the loaded `Material` that is not revoked and whose period contains now with `token.Leeway`, as `token.Key{KID: thumbprint, Algorithm: keys.EdDSA, Public, Chain: {leaf, intermediate}, NotBefore, NotAfter}`; `Active` and `Signer` are the current leaf's, or zero and nil when it is expired, revoked or the manager has stopped.

- [ ] **Step 1: Write the failing tests**

`TestNewIssuesFirstLeaf` (one leaf row; "not before" is now minus 60 s; "not after" is now plus W; the chain verifies; `Current` reports it); `TestNewStartStates` (no intermediate row and a row for another key: `ErrNoIntermediate`, the text naming both commands; an expired one: `ErrIntermediateExpired`; a key the stored root CRL revokes: `ErrIntermediateRevoked`; a root past its "not after" on the fake clock: `ErrRootExpired`; `kmsfake.SetDown(true)`: `errors.Is(err, keyprovider.ErrUnavailable)`; a key service whose pinned reference signs with another key: an error containing `the configured key is not the certificate's key` and no leaf row in use); `TestNewPicksNewestValidIntermediate` (after `Fixture.Renew`, the leaf's authority is unchanged and its "not after" is cut by the newer certificate); `TestLoadKeysPublishesVerifiedLeaves` (two managers over one store: each set holds both leaves and its own as `Active`; a self-signed leaf row put in by hand is in neither); `TestFailedInsertLeavesTheLeafUnused` (a Store that fails the insert: an error, `Current` unchanged); `TestNoPrivateKeyInTheStore` (every `trust_material.der` parses as a certificate or a CRL).

Run: `go test ./internal/core/signingkeys/ -run 'TestNew|TestLoadKeys|TestFailedInsert|TestNoPrivateKey' 2>&1 | tail`. Expected: compile failure.

- [ ] **Step 2: Implement.** **Step 3: Run** `go test -race ./internal/core/signingkeys/ ./internal/trusttest/`. Expected: `ok`.

- [ ] **Step 4: Close the task.** Commit: `feat(signingkeys): the leaf manager issues and publishes leaves (ADR 0019 section 4.6)`.

---

### Task 18: The manager: renewal at W/2, the retry schedule, expiry and the clock

**Files:**
- Create: `internal/core/signingkeys/renew.go`
- Test: `internal/core/signingkeys/renew_test.go`

**Interfaces (Produces):**

```go
// Step does what is due at the core's clock (a reload, a renewal, a retry) and returns when to call
// it again: the earliest of the next reload (token.ReloadInterval after the last one), the renewal
// time and a pending retry (Plan ruling 13).
func (m *Manager) Step(ctx context.Context) time.Time
// Run calls Step until ctx ends, sleeping until the time it returned. hints may be nil; Task 29
// makes a hint that carries no message wake it early.
func (m *Manager) Run(ctx context.Context, hints notify.Notifier)

type Failure struct {
	At      time.Time
	Message string // one line, at most 200 bytes; a key service error is the backend's redacted text
}
func (m *Manager) LastFailure() (Failure, bool) // cleared by the next successful issue
```

Rules (section 4.6): the next leaf is issued at the current leaf's issue time plus W/2 and signs from then on; the previous leaf stays in the published set until it expires. After a failed issue the next attempt is one eighth of the time left before the current leaf's "not after", never sooner than one minute. With the current leaf expired and no renewal, `LoadKeys` has a nil `Signer`. When the clock is outside the current leaf's validity period (before "not before" or after "not after"), the leaf counts as expired and a new one is issued at once (Ruling 13).

- [ ] **Step 1: Write the failing tests** (a fake clock in `core.Options.Now`; W 168 hours unless stated)

`TestRenewAtHalf` (a `Step` at 83 h 59 min issues nothing and returns a time no later than 84 h; a `Step` at 84 h issues: two leaves are published and the signer is the new one); `TestRetrySchedule` (the provider down from 84 h: the retry is due at 84 h + 10 h 30 min; failing again there: 9 h 11 min 15 s later; with 4 minutes left: one minute later); `TestExpiredLeafStopsSigning` (every attempt fails until past "not after": `Signer` is nil and an issuer over the manager fails `Mint` with `token.ErrSignerUnavailable`, while a bearer from another manager's valid leaf still verifies); `TestRecoveryClearsFailure`; `TestClockOutsideValidity` (the clock stepped to before "not before", and to after "not after": the next `Step` issues before anything is signed); `TestRenewalStoreFailure` (Review Focus 3: the provider works and the Store fails the insert once: `LastFailure` is set, the retry time follows the schedule, the current leaf keeps signing, the next `Step` at the retry time succeeds); `TestStepReturnsNextDue` (never in the past; at most `token.ReloadInterval` ahead); `TestRunStopsWithContext`.

Run: `go test ./internal/core/signingkeys/ -run 'TestRenew|TestRetry|TestExpiredLeaf|TestRecovery|TestClockOutside|TestStep|TestRun' 2>&1 | tail`. Expected: compile failure.

- [ ] **Step 2: Implement.** **Step 3: Run** `go test -race ./internal/core/signingkeys/`. Expected: `ok`.

- [ ] **Step 4: Close the task.** Commit: `feat(signingkeys): leaf renewal, retries and expiry on the manager's clock (ADR 0019 section 4.6)`.

State (Definition of Done D): section 5's "Leaf renewal" row: one timer per process, set from the current leaf; a failed run retries; nothing is repeated.

---

### Task 19: The manager: reloads, what it does when it finds a revocation or an expiry, rollback, and the bearer matrix

**Files:**
- Create: `internal/core/signingkeys/reload.go`
- Test: `internal/core/signingkeys/reload_test.go`, `internal/core/signingkeys/bearer_test.go`
- Modify: `internal/trusttest/trusttest.go` (`Leaf`), `internal/core/signingkeys/helpers_test.go` (the in-package `leaf`)

**Interfaces (Produces):**

```go
// Reload loads and verifies the trust material and reacts to it. Step and LoadKeys call it.
func (m *Manager) Reload(ctx context.Context) error
// Stopped is "" or why the manager no longer issues or signs:
// "intermediate_expired", "intermediate_revoked" or "root_expired".
func (m *Manager) Stopped() string

// trusttest: Leaf issues a leaf with the fixture's intermediate key and inserts its row, as another
// replica would; tests sign bearers with the key it returns.
func (f *Fixture) Leaf(t testing.TB, c *core.Core, now time.Time, validity time.Duration) (ed25519.PrivateKey, *x509.Certificate)
```

Reactions (sections 4.8 and 4.15): its own current leaf is revoked: issue a new one at once; the configured intermediate's key is in `RevokedKeys`, or no certificate of that key is valid now, or the root is outside its validity period: stop (no issue, a nil signer, one error log line per reload); a newer valid certificate of the same key appears: use it at the next issue, and leave the `intermediate_expired` stop, with no restart; `Material.Rollback` is not empty: under the `trust` lock, one transaction writes each newer CRL back with `PutCRL` and raises the trust number; whenever the trust number or the published set changed, call `OnChange`.

- [ ] **Step 1: Write the failing tests**

`TestOwnLeafRevoked` (another `Trust` puts the manager's leaf on the leaf CRL: after `Reload` the manager has a new current leaf and the old one is not published); `TestIntermediateKeyRevokedStops` (after `InstallRootCRL`: `Stopped() == "intermediate_revoked"`, no leaf is published, `Step` issues nothing); `TestIntermediateExpiryStops` and `TestIntermediateRenewalPickedUp` (a renewed certificate installed before the old one ends: the manager never stops and its next leaf chains through the new certificate); `TestRootExpiryStops` (Decision 34: past the root's "not after" no leaf is published, so every bearer is refused, and `Stopped() == "root_expired"`); `TestRollbackWrittenBack` (the stored leaf CRL is replaced by an older one: after `Reload` the row holds the newer one again, the trust number is higher and the log says `rollback`); `TestReloadVerifiesOnlyNewRows` (Review Focus 2: 2,000 leaf rows made with `Fixture.Leaf`; the second `Reload` calls `pki.CheckChain` zero times and takes under one second); `TestReloadCallsOnChange` (once per change, not at an unchanged reload).

`TestBearerMatrix` (section 7, "Bearers"): an issuer `token.NewIssuer(ctx, url, manager, time.Hour, clock)` and bearers the test signs with go-jose (`typ` `at+jwt`, `kid` and `x5t#S256` the leaf's thumbprint). Subtests, each asserting the named outcome of `Issuer.Verify`: `other-replica` (a `Fixture.Leaf` row: accepted); `row-missing` (`token.ErrUnknownKey`); `row-altered` (the row's DER is another certificate: refused); `self-signed` (a self-signed leaf whose row names the real intermediate key as its issuer: refused; this is the forged row of threat 2); `other-root` (refused); `expired` (the clock 61 s past the leaf's end: refused; 59 s: accepted); `revoked` (refused after the reload); `sibling-installation` (a leaf under `Fixture.Sibling("other")` with both rows stored: refused); `ca-without-usage` (an intermediate the same root signed without the agentmesh usage, and a leaf under it, both stored: refused); `lifetime-over-ceiling` (refused); `expiry-cap` (a bearer minted 10 minutes before the leaf's end with a one-hour lifetime expires at the leaf's end).

Run: `go test ./internal/core/signingkeys/ -run 'TestOwnLeaf|TestIntermediate|TestRootExpiry|TestRollback|TestReload|TestBearerMatrix' 2>&1 | tail`. Expected: compile failure.

- [ ] **Step 2: Implement.** Task 12's anchor line in `material.go` (`v, err := pki.CheckChain(...)`) stays as it is; `TestBearerMatrix/self-signed` is the test Task 35's mutation of it must fail.

- [ ] **Step 3: Run** `go test -race ./internal/core/signingkeys/`. Expected: `ok`.

- [ ] **Step 4: Close the task.** Commit: `feat(signingkeys): reloads react to revocation, expiry and rollback; the bearer matrix (ADR 0019 sections 4.7, 4.8)`.

---

### Task 20: Revocation: the leaf CRL, the forced renewal, and revoking leaves from the host

**Files:**
- Create: `internal/core/signingkeys/revoke.go`, `internal/core/signingkeys/manager_api.go`
- Test: `internal/core/signingkeys/revoke_test.go`, `internal/core/signingkeys/rotate_test.go`

**Interfaces (Produces):**

```go
type RevokeInput struct { // exactly one of the three
	All    bool              // every unexpired leaf under the configured key (the host form of rotate)
	Cert   *x509.Certificate // one leaf, which the configured intermediate key must have signed
	Serial *big.Int          // one serial number, listed as given (Ruling 32)
}
type RevokeResult struct {
	Revoked     []bus.RevokedLeaf
	NotCovered  []string // thumbprints of unexpired leaves under another intermediate key (Ruling 4)
	TrustNumber int64
	Changed     bool // false: every serial number was already listed; nothing was written
}
// Revoke is the host form: the trust lock, a load, the next leaf CRL, one transaction. It issues no leaf.
func (t Trust) Revoke(ctx context.Context, mem *Memory, in RevokeInput) (RevokeResult, error)
// List is the unexpired leaves with state other or revoked, and the trust number (the host form of list).
func (t Trust) List(ctx context.Context, mem *Memory) (bus.SigningKeyList, error)
// RemoveExpiredLeaves deletes leaf rows whose "not after" is more than an hour past, 500 a call.
func (t Trust) RemoveExpiredLeaves(ctx context.Context) (int, error)

// The admin API forms; Manager satisfies server.SigningKeys.
func (m *Manager) ListSigningKeys(ctx context.Context, admin string) (bus.SigningKeyList, error)
func (m *Manager) RotateSigningKey(ctx context.Context, admin string, in bus.RotateSigningKeyInput) (bus.SigningKeyRotation, error)

func countSigned(ctx context.Context, tx store.Tx, leafID int64) (int64, error) // 0 here; spec 2 counts messages
```

The next leaf CRL (section 4.8, step 5) lists: every entry of the stored leaf CRL of the configured key; every serial number `mem` keeps for that key; every unexpired leaf row under that key except the one being kept; the extra serial number of a `Cert` or `Serial` input. Its number is `pki.NextNumber(now, stored number)`. The intermediate key signs it under a context bounded by `SignTimeout`.

`RotateSigningKey`, the seven steps of section 4.8 in order: (1) a read transaction checks `RequireServerAdmin` and looks for the receipt of the idempotency key (a replay returns the first answer and changes nothing); (2) take the `trust` lock, or answer a retryable `unavailable`; (3) `Reload`; (4) issue a new leaf without inserting its row; (5) build the CRL, keeping the new leaf; (6) one transaction: the administrator check again, `countSigned` for each newly revoked leaf, the receipt, the new leaf's row, `PutCRL`, `BumpTrustNumber(now)`; (7) after the commit: sign with the new leaf, `OnChange`, release the lock. A failure before the transaction leaves a lost, unused leaf and nothing else. Leaves under another intermediate key are logged as not covered.

- [ ] **Step 1: Write the failing tests**

`TestRotateRevokesEveryOtherLeaf` (three managers over one store, one of them already renewed once: the CRL lists every unexpired leaf of the key except the new one, the caller's own former leaf included; one `Revoked` entry each with `HumanMessages` 0; the trust number is `pki.NextNumber`; the caller signs with the new leaf; the other managers issue new leaves at their next `Reload`); `TestRotateReplay` (the same key: the first answer, and no new row, CRL or number); `TestRotateAgainWithoutKey` (revokes the leaf the first rotation issued); `TestRotateNonAdminRefused` (`forbidden`; no lock taken, nothing written); `TestRotateLockHeld` (another owner holds `trust`: a retryable `unavailable`); `TestRotateTwoAtOnce` (one succeeds, the other answers `unavailable` and succeeds when retried); `TestRotateNumberAfterRestore` (the stored CRL number is ahead of the clock: the new number is the stored one plus one); `TestRotateCarriesTheUnion` (a serial number `mem` holds and the stored CRL lacks is in the new CRL: Decision 27); `TestRotateKeepsEntries` (entries whose leaf rows are gone stay: Ruling 7); `TestRotateFailsBeforeTheTransaction` (the provider down at step 4: an error, and the rows, the CRL and the number are unchanged); `TestRotateNotCovered` (a leaf under a second intermediate key is not on the CRL and is logged).

`TestRevokeAll`; `TestRevokeByCert` (a leaf with a row and one without: listed, count 0; a certificate another key signed: `ErrCheck`); `TestRevokeBySerial`; `TestRevokeAlreadyListed` (`Changed` false, the trust number unchanged); `TestRevokeInputs` (two inputs or none: an error); `TestRevokedLeafIsReplaced` (a running manager whose leaf `Revoke` listed issues a new one at its next `Reload`).

`TestListSigningKeys` (the current leaf first, then `previous`, `other`, `revoked`; the trust number; a non-administrator is refused); `TestRemoveExpiredLeaves` (a leaf 59 minutes past its end stays, one 61 minutes past goes, an intermediate never goes; its serial number stays on the CRL).

Run: `go test ./internal/core/signingkeys/ -run 'TestRotate|TestRevoke|TestListSigningKeys|TestRemoveExpired' 2>&1 | tail`. Expected: compile failure.

- [ ] **Step 2: Implement.** **Step 3: Run** `go test -race ./internal/core/signingkeys/`. Expected: `ok`.

- [ ] **Step 4: Close the task.** Commit: `feat(signingkeys): the leaf CRL, forced renewal and revoking one leaf (ADR 0019 section 4.8, Decisions 16, 25, 27)`.

State (Definition of Done D): section 5's rows "Forced renewal (API)", "Forced renewal (host command)" and "`signing-key revoke`", each a test above.

---

### Task 21: Host commands `agentmesh server admin signing-key list | rotate | revoke`

**Files:**
- Modify: `internal/server/cmd/admin.go` (`signingKeyCommand`, `signingKeyUsage`, `adminSubcommands`, `formatSigningKey` removed; `hostEnv` loses `Keys` and `OpenProvider`), `internal/server/cmd/admin_test.go`

**Interfaces:**
- Consumes: Task 20 (`Trust.Revoke`, `Trust.List`), Task 13 (`hostEnv.Trust`).
- Produces: `usage: agentmesh server admin signing-key list | rotate | revoke -cert FILE | -serial S`. Each command calls `cfg.RequireTrust()`.
  - `list`: `leaf <thumbprint> serial <hex> <not before> <not after> <state>` per unexpired leaf, then `trust-number <n>`.
  - `rotate`: `revoked <thumbprint> human-messages <n>` per leaf, then `trust-number <n>`; `not-covered <thumbprint>` lines on standard error. With nothing to revoke it prints the trust number alone, exit 0.
  - `revoke -cert FILE | -serial S` (`S` hexadecimal): `revoked <thumbprint or serial> human-messages <n>` and `trust-number <n>`, or `unchanged <serial>`. Both flags, neither, a serial number that is not hexadecimal, and a certificate another key signed: exit 2.
  - `-revoke-previous` no longer exists (exit 2, the flag package's message).

Until Task 23 the server still signs with the old key set, so these commands see no leaves (Transitional states).

- [ ] **Step 1: Rewrite the `signing-key` tests of `admin_test.go`**: `TestSigningKeyList`, `TestSigningKeyRotate` (leaves made with `Fixture.Leaf`; a second run revokes only leaves issued since), `TestSigningKeyRevoke` (the cases above, with a row and without one), `TestSigningKeyUsage`. Run them and see them fail.
- [ ] **Step 2: Implement.** **Step 3: Run** `go test ./internal/server/cmd/`. Expected: `ok`.
- [ ] **Step 4: Close the task.** Commit: `feat(server): signing-key list, rotate and revoke act on leaves (ADR 0019 sections 4.8, 4.13)`.

---

### Task 22: Every fixture that starts a real server gets a CA

The server does not need the settings yet (Task 23 makes them required), so this task changes fixtures only and every suite stays green before and after.

**Files** (find them all first: `rg -n 'cmd\.Run(With)?\(|exec\.Command\(binPath, "server"|agentmesh server' internal scripts deploy Dockerfile`):
- Modify: `internal/conformance/bus/auth_test.go` (the `cmd.Run` of `TestAuthEndToEnd`), `replicas_test.go:65`, `federated_test.go:54,66`: `trusttest.New`, `Fixture.Install` on the store the test already opens, `Fixture.Sets()` appended to the arguments
- Modify: the tests of `internal/server/cmd` that serve through `Run` or `run`, and any test of `internal/cli`, `internal/mcpcli`, `internal/client`, `internal/tui` the search finds
- Modify: `internal/e2e/e2e_test.go:261` (the built binary: `agentmesh ca init`, `server admin ca csr -out`, `ca sign`, `server admin ca install`, all through the binary, then the three `-set`s), `internal/e2e/slack_test.go` and `mcponly_test.go` (the in-process server: `trusttest`)
- Modify: `scripts/cats-harness.sh` (`up` runs the four commands in its directory and adds the three `-set`s to the server's arguments), `scripts/testdata/cats-harness/expected-argv.txt`, `scripts/cats-harness-selftest.sh`, `scripts/cats-precommit-selftest.sh`
- Modify: `scripts/docker-smoke.sh` (the four commands through `docker run` with the image's binary and a bind-mounted temporary directory, redirects on the host; the server's three settings; Plan ruling 25), `deploy/docker-compose.yml`, `deploy/example.env`

- [ ] **Step 1: Change the fixtures.** No assertion changes in this task except the harness's expected argument list.
- [ ] **Step 2: Run** `make test 2>&1 | tail -5`, `make test-conformance 2>&1 | tail -5`, `make cats-selftest 2>&1 | tail -3`, `make docker-smoke 2>&1 | tail -5`. Expected: all pass. Run `bash scripts/cats-harness.sh up && bash scripts/cats-harness.sh status && bash scripts/cats-harness.sh down` when `cats` is installed.
- [ ] **Step 3: Close the task** (`make release-lint` included). Commit: `test(fixtures): every server fixture bootstraps a CA (ADR 0019 section 7)`.

State (Definition of Done D): `cats-harness.sh up` twice: the second finds the root and the installed certificate and reuses them (`ca init` is skipped when `root.pem` exists; `ca install` answers `unchanged`); `down` removes the directory, CA included.

---

### Task 23: The switch: the server starts on the hierarchy

**Files:**
- Modify: `internal/server/cmd/cmd.go:146-177` and the `Ready` line at 230-233, the State comment at 55-62; `internal/server/cmd/serve.go` (`Config.SigningKeys *signingkeys.Manager`; `go c.SigningKeys.Run(mctx, nil)` under the wait group; `opts.SigningKeys = c.SigningKeys`; the maintenance service no longer gets the old jobs)
- Test: `internal/server/cmd/cmd_test.go`, `serve_test.go:535,588`, `internal/server/cmd/startup_test.go` (new), `internal/conformance/bus/auth_test.go`, `replicas_test.go`, `scripts/docker-smoke.sh:134`

**Interfaces:**
- Consumes: Tasks 9, 13, 17 to 20.
- Produces: the start sequence of `run`: `cfg.RequireTrust()`; `openRoot` (and a root outside its validity period); `openIntermediateProvider` and, for the file form, one `Provider.Next` so a missing, exposed or non-P-256 key file stops the start; the Store; the listener; `signingkeys.New`; `token.NewIssuer(ctx, issuerURL, manager, lifetime, c.Now)`; `manager.SetOnChange(issuer.Invalidate)`. The start line: `agentmesh server listening on <addr> (<engine>, registration <mode>, issuer <url>, leaf <thumbprint> until <RFC 3339>)`. The lines `generated signing key` and `adopted signing key` are gone.

Exit codes (section 4.15, first table):

| State at start | Exit |
| --- | --- |
| `root_certificate_file` unset, unreadable or not one CA certificate | 2 |
| The pinned root has expired | 2 |
| `installation_name` unset or not a valid name | 2 |
| Neither or both of `intermediate_key_file` and `intermediate_key_uri` | 2 |
| Key file missing, not owner-only or not an ECDSA P-256 key | 2 |
| `ErrNoIntermediate` (the message names `ca csr` and `ca install`) | 2 |
| `ErrIntermediateExpired`, `ErrIntermediateRevoked`, `ErrRootExpired` | 2 |
| A backend scheme that is not in this build (the message names the build tag) | 2 |
| `keyprovider.ErrUnavailable` while the first leaf is issued | 1 |
| `token_lifetime_seconds` or a human lifetime above W/2 | 2 (Task 9's `Validate`) |
| The store does not answer | as today |

- [ ] **Step 1: Write the failing tests**

`TestStartupStates` in `startup_test.go`: one subtest per row above through `run` with an injected serving function, asserting the exit code and one phrase of the message (the two command names for `ErrNoIntermediate`; `-tags awskms` for the missing backend; the setting's name for each configuration row). `TestStartLine` (the leaf thumbprint and an RFC 3339 time; neither old line). `TestSecondStartIssuesAnotherLeaf` (two starts over one store leave two leaf rows; the first leaf still verifies).

`internal/server` (the test environment gets its manager in Task 25; here one test builds its own with `trusttest`): `TestTokenEndpoint503WhenLeafExpired` (a manager on a fake clock whose renewals fail past the leaf's end: the token endpoint answers 503 `temporarily_unavailable`, both grants; a request with a bearer from another leaf that is still valid is served).

`TestAuthEndToEnd` keeps its 12 leaf names (Plan ruling 23) on the hierarchy: the test no longer creates a key row; `forged-bearer-refused` signs with a key of its own under the `kid` of a real leaf (read from `GET /v1/auth/jwks`), so only the signature check stops it (selftest block 14); `stale-bearer-on-token-endpoint` signs an expired bearer with a `Fixture.Leaf`; `signing-key-rotation` rotates, sees its bearer refused, exchanges again and lists. `TestReplicasSigningKeyRotation`: a bearer from replica A is accepted by B; after a forced renewal on A, A's new bearer presented to B makes B reload (the unknown-key path), after which B refuses A's old bearer and has issued a new leaf of its own; two forced renewals at once end with one winner and one retryable `unavailable`.

Run: `go test ./internal/server/cmd/ -run 'TestStartup|TestStartLine|TestSecondStart' 2>&1 | tail`. Expected: failures (the old start ignores the settings).

- [ ] **Step 2: Implement the switch.** The three `signing_key_*` settings are still accepted and now ignored; `openKeyProvider`, `signingSettings`, `signingkeys.Service` and `Keyring` are no longer called by the server (Task 24 deletes them).

- [ ] **Step 3: Run** `make test 2>&1 | tail -8`, `make test-conformance 2>&1 | tail -5`, then `log="$(mktemp)"; go test -count=1 -v -run '^TestAuthEndToEnd$' ./internal/conformance/bus/ > "$log" 2>&1; bash scripts/m5-exit-checks.sh "$log" | tail -3; rm -f "$log"`. Expected: all `ok`; `auth_sqlite=12 auth_postgres=12`. Update `scripts/docker-smoke.sh:134` to look for `, leaf ` in the listening line and run `make docker-smoke`.

- [ ] **Step 4: Close the task** (`make release-lint` included). Commit: `feat(server)!: bearers are signed by a leaf and verified by the chain to the pinned root (ADR 0019)`.

State (Definition of Done D): section 5's "Server start" row. A second start issues a fresh leaf; replicas start independently; a start that failed before the row was inserted left nothing, after it an unused row.

---

### Task 24: Removal 1: the old key set rules, the store provider, the three settings and the two jobs

**Files:**
- Delete: `internal/core/signingkeys/service.go`, `schedule.go`, `keyring.go`, `api.go`, `service_test.go`, `schedule_test.go`, `keyring_test.go`, `outage_test.go` (its Store wrapper already lives in `helpers_test.go`), `internal/conformance/bus/signingkeys_test.go`, `internal/conformance/bus/signingkeys_external_test.go` (they test the old key set), `internal/server/cmd/keyprovider.go` (the `keyBackends` map moves to `trust.go`), `internal/server/cmd/keyprovider_test.go` (what still applies moves to `trust_test.go`)
- Modify: `internal/keyprovider/keyprovider.go` (`StoreProvider`, `storeSigner`, `NameStore`, `Key.PrivatePEM` removed; `Provider.Name`'s comment; the package comment), `internal/keyprovider/keyprovider_test.go`, the four backends and `kmsfake` only where they mention the removed names
- Modify: `internal/server/config/config.go` (`SigningKeyURI`, `SigningKeyRotationHours`, `SigningKeyRotationCooldownSeconds`, their defaults and validation removed; `MaxTokenLifetimeSeconds` stays at 86400 with a comment that no longer names `MaxBearerLifetime`), `config_test.go` (`TestSigningKeyDefaults`, `TestSigningKeyURIValidation`, `TestSigningKeyRotationBounds`, `TestMaxBearerLifetimeIsTheCeiling` removed), `docs/ops/configuration.md`
- Modify (the remaining users of `signingkeys.Service` and `StoreProvider`): `internal/server/signing_keys_test.go` (a manager from `trusttest` in `Options.SigningKeys`), `internal/core/identities/service_test.go:584`, `internal/server/cmd/serve_test.go:535,588`
- Modify: `internal/core/maintenance/service.go:38-40,112-115` (`SigningKeys` becomes `Trust *signingkeys.Trust`; one job, `{"expired leaf removal", t.RemoveExpiredLeaves}`, where the two were), `jobs_test.go`, `internal/server/cmd/serve.go` (sets it from the manager's `Trust`), `internal/core/health` tests that list job names
- Modify: `internal/server/cmd/backend_awskms_test.go`, `backend_azurekms_test.go`, `backend_gcpkms_test.go`, `backend_hashivault_test.go` (`intermediate_key_uri`), `scripts/vet-tags.sh` if it names a removed setting
- Modify: every fixture that still passes `signing_key_rotation_cooldown_seconds`: `internal/e2e/e2e_test.go:261`, `scripts/cats-harness.sh:67`, `scripts/testdata/cats-harness/expected-argv.txt`, `internal/conformance/bus/auth_test.go`
- Modify: `scripts/m7-exit-checks.sh` (the `keyprovider-leaf` comment: the store provider is gone)
- Modify: `internal/store/sqlite/sqlite.go:39,86,147` and `internal/store/sqlite/perm_unix_test.go` (Plan ruling 9: the check stays; the text is `... which other accounts can read or write, and is the server's database; chmod 600 it`)

- [ ] **Step 1: Write the failing tests**: `TestExpiredLeafRemovalJob` in `internal/core/maintenance` (the job runs where the two ran, before the last job, and only when `Trust` is set; its count is the rows removed); `TestUnknownSettingRefused` in `internal/server/config` (each of the three old names is `unknown setting`).
- [ ] **Step 2: Delete and adjust.** `rg -n 'EnsureActive|PrepareRotation|ApplyRotation|RotatePrepared|RotateDue|RemoveExpired\b|RemoveAfter|ErrCooldown|ErrRotateNoChange|NewKeyring|StoreProvider|NameStore|PrivatePEM|signing_key_uri|signing_key_rotation' --glob '!docs/**' --glob '!internal/gen/**' .` must print nothing but the Store's own `PrivateKeyPEM` (Task 26).
- [ ] **Step 3: Run** `make test 2>&1 | tail -5`, `make vet-tags 2>&1 | tail -3`, `make cats-selftest 2>&1 | tail -2`, `bash scripts/m7-exit-checks.sh --deps-only | tail -1`. Expected: all pass.
- [ ] **Step 4: Close the task** (`make release-lint` included). Commit: `refactor(signingkeys)!: remove the key set rules, the store provider and the rotation settings (ADR 0019 section 4.16)`.

---

### Task 25: Test fixtures leave `StaticKeys`; a key always has a chain

**Files:**
- Modify (fixtures): `internal/server/testenv_test.go:76-111` (the issuer is built over `Fixture.Manager`; the environment keeps the `Fixture` and the `Manager`), `internal/server/auth_test.go:348,898,922,955`, `internal/tui/run_test.go:184`, `internal/e2e/e2e_test.go:710`, `internal/conformance/bus/auth_test.go:172,411,494` (whatever Task 23 left)
- Modify: `internal/auth/token/keyset.go` (`StaticKeys`, `staticKeys`, `cryptoSigner` and `keyOf` removed; `validate` requires a chain for every key), `internal/auth/token/issuer.go` (`serverAlgorithms` stays; a key without a chain is unreachable), `internal/auth/token/issuer_test.go`, `keyset_test.go`, `external_test.go` (their own `KeySource` over a certificate made with the standard library, in `certkey_test.go`)

**Interfaces (Produces):** `token.Key.Chain` is required: `validate` refuses a key without one.

- [ ] **Step 1: Move the fixtures** to `trusttest`, package by package, running each package's tests as it is done. A test that needs "an issuer with another key" (`auth_test.go:348`) uses a second `trusttest.New` (another root).
- [ ] **Step 2: Add `TestKeyNeedsAChain` to `internal/auth/token`**, see it fail, then remove `StaticKeys` and make the chain required.
- [ ] **Step 3: Run** `rg -n 'StaticKeys' --type go . ; make test 2>&1 | tail -5`. Expected: no match; all `ok`.
- [ ] **Step 4: Close the task.** Commit: `refactor(token): every key has a certificate chain; StaticKeys is gone (ADR 0019)`.

---

### Task 26: Removal 2: the `signing_keys` table and its Store methods

**Files:**
- Delete: `internal/store/signing.go`, `internal/store/sqlstore/signing.go`, `internal/conformance/store/signing_test.go`
- Modify: `internal/store/store.go` (`Tx` loses `SigningKeys`), both `0001_initial.sql` files (the table and `signing_keys_one_active` removed), `internal/store/meta.go:23,34` (the comments), `internal/conformance/store/reset_test.go:47,124,169,190`, `open_test.go:363`, `store_test.go:37-40`, `schema_test.go` if it lists tables

- [ ] **Step 1: Remove** the table, the type, the five methods and their suite. `rg -n 'SigningKey|signing_keys' internal/store internal/conformance/store` must print nothing.
- [ ] **Step 2: Run** `make test-conformance 2>&1 | tail -5 && make check-gates 2>&1 | tail -8`. Expected: all `ok`. A database an earlier build of this branch created is recreated, not converted (the pre-release rule).
- [ ] **Step 3: Close the task.** Commit: `refactor(store)!: remove the signing_keys table (ADR 0019 section 4.5)`.

---

## Phase C: the wire and the client

### Task 27: The trust bundle and the trust number on the wire and in the Bus types

Additive: the members exist and carry nothing until Tasks 28 to 30 fill them.

**Files:**
- Modify: `api/openapi.yaml`: new schemas `TrustBundle`, `HealthSigning`, `HealthCertificate`; `Discovery` (3439) gains `trust`; `OpenSessionRequest` (3564) and `ReceiveRequest` (3662) gain `trust_number`; `Session` (3620) and `ReceiveResult` (3798) gain `trust_number` and `trust`; `watch` (350) gains the query parameter `trust_number`; `Wake` (3360) gains `trust_number`; `Health` (4833) gains `signing`; `JWK` (5134) gains `x5c` and `x5t#S256`. A description and an example for each; the `discover` description still says it never touches the store. Then `make generate`
- Create: `internal/bus/trust.go`, `internal/server/trust.go`
- Modify: `internal/bus/sessions.go`, `internal/bus/health.go`, `internal/core/rules/bounds.go` (`MaxTrustNumber = 1 << 53`), `internal/core/sessions/open.go`, `internal/core/delivery/receive.go`, `internal/core/delivery/watch.go` (the bound check only), `internal/server/sessions.go`, `internal/server/health.go`, `internal/server/discovery.go`, `internal/bus/remote/sessions.go`, `internal/bus/remote/health.go`, `internal/bus/remote/convert.go`
- Modify (gates): `internal/server/wire_roundtrip_test.go`, `internal/mcpserver/coverage_test.go`, `internal/server/spec_bounds_test.go`, `internal/conformance/bus/testdata/core_bound_rows.txt` and the two probes it lists rows for, `internal/e2e/zz_examples_test.go`, the three `spec_jwk_*` tests

**Interfaces (Produces):**

```go
// internal/bus/trust.go
type TrustBundle struct {
	TrustNumber   int64
	Intermediates [][]byte // DER; every stored intermediate, the revoked and the expired included
	RootCRL       []byte   // DER; nil when none is installed
	LeafCRLs      [][]byte // DER; empty when no leaf was ever revoked
	Root          []byte   // DER; the discover document only
	Installation  string   // the discover document only
}

// New members (nil or zero from a local Bus):
OpenSessionInput.TrustNumber *int64
ReceiveInput.TrustNumber     *int64
WatchInput.TrustNumber       *int64
Session.TrustNumber          *int64
Session.Trust                *TrustBundle
ReceiveResult.TrustNumber    *int64
ReceiveResult.Trust          *TrustBundle
WatchResult.TrustNumber      *int64
Health.Signing               *HealthSigning // nil below the admin tier and in local mode

type HealthCertificate struct {
	Thumbprint          string
	NotBefore, NotAfter int64 // Unix milliseconds
	DaysLeft            int
}
type HealthSigning struct { // Plan ruling 16
	Installation                                                           string
	Intermediate, Leaf                                                     *HealthCertificate
	NextRenewalAt, TrustNumber, RootCRLNumber, LeafCRLNumber, LastFailureAt int64
	LastFailure, Stopped                                                   string
}
```

Wire names are the snake case of the members (section 4.9's table for the bundle; `intermediates`, `root_crl`, `leaf_crls` and `root` are base64 strings, `format: byte`). Every `trust_number` is an integer from 0 to 2^53; the core refuses a negative or larger one in open, receive and watch with `validation`, on the `local` transport too.

- [ ] **Step 1: Change the gate tables first**: `TestWireRoundTrip` pairs `gen.TrustBundle`, `gen.HealthSigning` and `gen.HealthCertificate` with their Bus types and covers the new members of the six changed schemas; `TestToolCoverage` lists `TrustNumber` and `Trust` of the three inputs and three results as `hidden: carried under the Bus by internal/client`, and `Health.Signing` as `used` (the `health` tool prints the document); `TestSpecBounds` gains the three request rows (`OpenSessionRequest.trust_number`, `ReceiveRequest.trust_number`, the `watch` parameter) with `rules.MaxTrustNumber`; `core_bound_rows.txt` gains the same three rows and `TestOverBoundRefused` and `TestAtBoundAccepted` cover them; `TestRequestExamples` gets the changed request examples.

Run: `go test ./internal/server/ ./internal/mcpserver/ ./internal/gen/ 2>&1 | tail -20`. Expected: failures naming the missing schemas and members.

- [ ] **Step 2: Change the spec, regenerate, implement** the types, the converters and the bound check: `make generate && make spec-lint`.

- [ ] **Step 3: Run** `make test 2>&1 | tail -8` and `go test -count=1 ./internal/conformance/bus/ -run 'TestOverBoundRefused|TestAtBoundAccepted' 2>&1 | tail -3`. Expected: `ok`.

- [ ] **Step 4: Close the task.** Commit: `feat(api): the trust bundle and the trust number on the wire (ADR 0019 section 4.11)`.

---

### Task 28: The server answers with its trust: discover from memory, session open and receive

**Files:**
- Create: `internal/core/trust.go`, `internal/core/signingkeys/status.go`
- Modify: `internal/core/core.go` (`Options.Trust`, `(*Core).Trust()`), `internal/core/sessions/open.go`, `internal/core/delivery/receive.go`, `internal/server/discovery.go`, `internal/server/cmd/serve.go` (the serving core gets `Options.Trust` from `Config.SigningKeys` when it is not nil)
- Test: `internal/server/trust_test.go`, `internal/core/signingkeys/status_test.go`
- Modify: the harness of `internal/conformance/bus` (where `core.New` builds the harness's core, and `transport_test.go:47`): under `AGENTMESH_BUS_TRANSPORT=inproc` the serving core gets `Options.Trust` from a `trusttest` manager built over a first core on the same Store and clock, as `cmd` does; the `local` run gets none (section 7: the fixture serves the inproc Bus suite)

**Interfaces (Produces):**

```go
// internal/core/trust.go
// TrustSource is the process's verified, in-memory copy of the trust material (the leaf manager in
// server mode; nil in local mode). Nothing behind it touches the Store.
type TrustSource interface {
	Bundle() bus.TrustBundle // with Root and Installation
}
// InBand is what session open and receive attach (section 4.9): always the number; the bundle,
// without Root and Installation, when the client's number is absent or differs (Decision 27).
func InBand(ts TrustSource, client *int64) (number *int64, bundle *bus.TrustBundle)

// internal/core/signingkeys/status.go
func (m *Manager) Bundle() bus.TrustBundle // one snapshot: the number and the material loaded with it
```

`InBand` holds this line exactly once, on one line (Task 35 anchors on it): `if client == nil || *client != b.TrustNumber {`. The snapshot is replaced at every `Reload` and at once after this process's own change (a forced renewal), so no in-band answer waits 30 seconds for a local change.

- [ ] **Step 1: Write the failing tests**

`TestDiscoverCarriesTrust` (`root`, `installation`, every stored intermediate with an expired and a revoked one among them, the CRLs, `trust_number`); `TestDiscoverLocalModeHasNoTrust`; `TestDiscoverAnswersWithStoreClosed` (close the Store, then `GET /v1/discover`: 200 with the bundle; this is what the operation's description promises); `TestOpenSessionTrust` and `TestReceiveTrust`, a table of four client numbers: lower, equal, higher, absent: the answer always carries the server's `trust_number`; `trust` is present for lower, higher and absent, missing for equal, and never has `root` or `installation`; a local-mode environment has neither member; `TestInBandAfterLocalChange` (a forced renewal on this process: the next open carries the new number at once); `TestInprocCarriesTrust` in `internal/conformance/bus` (a session opened in the `inproc` run has a trust number and a bundle, and `respcheck` has validated the answer; one opened in the `local` run has neither); `TestTamperedRowsNever500` (the no-500 rule: with a garbage row of each of the four kinds stored, discover, session open, receive, the token endpoint, `listSigningKeys` and `jwks` each answer a status the document declares; `respcheck` is already wired into this package's tests).

Run: `go test ./internal/server/ -run 'TestDiscover|TestOpenSessionTrust|TestReceiveTrust|TestInBand|TestTamperedRows' 2>&1 | tail`. Expected: failures (no `trust` in any answer).

- [ ] **Step 2: Implement.** **Step 3: Run** `go test ./internal/server/... ./internal/core/... && bash scripts/m4-exit-checks.sh --deps-only | tail -1`, then `make test-conformance 2>&1 | tail -5` (both transports of the Bus suite). Expected: `ok`, `deps_ok=1`.

- [ ] **Step 4: Close the task.** Commit: `feat(server): discover, session open and receive carry the trust bundle (ADR 0019 section 4.9)`.

---

### Task 29: A watch wakes when the trust numbers differ

**Files:**
- Modify: `internal/core/delivery/watch.go`, `internal/server/sessions.go` (the query parameter in, `Wake.trust_number` out), `internal/core/signingkeys/renew.go` (`Run` listens to hints), `internal/server/cmd/serve.go` (`SetOnChange` also publishes a hint on the serving core; `Run` gets the serving core's notifier)
- Test: `internal/core/delivery` tests through `internal/server/trust_test.go`, `internal/core/signingkeys/renew_test.go`

**Interfaces:**
- Consumes: Task 28 (`Core.Trust()`), Task 18 (`Manager.Run(ctx, hints)`).
- Produces: `delivery.Watch` returns `bus.WatchResult{Woke: true, Count: 0, TrustNumber: &n}` at once, after the watch is registered and at every later check, when `in.TrustNumber` is set and differs from `Core.Trust().Bundle().TrustNumber`, lower or higher (Decision 27). No merge window applies to that wake. Every result from a server, a timeout included, carries `TrustNumber`. In `Serve`: `manager.SetOnChange(func() { issuer.Invalidate(); cr.Publish(notify.Hint{}) })` and `go manager.Run(mctx, cr.Notifier())`. On a hint with sequence number 0 the manager reads `Tx.TrustNumber` (at most once a second) and calls `Reload` when it differs from the number it holds (Plan ruling 15); its own hint finds the numbers equal and ends there.

- [ ] **Step 1: Write the failing tests**: `TestWatchWakesOnTrustNumber` (a client number lower, and higher, than the server's: the answer comes at once with count 0 and the server's number; equal: no wake before the timeout, and the timeout answer carries the number; absent: no trust wake); `TestWatchWakesWhenTrustChanges` (a watch waiting with the current number; a forced renewal on the same process wakes it within one second, with no message pending); `TestManagerReloadsOnHint` (a hint with sequence number 0 after another `Trust` changed the material: `OnChange` runs without waiting for the 30-second reload; 100 hints in a burst cause at most two reads of the number; a hint when nothing changed causes no reload).

Run: `go test ./internal/server/ ./internal/core/signingkeys/ -run 'TestWatchWakes|TestManagerReloadsOnHint' 2>&1 | tail`. Expected: failures.

- [ ] **Step 2: Implement.** **Step 3: Run** `go test -race ./internal/core/... ./internal/server/...` and `AGENTMESH_BUS_TRANSPORT=inproc go test -count=1 ./internal/conformance/bus/ 2>&1 | tail -3`. Expected: `ok`.

- [ ] **Step 4: Close the task.** Commit: `feat(delivery): a watch wakes when the trust number differs (ADR 0019 Decisions 12, 27)`.

---

### Task 30: Health reports signing; the key set endpoint serves the chain

**Files:**
- Modify: `internal/core/trust.go` (`TrustSource` gains `Signing() bus.HealthSigning`), `internal/core/signingkeys/status.go` (`Manager.Signing`), `internal/core/health/health.go` (the admin tier and the `degraded` rules), `internal/server/health.go`, `internal/server/auth_handlers.go` (`Jwks`), `internal/bus/remote/health.go`
- Test: `internal/core/health/health_test.go`, `internal/server/health_test.go`, `internal/server/auth_test.go`

**Interfaces (Produces):** `Manager.Signing()` fills every member of `bus.HealthSigning` from the manager's state: the intermediate in use and the current leaf (nil when there is none), `NextRenewalAt`, the numbers of the bundle, the root CRL and the configured key's leaf CRL (0 when none), `LastFailure` from `Manager.LastFailure`, `Stopped` from `Manager.Stopped`. `health.Health` sets `Signing` at the admin tier only and makes the status `degraded` (still HTTP 200) when the intermediate's `DaysLeft` is below 30, when `LastFailureAt` is not 0, when there is no leaf or the leaf's `NotAfter` is past, or when `Stopped` is not empty (section 4.14). `GET /v1/auth/jwks` serves one JWK per key of the issuer's set (the unexpired, unrevoked leaves this process has verified) with `kid`, `x5t#S256` and `x5c` (leaf, then intermediate), as Task 16's `Issuer.JWKS` builds it.

- [ ] **Step 1: Write the failing tests**: `TestHealthSigning` (the admin tier carries every member; the identity and probe tiers and local mode carry none); `TestHealthDegradedBySigning`, on a fake clock: the intermediate with 29 days left (degraded) and 31 (ok); a failed renewal; an expired leaf; a revoked intermediate key; an expired root; `TestJWKSServesChains` (two leaves: two JWKs, each with two `x5c` entries and `kid` equal to `x5t#S256`; a revoked leaf is absent); the three `spec_jwk_*` tests pass with the new members.

Run: `go test ./internal/core/health/ ./internal/server/ -run 'TestHealthSigning|TestHealthDegradedBySigning|TestJWKS' 2>&1 | tail`. Expected: failures.

- [ ] **Step 2: Implement.** **Step 3: Run** `make test 2>&1 | tail -5`. Expected: `ok`.

- [ ] **Step 4: Close the task.** Commit: `feat(health): the signing object; jwks serves leaf chains (ADR 0019 sections 4.11, 4.14)`.

---

### Task 31: The client layer under the `Bus`: pin, discover, the held number, the bundle

**Files:**
- Create: `internal/client/trust.go`
- Modify: `internal/client/options.go` (`AcceptNewRoot bool`, `NoDiscover bool`, `Notice func(line string)`), `internal/client/server.go` (`openServer` and `openHuman` call `ensureTrust` and wrap the `Bus`), `internal/client/registration.go` (`RegisterIdentity` calls `ensureTrust` before `Register`), `internal/cli/stophook.go:137` (`NoDiscover: true`), `internal/cli/common.go` (`Notice` writes to standard error)
- Test: `internal/client/trust_test.go`, `internal/cli/stophook_test.go`, `internal/cli/wait_test.go`

**Interfaces:**
- Consumes: Task 11 (`trust.Store`), Task 10 (the profile members), Tasks 28 and 29 (the server side).
- Produces:

```go
// ensureTrust is what a process does once when it opens the Bus of a server profile (Ruling 24):
// Store.Check against the profile; unless o.NoDiscover, GET /v1/discover within 10 seconds, then
// Store.Accept and Store.Apply. Every refusal is a ResolveError (exit 2).
func ensureTrust(ctx context.Context, o Options, r Resolved, plain *gen.ClientWithResponses) (trust.Store, error)

// trustBus is the layer (spec 2 adds verification here). It embeds the remote Bus and replaces three methods.
type trustBus struct {
	bus.Bus
	store  trust.Store
	notice func(string)
}
func (b *trustBus) Open(ctx context.Context, in bus.OpenSessionInput) (bus.Session, error)
func (b *trustBus) Receive(ctx context.Context, in bus.ReceiveInput) (bus.ReceiveResult, error)
func (b *trustBus) Watch(ctx context.Context, in bus.WatchInput) (bus.WatchResult, error)
```

Rules (sections 4.9, 4.10 and 4.15, client table):
- Discover cannot be reached (a transport error or a status other than 200): with a pin the client goes on with what it holds and says so once; with no pin the error is the one of today.
- Discover answers 200 without `trust`: the command fails with `the server at <url> sent no trust material`, with or without a pin (Decision 33).
- A `trust.MismatchError`: the message names both values and `-accept-new-root`; with `o.AcceptNewRoot` the pin is replaced and the notice names the old and new thumbprints and names.
- First contact: one notice, `pinned root <thumbprint>, installation <name>, for profile <p> (<server>)`.
- `insecure_http` in effect, that is, an `http` server on a host that is not loopback (with an `https` URL the line would be false): one notice, `profile <p>: insecure_http is on; the connection to <server> is not protected`.
- Each of the three methods reads `store.TrustNumber()` before the call and sets the input's `TrustNumber` when there is one; after `Open` and `Receive` a returned bundle goes to `store.Apply`; each refused CRL is one notice and one line of `<data dir>/logs/trust.log` with both numbers.
- With `NoDiscover` and no pin the layer sends no number and applies nothing.

- [ ] **Step 1: Write the failing tests** (a real server through the package's existing harness plus `trusttest`; a plain `httptest` server where the answer has to be wrong)

`TestFirstContactPinsAndSaysSo` (one notice; a second `Open` gives none); `TestDifferentRootStops` (the server restarted under another root: `Open` fails with both thumbprints and the flag's name, and the trust directory is unchanged; with `AcceptNewRoot` it succeeds and names old and new); `TestDifferentInstallationStops`; `TestExpectedValues` (the profile's `root_thumbprint` and `installation`, each matching and not matching, at first contact and with `AcceptNewRoot`); `TestDiscoverWithoutTrust` (with and without a pin: the error above); `TestDiscoverUnreachable` (with a pin: the `Bus` opens and one notice says it goes on with the trust it holds; without: the error); `TestInBandNumbers` (the number the server receives on open, receive and watch is the stored one; after a forced renewal the next receive stores the bundle and the one after sends the new number); `TestRefusedCRLIsLogged` (a lower CRL number: one notice, one `trust.log` line with both numbers, the held CRL unchanged, the trust number recorded); `TestInsecureHTTPNotice`; `TestUnwritableTrustDirectory` (Review Focus 5: `Open` fails naming the directory and makes no call but discover).

`internal/cli`: `TestStopHookMakesNoDiscoverCall` (a counting server: zero requests to `/v1/discover`, and the hook still answers within its 500 ms); `TestWaitExitsZeroOnTrustWake` (a wake with count 0 is exit 0, as for a message; a parked session stays silent); `TestOneShotCallsDiscoverOnce` (`history` makes one discover request).

Run: `go test ./internal/client/ ./internal/cli/ -run 'Trust|FirstContact|DifferentRoot|DifferentInstallation|ExpectedValues|Discover|InBand|RefusedCRL|InsecureHTTP|StopHookMakesNo|WaitExitsZero|OneShot' 2>&1 | tail -20`. Expected: compile failure.

- [ ] **Step 2: Implement.** **Step 3: Run** `make test 2>&1 | tail -8 && bash scripts/m6-exit-checks.sh --deps-only | tail -1 && bash scripts/m10-exit-checks.sh --deps-only | tail -1`. Expected: `ok`; both `deps_ok=1` (the MCP-only binary gains `internal/trust` and `internal/pki` and still links 13 modules).

- [ ] **Step 4: Close the task.** Commit: `feat(client): pin the root from discover and carry the trust number under the Bus (ADR 0019 Decisions 12, 19, 33)`.

State (Definition of Done D): section 5's rows "Client first contact", "`-accept-new-root`" and "Client stores a bundle"; Task 11 tests the store, this task the calls.

---

### Task 32: `-accept-new-root` and what the commands print

**Files:**
- Modify: `internal/cli/register.go`, `internal/cli/login.go` (`login` and `login -human`), `internal/mcpcli/register.go`, `internal/mcpcli/check.go` (the `reach` step reports a mismatch as a `FAIL` whose fix line names `-accept-new-root`), `internal/mcpcli/help.go`, `internal/cli/cli.go` (`Usage`), the `using-agentmesh` skill text under `internal/cli/skills` only if it names a changed flag
- Test: `internal/cli/register_test.go`, `login_test.go`, `human_test.go`, `internal/mcpcli/register_test.go`, `check_test.go`, `help_test.go`

**Interfaces:**
- Consumes: Task 31 (`Options.AcceptNewRoot`, `Options.Notice`).
- Produces: the flag `-accept-new-root` on `agentmesh register`, `login`, `login -human`, and on `agentmesh-mcponly register` and `check` (section 4.13). No other command takes it. Notices go to standard error; standard output stays one JSON document (or, for `check`, its report).

- [ ] **Step 1: Write the failing tests**: `TestRegisterPinsBeforeRegistering` (against a counting server with a `root_thumbprint` that does not match: exit 2, both thumbprints on standard error, and the server received no registration request); `TestAcceptNewRootFlag` (each of the five commands replaces the pin and prints the old and new values; without the flag each is exit 2); `TestAcceptNewRootElsewhere` (`agentmesh history -accept-new-root` is exit 2: unknown flag); `TestCheckReportsMismatch` (`reach` is `FAIL` and the `next:` or fix line names the flag); `TestHelpNamesTrustFlags` (the help topics list `-accept-new-root`, `-insecure-http`, `-root-thumbprint`, `-installation` and the three variables).
- [ ] **Step 2: Implement.** **Step 3: Run** `go test ./internal/cli/ ./internal/mcpcli/ && go test ./internal/e2e/ -run 'TestHelpExamples|TestMCPOnly' 2>&1 | tail -3`. Expected: `ok`.
- [ ] **Step 4: Close the task.** Commit: `feat(cli): -accept-new-root, and first contact says what it pinned (ADR 0019 section 4.13)`.

---

## Phase D: both engines, the gates, the documents, the number

### Task 33: Replicas and restore on both engines

**Files:**
- Modify: `internal/conformance/bus/replicas_test.go` (`TestReplicasSigningKeyRotation` becomes `TestReplicasTrust`), `scripts/m7-exit-checks.sh` (the counts of `TestReplicasTrust`: 3 leaves on SQLite, 4 on Postgres; the usage text)
- Create: `internal/conformance/bus/restore_test.go`

**Tests (each is the deliverable):**

`TestReplicasTrust/<engine>`: `bearer-crosses-replicas`; `forced-renewal-revokes-across` (after a forced renewal on A, A's new bearer presented to B makes B reload; B then refuses A's old bearer and signs with a new leaf of its own); `two-forced-renewals` (at once: one answer and one retryable `unavailable`, which succeeds when retried); Postgres only, like the cross-server leaves of `TestReplicasWake`: `watch-wakes-across-replicas` (a watch on B with the current number wakes within 5 seconds of a forced renewal on A, count 0).

`TestRestore/<engine>` (Decision 27; a real server through `cmd.Run` and a client through `client.Open` with a profile in a temporary configuration directory; the rollback is written through the suite's raw database handle), subtests in order: `bundle-after-restore` (the stored leaf CRL and the trust number are put back to their values from before a forced renewal; the client, which holds the later ones, still gets the bundle on its next receive, because the numbers differ); `older-crl-refused-once` (one `trust.log` line; the client's kept revocations still hold the revoked serial number; its recorded trust number is the server's); `next-renewal-accepted` (the next forced renewal's CRL has a higher number than the client holds and is accepted); `union-on-the-client` (a leaf revoked before the rollback and missing from the new CRL is still in the client's kept revocations); `union-on-the-server` (the same scenario with the server process kept running across the rollback: the next CRL it builds lists the serial number); `trust-number-above-all` (the trust number of the first change after the rollback is above every value issued before it).

- [ ] **Step 1: Write the tests; see the new ones fail where the behavior is missing and fix what they find.**
- [ ] **Step 2: Run** `make test-conformance 2>&1 | tail -5`; `log="$(mktemp)"; go test -count=1 -v -run '^TestReplicas' ./internal/conformance/bus/ > "$log" 2>&1; bash scripts/m7-exit-checks.sh "$log" | tail -3; rm -f "$log"`. Expected: all `ok`; the m7 line shows `trust_sqlite=3 trust_postgres=4` beside the existing counts.
- [ ] **Step 3: Close the task** (`make release-lint` included). Commit: `test(trust): replicas and restore on both engines (ADR 0019 section 7, Decision 27)`.

---

### Task 34: A key service, a key change, an outside CA and the end-to-end flows

**Files:**
- Create: `internal/core/signingkeys/keyservice_test.go`, `internal/server/cmd/outsideca_test.go`, `internal/e2e/trust_test.go`

**Tests (each is the deliverable):**

`TestKeyServiceIntermediate` (`kmsfake`): the first leaf, a renewal and a leaf CRL are signed through the fake (its call count grows by one each); the fake down at a renewal follows the retry schedule and recovers; the fake down during a forced renewal is a retryable `unavailable` and changes nothing; a leaf signed by a repointed alias fails the chain check and is never used (Ruling 9).

`TestKeyChange` (section 4.4, the file form): a second key for the same name, signed with `sameInstallation` and installed; a manager on the old key and one on the new both issue leaves and each accepts the other's bearers; a forced renewal on the new one reports the old key's leaves as not covered; revoking the old key with the root tool and `InstallRootCRL` cuts them off.

`TestOutsideCAProfileAccepted` (`internal/server/cmd`): an intermediate made with plain `x509.CreateCertificate` by an RSA root, carrying exactly what the operator guide's profile lists plus an organization name in its subject and an extended key usage extension that is not critical, is accepted by `ca install` and the server starts on it; the same certificate without the usage, and with another name, is refused. (The guide's `openssl` example is run by hand in Task 36; no test depends on `openssl`.)

`internal/e2e/trust_test.go` (the built binary; not part of the pinned 13-step sequence): `TestFirstContactEndToEnd` (a fresh home: `register` prints the pin on standard error; a second server under another root at the same profile is exit 2 naming `-accept-new-root`; `register -accept-new-root` replaces it); `TestRotateThenList` (Review Focus 1: `agentmesh signing-keys rotate` then `agentmesh signing-keys list` in one home both exit 0; the list's current leaf is the rotation's `current`).

- [ ] **Step 1: Write the tests; see the new ones fail where the behavior is missing and fix what they find.**
- [ ] **Step 2: Run** `make test 2>&1 | tail -8`; `make vet-tags 2>&1 | tail -3`; `log="$(mktemp)"; go test -count=1 -v ./internal/e2e/ > "$log" 2>&1; bash scripts/m6-exit-checks.sh "$log" | tail -3; bash scripts/m10-exit-checks.sh "$log" | tail -3; rm -f "$log"`. Expected: all `ok`; the pinned counts of the e2e package unchanged (13 steps, 11 cells, `mcponly=9`, `help=6`).
- [ ] **Step 3: Close the task.** Commit: `test(trust): a key service, a key change, an outside CA and first contact end to end (ADR 0019 section 7)`.

---

### Task 35: Selftest block 41, and every existing block still fires

**Files:**
- Modify: `scripts/check-gates-selftest.sh` (block 41, `trust-gates-fire`, and its call at the end of the list), `.github/workflows/ci.yml` only if the selftest job's time limit needs raising

**The mutations** (section 8). Each uses `mutate_unit_block` (anchor exactly once, the named test must fail) or the probe helpers of blocks 12 and 22. The anchor lines are the ones Tasks 3, 4, 5, 8, 10, 11, 12 and 28 fixed:

| Label | File | Anchor becomes | Must fail |
| --- | --- | --- | --- |
| `pki-leaf-rule` | probe file in `internal/pki` and in `internal/pki/rootca` importing `internal/oidctest` | (m7 probe) | `deps_violation=` for each under `pki-leaf` |
| `trust-leaf-rule` | probe file in `internal/trust` importing `internal/oidctest` | (m7 probe) | `deps_violation=` under `trust-leaf` |
| `trusttest-in-binary` | probe file in the root package importing `internal/trusttest` | (m4 probe) | `deps_violation=` |
| `trust-row-trusted` | `internal/core/signingkeys/material.go` | `v, err := pki.CheckChain(...)` becomes `v, err := pki.Verified{Leaf: leaf, Intermediate: im, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, error(nil)` | `TestBearerMatrix/self-signed` |
| `chain-name-ignored` | `internal/pki/chain.go` | `if c.Subject.CommonName != installation {` becomes `if false {` | `TestVerifyChain/other-installation` |
| `chain-usage-intermediate` | `internal/pki/chain.go` | `if !HasAgentmeshUsage(c) {` becomes `if false {` | `TestVerifyChain/intermediate-without-usage` |
| `chain-usage-leaf` | `internal/pki/chain.go` | `if !HasAgentmeshUsage(leaf) {` becomes `if false {` | `TestVerifyChain/leaf-without-usage` |
| `chain-lifetime-ignored` | `internal/pki/chain.go` | `if leaf.NotAfter.Sub(leaf.NotBefore) > MaxLeafLifetime {` becomes `if false {` | `TestVerifyChain/leaf-lifetime-over` |
| `revocation-by-certificate` | `internal/pki/revocations.go` | `if r.RevokedKeys(intermediates)[issuer] {` becomes `if false {` | `TestRevocationByKey` |
| `bundle-only-when-lower` | `internal/core/trust.go` | `*client != b.TrustNumber {` becomes `*client < b.TrustNumber {` | `TestRestore/sqlite/bundle-after-restore` |
| `trust-number-counter` | `internal/store/sqlstore/trust.go` | `next := max(now, stored+1)` becomes `next := stored + 1` | `TestTrustNumber` (the SQLite half) |
| `ca-sign-name-unchecked` | `internal/pki/rootca/rootca.go` | `if taken && !sameInstallation {` becomes `if false {` | `TestSignNameTaken` |
| `expected-installation-ignored` | `internal/trust/pin.go` | `if e.Installation != "" && b.Installation != e.Installation {` becomes `if false {` | `TestExpectedInstallation` |
| `profile-loopback-ignored` | `internal/profile/config.go` | `if !loopbackHost(u.Hostname()) && !p.InsecureHTTP {` becomes `if false {` | `TestServerURLRule` |
| `pen-selftest` | none | (unmutated run of `scripts/pen-gate-selftest.sh`) | prints `6 run, 6 passed` |

- [ ] **Step 1: Check each anchor** with `grep -cF` (exactly 1 in its file). Where a source line differs, change the source to the form above in this task (one line, once per file) and rerun that package's tests.
- [ ] **Step 2: Write block 41** after block 40, in the style of block 32, and add `block_trust_gates_fire` to the list at the end. Commit before running: the selftest tests `HEAD`.
- [ ] **Step 3: Run the whole selftest**: `make check-gates-selftest > "$(mktemp)" 2>&1` in the background, then read its `selftest:` lines. Expected: no `selftest: FAIL` line, and `selftest: ok` for every label of block 41. Blocks 14, 15, 16, 22, 23, 33 and 34 to 40 are the ones this plan could have broken (anchors in `issuer.go`, the `keyprovider` rule names, the wire tables, the spec mutations that name a signing key operation); fix a broken anchor in the selftest, never by weakening the check.
- [ ] **Step 4: Close the task** (`make release-lint` included). Commit: `test(gates): selftest block 41, one mutation per trust rule (ADR 0019 section 8)`.

---

### Task 36: Documents

Every factual claim is checked against the source or a live run (Definition of Done E): each command line a document shows is run in a scratch directory, and its output is what the document quotes. No private host name, address or account detail.

**Files:**
- Rewrite: `docs/ops/signing-keys.md`: the hierarchy; the four commands of a first start; the outside-CA profile in the words of section 4.2 with an `openssl` example, run by hand and checked with `ca install`; the four backends as stores of the intermediate key (their sections stay true of the backends); forced renewal and what it costs; and the six statements section 9 requires: each installation under one root needs a name of its own (Decision 23); an outside CA issues the name, the extended key usage and one subject key identifier for every certificate of a key; revoking an intermediate means revoking every certificate of its key (Decision 26); what `signing-key revoke` is for (Decision 25); any root renewal needs `-accept-new-root` on every client, and what root expiry does (Decision 34); the shipped tool refuses a name it issued to another key, what `-same-installation` is for, and an outside CA has no such check (Decision 37). Also Ruling 12 in plain words: a single server whose renewals fail for W/2 stops serving authenticated requests until one succeeds.
- Modify: `docs/ops/configuration.md` (the five settings; the three removed), `docs/ops/deploy.md` and `deploy/` comments (the CA step; the key file as a mounted secret), `docs/ops/admin-bootstrap.md`, `docs/ops/backup.md` (the database holds no private key; after a restore install the latest root CRL again and, if a forced renewal was run after the backup, run one again: Decision 27), `docs/ops/health.md` (`signing`, the `degraded` reasons), `docs/ops/upgrade.md`, `docs/install.md` (HTTPS and the switch; `root_thumbprint` and `installation`, above all for a client that keeps no configuration directory: Decisions 30 and 38), `docs/cats.md` if it describes the harness's start, `docs/journeys.md` if the rotation journey names `revoke_previous`
- Modify: `CLAUDE.md`: the `agentmesh ca` and `server admin ca` and `signing-key revoke` commands; `signing-keys rotate` without `-revoke-previous`; the new flags and variables; the design notes on `internal/pki`, `internal/trust`, `internal/trusttest`, the leaf manager, `trust_material`, `core.TrustSource`, the m7 rules `pki-leaf` and `trust-leaf`, the m7 replica counts, selftest block 41, `make pen-check`, `make verify` running the m7 rule; the notes that describe `signing_keys`, `StoreProvider`, the two jobs and the three settings are removed; the done gate line names the m7 rule
- Modify: `docs/adr/0012-signing-key-rotation-and-key-providers.md` (the status line: the superseded parts are no longer "designed, not built" but removed, with the date and this plan's path), `docs/adr/0019-certificate-hierarchy-and-signed-messages.md` (the status line: spec 1 built, spec 2 designed; a "Plan rulings of the spec 1 plan" list naming rulings 1 to 29 of this plan as not Eric's), `docs/adr/0004-store-contract-and-storage.md` and `docs/adr/0002-authentication-and-credentials.md` (one line each at the passages ADR 0019 "What this supersedes" names, pointing to ADR 0019), `docs/adr/README.md` (the status cells of the ADR 0012 and ADR 0019 rows)
- Modify: `docs/security/threat-model-server.md` (SD1, SD3, SD6 and threats 1, 2, 6 and 15, now that spec 1 is built; threats are named in plain English)
- Controller step, not an implementer's: the TMI mirror of the threat model. It writes to an outside service, so the controller pauses for Eric with `Approve: update the TMI mirror of the server threat model for threats 1, 2, 6 and 15`.
- Spec 1's status lines (Open question 4): changed only when Eric has answered.

- [ ] **Step 1: Write the documents.** **Step 2: Verify**: run every quoted command; `rg -n 'signing_key_uri|signing_key_rotation|revoke-previous|revoke_previous|StoreProvider|signing_keys' docs CLAUDE.md` shows only ADR history and the two superseded specs. **Step 3: Close the task.** Commit: `docs: the certificate hierarchy in the operator guides, CLAUDE.md and the ADRs (ADR 0019 section 9)`.

---

### Task 37: The assigned enterprise number (blocked on Open question 2)

**Precondition:** ADR 0019 records the number IANA assigned (Ruling 42). Without it this task does not start.

**Files:**
- Modify: `internal/pki/eku.go` (the constant; the comment loses "stand-in"), `internal/pki/eku_test.go`, `Makefile` (`verify` runs `$(MAKE) pen-check`), `.github/workflows/ci.yml` (the `pen-gate` job's `if:` is removed), `scripts/check-gates-selftest.sh` (block 41 gains two mutations), `docs/ops/signing-keys.md` (the identifier in the outside-CA profile), `CLAUDE.md`

- [ ] **Step 1: Write the failing test** `TestExtKeyUsagePinned`: `ExtKeyUsageAgentmesh.String()` equals the literal `"1.3.6.1.4.1.<the assigned number>.1.1"`, written out in the test; `PrivateEnterpriseNumber` is neither 0 nor 32473. Run it: it fails on 32473.
- [ ] **Step 2: Set the constant.** Run: `go test ./internal/pki/ && make pen-check`. Expected: `ok` and `pen-gate: ok <n>`.
- [ ] **Step 3: Block 41** gains `pen-zero` and `pen-documentation`: the constant line mutated to 0 and to 32473; `bash scripts/pen-gate.sh` must exit 1 and `TestExtKeyUsagePinned` must fail.
- [ ] **Step 4: Check nothing else held the stand-in**: `rg -n '32473' .` shows only the gate, its selftest, the test's refusal and the RFC 5612 sentence in the documents; `rg -ln 'BEGIN CERTIFICATE|BEGIN X509 CRL' --glob '!docs/**' .` shows nothing (no committed certificate).
- [ ] **Step 5: Close the task** (`make verify` now includes `pen-check`). Commit: `feat(pki): the assigned enterprise number of the agentmesh extended key usage (ADR 0019 Decision 36)`.

---

### Task 38: The done gate

- [ ] **Step 1:** `make verify 2>&1 | tail -15` (Docker running; the Postgres suites ran; ends `verify: OK`).
- [ ] **Step 2:** `make check-gates-selftest` in the background; no `selftest: FAIL` line.
- [ ] **Step 3:** `make pen-check`, `make vet-tags`, `make docker-smoke`, `make release-lint`, `make release-check`, `make cats-selftest`; each exits 0.
- [ ] **Step 4:** the exit scripts with fresh logs: `scripts/m4-exit-checks.sh`, `m5` (12 and 12), `m6` (13 steps, 11 cells), `m7` (the replica counts with `trust_sqlite=3 trust_postgres=4`), `m8`, `m10` (`mcponly=9`, `help=6`).
- [ ] **Step 5:** A CATS campaign over the changed paths when `cats` is installed: `make cats-run`; findings go through the `cats:*` skills.
- [ ] **Step 6:** Report the outputs and stop. Merging `adr-0019-spec-1` into `main` and pushing are Eric's: `Approve: merge adr-0019-spec-1 into main and push`. After the push, `ci.yml` (every job, `pen-gate` and `release-check` included) and `windows.yml` must be green; a red `windows.yml` is fixed first.

## Self-review record

- **Spec coverage.** Section 4.1: Tasks 23, 28 (local mode has none of it). 4.2: Tasks 1, 3. 4.3: Tasks 5, 6. 4.4: Tasks 7, 12, 13. 4.5: Tasks 8, 26. 4.6: Tasks 17, 18. 4.7: Tasks 16, 19, 23. 4.8: Tasks 4, 19, 20, 21, 33, 34. 4.9: Tasks 27, 28, 29, 31. 4.10: Tasks 10, 11, 31, 32. 4.11: Tasks 15, 27, 30. 4.12: Tasks 9, 10, 24. 4.13: Tasks 6, 13, 21, 32. 4.14: Task 30. 4.15: Tasks 23 (start), 18 and 19 (running), 31 (client). 4.16: Tasks 24, 26. Section 5: the State lines of Tasks 5, 8, 12, 18, 20, 22, 23, 31, and Task 33 for the restore. Section 7: every bullet has a named test (the fixtures: Tasks 14, 22; `internal/pki`: Tasks 1, 3, 4; the root tool: Tasks 5, 6; host commands: Tasks 13, 21; start-up: Task 23; the fake clock: Task 18; bearers: Task 19; replicas: Task 33; the report: Task 20; the inproc Bus suite: Task 28; discover and in-band: Tasks 28, 29; the trust number: Task 8; restore: Task 33; root expiry: Tasks 17, 19, 30; the profile rule: Task 10; the client trust store: Tasks 11, 31, 34; a key service: Task 34; no 500: Task 28). Section 8: Tasks 15, 27 (tables), 1, 5, 11, 14 (import rules), 35 (mutations), 37 (the identifier). Section 9: Task 36.
- **Not built, on purpose:** everything in "Left for spec 2".
