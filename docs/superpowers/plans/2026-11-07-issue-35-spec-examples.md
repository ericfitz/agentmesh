# Issue 35: Spec Examples and Descriptions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `api/openapi.yaml` reads on its own: every operation has a `description` (behavior, access rule, side effects, idempotency, source), every tag, parameter, schema, property, response and request body a `description`, every request body, response body and parameter an example, `bearerAuth` describes the token, `servers` names the placeholder, and none of it can rot: `TestSpecDescriptions` and `TestSpecExamples` (`internal/gen`) fail on an undocumented element or an example that is a placeholder or names a real host, kin-openapi validates every example against its schema (`TestDocumentIs31AndValidates`, already in place), `TestRequestExamples` (`internal/e2e`) replays every request example against the e2e servers and checks the answer against the documented response, `make spec-lint` runs with `oas3-missing-example` and `oas3-api-servers` on, and `scripts/check-gates-selftest.sh` block 39 proves each check fires.

**Architecture:** No production code changes. Examples live on the component schemas (one `example` per schema), on inline media-type schemas and on every parameter; a media type whose schema is a `$ref` inherits the schema's example (vacuum agrees: probe below), so nothing is written twice. The document tests walk `spec.GetSpec()` (the embedded document, like `TestOperationShape`), never the YAML. The replay test is the last file of `internal/e2e` and uses the two fixtures that exist (`fx`, the binary's server; `slackFx`, the in-process server with the Slack fake); it registers the example identity by replaying `register`, so the example values are literally true on the server, and substitutes only server-assigned values (ids, tokens, sequence numbers) through a per-row list of JSON pointers. `internal/gen` is regenerated after every spec task (descriptions become Go comments; examples generate nothing).

**Tech Stack:** Go (`CGO_ENABLED=0`), oapi-codegen v2.8.0, kin-openapi v0.151.0 (`openapi3`: `Validate` validates examples by default, `example_validation.go`, `schema.go:2079`, `parameter.go:390`, `media_type.go:141`, `response.go:194`), vacuum 0.36.2, bash gate scripts (`set -euo pipefail`, shellcheck-clean).

**Spec:** GitHub issue #35 (body); Eric's decisions of 2026-11-06 (no `contact` and no `license` in `info`; `servers` is the placeholder `http://localhost:8420`, deployments vary); CLAUDE.md (the `api/openapi.yaml` and `make generate` rules, the pre-release rule, Definition of Done E); ADR 0001 (choices and the #32, #33, #34 addenda), ADR 0002 (the token profile), ADR 0007; the issue #32 and #34 plans for the table style and the selftest conventions. Evidence on branch `issue-35-spec-examples` at `9ee2b5e`.

## Baseline (vacuum 0.36.2 on 9ee2b5e, `spectral:oas` `all` with only `camel-case-properties`, `openapi-tags-alphabetical`, `info-contact`, `info-license` off)

| Rule | Findings | Where |
|---|---|---|
| `oas3-missing-example` | 139 | 20 request media types; 47 inline success media types (41 `200`, 6 `201`); 13 shared responses (the 12 Problem responses and `OAuthError`); 6 on three inline array parameters (`unsubscribeTags` `pattern`, `history` `tags`, `search` `tags`: the parameter and its schema); 54 schemas (5 reported on the schema, 49 on a property; the 18 others are not reported, all `$ref`-only or array schemas) |
| `description-duplication` | 70 | the shared #34 bound texts ("At most 128 bytes (the server counts bytes)." and kin) and the paired `Subscribed.`/`Unsubscribed.` response descriptions |
| `oas3-api-servers` | 1 | no `servers` |
| `operation-description`, `component-description`, `oas3-parameter-description`, `tag-description` | 0 | vacuum accepts a `summary` as the operation description (probe: removing `discover`'s summary makes `operation-description` fire once); 46 of 57 operations have no `description` (the 11 that do: `peek`, `setAgentStatus`, `listAgentStatuses`, `agentStatusHistory`, `adminUsage`, `token`, `register`, `listSigningKeys`, `rotateSigningKey`, `createAgentIdentity`, `createBridge`); 223 of 320 schema properties have no `description` (the 97 others are `$ref` members); all 9 tags, 5 component parameters, 12 component responses and 72 schemas have one |

Probes (scratchpad `issue35/`, 2026-11-07): adding `example` to the `Session` schema removes vacuum's finding on `openSession`'s `201` media type (139 to 137), so a referenced schema's example satisfies the media-type rule; adding `servers: [{url: http://localhost:8420}]` and regenerating leaves `go test ./internal/gen/ ./internal/server/` green (`server.Spec()` clears `Servers`, `server.go:62`; the `internal/gen` validator tests pass with it present).

Counts the tests will pin: 57 operations, 9 tags, 72 schemas, 320 properties, 12 shared responses, 5 shared parameters, 20 request bodies, 23 operations with `Idempotency-Key`, 8 open operations (`wellKnown`, `authorizationServerMetadata`, `openidConfiguration`, `discover`, `token`, `jwks`, `register`; `health` with optional bearer).

## Global Constraints

- **Eric's decisions (2026-11-06, issue #35), binding:** no `contact` and no `license` in `info`; the ruleset keeps `info-contact` and `info-license` off with this decision as the reason; `servers` is one placeholder entry, `http://localhost:8420`, whose description says deployments vary.
- **Issue acceptance criteria, binding** (less the dropped contact/license one): every operation has a one-line `summary` and a `description` with behavior, access rule, side effects, idempotency key use and the spec section or ADR it comes from; every tag, parameter, schema, property and response has a `description`; every request body, response body and parameter has an example; examples are realistic and carry no real hostname, email, token, key or account detail; a test validates every example against its schema and an e2e test replays each request example against the e2e server and checks the answer against the documented response; `bearerAuth` describes the token (issuer, lifetime ceiling, the client assertion flow) and cites RFC 8725; the ruleset turns the description and example rules on; every factual claim is checked against the source; descriptions do not restate the generator's types; `make generate`; `make verify`; `ci.yml` and `windows.yml` green.
- **Definition of Done E, binding:** hostnames in examples are `localhost` or the reserved `example.com`, `example.org`, `example.net`, `example.test`; emails end in one of those; every token-shaped value decodes to or contains the word `example` or is the fixed pattern of the conventions table below; `TestSpecExamples/no-real-values` enforces the host and email rule and the literal denylist `trojanunicorn`, `efitz`, `fitzgerald`, `github.com`.
- **The protocol version stays `1.0.0`** (`info.version` and `version.Protocol` untouched; descriptions and examples are a documentation change and the pre-release rule of CLAUDE.md holds).
- **Never edit `internal/gen` by hand**: every spec task ends with `make generate`, and every selftest spec mutation regenerates in the throwaway worktree (`mutate_spec_block`) because the tests read the embedded document.
- **No wire change.** No schema gains or loses a member, type, bound, enum value or `required` entry; no operation gains or loses a response, parameter or security requirement. `git diff --stat internal/gen` after each spec task shows comment-only changes (`gen.go` and `spec/spec.go`: the embedded document changes, the Go types do not); `TestWireRoundTrip`, `TestSpecBounds`, `TestToolCoverage`, `TestOperationShape`, `TestStatusTable` and `TestOperationErrorTable` stay untouched and green.
- **Every factual claim in a description is checked against source** (the files each area task names), and the reviewer checks every operation description the same way: open the handler and the core function the task names and confirm each clause. A claim that cannot be found in source is removed, never kept.
- **No descriptions in the generator's words**: no "string", "integer", "array of", "boolean", "int64" as the content of a description (`TestSpecDescriptions/not-a-type` fails on a description that is only a type name, case-insensitively, optionally with a trailing period).
- **Every commit on the branch is green** (`go test ./internal/gen/ ./internal/server/ ./internal/e2e/` at least): the document tests carry a literal deny-list of the elements still undocumented (ruling 3), which each area task shrinks and the last one deletes. A task reviewer applies the Definition of Done per task.
- **`TestAccessRuleSites`** is untouched: no task reads `Admin`, `Creator`, `Owner`, `Scope` or a `Kind` outside `access`. The e2e replay uses the host command `server admin ... admins add` for the administrator flag, as `TestArazzoWorkflows` does.
- **Import rules hold.** `internal/gen` tests import `internal/gen/spec` and kin only (as today); `internal/e2e` tests import `internal/respcheck`, `internal/arazzotest`, `internal/auth/...`, `internal/server` (for `Spec()`), `internal/slackapi` and `internal/slackapi/slackfake` (as today); nothing new in a non-test file.
- American English everywhere. Work lands on the branch `issue-35-spec-examples`, one commit per task in the `type(scope): subject` style, ending with the two attribution lines the session reminder gives. No task pushes.
- Done gate: `make verify` (needs Docker; a run that skips the Postgres suites is not a pass) and `make check-gates-selftest`; then `ci.yml` and `windows.yml` green on the pushed commit. Task 11 runs the two make targets and shows their output.
- Shell: the gate script stays `set -euo pipefail`, shellcheck-clean (`make release-lint`).

## Rulings made by this plan (Eric may overrule)

1. **Examples live on the component schemas, inline media-type schemas and parameters; a `$ref` media type inherits.** Every one of the 72 component schemas gets one schema-level `example`. A response schema's example carries every member, including the optional ones, so the replay's superset check (ruling 9) has something to compare against. A request schema's example carries the members of one valid request, the one the replay sends: `TokenRequest` is a `client_credentials` request (no exchange members), `TaskCreateRequest` has `parent` and `blocked_by` but not `before`/`after` (two sibling tasks the setup never creates), `OpenSessionRequest`'s schema example is the fresh open, `CreateChannelRequest` has no `scope`; the members the example omits are documented by their property descriptions. A media type gets its own `example` only when its schema is inline: the 12 Problem responses (`allOf`), `OAuthError`'s response, the 14 inline array responses (`listIdentities`, `listAgentStatuses`, `agentStatusHistory`, `listChannels`, `getACL`, `listTagSubscriptions`, `history`, `listMemoryRevisions`, `listTasks`) and `setACL`'s inline array request body. Every parameter (5 shared, 26 inline) gets `example` on the parameter object. "The effective example" of a media type is its `example`, else the first of its `examples` (`default` when present, else by name), else the referenced schema's `example`; `TestSpecExamples` resolves it this way and fails when nothing is found. Why: no duplication (the probe shows vacuum, like Redoc and Swagger UI, reads the schema's example through the `$ref`), one place to fix when a schema changes, and kin validates a schema example once instead of per use.
2. **Named request examples.** A request body media type may carry `examples` (a named map) where one example cannot stand for the operation. This plan adds one: `openSession` gets `default` (a fresh open: `hint` and `cursors`, no `resume_token`) and `resume` (a `resume_token`, no cursors). Every named example of every request body is replayed by its own row (ruling 8); a singular `example` and an inherited schema example count as the name `default`.
3. **The document tests land green in Task 1 behind a literal deny-list.** `TestSpecDescriptions` and `TestSpecExamples` carry `var undocumented = map[string]string{...}` keyed by the subtest path without the test name (`operations/<id>`, `schemas/<Name>`, `properties/<Name>.<member>`, `parameters/<op>.<name>` or `parameters/<Name>`, `requests/<op>[.<name>]`, `responses/<op>.<status>` or `responses/<Name>`, `tags/<name>`; pinned in Task 1), one value per key naming the area task that will document it. A key in the list whose element is documented fails as `stale`; an undocumented element missing from the list fails as `undocumented`. Each area task's first step deletes its keys (red), its last step documents them (green); Task 6 deletes the variable. This is the house pattern (`TestToolCoverage`'s `hidden`, the bounds table) and keeps every commit green.
4. **The operation description template** is five clauses in this order, separated by sentences, each present: behavior (what the operation reads or writes); access (`Open operation.`, `Any registered identity.`, `Administrator only.`, `The channel ACL's <action>.`, `Inside the caller's scope.` or the exact rule of `internal/core/access/decide.go`); side effects (`Writes nothing.` for a read, else what is appended, deleted or woken); idempotency (`Idempotency-Key: a repeat with the same key and body returns the first answer.` for the 23 operations that take the header, `No idempotency key.` for the rest, with the reason where one exists, as `createAgentIdentity` says today); source (`spec N.N`, `ADR NNNN` or `Decision NN`, at least one). `TestSpecDescriptions/<op>/cites-source` matches `(spec [0-9]+(\.[0-9]+)*|ADR 00[0-9]{2}|Decision [0-9]+)` and `TestSpecDescriptions/<op>/idempotency` requires the word `Idempotency-Key` in the description of exactly the operations whose parameters include `IdempotencyKeyParam` (and `idempotency key` in the others, so the clause is never silently skipped). The 11 existing descriptions are completed to the template, not replaced.
5. **`$ref`-only properties inherit the target's description.** OpenAPI 3.1 allows a `description` beside `$ref`, but kin-openapi's `SchemaRef` exposes the target, not the sibling, so the test could not see it. A property whose `SchemaRef.Ref` is non-empty is documented when the target schema has a description (always true after Task 1); every other property (223) needs its own `description`. Array `items` and `additionalProperties` schemas are not properties and need no description of their own (the property's description covers them), but an inline `items` object's properties are walked.
6. **`description-duplication` stays off**, with its reason updated: the #34 bound texts repeat by design and the property descriptions of this issue add more legitimate repeats (`created_at` is "Unix milliseconds" in every schema). `oas3-missing-example` and `oas3-api-servers` turn on; `info-contact` and `info-license` stay off citing Eric's decision of 2026-11-06 (issue #35) instead of "issue #35 decides".
7. **The replay identity is the example identity.** `TestRequestExamples` registers `acme-coder-1` by replaying the `register` example (substituting the live JWK and enrollment token), mints its bearer by replaying `token`, then runs `agentmesh server admin -sqlite <fixture db> admins add -identity acme-coder-1` (host command, like `TestArazzoWorkflows`), so every later example that names `acme-coder-1`, the scope `acme`, the channels `release-train` and `release-notes`, the task and the memory is literally true. Server-assigned values are substituted per row (ruling 8). The committed example JWK, enrollment token and client assertion are therefore any syntactically valid fakes of the conventions table.
8. **The replay table is a slice in replay order, one row per `(operation, example name)`, 58 rows**, with both-ways coverage (`TestRequestExamples/coverage`: an operation or named request example without a row, a row naming an unknown operation or example). A row is `{op, example, fixture, status, live, setup}`: `live` maps JSON pointers into the request (`/body/<pointer>`, `/path/<name>`, `/query/<name>`, `/header/<name>`) to a function of the replay state; a pointer whose target is absent from the documented example fails (`live pointer %s is not in the example of %s`: the analog of "refuse unknown placeholders"; there are no placeholders in the spec). `setup` runs before the request and may use the replay state (the bearer, ids, seqs). The request is built from every parameter's documented example plus the effective request example, then `live` is applied. Rows run on `fx` except the four bridge rows and their setup on `slackFx` (fixture 1 answers 503 `unavailable` for bridges).
9. **The response check is status, schema and shape.** The status must equal the row's documented 2xx (the one the operation declares, or the one the row names where there are two: `watch` names `200`). The body is validated against the schema by the fixture's validating proxy (`respcheck`, `runMain`'s final checks). The shape check: every member of the live body (recursively through objects; the first element of a non-empty array against the first element of the example's array) is present in the effective response example with the same JSON kind (string, number, boolean, object, array, null). The reverse is not required: the example documents every member a response can carry, the live body omits optional ones. Values are not compared. `204` rows check that the body is empty. Only success examples are replayed; the Problem examples are covered by `TestSpecExamples` and kin's validation.
10. **The replay file is `internal/e2e/zz_examples_test.go`**, `//go:build !windows` like its siblings, and the package's file-order convention (the package doc, `e2e_test.go:14-16`) puts it last: `adminReset scope=data` wipes the bus data of fixture 1 and `rotateSigningKey` has the fixture's 1 s cooldown behind `TestArazzoWorkflows`' rotation. The file comment says so.
11. **Examples never carry a placeholder.** No `<...>`, `{{...}}`, `TODO`, `TBD`, `xxx`, `changeme`, `string`, `example` as the whole value of a non-token member (`TestSpecExamples/no-placeholders`); token-shaped members (ruling 1 of the conventions table) are the exception: they must contain `example` when decoded.
12. **`bearerAuth` describes what `Issuer.Verify` enforces**, nothing more: compact JWS; `alg` in `EdDSA`, `ES256` (`serverAlgorithms`, `issuer.go:45`); `typ` `at+jwt` or `application/at+jwt` (RFC 9068 section 2.1); one signature; `exp` and `sub` required; the key by `kid` from the server's key set; minted by this server (`iss` and `aud` the issuer URL of `/.well-known/oauth-authorization-server`); lifetime `token_lifetime_seconds` (default 3600) at most `MaxTokenLifetimeSeconds` 86400 (`config.go:21`, `signingkeys.MaxBearerLifetime`); obtained by the RFC 7523 `private_key_jwt` client credentials grant or the RFC 8693 exchange at `token`; RFC 8725 is cited for the algorithm allowlist, the `typ` check and the audience. The implementer reads `issuer.go:330-400` before writing and lists in the commit message which claim checks the text names.
13. **Response descriptions are completed, not rewritten**: the `Subscribed.`/`Unsubscribed.` pairs and the shared responses already have descriptions; a response description that is one word gains the member list ("Subscribed: no body." is enough).
14. **The replay suffixes `Idempotency-Key`.** Receipts are keyed `(identity, key)` (`PRIMARY KEY (identity, key)` in both `0001_initial.sql`; `TestWithReceiptConflictOnDifferentPayload`), so the documented example key sent by 23 rows of one identity would answer 409 from the second row on. The request builder sends `<documented example>-<row number>` on every operation that takes the header; the suffix keeps the example's shape and stays under `rules.MaxTokenBytes`. The documented key itself is never sent (the header is opaque; nothing about its value is documented beyond the bound).
15. **`include_own` is `true` in the examples of `watch`, `peek` and `ReceiveRequest`.** The replay has one identity, so with the default `false` nothing it sent would count: `watch` would wait its 30 s example timeout and answer 204, `receive` would deliver nothing and the `ack` row would have no batch token. The parameter and property descriptions state the default `false` and what `true` means; the example shows the flag in use. A second identity for the sends would need a second registration and bearer and buys nothing the ACL matrix does not already prove.

## Open for Eric

1. **`description-duplication` off (ruling 6).** Recommendation: keep it off; a rule that punishes "Unix milliseconds" said twice produces worse descriptions. The alternative is per-schema phrasing of the same fact.
2. **A second `token` example for the RFC 8693 exchange.** Not added (the e2e server has no OIDC issuer configured, so it could not be replayed; `TestAuthEndToEnd` covers the exchange). Recommendation: leave it to a later issue if the human sign-in documentation needs it.
3. **The replay identity holds the administrator flag (ruling 7)**, so no `forbidden` path is exercised by the replay. Recommendation: accept; the ACL matrix and the e2e exit-code table cover refusals.

## Review Focus

1. A description written from memory: the reviewer opens the handler (`internal/server/<aggregate>.go`) and the core function the area task names and confirms each of the five clauses; a clause with no source line is a finding.
2. An example that is realistic but wrong (a `seq` of `0` where the server starts at 1, a `kind` not in the enum, an `expires_in` above the ceiling): kin's `TestDocumentIs31AndValidates` catches the schema part; the replay's shape check catches a member name; a wrong *value* that validates is the reviewer's job: compare each schema example with the Bus type in `internal/bus` and one real response from the e2e log.
3. A `live` pointer that substitutes a value the example should carry literally (a channel name, an identity): ruling 7 wants those literal; the reviewer reads the `live` lists for anything that is not an id, token, sequence number, timestamp or signed material.
4. The deny-list: a task that deletes keys and leaves the elements undocumented cannot pass (the test is red); a task that documents elements of another area without deleting their keys fails as `stale`. The reviewer checks the key count in the commit matches the task's table.
5. The replay order: a row that reads state a later row creates, or a row after `deleteChannel release-train` that names the channel. The table in Task 8 is the order; the reviewer checks the file matches it.
6. `make generate` after every spec task: `git status --porcelain internal/gen` empty after `make generate-check`.
7. The selftest anchors are written against the file as it stands after Task 7; each must occur exactly once in its scope (`mutate_spec_block` checks).

## Example conventions (every area task follows this table; the replay depends on it)

| Thing | Example value | Shape, source |
|---|---|---|
| Agent identity | `acme-coder-1` (the caller); `acme-builder` (created by `createAgentIdentity`, scope `acme`) | `store.NameRule`; registered and created by the replay |
| Human identity | created from `dana@example.com`; the identity string the server returns is used in the `HumanIdentity` example as the server forms it (check `internal/core/identities/email.go` before writing) | reserved domain |
| Scope | `acme` | `createScope`; retired by `doneScope` `retire: normal` late in the replay |
| Channels | `release-train` (ordinary, kind `ordinary`; renamed to `release-train-archive` by `renameChannel`, deleted by `deleteChannel`); `release-notes` (kind `memory`); `acme-ops` (the scoped channel of the bridge rows, fixture 2) | an unscoped name must not start with `<scope>-` (`decide.go:217-219`): `release-*` never collides with scope `acme` |
| Tags | `deploy-prod`, `build-42`; tag patterns `deploy-*` | `rules.MaxTagLen`, the pattern rule of `internal/core/channels/subscriptions.go` |
| Session id | `9f1c2e7a4b3d5c6e8f0a1b2c3d4e5f60` | 32 lowercase hex (`RandomHex(16)`, `open.go:52`); substituted live |
| Resume token | `ZXhhbXBsZS1yZXN1bWUtdG9rZW4tbm90LWEtcmVhbDE` | 43 base64url characters (`RandomToken(32)`): base64url of `example-resume-token-not-a-real1`; substituted live |
| Receive batch token (`ack`) | `0123456789abcdef01234567:o1` | 24 hex plus `:o0` or `:o1` (`makeBatchToken`, `delivery/service.go`); substituted live |
| Enrollment token | `abe_ZXhhbXBsZS1lbnJvbGxtZW50LXRvay1ub3QtcmVhbDE` | `abe_` + 43 base64url (`enrollment.go:79-83`); substituted live |
| Signing key id, JWK `kid` | `ZXhhbXBsZS1zaWduaW5nLWtleS1pZC1ub3QtcmVhbDE` | 43 base64url (`keys.KID`, sha-256); live where the replay needs one |
| Client assertion, access token | assertion: `eyJhbGciOiJFZERTQSIsImtpZCI6IlpYaGhiWEJzWlMxemFXZHVhVzVuTFd0bGVTMXBaQzF1YjNRdGNtVmhiREUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY21lLWNvZGVyLTEiLCJzdWIiOiJhY21lLWNvZGVyLTEiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0Ojg0MjAiLCJqdGkiOiJleGFtcGxlLWp0aS0xIiwiZXhwIjoxNzk0MDk5NjAwfQ.ZXhhbXBsZS1zaWduYXR1cmUtbm90LXJlYWw`; access token: `eyJhbGciOiJFZERTQSIsImtpZCI6IlpYaGhiWEJzWlMxemFXZHVhVzVuTFd0bGVTMXBaQzF1YjNRdGNtVmhiREUiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojg0MjAiLCJzdWIiOiJhY21lLWNvZGVyLTEiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0Ojg0MjAiLCJjbGllbnRfaWQiOiJhY21lLWNvZGVyLTEiLCJqdGkiOiJleGFtcGxlLWp0aS0xIiwiaWF0IjoxNzk0MDk2MDAwLCJleHAiOjE3OTQwOTk2MDAsImFnZW50bWVzaF9raW5kIjoiYWdlbnQifQ.ZXhhbXBsZS1zaWduYXR1cmUtbm90LXJlYWw` | three base64url segments each. Assertion: header `{"alg":"EdDSA","kid":"<signing key id below>","typ":"JWT"}`, payload `{"iss":"acme-coder-1","sub":"acme-coder-1","aud":"http://localhost:8420","jti":"example-jti-1","exp":1794099600}`. Access token (as `Issuer.Mint` forms it, `issuer.go:281-340`): header `{"alg":"EdDSA","kid":"<signing key id below>","typ":"at+jwt"}`, payload `{"iss":"http://localhost:8420","sub":"acme-coder-1","aud":"http://localhost:8420","client_id":"acme-coder-1","jti":"example-jti-1","iat":1794096000,"exp":1794099600,"agentmesh_kind":"agent"}`; signature `example-signature-not-real` in both; substituted live |
| `Idempotency-Key` | `6b1f2d4e-0c3a-4f8b-9e7d-example00001` | opaque, `rules.MaxTokenBytes`; the replay sends it with a `-<row>` suffix (ruling 14) |
| Key order inside a component schema | `example:` is the first key under the schema name, then `description:`, then the rest | makes `$'    <Name>:\n      example:'` a unique anchor for the selftest (block 39) and keeps every example in one predictable place |
| JWK | `{"kty":"OKP","crv":"Ed25519","x":"ZXhhbXBsZS1wdWJsaWMta2V5LW5vdC1yZWFsLTMyYnk","kid":"ZXhhbXBsZS1zaWduaW5nLWtleS1pZC1ub3QtcmVhbDE","alg":"EdDSA","use":"sig"}` | the members the server emits (`keys.ToJWK`); `x` is 43 base64url characters (32 bytes, `example-public-key-not-real-32by`); substituted live in `register` |
| Sequence numbers | `41` (a cursor or reply target), `42` (the message, memory or task of the moment), `43` | int64 at least 1 after the first append (check `internal/store` sequence start before writing `0` anywhere); substituted live |
| Timestamps | `1794096000000` (created: 2026-11-08 00:00 UTC), `1794099600000` (an hour later), `1794182400000` (a day later), `1825632000000` (2027-11-08, the `search` `until` example) | Unix milliseconds (checked with Python `datetime`; 1762560000000 is 2025-11-08, a common slip); `leased_until` substituted live (now + 1 h) because a fixed instant is in the past at the next run |
| Base URL, issuer | `http://localhost:8420` | Eric's placeholder |
| Problem | `{"type":"urn:agentmesh:problem:<code>","title":"...","status":<n>,"code":"<code>","detail":"...","retryable":<bool>}` | `ProblemTypePrefix` (`problem.go:18`); the implementer copies the members of `Problem` and one live problem from a server test before writing the 12 |
| Email, display name | `dana@example.com`, `Dana` | reserved domain |
| Slack | channel name `acme-ops`, Slack channel id `C0EXAMPLE01`, team `T0EXAMPLE`, user `U0EXAMPLE1` | the shapes `slackfake` uses (`slack_test.go:51`: `T1`, `UBOT`); ids are uppercase letters and digits |
| Content | `"Build 42 is green on main; deploying to staging."`, memory `"Release notes for 2026.11: ..."`, task subject `"Cut release 2026.11"` | ordinary prose |

---

### Task 1: `TestSpecDescriptions` and `TestSpecExamples` behind the deny-list

**Files:**
- Create: `internal/gen/spec_docs_test.go` (the two tests, the walker, the effective-example resolver, the deny-list)
- Create: `internal/gen/spec_docs_undocumented_test.go` (`var undocumented = map[string]string{...}`: one file, deleted in Task 6)

**Subtest names and keys (pinned here so block 39's `want` strings are not a guess):** `TestSpecDescriptions/tags/<name>`, `TestSpecDescriptions/operations/<id>` with the nested `cites-source`, `idempotency`, `access`, `request-body`; `TestSpecDescriptions/parameters/<key>`, `TestSpecDescriptions/responses/<key>`, `TestSpecDescriptions/schemas/<Name>`, `TestSpecDescriptions/properties/<Name>.<member>`, `TestSpecDescriptions/not-a-type`, `TestSpecDescriptions/counts`; `TestSpecExamples/requests/<op>[.<name>]`, `TestSpecExamples/responses/<key>`, `TestSpecExamples/parameters/<key>`, `TestSpecExamples/schemas/<Name>`, `TestSpecExamples/no-placeholders`, `TestSpecExamples/no-real-values`, `TestSpecExamples/validates`. A deny-list key is the subtest path without the test name (`operations/listChannels`, `properties/SendRequest.subject`, `schemas/Session`, `requests/openSession.resume`, `responses/openSession.201`, `responses/BadRequest`, `parameters/history.tags`, `parameters/SessionParam`, `tags/admin`), and the failure texts are `undocumented: <key>` and `stale: <key> is documented; remove it from undocumented`. The parameter key for an inline parameter is `<op>.<name>`, for a shared one its component name.

**What the tests check** (over `loadDoc(t)`, i.e. `spec.GetSpec()`):

`TestSpecDescriptions`:
- `tags`: every `doc.Tags` entry has a non-empty description (count pinned at 9).
- `operations/<id>`: `Summary` non-empty and one line; `Description` non-empty; `cites-source` (ruling 4 regex); `idempotency` (ruling 4: `Idempotency-Key` present iff the operation's parameters include `#/components/parameters/IdempotencyKeyParam`; else the words `idempotency key`); `access` (one of the access phrases of ruling 4 or the word `ACL`); the request body (`RequestBody.Value.Description`) non-empty where there is one.
- `parameters/<key>`: every shared parameter and every inline parameter has a description; key `parameter/<Name>` for `components.parameters`, `parameter/<op>.<name>` inline.
- `responses/<key>`: every shared response and every inline response has a description.
- `schemas/<Name>` and `property/<Name>.<member>`: every component schema has a description; every property with an empty `Ref` has one (ruling 5), recursively into inline `items` and inline object properties (key `property/<Name>.<member>.<sub>`); `allOf`/`oneOf`/`anyOf` members that are inline objects are walked the same way.
- `not-a-type`: no description equals (case-insensitively, trailing period allowed) one of `string`, `integer`, `number`, `boolean`, `array`, `object`, `int64`, `int32`, or starts with `array of`.
- `counts`: 57 operations, 72 schemas, 320 properties (the walker's property count over component schemas: the number `TestSpecBounds`' walker would also see; pin the number the walker reports and state it in the commit).

`TestSpecExamples`:
- `requests/<op>[.<name>]`: every request body media type has an effective example (ruling 1), and when `Examples` is set every named example has a `Value`.
- `responses/<op>.<status>` and `responses/<Name>`: every media type of every response (inline and shared) has an effective example.
- `parameter/<key>`: every parameter has `Example` (on the parameter object; `Examples` also accepted when non-empty).
- `schema/<Name>`: every component schema has `Example`.
- `no-placeholders` (ruling 11) and `no-real-values` (Global Constraints: hosts after `://` and after `@` in every example string, recursively, must be `localhost` or a reserved example domain; the literal denylist) over every example value in the document.
- `validates`: `doc.Validate(ctx)` passes (kin validates examples by default; this is the explicit statement of the acceptance criterion, beside `TestDocumentIs31AndValidates`), plus, for each named example of each request body, `openapi3.VisitAsRequest()`-style validation against the media type schema so an `examples` entry is not only present but valid as a request (kin's `media_type.go:141` does this inside `Validate` too; the explicit loop names the failing example).

The deny-list (ruling 3): both tests consult `undocumented[key]`; a listed key whose element passes fails `stale: <key> is documented; remove it from undocumented`; an unlisted failing key fails `undocumented: <key>`. The initial list is produced by running the tests once with an empty map and pasting the `undocumented:` keys with the owning task name as the value (Task 2 to Task 6 by area; the areas are the tags: `discovery`+`health`+`auth`+shared components to Task 2, `sessions` to Task 3, `channels`+`messages` to Task 4, `memories`+`tasks` to Task 5, `admin` to Task 6). The committed list has about 46 operation keys, 223 property keys, 72 schema keys, 20 request keys, about 60 response keys and 31 parameter keys; the exact count is in the commit message.

- [ ] **Step 1: Write both tests with an empty `undocumented`; run them**

Run: `go test ./internal/gen/ -run 'TestSpec(Descriptions|Examples)$' 2>&1 | rg -c 'undocumented:'`
Expected: a number in the hundreds; zero `stale:` lines; `not-a-type`, `no-placeholders`, `no-real-values` green (nothing to find yet); `validates` green.

- [ ] **Step 2: Fill `undocumented` from the output; run again**

Run: `go test ./internal/gen/ -run 'TestSpec(Descriptions|Examples)$'`
Expected: `ok`. Then two negative probes by hand. Probe 1: delete one key from the map, run, see `undocumented: <key>`; restore. Probe 2: add a key for an element that is documented (for example `"tags/admin": "none"`), run, see `stale: tags/admin is documented; remove it from undocumented`; restore. Probe 3: delete the `description` line of `listChannels`' `200` response in the YAML (a documented element, so it has no key), `make generate`, run, see `undocumented: responses/listChannels.200`; restore with `git checkout -- api/openapi.yaml && make generate`. These are the shapes block 39 automates.

- [ ] **Step 3: Commit**

```bash
git add internal/gen/spec_docs_test.go internal/gen/spec_docs_undocumented_test.go
git commit -m "test(gen): TestSpecDescriptions and TestSpecExamples over the embedded document, with the deny-list of what issue #35 still documents"
```

---

### Task 2: Area 1: discovery, health, auth and the shared components

**Files:**
- Modify: `api/openapi.yaml` (operations `wellKnown`, `authorizationServerMetadata`, `openidConfiguration`, `discover`, `health`, `token`, `jwks`, `register`; schemas `WellKnown`, `AuthMethod`, `Discovery`, `AuthorizationServerMetadata`, `Health`, `HealthStore`, `HealthEmbeddings`, `HealthMaintenance`, `HealthJob`, `TokenRequest`, `OAuthError`, `AccessToken`, `JWK`, `JWKS`, `RegisterRequest`, `Registration`, `Problem`; the 12 shared responses and `OAuthError` response; the 5 shared parameters)
- Modify: `internal/gen/spec_docs_undocumented_test.go` (delete this area's keys)
- Regenerate: `internal/gen`

**Sources to check against (the reviewer opens the same):** `internal/server/discovery.go` (the well-known documents, `protocol_version`, the metadata's issuer rule at `:50-76`), `internal/server/health.go` and `internal/core/health` (the three tiers, the 503 rule; `docs/ops/health.md`, ADR 0010), `internal/server/oauth.go` and `internal/server/auth_exchange.go` (the two grants, the RFC 6749 error body, the single-use `jti`: `Tx.PutAssertionJTI`), `internal/server/auth_handlers.go` and `internal/core/identities/register.go` (trust on first use versus enrollment, the `created` flag), `internal/auth/token/issuer.go` (`Mint`, the JWKS members), `internal/server/problem.go` (`Problem` members, `ProblemTypePrefix`, `retryable`), `internal/core/rules/bounds.go` and `store.MaxNameBytes` for the parameter texts (already there from #34; keep them, add the meaning: "The session id from openSession", "The channel name, percent-encoded once", and so on), `internal/server/status_table_test.go` (which code each shared response carries: the texts already name them).

Examples: `Problem` and each shared response (12 media-type examples, one per code; `Forbidden` and `Conflict` and `Gone` carry two codes in their enum: the example uses the first and the description names both, as today); `OAuthError` (`invalid_client`); `WellKnown`, `Discovery` (capabilities as `discover.go` lists them: copy from a live `GET /v1/discover` in a server test log), `AuthorizationServerMetadata` (issuer `http://localhost:8420`, the endpoints under it, `grant_types_supported` as the server emits them), `Health` with its sub-objects (the administrator tier, so every member is present: ruling 1), `TokenRequest` (the `client_credentials` grant with the conventions' assertion: `grant_type`, `client_assertion_type`, `client_assertion` only; ruling 1's request rule), `AccessToken` (`token_type` `Bearer`, `expires_in` 3600), `JWK`, `JWKS`, `RegisterRequest`, `Registration`. Parameter examples: `SessionParam` the session id, `ChannelParam` `release-train`, `ScopeParam` `acme`, `IdParam` `42`, `IdempotencyKeyParam` `6b1f2d4e-0c3a-4f8b-9e7d-example00001` (a UUID-shaped string with `example`; the header is opaque, `rules.MaxTokenBytes`).

- [ ] **Step 1: Delete this area's keys from `undocumented`; run the tests**

Run: `go test ./internal/gen/ -run 'TestSpec(Descriptions|Examples)$' 2>&1 | rg -c 'undocumented:'`
Expected: the number of keys deleted (state it).

- [ ] **Step 2: Write the descriptions and examples; regenerate**

Run: `make generate && go test ./internal/gen/ ./internal/server/ && git diff --stat internal/gen`
Expected: all green (kin validates every new example in `TestDocumentIs31AndValidates` and `TestSpecExamples/validates`; a malformed example fails here with the path); the diff touches `gen.go` comments and `spec/spec.go` only.

- [ ] **Step 3: Vacuum count**

Run: `vacuum spectral-report -r <scratch ruleset of the baseline> -q api/openapi.yaml /tmp/r35.json >/dev/null; jq -r '.[].code' /tmp/r35.json | sort | uniq -c`
Expected: `oas3-missing-example` below 139 by this area's media types, parameters and schemas (state the number); nothing new.

- [ ] **Step 4: Commit**

```bash
git add api/openapi.yaml internal/gen internal/gen/spec_docs_undocumented_test.go
git commit -m "docs(api): descriptions and examples for discovery, health, auth and the shared components (issue #35)"
```

---

### Task 3: Area 2: sessions

**Files:** as Task 2, for operations `openSession`, `closeSession`, `receive`, `watch`, `peek`, `listIdentities`, `setAgentStatus`, `listAgentStatuses`, `agentStatusHistory`; schemas `Wake`, `Peek`, `OfferedCursor`, `OpenSessionRequest`, `RejectedCursor`, `PendingChannel`, `Session`, `ReceiveRequest`, `Gap`, `Message`, `ReceiveResult`, `SessionInfo`, `Identity`, `SetAgentStatusRequest`, `AgentStatus`, `AgentStatusEntry`; the inline parameters of `watch` (`after`, `timeout`, `include_own`), `peek` (`include_own`), `agentStatusHistory` (`identity`); the inline array responses of `listIdentities`, `listAgentStatuses`, `agentStatusHistory`.

**Sources:** `internal/server/sessions.go`, `internal/server/peek.go`, `internal/server/agentstatus.go`; `internal/core/sessions/open.go` (hint, resume, replaced, the cursor offer and rejection reasons, the 32-hex id, the 43-character token), `close.go`, `identities.go`; `internal/core/delivery/receive.go` (ack semantics: the batch token, `AckIgnored`, the gap rows, `count` clamp), `watch.go` (the floor, `after`, `timeout`, `include_own`, the 204, `replaced`), `peek.go`; `internal/core/statuses` and ADR 0014 (the tag vocabulary `rules.CheckStatusTag`, offline derived at read, `status_history_count`); the `Deliver` action of `internal/core/access` (agents never receive memory channels: decision 20); spec section 3 and ADR 0003.

Examples: `OpenSessionRequest` gets media-type `examples` on `openSession` (`default`: `{"hint":"builder","cursors":[{"channel":"release-train","seq":41}]}`; `resume`: `{"resume_token":"<conventions>"}`) and a schema example equal to `default`; `Session` (`resumed: false`, one rejected cursor with the reason the core uses, one pending channel); `ReceiveRequest` (`ack`, `count: 10`, `channels: ["release-train"]`, `include_own: true`: ruling 15; the `watch` and `peek` `include_own` parameter examples are `true` too, `watch` `timeout` `30`, `after` `41`); `ReceiveResult` (one `Message`, the batch token, one `Gap`); `Message` (every member including `reply_to`, `metadata`, `memory_id`, `revision`, `tags`, `matched_tags`); `Wake`, `Peek`, `SessionInfo`, `Identity`, `SetAgentStatusRequest` (`tag: working`, `text`, `problem` present as `""`? No: `problem` is set only with `needs-human`; the schema example uses `tag: needs-human` with a `problem` so every member is present, and the replay row uses the same), `AgentStatus`, `AgentStatusEntry`.

- [ ] **Step 1: Delete this area's keys; run** (as Task 2 Step 1)
- [ ] **Step 2: Write; regenerate; `go test ./internal/gen/ ./internal/server/`** (as Task 2 Step 2)
- [ ] **Step 3: Vacuum count** (as Task 2 Step 3)
- [ ] **Step 4: Commit**

```bash
git add api/openapi.yaml internal/gen internal/gen/spec_docs_undocumented_test.go
git commit -m "docs(api): descriptions and examples for sessions, receive, watch, peek and agent status (issue #35)"
```

---

### Task 4: Area 3: channels and messages

**Files:** as Task 2, for operations `listChannels`, `createChannel`, `deleteChannel`, `renameChannel`, `getACL`, `setACL`, `subscribe`, `unsubscribe`, `listTagSubscriptions`, `subscribeTags`, `unsubscribeTags`, `sendMessage`, `history`, `search`; schemas `Channel`, `ChannelInfo`, `ACLEntry`, `CreateChannelRequest`, `RenameChannelRequest`, `SubscribeRequest`, `TagPatterns`, `SendRequest`, `SendResult`, `SearchHit`, `SearchResult`; inline parameters of `unsubscribeTags` (`pattern`), `history` (`before`, `after`, `count`, `thread`, `tags`), `search` (`q`, `mode`, `channel`, `sender`, `since`, `until`, `thread`, `tags`, `count`, `cursor`); inline responses of `listChannels`, `getACL`, `listTagSubscriptions`, `history`; the inline request body of `setACL`.

**Sources:** `internal/server/channels.go`, `internal/server/messages.go`; `internal/core/channels/channels.go` (kinds, the ACL at creation, the scope rule `TakeName`), `subscriptions.go` (`from` `now`/`oldest`, tag patterns, the empty-channel rule of decision 20 in ADR 0009), `acl.go` in `internal/core/scopes` and `internal/core/access/decide.go` (`Read`, `Write`, `Admin`, `List`, `Unsubscribe`; the three groups `everyone`, `admins`, `humans`; the protected-entry rule), `internal/core/messaging/send.go` (`reply_to` validation and the thread-root rewrite on a bridged channel, `Idempotency-Key`, the inspection step of ADR 0013), `history.go` (`before`/`after` windows, `thread`, `tags`, the count clamp), `internal/core/search` (`mode` values, the cursor's 19 digits, `since`/`until` in Unix ms); ADR 0008, ADR 0009, spec section 3.

Examples: `Channel`/`ChannelInfo` (`capabilities: ["bridged"]` in the schema example since every member is present; the replay's shape check does not require it live), `ACLEntry` and the `setACL` body (`[{"identity":"acme-coder-1","permissions":["read","write","admin"]},{"identity":"everyone","permissions":["read"]}]`: check the permission vocabulary in `internal/bus` first), `CreateChannelRequest` (`name: release-train`, `kind: ordinary`, `acl`, no `scope` in the replayed example; the schema example includes `scope: acme`? No: ruling 7 wants the replay literal; the schema example has no `scope` and the `scope` property's description explains it), `SubscribeRequest` (`from: oldest`), `TagPatterns` (`["deploy-*"]`), `SendRequest` (subject, content, `type: text`? check what `type` the CLI sends by default, `reply_to: 41`? No: the replayed example must succeed on a fresh channel, so `reply_to` is live-substituted (ruling 8) with the seq of a message the row's setup sends first; `metadata: {"build":"42"}`, `tags: ["deploy-prod","build-42"]`, `session` the conventions id, live), `SendResult`, `SearchHit`, `SearchResult` (`hits`, `cursor`). The `listChannels` description carries exactly one citation (block 39 mutation 2 replaces it); the other operations may cite more than one source. Parameter examples: `history` `before: 100`, `after: 0`? The replay sends every documented parameter (ruling 8), so `before` and `after` together must form a sensible window: `after: 40`, `before: 50`, `count: 20`, `thread` live, `tags: ["deploy-prod"]`; `search` `q: "build 42"`, `mode: keyword` (check the enum: the semantic mode needs an embedder the e2e server lacks), `channel: release-train`, `sender: acme-coder-1`, `since: 1794096000000` (2026-11-08), `until: 1825632000000` (2027-11-08): the replay runs inside that window until 2027-11-08 and the row's comment says so (a later run widens the example by a year; the alternative, substituting `until` live, would hide a server-assigned value that is not one). `thread` live, `tags`, `count: 20`, `cursor` omitted from the request? Every documented parameter is sent: the `cursor` example is `0000000000000000041` (19 digits, `rules.MaxSearchCursorLen`) and a cursor past the single hit returns 200 with empty `hits`: acceptable (the shape check passes on an empty array).

- [ ] **Step 1: Delete this area's keys; run**
- [ ] **Step 2: Write; regenerate; test**
- [ ] **Step 3: Vacuum count.** The baseline flagged the three array parameters (`unsubscribeTags` `pattern`, `history` `tags`, `search` `tags`) twice each, on the parameter and on its `schema`. If the count shows the `/schema` finding survives an `example` on the parameter object, add `example` inside those three parameters' `schema` as well (the same value) and say so in the commit; Task 6 expects 0.
- [ ] **Step 4: Commit**

```bash
git add api/openapi.yaml internal/gen internal/gen/spec_docs_undocumented_test.go
git commit -m "docs(api): descriptions and examples for channels, ACLs, subscriptions, send, history and search (issue #35)"
```

---

### Task 5: Area 4: memories and tasks

**Files:** as Task 2, for operations `getMemory`, `deleteMemory`, `listMemoryRevisions`, `editMemory`, `createTask`, `listTasks`, `getTask`, `updateTask`, `claimTask`, `releaseTask`; schemas `EditMemoryRequest`, `EditResult`, `Task`, `TaskSummary`, `TaskCreateRequest`, `TaskPatch`, `TaskUpdateResult`, `ClaimTaskRequest`; inline parameters of `listTasks` (`status`, `owner`); inline responses of `listMemoryRevisions`, `listTasks`.

**Sources:** `internal/server/memories.go`, `internal/server/tasks.go`; `internal/core/memories/memories.go` (a memory is a message on a memory channel: the id, `if_revision`, the conflict, the delete rule, revisions), `internal/core/tasks/create.go`, `read.go`, `update.go` (the transition rules at `:130-181`: `completed` to `in_progress` needs `pending` first, an `in_progress` task needs an owner, the blocker rule at `:21`), `reclaim.go` (`reclaimed_from`, `reclaimed_at`: ADR 0009 decisions of 2026-11-05), `doc.go` (subject and description bounds), the `claim`/`release` functions (`:422`: release is an update to `pending` with no owner and `leased_until` zero); ADR 0009, spec section 3.

Examples: `EditMemoryRequest` (`if_revision: 1`, live), `EditResult`, `Task` (every member: `id`, `channel`, `subject`, `description`, `status`, `owner`, `leased_until`, `blocked_by`, `parent`, `before`/`after` if present, `metadata`, `reclaimed_from`, `reclaimed_at`, timestamps: copy the member list from the schema), `TaskSummary`, `TaskCreateRequest` (`subject`, `description`, `metadata`; `blocked_by: []`? Every member present: `blocked_by: [41]` would need task 41 to exist and be in the channel; the schema example has `blocked_by` and `parent`, the replay row substitutes both live with the id of a task the setup creates first (ruling 8)), `TaskPatch` (the replayed example is `{"status":"completed","metadata":{"release":"2026.11"}}` after `claimTask`: the transition `in_progress` to `completed` by the owner), `ClaimTaskRequest` (`leased_until` live), `TaskUpdateResult`.

- [ ] **Step 1: Delete this area's keys; run**
- [ ] **Step 2: Write; regenerate; test**
- [ ] **Step 3: Vacuum count**
- [ ] **Step 4: Commit**

```bash
git add api/openapi.yaml internal/gen internal/gen/spec_docs_undocumented_test.go
git commit -m "docs(api): descriptions and examples for memories and tasks (issue #35)"
```

---

### Task 6: Area 5: admin; the deny-list is deleted

**Files:** as Task 2, for operations `adminStatus`, `adminUsage`, `adminReset`, `resetCredential`, `listSigningKeys`, `rotateSigningKey`, `createIdentityByEmail`, `createAgentIdentity`, `createScope`, `listScopes`, `getScope`, `doneScope`, `createBridge`, `listBridges`, `getBridge`, `removeBridge`; schemas `Notice`, `Status`, `Usage`, `CreateIdentityByEmailRequest`, `HumanIdentity`, `CredentialReset`, `SigningKey`, `SigningKeyList`, `SigningKeyRotation`, `CreateAgentIdentityRequest`, `AgentIdentity`, `CreateScopeRequest`, `DoneScopeRequest`, `Scope`, `ScopeList`, `CreateBridgeRequest`, `Bridge`, `BridgeNotInvited`, `BridgeCreated`, `BridgeList`; inline parameters of `adminReset` (`scope`), `resetCredential` (`identity`), `rotateSigningKey` (`revoke_previous`).
- Delete: `internal/gen/spec_docs_undocumented_test.go`; remove the `undocumented` lookups from `spec_docs_test.go` (the tests fail on any undocumented element from now on).

**Sources:** `internal/server/admin.go`, `admin_auth.go` (`AdminReset`: `data` keeps identities and keys, `everything` removes them: Decision 48), `admin_usage.go`, `signing_keys.go`, `scopes.go`, `bridges.go`; `internal/core/identities/admin.go` (`ResetCredentialAs`, `Reset`), `agent.go`, `email.go`, `human.go`; `internal/core/scopes` (`service.go`, `retire.go`: `with_bridge` versus `normal`, a scope with a live bridge and no `Archiver` is held), `internal/core/signingkeys` (`PrepareRotation`/`ApplyRotation`, `ErrCooldown`, `ErrRotateNoChange`, states `active`/`retiring`, `revoke_previous` skips the cooldown), `internal/slackbridge` (create, the invitation, `BridgeNotInvited`), `internal/core/health`/`usage` for `Usage` and `Notice`; ADR 0009, ADR 0011, ADR 0012, spec 3.2.

Examples: `Status`, `Usage`, `Notice` (the tiers as `usage.go` names them), `HumanIdentity`, `CredentialReset`, `SigningKey` (`kid`, `algorithm`, `state`, timestamps; never a private member: `listSigningKeys` says so), `SigningKeyList`, `SigningKeyRotation`, `CreateAgentIdentityRequest` (`name: acme-builder`, `scope: acme`), `AgentIdentity` (with the one-time enrollment token of the conventions), `CreateScopeRequest`, `Scope`, `ScopeList`, `DoneScopeRequest` (`retire: normal`), `CreateBridgeRequest` (`channel: acme-ops`, `slack_name: acme-ops`), `Bridge`, `BridgeCreated` (the bridge and the `not_invited` list: every member), `BridgeNotInvited`, `BridgeList`.

- [ ] **Step 1: Delete this area's keys; run** (the map is now empty)
- [ ] **Step 2: Write; regenerate; test**
- [ ] **Step 3: Delete the deny-list file and the lookups; run the two tests**

Run: `go test ./internal/gen/ -run 'TestSpec(Descriptions|Examples)$' -v 2>&1 | rg -c '^\s+--- PASS'`
Expected: `ok`; the counts subtest reports 57, 9, 72, 320.

- [ ] **Step 4: Vacuum count**

Run: as Task 2 Step 3.
Expected: `oas3-missing-example` 0; only `description-duplication` (a higher number than 70: state it) and `oas3-api-servers` 1 remain.

- [ ] **Step 5: Commit**

```bash
git add api/openapi.yaml internal/gen internal/gen/spec_docs_test.go
git rm internal/gen/spec_docs_undocumented_test.go
git commit -m "docs(api): descriptions and examples for the admin operations; the deny-list is gone (issue #35)"
```

---

### Task 7: `bearerAuth`, `servers`, the ruleset

**Files:**
- Modify: `api/openapi.yaml` (`servers` after `info`; `components.securitySchemes.bearerAuth.description`)
- Modify: `api/vacuum-ruleset.yaml` (remove `oas3-missing-example: off` and `oas3-api-servers: off`; reword `info-contact`, `info-license` and `description-duplication` reasons per ruling 6; the header comment says five rules are off)
- Regenerate: `internal/gen`

- [ ] **Step 1: `servers`**

```yaml
servers:
  - url: http://localhost:8420
    description: "A placeholder: deployments vary (Eric, 2026-11-06). A client takes the base URL from its profile; the server's own listener is -listen."
```

Run: `make generate && go test ./internal/gen/ ./internal/server/`
Expected: green (the probe of the baseline; `server.Spec()` clears `Servers`).

- [ ] **Step 2: `bearerAuth` (ruling 12)**

Read `internal/auth/token/issuer.go:279-400` first (`Mint`, `Verify`, `isAccessTokenType`) and `docs/adr/0002-authentication-and-credentials.md` item 8.4. Write the description: an RFC 9068 access token (`typ` `at+jwt`) minted by this server at `POST /v1/auth/token`, by the RFC 7523 `private_key_jwt` client credentials grant (an agent signs a client assertion with its registered key; `iss` and `sub` the identity, `aud` the issuer URL of `/.well-known/oauth-authorization-server`; single use by `jti`) or the RFC 8693 exchange of a configured issuer's token (a human); `iss` and `aud` the issuer URL; lifetime `token_lifetime_seconds` (default 3600, at most 86400; a human's `human_token_lifetime_seconds`, default 900); verified per RFC 8725: `alg` in `EdDSA`, `ES256` (no other algorithm, never `none`), `typ` checked, the key by `kid` from `GET /v1/auth/jwks`, `exp` required; sent as `Authorization: Bearer <token>`; a missing, malformed or expired token answers 401 `unauthenticated`. Every clause is one the implementer found in `Verify`, `Mint` or the config (`config.go:17-21, 123, 419-420`); the commit message lists the lines.

Run: `make generate && go test ./internal/gen/`
Expected: green; `TestSpecExamples/no-real-values` still green (the description is not an example, but the test's string scan may cover descriptions too: if it does, `localhost` is allowed).

- [ ] **Step 3: The ruleset; `make spec-lint`**

Run: `make spec-lint`
Expected: exit 0, `0 errors, 0 warnings and 0 informs` (or vacuum's equivalent line). Negative probe by hand: remove one schema's `example`, `make spec-lint` fails with `oas3-missing-example`; restore.

- [ ] **Step 4: Commit**

```bash
git add api/openapi.yaml api/vacuum-ruleset.yaml internal/gen
git commit -m "docs(api): bearerAuth describes the token, servers names the placeholder, the ruleset turns the example and servers rules on (issue #35)"
```

---

### Task 8: `TestRequestExamples`: the replay

**Files:**
- Create: `internal/e2e/zz_examples_test.go` (`//go:build !windows`; the file comment explains the name: ruling 10)

**Design** (rulings 7 to 10): the test loads `server.Spec()` (the embedded document), builds `rows` (the slice below), checks coverage both ways, then runs the rows in order as subtests named `<op>` or `<op>/<example>`; a failure ends the sequence (`t.FailNow`, as `wfRunner.run` does) because later rows depend on earlier state. Helpers: `effectiveExample(mt *openapi3.MediaType, name string) any`, `buildRequest(op, row, state) *http.Request` (path parameters from their examples percent-encoded once, query parameters from their examples serialized in the parameter's style, `Idempotency-Key` from its example with the `-<row>` suffix where the operation takes it (ruling 14), `Authorization` from the state's bearer except for the open operations, the body as JSON or form from the effective request example, then the `live` substitutions by pointer), `shapeCheck(t, live, example any, path string)` (ruling 9), `signAssertion(identity, audience)` (reuse `wfRunner.register`'s key and `assertion.Sign` code: move the key and JWK part into a shared helper `freshKeyJWK(t)` in `workflows_test.go` if that keeps both files short).

State: `bearer`, `sessionID`, `resumeToken`, `ack`, `seqs` (`first`, `reply`, `memory`, `task`, `blocker`), `memoryRevision`, `kid`.

**The rows (58), in replay order.** Fixture `fx` unless marked `slackFx`. `live` lists the substituted pointers; `setup` what runs first; `status` the documented 2xx.

| # | Operation (example) | status | setup; live |
|---|---|---|---|
| 1 | `wellKnown` | 200 | none |
| 2 | `authorizationServerMetadata` | 200 | none |
| 3 | `openidConfiguration` | 200 | none |
| 4 | `discover` | 200 | none |
| 5 | `jwks` | 200 | none |
| 6 | `health` | 200 | no bearer (the probe tier) |
| 7 | `register` | 201 | setup: fresh EdDSA key, `enrollment create` host command; live `/body/public_key_jwk`, `/body/enrollment_token` |
| 8 | `token` | 200 | live `/body/client_assertion` (signed for `fx.serverURL()`); then the host command `admins add -identity acme-coder-1`; state `bearer` |
| 9 | `createScope` | 200 | none (`acme`) |
| 10 | `createAgentIdentity` | 200 | none (`acme-builder` in `acme`) |
| 11 | `listScopes` | 200 | none |
| 12 | `getScope` | 200 | none (`acme`) |
| 13 | `createIdentityByEmail` | 200 | none (`dana@example.com`) |
| 14 | `resetCredential` | 200 | none (path `acme-builder`); confirm first that `ResetCredentialAs` (`internal/core/identities/admin.go:115`, `TestResetCredential`) answers 200 for an identity that never registered a key; else the row's setup registers `acme-builder` with the enrollment token row 10 returned |
| 15 | `createChannel` | 201 | none (`release-train`) |
| 16 | `listChannels` | 200 | none |
| 17 | `setACL` | 204 | none |
| 18 | `getACL` | 200 | none |
| 19 | `subscribe` | 204 | none (`release-train`, `from: oldest`) |
| 20 | `subscribeTags` | 204 | none (`deploy-*`) |
| 21 | `listTagSubscriptions` | 200 | none |
| 22 | `openSession` (`default`) | 201 | none; state `sessionID`, `resumeToken` |
| 23 | `openSession` (`resume`) | 201 | live `/body/resume_token`; state updated |
| 24 | `sendMessage` | 201 | setup: send one plain message to `release-train` (state `seqs.reply`); live `/body/reply_to`, `/body/session` |
| 25 | `peek` | 200 | live `/path/session` |
| 26 | `watch` | 200 | live `/path/session`, `/query/after` (the seq before `seqs.reply`); two messages the session itself sent are pending and `include_own` is `true` (ruling 15), so the wake is immediate (confirm the floor rule in `delivery/watch.go:28-60, 114` while writing) |
| 27 | `receive` | 200 | setup: one receive with no ack and `include_own: true` to obtain a batch token (state `ack`); live `/path/session`, `/body/ack` |
| 28 | `setAgentStatus` | 200 | live `/path/session` |
| 29 | `listAgentStatuses` | 200 | none |
| 30 | `agentStatusHistory` | 200 | none (path `acme-coder-1`) |
| 31 | `listIdentities` | 200 | none |
| 32 | `history` | 200 | live `/query/thread` (`seqs.reply`); `after`/`before`/`count`/`tags` literal |
| 33 | `search` | 200 | live `/query/thread`; the rest literal (the `until` window note of Task 4) |
| (setup, not a row) | before row 34: `createChannel` `release-notes` (kind `memory`) by hand plus one `sendMessage` to it (state `seqs.memory`, `memoryRevision`) | | |
| 34 | `getMemory` | 200 | live `/path/id` |
| 35 | `editMemory` | 201 | live `/path/id`, `/body/if_revision` |
| 36 | `listMemoryRevisions` | 200 | live `/path/id` |
| 37 | `deleteMemory` | 204 | live `/path/id` |
| 38 | `createTask` | 201 | setup: one plain `createTask` in `release-train` (state `seqs.blocker`), completed by hand so the blocker rule (`update.go:21`) does not hold the example task; live `/body/blocked_by/0`, `/body/parent`; state `seqs.task` |
| 39 | `claimTask` | 200 | live `/path/id`, `/body/leased_until` (now + 1 h) |
| 40 | `listTasks` | 200 | none (`status: in_progress`, `owner: acme-coder-1`) |
| 41 | `getTask` | 200 | live `/path/id` |
| 42 | `releaseTask` | 200 | live `/path/id` |
| 43 | `updateTask` | 200 | setup: claim again by hand (the example patch completes an owned task); live `/path/id` |
| 44 | `unsubscribeTags` | 204 | none (`pattern: deploy-*`) |
| 45 | `unsubscribe` | 204 | none (`release-train`) |
| 46 | `renameChannel` | 204 | none (`release-train` to `release-train-archive`) |
| 47 | `deleteChannel` | 204 | path is `release-train-archive`: the `ChannelParam` example is `release-train`, so this row substitutes `/path/channel` (the one literal-name substitution; stated in the row's comment) |
| 48 | `closeSession` | 204 | live `/path/session` |
| 49 | `adminStatus` | 200 | none |
| 50 | `adminUsage` | 200 | none |
| 51 | `listSigningKeys` | 200 | none |
| 52 | `rotateSigningKey` | 200 | setup: `time.Sleep(1100 * time.Millisecond)` (the fixture's cooldown; `TestArazzoWorkflows` rotated earlier); `revoke_previous: false` so the bearer stays valid |
| 53 | `doneScope` | 200 | none (`acme`, `retire: normal`) |
| 54 | `createBridge` (`slackFx`) | 200 | setup on fixture 2: register `acme-coder-1` with a fresh key and `slackFx.token(t)`, mint a bearer, `admins add` on `slackFx.sqlite`, `createScope acme`, `createIdentityByEmail dana@example.com`, `slackFx.fake.AddUser` with that email, `createChannel acme-ops` in scope `acme` with a named-only ACL (as the Arazzo `bridges` workflow does); live none |
| 55 | `listBridges` (`slackFx`) | 200 | none |
| 56 | `getBridge` (`slackFx`) | 200 | none (path `acme-ops`: the `ChannelParam` example is `release-train`, so `/path/channel` is substituted: the second literal-name substitution) |
| 57 | `removeBridge` (`slackFx`) | 204 | same substitution |
| 58 | `adminReset` | 204 | last on `fx`; `scope: data` |

The table has 58 rows: 57 operations plus `openSession/resume`; the memory setup line is not a row.

- [ ] **Step 1: Write the coverage subtest first; run**

Run: `go test ./internal/e2e/ -run 'TestRequestExamples$' -v 2>&1 | rg 'coverage|FAIL' | head`
Expected: `coverage` fails naming the 58 missing rows (an empty table).

- [ ] **Step 2: Write the helpers and the rows; run**

Run: `go test ./internal/e2e/ -run 'TestRequestExamples$' -v 2>&1 | tee /tmp/examples-35.log | rg -c '^\s+--- PASS'`
Expected: 58 passing subtests plus `coverage`; `runMain`'s final checks green (no response-validation failure, no unrouted response). Then the whole package once: `go test ./internal/e2e/` green (about 40 s).

- [ ] **Step 3: Two negative probes by hand** (the ones block 39 automates): change `Session`'s example member `resumed` to `"resumed_at"` in the YAML, `make generate`, run: `openSession/default` fails with `member resumed of the live body is not in the example`; restore. Add a `live` pointer `/body/nope` to row 24, run: fails with `live pointer /body/nope is not in the example of sendMessage`; restore.

- [ ] **Step 4: Commit**

```bash
git add internal/e2e/zz_examples_test.go internal/e2e/workflows_test.go
git commit -m "test(e2e): TestRequestExamples replays every request example of the document and checks the answer against the documented response (issue #35)"
```

---

### Task 9: Selftest block 39

**Files:**
- Modify: `scripts/check-gates-selftest.sh` (`block_spec_examples_fire` after `block_spec_validation_fires` in the function definitions and the call list; the header comment names issue #35 and the three tests)

Mutations (9; anchors are written against the file after Task 7 and must occur once in their scope; the schema examples are written as YAML block mappings with `example:` as the first key of the schema, per the conventions table):
1. `operation-description-removed`: `mutate_spec_block` scope `operationId: listChannels`, from the whole `      description: "..."` line of `listChannels` (copy it from the file) to `` → `./internal/gen/ '^TestSpecDescriptions$' TestSpecDescriptions/operations/listChannels`, extra `undocumented: operations/listChannels`.
2. `citation-removed`: same scope, the description's one citation (Task 4 makes `listChannels` carry exactly one: `spec 3.N`, `ADR 0008` or `Decision NN`) replaced by `the design` → `TestSpecDescriptions/operations/listChannels/cites-source`.
3. `property-description-removed`: scope `    SendRequest:`, the `subject` property's `description:` line → `` → `TestSpecDescriptions/properties/SendRequest.subject`, extra `undocumented: properties/SendRequest.subject`.
4. `schema-example-removed`: scope `    Session:`, `      example:` → `      x-example-removed:` (the block becomes an unknown extension; the YAML stays valid) → `./internal/gen/ '^TestSpecExamples$' TestSpecExamples/schemas/Session`, extra `undocumented: schemas/Session`. The same run also fails `TestSpecExamples/responses/openSession.201` (the inherited example is gone); the block does not assert it (one `extra` per mutation).
5. `spec-lint-example-fires`: `mutate_lint_block api/openapi.yaml` with the two-line anchor `$'    Session:\n      example:'` → `$'    Session:\n      x-example-removed:'` → `oas3-missing-example`.
6. `example-invalid`: scope `    Session:`, the example's `resumed: false` line → `resumed: "no"` → `./internal/gen/ '^TestDocumentIs31AndValidates$' TestDocumentIs31AndValidates` (kin's example validation; `TestSpecExamples/validates` fails too).
7. `real-host-in-example`: scope `    AuthorizationServerMetadata:`, the example's whole `        issuer: http://localhost:8420` line (the URL alone occurs again in the endpoint members of the same example; the `issuer:` line is unique in the scope) → `        issuer: https://mesh.corp.internal` → `TestSpecExamples/no-real-values`.
8. `replay-shape-fires`: `mutate_spec_block` scope `    Task:`, the example's `parent:` line removed (`parent` is optional in `Task`, so kin still accepts the example; row 38 sets `parent` live, so the live `Task` carries it) → `./internal/e2e/ '^TestRequestExamples$' TestRequestExamples/createTask`, extra `member parent of the live body is not in the example`. The implementer confirms during Step 1 that `parent` is not in `Task.required` and that the live `createTask` answer echoes it (else the member is `Message.metadata` through `getMemory`, with the setup message carrying metadata) and records the choice in the block's comment. This mutation runs the e2e package (about 40 s, no Docker).
9. `replay-row-missing`: `mutate_unit_block internal/e2e/zz_examples_test.go`, the `{op: "peek",` row line → removed → `./internal/e2e/ '^TestRequestExamples$' TestRequestExamples/coverage`, extra `no row for peek`.

- [ ] **Step 1: Add the block; run it alone**

The script has no single-block switch. Run: `make check-gates-selftest 2>&1 | tee /tmp/selftest-35-dev.log | rg 'selftest: (ok|problem)' | tail -12`
Expected: nine `selftest: ok <label>` lines for the block 39 labels and no `problem` line; `shellcheck scripts/check-gates-selftest.sh` clean.

- [ ] **Step 2: Commit**

```bash
git add scripts/check-gates-selftest.sh
git commit -m "test(gates): selftest block 39, the spec description, example and replay checks fire (issue #35)"
```

---

### Task 10: Docs

**Files:**
- Modify: `CLAUDE.md` (one Design bullet after the "Request bounds" bullet)
- Modify: `docs/adr/0001-transport-and-api.md` (a "Spec examples and descriptions addendum (issue #35)" after the spec validation addendum)

CLAUDE.md bullet (terse, in the style of the #32 and #34 bullets): "Spec examples and descriptions (issue #35; Eric 2026-11-06: no `contact` or `license` in `info`, `servers` is the placeholder `http://localhost:8420`): every operation description has behavior, access, side effects, idempotency and a source citation; every tag, parameter, schema, property (`$ref` members inherit), response and request body has a description; every component schema, inline media type and parameter has an example (a `$ref` media type inherits the schema's); `TestSpecDescriptions` and `TestSpecExamples` (`internal/gen/spec_docs_test.go`) fail on an undocumented element, a placeholder or a real host; kin validates every example (`TestDocumentIs31AndValidates`); `TestRequestExamples` (`internal/e2e/zz_examples_test.go`, the package's last file) replays every request example of the 57 operations (58 rows: `openSession` has `default` and `resume`) against the two fixtures with server-assigned values substituted by pointer and checks status, schema (the proxy) and shape; `oas3-missing-example` and `oas3-api-servers` are on in `api/vacuum-ruleset.yaml` (five rules off). Mutations: `scripts/check-gates-selftest.sh` block 39."

ADR addendum: Eric's decisions (the two of 2026-11-06, labeled), then "Where things live", then "Plan rulings (2026-11-07; Eric may overrule; not his decisions)" listing rulings 1 to 15 of this plan in one line each, the three Open for Eric items, and the mutation count.

- [ ] **Step 1: Write both; check every claim against the files** (counts from the tests' output, file names from the tree)
- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md docs/adr/0001-transport-and-api.md
git commit -m "docs: CLAUDE.md and ADR 0001 record the spec examples and descriptions (issue #35)"
```

---

### Task 11: Done gate

- [ ] **Step 1: `make verify`**

Run: `make verify 2>&1 | tee /tmp/verify-35.log | tail -15`
Expected: every step passes, `spec-lint` included with the example rule on, the Postgres suites included (a skip is not a pass); `check-gates` green.

- [ ] **Step 2: `make check-gates-selftest`**

Run: `make check-gates-selftest 2>&1 | tee /tmp/selftest-35.log | rg -c 'selftest: ok'`
Expected: the previous count plus 9; no `selftest: problem` line.

- [ ] **Step 3: Report**

Show both tails, the final vacuum count table (every rule 0 except `description-duplication`, which is off), the counts the tests pin (57, 9, 72, 320, 58 rows), and the three Open for Eric items. Nothing is pushed.

## What Eric should see

1. Ruling 1: examples live on the schemas and are inherited by `$ref` media types; only inline media types and parameters carry their own.
2. Ruling 6: `description-duplication` stays off (Open item 1).
3. Ruling 7: the replay registers the example identity `acme-coder-1` and makes it an administrator; no refusal path is replayed (Open item 3).
4. Ruling 10: the replay file is named `zz_examples_test.go` to run last, because `adminReset` wipes the bus data and the rotation has a cooldown.
5. Ruling 12: `bearerAuth` claims only what `Issuer.Verify` enforces, with RFC 8725 cited for the algorithm allowlist, `typ` and audience.
6. Open item 2: no RFC 8693 `token` example in this issue.
7. Rulings 14 and 15: the replay suffixes `Idempotency-Key` per row (receipts are keyed per identity and key), and the `include_own` examples are `true` so one identity's replay wakes and receives.
