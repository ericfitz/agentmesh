# Issue 33: Declared Error Responses Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every operation of `api/openapi.yaml` declares exactly the error responses the server can give it, through one shared `components/responses` entry per status, each narrowing `Problem.code` to the codes that status carries; `default` is gone and 500 is explicit; every 429 carries `Retry-After`; and three checks keep the code and the spec aligned: a code-to-status table test, a per-operation literal table test, and test-only runtime response validation (`internal/respcheck`) wired into the inproc conformance suite, `TestAuthEndToEnd`, the `internal/server` tests and the e2e suite. Each check has a mutation in `scripts/check-gates-selftest.sh`.

**Architecture:** The server keeps Choice 4 of ADR 0001 (handlers return `nil, err`; one hook writes the problem) and one Go `Problem` type; the narrowing lives in the spec only (`allOf` + `x-go-type: Problem`, ruling 4). The remote client stops reading the generated `ApplicationproblemJSONDefault` member and decodes the problem body at any non-2xx status (`errorOf` already has that path), so the generator's per-status response members are unused plumbing on both sides. `Retry-After` is computed once, by the limiter (`core.Limiter.Check` returns the wait) or by Slack (`slackapi.RateLimitedError.RetryAfter`), carried on `bus.Error.RetryAfter` and written by `responseError`. Response validation is `openapi3filter.ValidateResponse` with `IncludeResponseStatus: true` over the embedded document, as an `http.RoundTripper` wrapper (inproc, TCP clients) and an `httputil.ReverseProxy` (the e2e CLI processes); production code never links it (an m4 import rule).

**Tech Stack:** Go (`CGO_ENABLED=0`), oapi-codegen v2.8.0 output in `internal/gen` (never edited by hand), kin-openapi v0.151.0 (`openapi3filter`, `routers/gorillamux`; `github.com/gorilla/mux v1.8.1` is already an indirect dependency through `nethttp-middleware`, `go.mod:105`, so R1 adds no module), `go/ast` in tests, bash gate scripts (`set -euo pipefail`, shellcheck-clean).

**Spec:** GitHub issue #33 (the body and Eric's decisions of 2026-11-06, mirrored in the controller brief), issue #32's decision 1 (response validation in the test suites only), ADR 0001 items 11 and 12 and choices 3, 4 and 13, ADR 0007 need 2, ADR 0010 decisions 2, 3 and 11, ADR 0013 open note 5, the issue #29 plan (`docs/superpowers/plans/2026-11-06-issue-29-protocol-drift.md`) for the literal-table style. Checked on `53da05b`: 57 operations, every one `default: $ref: "#/components/responses/Problem"` but `token` (200, 400, 401, 500, 503 as `OAuthError`) and `watch` (an inline 409 `Problem`); `StatusFor` (`internal/server/problem.go:19-45`) maps the 13 codes; `limitBody` (`internal/server/server.go:160-186`) answers 413 with code `validation` and the token path's 413 as `OAuthError`; six `rate_limited` sites (`internal/core/messaging/send.go:138`, `internal/core/memories/memories.go:140,314`, `internal/core/tasks/service.go:43`, `internal/core/statuses/statuses.go:63`, `internal/slackbridge/service.go:203`); `GetApplicationproblemJSONDefault()` is read by `internal/bus/remote` (43 sites plus `remote_test.go:55`) and by `internal/server` tests (16 sites).

## Global Constraints

- **Eric's decisions (2026-11-06, issue #33), binding:** (1) every 429 `rate_limited` answer carries `Retry-After`, whole seconds rounded up, taken from the limiter's known wait; the shared 429 response declares the header. (2) `default` is removed from every operation and 500 is declared explicitly beside the other error responses; the spec is exhaustive, so response validation fails on any undeclared status. (3) `Problem.code` is narrowed per shared response in the spec only; Go keeps the single `Problem` type.
- **Controller rulings, binding:** R1: this issue builds the test-only runtime response validation as a reusable helper (`internal/respcheck`, Task 7) over `openapi3filter.ValidateResponse` against the embedded spec, wired into the e2e and inproc conformance paths (Task 8); #32 reuses it and does not rebuild it; production code never validates responses (the m4 rule of Task 7 proves the two binaries do not link it). R2: the protocol version stays `1.0.0` (`info.version` and `version.Protocol` untouched; the spec changes here are documentation of existing behavior plus one enum value, which the pre-release rule of CLAUDE.md allows without a bump). R3: the generator limitation is real (ruling 4 below holds the evidence) and the plan picks the closest approach without asking.
- Issue #32 decision 1 (2026-11-06): response validation runs in the test suites only, never in the production server. The `vacuum` target and the Arazzo runner are #32's and are not touched here.
- Decision 47 stands: `internal/bus/remote` wraps the generated client and never imports kin-openapi, `internal/server` or `internal/core` (`scripts/m4-exit-checks.sh`); consumers see `bus.Error` only. The new `bus.Error.RetryAfter` member is `json:"-"`, so `Error()` (the CLI's `agentmesh: <code>: <message>` and the MCP tool text) does not change.
- Never edit `internal/gen` by hand: every spec change is followed by `make generate` in the same task, and a selftest mutation of `api/openapi.yaml` regenerates inside the throwaway worktree (`mutate_spec_block`, Task 9) before running the test, because the tests read the embedded document (`spec.GetSpec()` through `server.Spec()`), never the YAML file.
- Each task leaves the tree compiling and its named tests green; the inproc conformance suite (`AGENTMESH_BUS_TRANSPORT=inproc go test -count=1 ./internal/conformance/bus/`) is the regression net for Tasks 2 to 5 and 8. The removal of `default` is split so no commit is red: client off the Default member (Task 2), server tests off it (Task 3), then the spec (Task 5).
- Until the first release (Eric, 2026-10-25): no compatibility shims. The wire bytes of every existing answer do not change except for the new `Retry-After` header on 429 and the new `payload_too_large` code on 413 (ruling 1).
- `TestAccessRuleSites` (`internal/core/access/sites_test.go`) is not touched: no task reads `Admin`, `Creator`, `Owner`, `Scope` or a `Kind` outside `access`.
- `TestWireRoundTrip` (`internal/server/wire_roundtrip_test.go`) and `TestToolCoverage` (`internal/mcpserver/coverage_test.go`) stay green: the only change is `plumbingPatterns` gaining `{Suffix: "Headers"}` (Task 5) for the generated `<Op>Response429Headers` and `TooManyRequestsResponseHeaders` structs; `gen.Problem` stays in `exceptions` with its reason updated to name the new reader (`errorOf` over the body).
- American English everywhere. Work lands on the branch `issue-33-error-responses`, one commit per task in the `type(scope): subject` style, ending with the two attribution lines the session reminder gives. No task pushes.
- Done gate: `make verify` (needs Docker; a run that skips the Postgres suites is not a pass) and `make check-gates-selftest`, then `ci.yml` (every job, `release-check`, `gates-selftest` and `release-lint` included) and `windows.yml` green on the pushed commit. Task 11 runs the two make targets and shows their output.
- Shell: the gate scripts stay `set -euo pipefail`, shellcheck-clean (`make release-lint`), with the `deps_violation=<pkg> imports <imp>` output contract.

## Rulings made by this plan (Eric may overrule)

1. **413 gets its own code, `payload_too_large`.** The acceptance criterion wants every code mapped to exactly one status in `StatusFor` and in the shared responses, and the server already answers 413 (`limitBody`, `internal/server/server.go:177`) with code `validation`, which would be `validation`'s second status. The plan adds `bus.CodePayloadTooLarge = "payload_too_large"` (not retryable; precedent: ADR 0013 added `inspection_rejected`), `StatusFor` maps it to 413, `limitBody` sends it, and the spec enum gains it (14 codes). Alternative, one-line to switch to: keep `validation` on 413 and have `TestStatusTable` carry 413 as the one documented second status of `validation`; rejected because it weakens the bijection the issue asks for. The issue's list of statuses (400, 401, 403, 404, 409, 410, 422, 429, 500, 503) omits 413 because the vacuum rules do not look for it; the server sends it, so it is declared.
2. **Where 413 is declared:** on every operation with a `requestBody` (20 operations: `openSession`, `receive`, `setAgentStatus`, `createChannel`, `renameChannel`, `setACL`, `subscribe`, `subscribeTags`, `sendMessage`, `editMemory`, `createTask`, `updateTask`, `claimTask`, `register`, `createIdentityByEmail`, `createAgentIdentity`, `createScope`, `doneScope`, `createBridge`, and `token` as `OAuthError`). `limitBody` runs before routing and reads any body regardless of method, so a body sent to a bodiless operation can also be refused; that is outside the contract and the spec says so in the 413 response description. No test sends a body to a bodiless operation.
3. **400 and 500 on every operation.** 500: Eric's decision 2. 400: `limitBody` answers 400 to a body it cannot read on any path (`server.go:169`), and the validator, the mux binder and the strict decoder answer 400 on every operation with a parameter or body; so `validation` is in every operation's set, the four discovery operations included.
4. **Narrowing shape (R3).** Evidence from a spike with the pinned generator (`go tool oapi-codegen` v2.8.0 on a three-response spec, scratchpad, 2026-11-07): an `allOf` of `$ref: Problem` plus `{properties: {code: {enum: [...]}}}` with no extension generates a fresh struct per response whose `Code` is `interface{}` (`type NotFound struct { Code interface{} ... }`), that is, a second Go type and a lost enum; the same `allOf` with `x-go-type: Problem` beside it generates `type NotFound = Problem`, an alias, both as a named schema and inline under the response's `application/problem+json` schema. kin-openapi ignores `x-go-type` and validates the `allOf`, so validators see the narrowed enum. The plan uses the inline form on each shared response (no extra named schemas):

   ```yaml
   NotFound:
     description: "The named channel, session, memory, task, scope, bridge or identity does not exist, or is outside the caller's scope. code: not_found."
     content:
       application/problem+json:
         schema:
           x-go-type: Problem
           allOf:
             - $ref: "#/components/schemas/Problem"
             - type: object
               properties:
                 code:
                   enum: [not_found]
   ```

   Cost, stated once: the strict server generates one `<Op><Status>ApplicationProblemPlusJSONResponse` type per operation and status (about 400 types) plus the response aliases; nothing uses them (handlers keep returning `nil, err`), `plumbingPatterns` already excludes `*Response` names, and `gen.go` grows by roughly a third.
5. **Response names** (`components/responses`, generated as aliases of `gen.Problem`, none clashing with an existing `gen` type): `BadRequest` (400: `validation`), `Unauthorized` (401: `unauthenticated`), `Forbidden` (403: `forbidden`, `not_registered`), `NotFound` (404: `not_found`), `Conflict` (409: `conflict`, `replaced`), `Gone` (410: `session_lapsed`, `session_closed`), `PayloadTooLarge` (413: `payload_too_large`), `UnprocessableEntity` (422: `inspection_rejected`), `TooManyRequests` (429: `rate_limited`, header `Retry-After`), `InternalServerError` (500: `internal`), `ServiceUnavailable` (503: `unavailable`). The old `Problem` response component is deleted (nothing references it afterwards); `OAuthError` stays and `token` adds a 413 `OAuthError`. `watch`'s inline 409 becomes the shared `Conflict` (its enum carries `replaced`).
6. **The client decodes the body at any status and reads `Retry-After`.** `remote.mtResponse` drops `GetApplicationproblemJSONDefault()`; `errorOf` takes the response header instead of a parsed problem, decodes the body as `gen.Problem` when it carries a `code`, and sets `bus.Error.RetryAfter` from `Retry-After` (integer seconds) on a 429. `TestSendRateLimited` asserts `RetryAfter > 0` on both transports, so the header is proved end to end over inproc.
7. **The limiter returns the wait.** `Limiter.Check(identity, n, now)` returns `(ok bool, wait time.Duration)`; when refused, `wait` is the larger of the count deficit `(1 - count) / perSec` and the bytes deficit `(n - bytes) / bytesSec`, computed under the lock from the same bucket. `core.RateLimited(wait, format, args...)` is the one constructor of a `rate_limited` error (`TestRateLimitedSites` refuses any other construction in the module); the bridge passes Slack's `rl.RetryAfter`. The server writes `Retry-After: max(1, ceil(wait.Seconds()))`. Configuration bounds (`docs/ops/configuration.md:71-72`: 1 to 10000 messages per second, 64 to 65536 KiB per second) keep both rates positive, so the wait is finite.
8. **`internal/respcheck`** is a non-test package (so `internal/e2e`, `internal/conformance/bus` and `internal/server` tests can import it) that imports only the standard library, kin-openapi and nothing of this module: the document is a parameter (`respcheck.New(doc *openapi3.T)`), and callers pass `server.Spec()` (whose `Servers` is nil, so the gorillamux router matches any host). A request the router cannot match (the token path's 405 and trailing-slash 404 from `tokenRouteGuard`, unknown paths) is not an operation: the checker skips it and counts it (`Skipped()`), and the self-test pins that. An m4 rule proves neither binary links the package.
9. **The e2e wiring is a validating reverse proxy** (`respcheck.Proxy`) in front of the server port, with `fixture.serverURL()` pointing at the proxy. The proxy's listener starts before the server (`httptest.NewUnstartedServer` with a handler whose target is set once the server's listening line gives the port), and the server is started with `-set issuer=<proxy URL>`, so the issuer the server advertises and checks (`cmd.go:129-133`: `cfg.Issuer`, else `http://<bound authority>`; `auth_exchange.go:79-81`: `audience` must equal `iss.URL()`; the client sends the discovered issuer as the audience, `credential/source.go:227`) is the proxy, and every call, the token exchange included, crosses the proxy. The proxy forwards the client's `Host` header unchanged (an `httputil.ReverseProxy` with a `Rewrite` that sets only `Out.URL`), because `metadata` and `Discover` build `token_endpoint` from the request's base URL (`discovery.go:54,84`), and buffers each response body for validation (`ModifyResponse`). Violations are collected and `runMain` fails after `m.Run()` when any were recorded.
10. **The tables read the embedded document.** `TestStatusTable` and `TestOperationErrorTable` (`internal/server/status_table_test.go`) use `Spec()` like `TestRunRefusesEveryProtectedOperation` does; `make generate-check` keeps it equal to `api/openapi.yaml`. The per-operation table is the extras beyond three rule tiers computed from the document (`validation` and `internal` everywhere; `payload_too_large` where `requestBody` is set; `unauthenticated`, `not_registered` and `unavailable` where the operation carries the global security requirement), so a reader audits the extras and the rules separately.
11. **`make verify` runs `bash scripts/m4-exit-checks.sh --deps-only`** beside the m6 and m10 lines, so the new respcheck rule is in the done gate (CI already runs it as a step).

## Review Focus

1. A `rate_limited` error built without a wait, or a 429 written without the header: `TestRateLimitedSites` (syntactic, constructions only) and, on the wire, `TestSendRateLimited`'s `RetryAfter > 0` on inproc plus respcheck's required-header check (kin `validate_response.go:80-93`). The generated client's header binding does not catch it: `Parse<Op>Response` binds `Retry-After` only when the header is present (`if values := rsp.Header.Values("Retry-After"); len(values) > 0`, spike line 376), so a missing header leaves `Headers429.RetryAfter` zero and `errorOf` sees `RetryAfter == 0` without an error. The server clamps to at least 1 second, never 0.
2. A shared response referenced under the wrong status key (`"404": $ref: Conflict`): `TestStatusTable/references` fails.
3. A table extra the spec lacks or a declared status the table lacks: `TestOperationErrorTable/<op>` names the status in both directions.
4. The proxy and the e2e timing: the server's `listening` line and enrollment detection are unchanged; only `serverURL()` changes. If `TestHelpExamples` or `TestMCPOnly` prints the server URL, the proxy's URL is what the CLI sees; nothing asserts the port.
5. `validatorCode` keeps its 422 case (kin's request validator answers 400 for body violations, so the case is dead but harmless) and its 403 default (`internal`): the middleware never answers 403 (`oapi_validate.go:283-285` maps `SecurityRequirementsError` to 401), so no 403 `internal` can reach the wire. Task 6's table test would catch it if it did.

## The per-operation table

Tiers (composed by the test from the document): **T0** every operation: `validation` (400), `internal` (500). **T1** operations with `requestBody`: `payload_too_large` (413). **T2** the 49 operations under the global `bearerAuth` requirement: `unauthenticated` (401, the validator), `not_registered` (403, `access/principal.go:46`, `access/decide.go:159`), `unavailable` (503, `core.FromStore` on `store.ErrRetryable`, `access/principal.go:62`).

Extras per operation (file:line is the producing site; "receipt" is `internal/core/receipts.go:34`, "inspect" is `internal/core/inspect.go:320` (conflict), `:361,:378` (unavailable, in T2) and `:393` (`inspection_rejected`); session lookups are `sessions/service.go:81` (`Owned`: not_found) and `:98,:102` (`RequireAs`: session_closed, session_lapsed)):

| operation | extras |
| --- | --- |
| `wellKnown`, `authorizationServerMetadata`, `openidConfiguration`, `discover` | none (no store, no parameters) |
| `health` (open) | `unauthenticated` (`server/health.go:18`), `not_registered` (`core/health/health.go:24`, `server/health_test.go:105`), `unavailable` (`core/health/health.go:31,37`); `forbidden` only if the implementer finds a path (`Access.Check` returns a decision, not an error) |
| `openSession` | `not_found` (`sessions/open.go:87`), `session_closed` (`sessions/open.go:90`) |
| `closeSession` | `not_found` (`sessions/close.go` via `Owned`), `conflict` (receipt) |
| `receive` | `not_found` (`RequireAs`; `FilterReceive` out of scope `decide.go:320,402`), `session_closed`, `session_lapsed` (`delivery/receive.go:148`) |
| `watch` | `not_found`, `session_closed`, `session_lapsed` (`delivery/watch.go:42` through `Require`), `replaced` (`watch.go:108`) |
| `peek` | `not_found`, `session_closed`, `session_lapsed` (`delivery/peek_counts.go:30-39`) |
| `listIdentities`, `listAgentStatuses`, `listChannels`, `listTagSubscriptions` | none |
| `setAgentStatus` | `forbidden` (`decide.go:193,196`), `not_found`, `session_closed`, `session_lapsed` (`statuses.go:54`), `rate_limited` (`statuses.go:63`), `conflict` (receipt) |
| `agentStatusHistory` | `not_found` (`decide.go:184,190` through `statuses.go:161`) |
| `createChannel` | `forbidden` (`decide.go:235,257`), `not_found` (scope `scopes/service.go:40,46`), `conflict` (scope done `:31`; name taken, `FromStore`; receipt) |
| `deleteChannel` | `forbidden` (`channels.go:125`), `not_found`, `conflict` (live bridge `channels.go:200`; receipt) |
| `renameChannel` | `forbidden`, `not_found`, `conflict` (name taken; receipt) |
| `getACL` | `forbidden` (`channels.go:125`), `not_found` |
| `setACL` | `forbidden` (`decide.go:434`, `scopes/acl.go:23,27,34`, `channels.go:312`), `not_found`, `conflict` (receipt) |
| `subscribe` | `forbidden` (`decide.go:348`), `not_found`, `conflict` (receipt) |
| `unsubscribe` | `forbidden` (`subscriptions.go:63`), `not_found`, `conflict` (receipt) |
| `subscribeTags`, `unsubscribeTags` | `conflict` (receipt) |
| `sendMessage` | `forbidden` (`send.go:116`), `not_found` (`lookup.go:28`, `append.go:120`, `send.go:84`), `session_closed`, `session_lapsed` (`send.go:93,95`), `conflict` (receipt; inspect), `inspection_rejected`, `rate_limited` (`send.go:138`) |
| `history` | `forbidden` (`history.go:31`), `not_found` |
| `search` | `forbidden` (`search/service.go:65`), `not_found` |
| `getMemory`, `listMemoryRevisions` | `forbidden` (`memories.go:33,71`), `not_found` (`memory.go:20`, `memories.go:69`) |
| `deleteMemory` | `forbidden` (`memories.go:307`), `not_found` (`memories.go:321`), `rate_limited` (`memories.go:314`), `conflict` (receipt) |
| `editMemory` | `forbidden` (`memories.go:101`), `not_found`, `conflict` (`memories.go:112`; receipt; inspect), `inspection_rejected`, `rate_limited` (`memories.go:140`) |
| `createTask` | `forbidden` (`tasks/service.go:57`), `not_found` (`tasks/service.go:74`, `tasks/update.go:110`), `conflict` (receipt; inspect; `update.go:143`), `inspection_rejected`, `rate_limited` (`tasks/service.go:43`) |
| `listTasks` | `forbidden`, `not_found` |
| `getTask` | `forbidden` (`tasks/service.go:74`), `not_found` (`tasks/read.go:41`) |
| `updateTask`, `claimTask`, `releaseTask` | `forbidden`, `not_found` (`update.go:314,331`), `conflict` (`update.go:50,143`; receipt; inspect), `inspection_rejected`, `rate_limited` (claim and release are `Update` with a fixed patch, `update.go:395,405`) |
| `adminStatus`, `adminUsage`, `listScopes` | `forbidden` (`lookup.go:21`) |
| `token` (open, `OAuthError`) | statuses 400, 401, 413, 500, 503 (`oauth.go:52-66`, `auth_handlers.go:46-65,113`, `server.go:174`) |
| `jwks` (open) | `unavailable` (`auth_handlers.go:23,128`) |
| `register` (open) | `forbidden` (`identities/register.go:49-170`), `conflict` (`register.go:158`), `unavailable` (`FromStore`) |
| `adminReset` | `forbidden`, `conflict` (receipt) |
| `resetCredential` | `forbidden`, `not_found` (`identities/admin.go:145`), `conflict` (receipt) |
| `listSigningKeys` | `forbidden` (`signing_keys.go:31` is `unavailable`, in T2) |
| `rotateSigningKey` | `forbidden`, `conflict` (`signingkeys/service.go:277,318,323`; receipt) |
| `createIdentityByEmail` | `forbidden`, `conflict` (`identities/human.go:71,73,169`; receipt) |
| `createAgentIdentity` | `forbidden`, `not_found` (scope), `conflict` (`identities/agent.go:126,129,136`; scope done) |
| `createScope` | `forbidden`, `conflict` (`decide.go:242,247`; `FromStore`; receipt) |
| `getScope` | `forbidden`, `not_found` (`scopes/service.go:40`) |
| `doneScope` | `forbidden`, `not_found`, `conflict` (`scopes/service.go:165,177`; receipt) |
| `createBridge` | `forbidden` (`slackbridge/service.go:174`), `not_found` (channel), `conflict` (bridge exists, `FromStore`), `rate_limited` (`slackbridge/service.go:203`); `unavailable` in T2 (`bridges.go:33`, `service.go:166,205-209`) |
| `listBridges` | `forbidden` |
| `getBridge`, `removeBridge` | `forbidden`, `not_found` (`slackbridge/service.go:220`) |

Rows marked with a site are read from the code on `53da05b`; Task 6 Step 1 has the implementer confirm each row by reading the handler and its core path and correct the table where the reading disagrees (the test then fails against the spec, and Task 6 fixes the spec, never the reading).

---

### Task 1: The limiter's wait, `bus.Error.RetryAfter` and the 429 header

**Files:**
- Modify: `internal/bus/errors.go` (`Error` gains `RetryAfter time.Duration` with tag `json:"-"`; doc comment)
- Modify: `internal/core/errors.go` (add `RateLimited`)
- Modify: `internal/core/limiter.go` (`Check` returns the wait), `internal/core/limiter_test.go`
- Modify: `internal/core/messaging/send.go:137`, `internal/core/memories/memories.go:139,313`, `internal/core/tasks/service.go:42`, `internal/core/statuses/statuses.go:62`, `internal/slackbridge/service.go:203`
- Create: `internal/core/ratelimited_sites_test.go` (`TestRateLimitedSites`)
- Modify: `internal/server/problem.go` (`responseError` sets `Retry-After`; `writeProblemBody` unchanged), `internal/server/problem_test.go`
- Modify: `internal/conformance/bus/send_test.go` (`TestSendRateLimited` asserts the wait on the `local` transport; Task 2 extends it to inproc)

**Interfaces:**
- `func (l *Limiter) Check(identity string, n int, now time.Time) (ok bool, wait time.Duration)`: `wait` is 0 when `ok`; else the larger of `time.Duration((1-bk.count)/l.perSec*float64(time.Second))` and `time.Duration((float64(n)-bk.bytes)/l.bytesSec*float64(time.Second))`, each taken only when its deficit is positive; never negative.
- `func RateLimited(wait time.Duration, format string, args ...any) *bus.Error` in `internal/core/errors.go`: `E(bus.CodeRateLimited, ...)` with `RetryAfter: wait`.
- `func retryAfterSeconds(d time.Duration) int` in `internal/server/problem.go`: `max(1, int(math.Ceil(d.Seconds())))`.
- `responseError` (and `ProblemFor`'s caller path) sets `Retry-After: <seconds>` when the error is a `*bus.Error` with code `rate_limited`, before `writeProblemBody`.

- [ ] **Step 1: Write the failing tests**

`internal/core/limiter_test.go`: `TestCheckReturnsWait`: a limiter of 2 per second and 64 KiB per second; after two `Charge`s at `t0`, `Check(id, 10, t0)` is `(false, 500ms)` (count deficit 1 at 2 per second); a check of `n` = 2 MiB with full buckets is refused with the bytes deficit's wait (greater than the count's); a check that passes returns `(true, 0)`; the wait is never negative.

`internal/core/ratelimited_sites_test.go`: `TestRateLimitedSites` parses every non-test `.go` file under `internal/` (walk from the module root found by `runtime.Caller`) and fails on any *construction* of a `rate_limited` error outside the function `RateLimited` in `internal/core/errors.go`: a `CallExpr` whose function is `E`, `core.E`, `bus.Errorf` or `Errorf` and whose first argument is the selector `bus.CodeRateLimited` (or the identifier `CodeRateLimited` inside package `bus`), or a composite literal of `bus.Error`/`Error` with a `Code: bus.CodeRateLimited` element. Reads of the constant (`StatusFor`'s `case bus.CodeRateLimited:`, `core.E`'s retryable check, `responseError`'s `be.Code == bus.CodeRateLimited`) are not matched. The failure names file and line. (Reading the limiter's refusal by hand is what the rule prevents.)

`internal/server/problem_test.go`: `TestRateLimitedRetryAfterHeader`: `responseError` with `core.RateLimited(1500*time.Millisecond, "x")` writes 429, `Retry-After: 2`; with a wait of 0 writes `Retry-After: 1`; a `conflict` writes no `Retry-After`. `TestWriteProblemStatusMatches`: for every code of `TestStatusForEveryCode`'s table, `WriteProblem` with `StatusFor(code)` and `responseError` with `core.E(code, "x")` give a recorder status equal to the body's `status` member. `TestRetryAfterSeconds`: 0 is 1, 1 ns is 1, 1 s is 1, 1.001 s is 2.

Run: `go test ./internal/core/ ./internal/server/ -run 'TestCheckReturnsWait|TestRateLimitedSites|TestRateLimitedRetryAfterHeader|TestWriteProblemStatusMatches|TestRetryAfterSeconds' 2>&1 | tail -20`
Expected: compile failures (`Check` arity, `RateLimited` undefined) and `TestRateLimitedSites` naming the six sites.

- [ ] **Step 2: Implement**

The six sites become `core.RateLimited(wait, "send_messages_per_second rate limit exceeded for %s", identity)` with `ok, wait := s.Limits.Check(...)`; the bridge site becomes `core.RateLimited(rl.RetryAfter, "Slack is rate limiting the bridge (%s); retry after %s", rl.Method, rl.RetryAfter)`. `TestSendRateLimited` (`send_test.go:358`) adds: `errors.As(err, &be)` and `be.RetryAfter > 0`.

- [ ] **Step 3: Run the tests**

Run: `go test ./internal/core/... ./internal/server/ ./internal/slackbridge/ && go test -count=1 ./internal/conformance/bus/ -run 'TestSendRateLimited' 2>&1 | tail -5`
Expected: all `ok`.

- [ ] **Step 4: Vet, format, lint; commit**

Run: `go vet ./... && make fmt-check && make lint`

```bash
git add internal/bus/errors.go internal/core internal/slackbridge/service.go internal/server/problem.go internal/server/problem_test.go internal/conformance/bus/send_test.go
git commit -m "feat(server): every 429 carries Retry-After from the limiter's wait (issue #33)"
```

---

### Task 2: The client decodes the problem body at any status and reads `Retry-After`

**Files:**
- Modify: `internal/bus/remote/remote.go` (`errorOf`), `internal/bus/remote/memories.go` (`mtResponse`, `mtCheck`), every `internal/bus/remote/*.go` call site of `errorOf` and `ApplicationproblemJSONDefault` (43 sites: `admin.go`, `admin_identities.go`, `agentstatus.go`, `auth.go`, `channels.go`, `health.go`, `memories.go`, `messages.go`, `peek.go`, `scopes.go`, `sessions.go`, `signingkeys.go`, `usage.go`), `internal/bus/remote/remote_test.go:55`
- Modify: `internal/conformance/bus/send_test.go` (the Task 1 assertion now holds on inproc too; no change if written transport-agnostically)

**Interfaces:**
- `func errorOf(ctx context.Context, status int, header http.Header, body []byte, err error) error`: as before, but the problem is always decoded from `body` (`json.Unmarshal` into `gen.Problem`, accepted when `Code != ""`), and on 429 `RetryAfter` is parsed from `header.Get("Retry-After")` as integer seconds (a missing or malformed header leaves 0 and is not an error here; the generated parse binds the header only when present, see Review Focus 1, and the suites catch its absence through `TestSendRateLimited` and respcheck).
- `mtResponse` is `StatusCode() int; GetBody() []byte; GetHTTPResponse() *http.Response` (the generated responses carry `HTTPResponse *http.Response`; add the getter to the interface only if the generator provides one, else pass the field at the call sites).

- [ ] **Step 1: Rewrite `errorOf` and its tests**

`remote_test.go`: the existing `errorOf` cases pass `nil` header and the body; add `TestErrorOfRetryAfter` (429 body with `code: rate_limited`, header `Retry-After: 3` gives `RetryAfter == 3*time.Second`; no header gives 0) and `TestErrorOfDecodesAnyStatus` (a 404 problem body is decoded without a typed member).

- [ ] **Step 2: Remove every `ApplicationproblemJSONDefault` read in `internal/bus/remote`**

Run: `rg -n 'ApplicationproblemJSONDefault' internal/bus/remote/` afterwards.
Expected: no output.

- [ ] **Step 3: Run the regression net**

Run: `go test ./internal/bus/remote/ && AGENTMESH_BUS_TRANSPORT=inproc go test -count=1 ./internal/conformance/bus/ 2>&1 | tail -5`
Expected: `ok` twice; `TestSendRateLimited` passes on inproc with `RetryAfter > 0`.

- [ ] **Step 4: Vet, format, lint; commit**

```bash
git add internal/bus/remote internal/conformance/bus/send_test.go
git commit -m "refactor(remote): decode the problem body at any status and read Retry-After (issue #33)"
```

---

### Task 3: The server tests stop reading the generated Default member

**Files:**
- Create: `internal/server/problem_helpers_test.go` (`problemOf(t testing.TB, body []byte) gen.Problem`)
- Modify: `internal/server/server_test.go:118`, `health_test.go:105,106,124`, `channels_test.go` (4), `memories_tasks_test.go` (4), `messages_test.go` (2), `sessions_test.go` (2); any other site `rg -n 'ApplicationproblemJSONDefault' . -g '!internal/gen/**'` finds (check `internal/gen/*_test.go` too)

- [ ] **Step 1: Replace each read**

`r.ApplicationproblemJSONDefault.Code` becomes `problemOf(t, r.Body).Code`; the `== nil` guards become `len(r.Body) == 0` or are dropped where `problemOf` fails the test on an undecodable body.

- [ ] **Step 2: Run the package tests**

Run: `go test ./internal/server/... ./internal/gen/... && rg -n 'ApplicationproblemJSONDefault' . -g '!internal/gen/gen.go'`
Expected: `ok`; the `rg` prints nothing.

- [ ] **Step 3: Commit**

```bash
git add internal/server
git commit -m "test(server): read problems from the body, not the generated Default member (issue #33)"
```

---

### Task 4: The `payload_too_large` code (ruling 1)

**Files:**
- Modify: `internal/bus/errors.go` (`CodePayloadTooLarge`, `validCodes`; doc comment: "the request body exceeds the server's limit; not retryable")
- Modify: `internal/server/problem.go` (`StatusFor`: 413), `internal/server/server.go:177` (`limitBody` sends `bus.CodePayloadTooLarge`)
- Modify: `api/openapi.yaml` (`Problem.code` enum gains `payload_too_large` after `inspection_rejected`), then `make generate`
- Modify: `internal/server/problem_test.go` (`TestStatusForEveryCode`: 14 codes), `internal/server/server_test.go` (the existing 413 test, if any, expects the new code; else add `TestLimitBodyPayloadTooLarge`), `internal/bus/errors_test.go` (`ValidCode` count, if pinned)
- Modify: `docs/superpowers/specs/*` are not touched; ADR 0001 choice 3 is amended in Task 10

- [ ] **Step 1: Tests first**

`TestStatusForEveryCode` gains `bus.CodePayloadTooLarge: 413` and `want 14`; `TestLimitBodyPayloadTooLarge` posts a body one byte over the limit to `/v1/channels` through `New(...)` and expects 413, `application/problem+json`, `code: payload_too_large`, `retryable: false`, `status: 413`. Checked on `53da05b`: `rg -n '413|too large|exceeds' internal/e2e internal/cli internal/mcpserver internal/mcpcli` finds nothing, so no e2e exit-code cell or CLI text asserts `validation` on an oversize body; rerun the search before Step 2 and update any site it finds.

Run: `go test ./internal/server/ -run 'TestStatusForEveryCode|TestLimitBodyPayloadTooLarge' 2>&1 | tail -5`
Expected: FAIL (undefined code).

- [ ] **Step 2: Implement, regenerate**

Run: `make generate && git status --porcelain internal/gen`
Expected: `internal/gen/gen.go` (the new `ProblemCodePayloadTooLarge` constant) and `internal/gen/spec/spec.go` modified; nothing else.

- [ ] **Step 3: Run the tests**

Run: `go test ./internal/bus/ ./internal/server/... ./internal/gen/... && AGENTMESH_BUS_TRANSPORT=inproc go test -count=1 ./internal/conformance/bus/ 2>&1 | tail -3`
Expected: `ok`.

- [ ] **Step 4: Commit**

```bash
git add internal/bus/errors.go internal/server api/openapi.yaml internal/gen
git commit -m "feat(server): 413 carries its own code, payload_too_large (issue #33)"
```

---

### Task 5: The spec declares every error response; `default` is gone

**Files:**
- Modify: `api/openapi.yaml` (`components/responses`: delete `Problem`, add the eleven responses of ruling 5 in the shape of ruling 4; `TooManyRequests` declares `headers: Retry-After: {required: true, schema: {type: integer, minimum: 1}, description: ...}`; every operation lists its responses per the table; `token` adds `"413": $ref OAuthError`; `watch`'s inline 409 becomes `$ref: "#/components/responses/Conflict"`; `info.version` stays `1.0.0`)
- Run: `make generate`
- Modify: `internal/server/wire_roundtrip_test.go` (`plumbingPatterns` gains `{Suffix: "Headers", Reason: "generated response-header structs (the 429 Retry-After)"}`; the `Problem` exception's reason names `errorOf` over the body)
- Modify: `internal/gen/openapi31_test.go` if a pin counts responses or asserts `default` (check with `rg -n 'default|Default|responses' internal/gen/openapi31_test.go`)
- Modify: `internal/server/problem.go` (the `// open note: write-inspection 5` comment on the 422 case becomes "declared per operation as UnprocessableEntity (issue #33)")

**Interfaces:** the generated client gains `ApplicationproblemJSON<status> *gen.<Name>` members (aliases of `Problem`) and `Headers429 *<Op>Response429Headers` on every 429-declaring operation; the strict server gains `<Op><Status>ApplicationProblemPlusJSONResponse` types. Nothing in `internal/bus/remote` or `internal/server` references them.

- [ ] **Step 1: Write the spec change**

Author each response description to name its codes (the vacuum `owasp-define-error-responses-*` rules read descriptions). The 413 description states ruling 2's limit ("a body sent to an operation without a request body is refused the same way and is outside the contract"). The order of a response list is numeric.

- [ ] **Step 2: Regenerate and check the generated shape**

Run: `make generate && rg -n '^type (BadRequest|Unauthorized|Forbidden|NotFound|Conflict|Gone|PayloadTooLarge|UnprocessableEntity|TooManyRequests|InternalServerError|ServiceUnavailable) = Problem$' internal/gen/gen.go | wc -l && rg -c 'ApplicationproblemJSONDefault' internal/gen/gen.go`
Expected: `11`; `0` (the `rg -c` exits 1 with no match: that is the pass).

- [ ] **Step 3: Run the regression net and the round-trip test**

Run: `go test ./internal/server/... ./internal/gen/... ./internal/bus/remote/ && AGENTMESH_BUS_TRANSPORT=inproc go test -count=1 ./internal/conformance/bus/ 2>&1 | tail -3 && go test ./internal/conformance/... -count=1 -run 'TestBothModes|TestAuthEndToEnd' 2>&1 | tail -3`
Expected: `ok`; `TestWireRoundTrip/coverage` still enumerates at least 120 structs and no new unpaired model (the aliases are not structs; the header structs are plumbing).

- [ ] **Step 4: Commit**

```bash
git add api/openapi.yaml internal/gen internal/server/wire_roundtrip_test.go internal/server/problem.go internal/gen/openapi31_test.go
git commit -m "feat(api): declare every error response per operation; no default (issue #33)"
```

---

### Task 6: The code-to-status table and the per-operation table tests

**Files:**
- Create: `internal/server/status_table_test.go` (`TestStatusTable`, `TestOperationErrorTable`)

**Interfaces (test literals):**

```go
// statusTable is the one status per code (StatusFor and the shared responses agree with it).
var statusTable = map[bus.Code]int{ bus.CodeValidation: 400, ..., bus.CodePayloadTooLarge: 413 } // 14 entries
// responseFor names the shared response a status is declared through.
var responseFor = map[int]string{400: "BadRequest", 401: "Unauthorized", 403: "Forbidden", 404: "NotFound", 409: "Conflict", 410: "Gone", 413: "PayloadTooLarge", 422: "UnprocessableEntity", 429: "TooManyRequests", 500: "InternalServerError", 503: "ServiceUnavailable"}
// operationExtras: the codes beyond the tiers (the table above); every operation has an entry, possibly empty.
var operationExtras = map[string][]bus.Code{ "wellKnown": {}, ..., "sendMessage": {bus.CodeForbidden, bus.CodeNotFound, bus.CodeSessionClosed, bus.CodeSessionLapsed, bus.CodeConflict, bus.CodeInspectionRejected, bus.CodeRateLimited}, ... }
var tokenStatuses = []int{400, 401, 413, 500, 503}
```

- [ ] **Step 1: Audit the table**

For each row of "The per-operation table", open the handler (`internal/server/<file>.go`) and the core path it calls and confirm each extra has a producing site; note a correction in the commit message. The audit is a reading, not a test run.

- [ ] **Step 2: Write `TestStatusTable`**

Subtests: `status_for` (every `statusTable` code: `StatusFor(code) == status`; `len(statusTable) == 14`; every spec `Problem.code` enum value is a key and `bus.ValidCode` of it, and vice versa, so no code lacks a status and no status lacks a code); `shared_responses` (for each `responseFor` entry, the component exists, its `application/problem+json` schema is an `allOf` of `$ref Problem` plus an object whose `code.enum` equals exactly the `statusTable` keys mapping to that status; `TooManyRequests` declares header `Retry-After` required with an integer schema; no other `application/problem+json` response component exists); `references` (every operation's response under a numeric key `s` that is a `$ref` into `components/responses` names `responseFor[s]`, or `OAuthError` on `token`; no operation declares a `default`: `op.Responses.Default() == nil`).

- [ ] **Step 3: Write `TestOperationErrorTable`**

One subtest per operation (`t.Run(operationId)`): compute `want` as the union of T0, T1 when `op.RequestBody != nil`, T2 when the operation's effective security is the global `bearerAuth` requirement (`op.Security == nil`), and `operationExtras[op]`; map through `StatusFor` to a status set; compare with the declared non-2xx keys of the operation; report a status declared but not produced and a status produced but not declared, each with the codes. `token` compares `tokenStatuses` with its declared keys and that each is `OAuthError`. A `staleness` subtest fails when `operationExtras` names an operation the document lacks or lacks one the document has, and when `tokenStatuses` is not sorted and unique.

Run: `go test ./internal/server/ -run 'TestStatusTable|TestOperationErrorTable' -v 2>&1 | rg -- '^(---|\s+---|ok|FAIL)'`
Expected: every leaf PASS. A failure here is either a spec row (fix `api/openapi.yaml`, `make generate`) or a table row the audit missed (fix the table and say so in the commit message); never a loosened rule.

- [ ] **Step 4: Commit**

```bash
git add internal/server/status_table_test.go api/openapi.yaml internal/gen
git commit -m "test(server): the code-to-status table and the per-operation error table (issue #33)"
```

---

### Task 7: `internal/respcheck`, its self-tests and the import rule

**Files:**
- Create: `internal/respcheck/doc.go`, `internal/respcheck/respcheck.go`, `internal/respcheck/respcheck_test.go`
- Modify: `scripts/m4-exit-checks.sh` (`--deps-only`: two new `check_deps` lines; header comment), `Makefile` (`verify` runs `bash scripts/m4-exit-checks.sh --deps-only` after the m6 line; the help comment names "the m4, m6 and m10 dependency rules"), `scripts/check-gates-selftest.sh` (block 12 `block_deps_rule_fires` gains a `deps_probe` for the new rule)
- Modify: `internal/gen/spec/doc.go` ("imported by internal/server only" becomes "imported by internal/server and, in tests, by the packages that pass server.Spec() to internal/respcheck")

**Interfaces:**

```go
package respcheck // imports: standard library, github.com/getkin/kin-openapi/{openapi3,openapi3filter,routers,routers/gorillamux}; nothing of this module
var ErrNoRoute = errors.New("respcheck: no operation matches the request")
type Checker struct { /* router, doc, skipped atomic.Int64 */ }
func New(doc *openapi3.T) (*Checker, error)                 // gorillamux.NewRouter(doc)
func (c *Checker) Check(req *http.Request, status int, header http.Header, body []byte) error
    // FindRoute; ErrNoRoute (counted) when none; else openapi3filter.ValidateResponse with
    // Options{IncludeResponseStatus: true}; the error text names method, path, operationId, status and the reason.
func (c *Checker) Skipped() int64
type Transport struct { Next http.RoundTripper; Checker *Checker; Report func(error) }  // exported so a test can assert the wrap
func (c *Checker) Transport(next http.RoundTripper, report func(error)) *Transport
    // RoundTrip: next.RoundTrip, read and restore the body, Check, Report on a non-ErrNoRoute error; the response is returned unchanged
func (c *Checker) Proxy(target *url.URL, report func(error)) http.Handler
    // httputil.ReverseProxy{Rewrite: sets Out.URL scheme and host only (Host header kept), ModifyResponse: buffer, Check, Report, restore}
```

- [ ] **Step 1: Write the self-tests (Docker-free)**

`respcheck_test.go` builds a small `openapi3.T` in code (one `GET /things/{id}` with 200 JSON `{"ok": boolean}`, 404 `application/problem+json` whose `code` enum is `[not_found]`, 429 with a required `Retry-After` integer header; no `default`) and an `http.Handler` driven by the test. Cases: `declared_ok` (200 with a valid body: nil, `Skipped()` 0); `undeclared_status` (500: error mentions `500` and the operationId); `wrong_body` (404 with `code: conflict`: error names `code`); `missing_header` (429 without `Retry-After`: error names the header); `wrong_content_type` (404 as `application/json`); `no_route` (`DELETE /nothing`: `ErrNoRoute`, `Skipped()` 1, `Transport` does not report it); `transport_restores_body` (the caller reads the full body after a check); `proxy_keeps_host` (a `Proxy` to an `httptest.Server` that echoes `r.Host`: the echoed host is the proxy's, not the target's; a violation behind the proxy is reported); `proxy_streams_bodiless` (a 204 passes).

Run: `go test ./internal/respcheck/ 2>&1 | tail -3`
Expected: compile failure, then after Step 2 `ok`.

- [ ] **Step 2: Implement the package**

Keep `Check` free of `testing`: `Report` is the caller's. `Transport.RoundTrip` never swallows `next`'s error.

- [ ] **Step 3: The import rule and its probe**

In `scripts/m4-exit-checks.sh` `--deps-only`, add `check_deps . internal/respcheck` and `check_deps ./cmd/agentmesh-mcponly internal/respcheck` with a header line: "`internal/respcheck` (test-only response validation, issue #33) is linked by neither binary". In block 12 of the selftest add `deps_probe m4-respcheck-linked cmd/agentmesh-mcponly/probe_m4.go "$m/internal/respcheck" "deps_violation=$m/cmd/agentmesh-mcponly imports $m/internal/respcheck"` (the probe is package `main`, which `deps_probe` handles for `cmd/*`), and a second probe at the root main package only if `deps_probe` can name it (`basename "$(dirname probe.go)"` is `.`, which is not a package name; if so, extend `deps_probe`'s `case` with `probe*.go) pkgname=main ;;` for a root-level file, and probe the root too).

Run: `bash scripts/m4-exit-checks.sh --deps-only && shellcheck -x scripts/m4-exit-checks.sh scripts/check-gates-selftest.sh`
Expected: `deps_ok=1`; no shellcheck findings. Then by hand: create `cmd/agentmesh-mcponly/probe_m4.go` with `package main` and `import _ "github.com/ericfitz/agentmesh/internal/respcheck"`, run the script, expect exit 1 and the `deps_violation` line, delete the probe.

- [ ] **Step 4: Commit**

```bash
git add internal/respcheck internal/gen/spec/doc.go scripts/m4-exit-checks.sh scripts/check-gates-selftest.sh Makefile
git commit -m "test(respcheck): runtime response validation against the embedded spec, test-only (issue #33)"
```

---

### Task 8: Wire response validation into every test path that crosses the wire

**Files:**
- Modify: `internal/conformance/bus/main_test.go` (one `check *respcheck.Checker` built from `server.Spec()` in `TestMain`; a new helper `inprocTransport(h *harness, identity string) http.RoundTripper` returning `check.Transport(server.InProcessTransport(handlerFor(h), identity), func(err error) { h.t.Errorf("response validation: %v", err) })`; `newBus` at line 25 uses it), `internal/conformance/bus/transport_test.go:89` (uses `inprocTransport(h, "pat")` too; a new test `TestInprocResponseCheckWired`, skipped on `local`, asserts `inprocTransport(h, "pat")` is a `*respcheck.Transport` whose `Next` is the in-process transport, so the mutation of Task 9 that unwraps the helper fails it)
- Modify: `internal/conformance/bus/auth_test.go:176-184` (`newClient` passes `gen.WithHTTPClient(&http.Client{Transport: check.Transport(http.DefaultTransport, report)})`)
- Modify: `internal/server/server_test.go:155`, `channels_test.go:207,314` and the `env` client helper that builds `InProcessTransport` for the package's tests: one helper `checkedTransport(t testing.TB, next http.RoundTripper) http.RoundTripper` in `internal/server/problem_helpers_test.go` wraps with `t.Errorf`, and every test site builds its transport through it; the route-guard tests (`tokenRouteGuard`, trailing slash) hit `ErrNoRoute` and are skipped by design (ruling 8)
- Modify: `internal/e2e/e2e_test.go` (`fixture` gains `proxy *httptest.Server`, `target atomic.Pointer[url.URL]` and `violations` (a mutex-guarded `[]string`); `startFixture` creates `httptest.NewUnstartedServer` first with `check.Proxy` over a `Rewrite` that reads `f.target`, starts it, passes `-set issuer=<f.proxy.URL>` to the server command, sets `f.target` once the listening line gives the port, and `serverURL()` returns `f.proxy.URL`; `stopServer` closes the proxy first; `runMain` prints the violations and returns 1 when any were recorded, after `m.Run()`). The `listeningRE` still matches (the issuer group is `\S+`); the "registration enrollment" check is unchanged.

- [ ] **Step 1: Wire the conformance suite and prove it bites**

Run: `AGENTMESH_BUS_TRANSPORT=inproc go test -count=1 ./internal/conformance/bus/ 2>&1 | tail -3`
Expected: `ok`. Then a throwaway check (not committed): in `internal/server/problem.go` make `responseError` skip the `Retry-After` header; rerun; expected `TestSendRateLimited` FAIL with "response validation" naming `Retry-After`; revert.

- [ ] **Step 2: Wire `TestAuthEndToEnd` and the `internal/server` tests**

Run: `go test ./internal/server/... && go test -count=1 ./internal/conformance/bus/ -run 'TestAuthEndToEnd' 2>&1 | tail -3`
Expected: `ok`; `Skipped()` is nonzero only in the route-guard tests.

- [ ] **Step 3: Wire the e2e proxy**

Run: `go test -count=1 ./internal/e2e/ 2>&1 | tail -5`
Expected: `ok` (about 30 s). If `register`, `login` or `check reach` fail with `invalid_target` or a token endpoint naming the server's port, the issuer setting or the `Host` forwarding is wrong (ruling 9): fix the fixture, never the server. Then the throwaway check of Step 1 against the e2e suite: expected failure after `m.Run()` listing the violation; revert.

- [ ] **Step 4: Run the exit-check scripts the e2e counts feed**

Run: `go test -count=1 -v ./internal/e2e/ > /tmp/e2e.log 2>&1; bash scripts/m6-exit-checks.sh /tmp/e2e.log && bash scripts/m10-exit-checks.sh /tmp/e2e.log`
Expected: the counts unchanged (13 sequence steps, 11 exit-code cells, `mcponly=9`, `help=6`).

- [ ] **Step 5: Commit**

```bash
git add internal/conformance/bus internal/server internal/e2e
git commit -m "test: validate every wire response against the spec in the suites (issue #33)"
```

---

### Task 9: Selftest block 36: each check fails under mutation

**Files:**
- Modify: `scripts/check-gates-selftest.sh` (a `mutate_spec_block` helper; block 36 `block_error_responses_fire`; its invocation after `block_tool_coverage_fires`; the header comment numbering)

**Interfaces:**

```bash
# mutate_spec_block LABEL SCOPE FROM TO PKG RUN WANT: mutate api/openapi.yaml inside one scope and
# regenerate internal/gen (both oapi-codegen configs) in $wt before the test, because the tests
# read the embedded spec. SCOPE is "operationId: <id>" or a component key such as
# "    TooManyRequests:"; the span runs from the SCOPE line to the next line matching
# '^ {6}[a-z]+:$|^    operationId: |^  [a-z]+:$|^components:' after it. FROM must occur exactly
# once in the span (whole-string count via ${span//"$from"/} length arithmetic, so a multi-line
# FROM works; grep -cF would count each line of it separately) and is replaced by TO in that
# span only. Regeneration failure is a problem, not a skip.
mutate_spec_block() { ...; (cd "$wt" && go tool oapi-codegen -config api/oapi-codegen.yaml api/openapi.yaml && go tool oapi-codegen -config api/oapi-codegen-spec.yaml api/openapi.yaml) >"$log" 2>&1 || problem "$label" "regenerate: $(tail -n 3 "$log" | tr '\n' ' ')"; ... }
```

- [ ] **Step 1: Write the block**

```bash
# --- 36. error-responses-fire ---------------------------------------------------------
# issue #33: the code-to-status table (TestStatusTable), the per-operation table
# (TestOperationErrorTable), the Retry-After header, the rate_limited constructor rule and
# the response validation wiring must each turn red under one mutation. Spec mutations
# regenerate internal/gen in the worktree first (mutate_spec_block). Docker-free except the
# two conformance runs, which use SQLite.
block_error_responses_fire() {
	mutate_spec_block spec-status-undeclared 'operationId: sendMessage' \
		$'        "429":\n          $ref: "#/components/responses/TooManyRequests"\n' '' \
		./internal/server/ '^TestOperationErrorTable$' TestOperationErrorTable/sendMessage
	mutate_spec_block spec-default-restored 'operationId: listChannels' \
		'          $ref: "#/components/responses/ServiceUnavailable"' \
		$'          $ref: "#/components/responses/ServiceUnavailable"\n        default:\n          $ref: "#/components/responses/BadRequest"' \
		./internal/server/ '^TestStatusTable$' TestStatusTable/references
	mutate_spec_block spec-code-narrowed-wrong '    TooManyRequests:' \
		'enum: [rate_limited]' 'enum: [conflict]' \
		./internal/server/ '^TestStatusTable$' TestStatusTable/shared_responses
	mutate_spec_block spec-retry-after-optional '    TooManyRequests:' \
		'required: true' 'required: false' \
		./internal/server/ '^TestStatusTable$' TestStatusTable/shared_responses
	mutate_unit_block status-for-wrong internal/server/problem.go \
		'return http.StatusTooManyRequests' 'return http.StatusConflict' \
		./internal/server/ '^TestStatusTable$' TestStatusTable/status_for
	mutate_unit_block table-entry-spec-lacks internal/server/status_table_test.go \
		'"listChannels": {},' '"listChannels": {bus.CodeRateLimited},' \
		./internal/server/ '^TestOperationErrorTable$' TestOperationErrorTable/listChannels
	mutate_unit_block retry-after-header-dropped internal/server/problem.go \
		'<the Retry-After Set line>' '' \
		./internal/server/ '^TestRateLimitedRetryAfterHeader$' TestRateLimitedRetryAfterHeader
	mutate_unit_block problem-status-mismatch internal/server/problem.go \
		'w.WriteHeader(p.Status)' 'w.WriteHeader(p.Status + 1)' \
		./internal/server/ '^TestWriteProblemStatusMatches$' TestWriteProblemStatusMatches
	mutate_unit_block rate-limited-site-unwrapped internal/core/messaging/send.go \
		'<the core.RateLimited( call line>' $'<same line>\n\t\t_ = core.E(bus.CodeRateLimited, "x")' \
		./internal/core/ '^TestRateLimitedSites$' TestRateLimitedSites
	# the header's absence reaches the inproc suite through respcheck (header required: true)
	inproc_mutation_block retry-after-unvalidated internal/server/problem.go \
		'<the Retry-After Set line>' '' TestSendRateLimited 'response validation' 'Retry-After'
	# unwrap the one helper every inproc client goes through (Task 8): the wired test fails
	inproc_mutation_block respcheck-unwired internal/conformance/bus/main_test.go \
		'return check.Transport(server.InProcessTransport(handlerFor(h), identity), ' \
		'return server.InProcessTransport(handlerFor(h), identity); _ = ' \
		TestInprocResponseCheckWired '--- FAIL: TestInprocResponseCheckWired'
}
```

The `respcheck-unwired` anchor assumes the helper's return statement is written on one line as `return check.Transport(server.InProcessTransport(handlerFor(h), identity), func(err error) { ... })`; the mutation turns it into a bare return followed by a discarded closure. If Task 8 formats it differently, the implementer adapts the anchor and the replacement, keeping the property: after the mutation the helper returns the unwrapped transport and the file still compiles.

`inproc_mutation_block` is `mutate_block` with `AGENTMESH_BUS_TRANSPORT=inproc` on the `go test` line (model: `block_inproc_crosses_the_wire`, line 268). The placeholders in angle brackets are the exact anchor texts, each occurring once in its file; the implementer fills them from the files as committed by Tasks 1 to 8.

- [ ] **Step 2: Run the block alone, then the whole selftest**

Run: `bash scripts/check-gates-selftest.sh 2>&1 | rg -n 'selftest: (ok|problem)' | rg -n 'spec-|status-for|table-entry|retry-after|problem-status|rate-limited-site|respcheck' `
Expected: `selftest: ok <label>` for each of the eleven labels. Then `make check-gates-selftest` in Task 11 runs everything.

- [ ] **Step 3: Lint and commit**

Run: `shellcheck -x scripts/check-gates-selftest.sh`

```bash
git add scripts/check-gates-selftest.sh
git commit -m "test(gates): selftest block 36, the error-response checks fire (issue #33)"
```

---

### Task 10: Docs: CLAUDE.md, the ADRs and the operator guide

**Files:**
- Modify: `CLAUDE.md` (the Commands line of `make verify` names the m4, m6 and m10 rules; a new Design bullet "Error responses (issue #33, Eric 2026-11-06, ADR 0001 addendum)": the eleven shared responses with narrowed `code` (`x-go-type: Problem`, one Go type), no `default`, `payload_too_large` on 413, `Retry-After` on every 429 from `Limiter.Check`'s wait through `core.RateLimited` (`TestRateLimitedSites`), `TestStatusTable` and `TestOperationErrorTable` in `internal/server/status_table_test.go`, `internal/respcheck` wired into the inproc suite, `TestAuthEndToEnd`, the `internal/server` tests and the e2e proxy, never in production (m4 rule), selftest block 36; the `GET /v1/health` bullet adds "declares 401 and 503")
- Modify: `docs/adr/0001-transport-and-api.md` (an addendum "Error responses declared per operation (issue #33, Eric 2026-11-06)": the three decisions labeled as Eric's, the plan rulings labeled as such, choice 3 now 14 codes including `payload_too_large`, choice 13 now "decodes the problem body at any status and reads `Retry-After`")
- Modify: `docs/adr/0007-openapi-code-generator.md` (addendum to need 2: the shared `default` response is gone; the generator's handling of `allOf` + `x-go-type` is what makes the narrowing free on the Go side, with the spike's evidence)
- Modify: `docs/adr/0010-server-health.md` (decisions 2 and 3: the 401 and 503 are now declared on `health`; decision 12's pins unchanged)
- Modify: `docs/adr/0013-write-inspection.md` (open note 5 closed: 422 is declared per inspected operation as `UnprocessableEntity`)
- Modify: `docs/ops/health.md` (the 401 and 503 paragraph names the declared responses), `docs/ops/deploy.md:74` (rate limits: a refused send answers 429 with `Retry-After` in whole seconds)

- [ ] **Step 1: Write the changes**

Every factual claim is checked against the committed code (Docs (E)): counts (14 codes, 11 responses, 57 operations, 20 with a request body), file names and test names.

- [ ] **Step 2: Check and commit**

Run: `rg -n 'default problem|responses/Problem|open note: write-inspection 5' CLAUDE.md docs internal -g '!docs/superpowers/**'`
Expected: no output (the superpowers plans and specs are history and stay).

```bash
git add CLAUDE.md docs/adr docs/ops
git commit -m "docs: declared error responses, the 413 code and Retry-After (ADR 0001, 0007, 0010, 0013; issue #33)"
```

---

### Task 11: The done gate

**Files:** none (fixes found here go into a `fix:` commit naming the task they belong to).

- [ ] **Step 1: `make verify`**

Run: `make verify 2>&1 | tail -30`
Expected: `verify: OK`, with the Postgres suites run (not skipped) and `check-gates` green.

- [ ] **Step 2: `make check-gates-selftest`**

Run: `make check-gates-selftest 2>&1 | rg -n 'selftest: (ok|problem)|PASS|FAIL' | tail -60`
Expected: every block `ok`, block 36 included; no `problem`.

- [ ] **Step 3: Report**

Report both outputs' tails, the final `git log --oneline main..HEAD`, and stop: pushing and the CI check (`ci.yml` and `windows.yml` green on the pushed commit, `release-check` included) are Eric's call.
