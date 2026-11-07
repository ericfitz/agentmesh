# Issue 32: Spec Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Tasks 1 to 6 run before the human gate; the controller steps and Task 7 run after it.

**Goal:** `api/openapi.yaml` lints clean under a committed vacuum ruleset that `make verify` runs (`make spec-lint`), every operation carries a summary, every documented operation is the one the server serves and nothing else is served (a two-direction test), the acceptance criteria already met by issues #29, #33 and #34 are named rather than re-implemented, and the main customer journeys exist as Arazzo workflows (`api/arazzo.yaml`) that a small test-only runner (`internal/arazzotest`) executes against the e2e server.

**Architecture:** Nothing new runs in production. The server's router is generated from the document (`gen.HandlerWithOptions`, `internal/server/server.go:102`) and `var _ gen.StrictServerInterface = (*api)(nil)` (`internal/server/api.go:39`) makes "every operation is served" a compile-time fact; no non-test code outside `server.New` registers a route (`rg -n '\.Handle\(|\.HandleFunc\(|NewServeMux\(' internal cmd --glob '!*_test.go'` finds only `internal/gen`, `internal/oidcclient` and `internal/oidctest`). The completeness test therefore pins that fact with a sites scan plus a method-level probe through `server.New`, instead of pretending to enumerate an `http.ServeMux`. Response validation is already `internal/respcheck`, wired into the inproc Bus suite, `TestAuthEndToEnd`, the `internal/server` and `internal/server/cmd` tests and the e2e validating proxy (issue #33); the code-to-status table is `TestStatusTable`/`TestOperationErrorTable` (issue #33); the request bounds are `TestSpecBounds` (issue #34). The lint is vacuum 0.36.2 over a ruleset that extends `all` and turns eight rules off, each with a reason in the file. The Arazzo runner is a test-only package (kept out of both binaries by the m4 rule, like `internal/respcheck`) that supports exactly the features of Eric's decision 3 and refuses everything else by name.

**Tech Stack:** Go (`CGO_ENABLED=0`), kin-openapi v0.151.0 (`openapi3`), oapi-codegen v2.8.0 (`internal/gen`, never edited by hand), `gopkg.in/yaml.v3` v3.0.1 (already in the module graph, indirect today), vacuum 0.36.2 (Homebrew locally, `/opt/homebrew/bin/vacuum`; brew stable is already 0.39.2, so the pin is exact), bash gate scripts (`set -euo pipefail`, shellcheck-clean).

**Spec:** GitHub issue #32 (body) and Eric's decisions of 2026-11-06 (1: response validation in the test suites only; 2: `spec-lint` in `make verify`, fail-fast install hint, CI installs a pinned vacuum, the ruleset disables `info-license` and `info-contact` citing #35; 3: journeys from `profile:journeys`, Eric tunes them by hand, `openapi:arazzo` emits `arazzo.yaml`, a small test-only Go runner using kin-openapi runs them against the e2e server, supporting steps by operationId, runtime-expression parameters and bodies, success criteria on status and JSON pointer, and step outputs, refusing any other feature loudly, with its own tests). CLAUDE.md (the `api/openapi.yaml` and `make generate` rules, Decision 47 and the m4/m6/m7/m10 import rules, the pre-release rule), ADR 0001 (choices 3, 11, 13; the issue #29, #33 and #34 addenda), ADR 0007 (choice 6, the validator). Evidence on `e65a651` (2026-11-07, read-only runs, output in the scratchpad `issue32/`): `vacuum lint` with the stock recommended ruleset (55 rules) exits 0 with 0 errors, 389 warnings, 69 informs, quality 25/100: `oas3-missing-example` 139, `camel-case-properties` 102, `description-duplication` 69, `component-description` 68 (67 schemas, 1 parameter), `operation-description` 66 (46 operations with neither summary nor description, 20 request bodies without a description), `oas3-parameter-description` 13, `oas3-api-servers` 1. Hard mode (`-z`, OWASP included) exits 1 with 568 errors, 450 warnings, 79 informs: `owasp-rate-limit` 311, `owasp-string-restricted` 172, `owasp-integer-limit` 66, `owasp-define-error-responses-429` 47, `owasp-integer-format` 14, `owasp-protection-global-safe` 5, `owasp-protection-global-unsafe-strict` 2, `owasp-protection-global-unsafe` 2, `owasp-no-additional` 2, `owasp-no-numeric-ids` 1, `owasp-jwt-best-practices` 1, `info-license` 1, `info-contact` 1 (plus the recommended set). A probe ruleset extending `all` (60 rules) with the six rules of ruling 2 off and the three description rules off leaves 14 findings: `tag-description` 9, `openapi-tags-alphabetical` 3 (informs), `operation-singular-tag` 2 (`DELETE` and `PATCH /v1/channels/{channel}` carry `[channels, admin]`). The document has 57 operations, 57 `operationId`s, 0 `summary` members, 8 operation-level `security` members (the open operations), one global `bearerAuth` requirement, no `servers`. Default fail severity is `error`, so the stock run passes with 389 warnings: `-n info` is what makes the gate bite.

## Global Constraints

- **Eric's decisions (2026-11-06, issue #32), binding:** see Spec. The production server does not validate its responses; nothing in this plan adds a response validator to `server.New`.
- **Issue acceptance criteria, binding:** `openapi:init` records the spec and the validator's verdict goes on the issue; `vacuum lint` runs with a committed ruleset and is clean, or each remaining rule is disabled with a reason; every operation has `operationId`, a summary, its security and every response it can give; a test enumerates routes against operations in both directions; response validation in the suites (done: #33); every `bus.Code` maps to a documented code and status (done: #33); Arazzo workflows for register and log in, send and receive with ack, memories, task claim and complete, admin bootstrap, bridges, each run against the e2e server; every gap fixed in the spec (then `make generate`) or the server, with a test; #29's `TestWireRoundTrip` and `TestToolCoverage` stay green.
- **The protocol version stays `1.0.0`** (`info.version` and `version.Protocol` untouched; pre-release rule, Eric 2026-10-27). Every spec change here is documentation (summaries, descriptions, tags): no schema, path, member or status changes.
- **Never edit `internal/gen` by hand.** Every spec task ends with `make generate` and `git diff --stat internal/gen` showing `gen.go` changed only in comments and `spec/spec.go` in the embedded bytes. A generated type change means a task wrote something other than text: stop and report.
- **Coordination with #29, #33, #34:** `TestWireRoundTrip`, `TestToolCoverage`, `TestStatusTable`, `TestOperationErrorTable`, `TestSpecBounds` and the selftest blocks 34 to 37 run unchanged. A text edit that moves an anchor a `mutate_spec_block` call depends on (`scripts/check-gates-selftest.sh` blocks 36 and 37 anchor on `operationId: sendMessage`, `operationId: listChannels`, `    TooManyRequests:` and the bound lines) must keep that anchor unique in its span: summaries go on the line directly after `operationId:`, descriptions after `summary:`.
- **Import rules hold.** `internal/arazzotest` imports the standard library, kin-openapi `openapi3` and `gopkg.in/yaml.v3` only, never `internal/server`, `internal/gen`, `internal/core`, `internal/bus` or `internal/store`; the m4 rule (`scripts/m4-exit-checks.sh:73-74`) gains the rows `check_deps . internal/arazzotest` and `check_deps ./cmd/agentmesh-mcponly internal/arazzotest`, so neither binary links it. `internal/e2e` is `//go:build !windows` and already imports `internal/server`, `internal/respcheck`, `internal/auth/keys` and `internal/auth/token`; the Arazzo test adds `internal/arazzotest` and `internal/auth/assertion`. `internal/gen`'s test file imports nothing new. The m6 consumer group, the m7 and m10 rules are untouched.
- **Shell:** every script change stays `set -euo pipefail` and shellcheck-clean (`make release-lint`). Never run `vacuum generate-ruleset` inside the checkout: it writes `ruleset-<name>.yaml` into the working directory.
- **Vacuum needs no network:** no remote `$ref`, `--ext-refs` off, the ruleset is a local file. The install does (`go install`): CI jobs that run `make verify` install it in a step; developers install it once.
- American English everywhere. Work lands on the branch `issue-32-spec-validation`, one commit per task in the `type(scope): subject` style, ending with the two attribution lines the session reminder gives. No task pushes.
- Done gate: `make verify` (needs Docker; a run that skips the Postgres suites is not a pass) and `make check-gates-selftest`; then `ci.yml` and `windows.yml` green on the pushed commit. Task 6 and Task 7 each run both make targets and show their output.

## Rulings made by this plan (Eric may overrule)

1. **The ruleset extends `all`, not `recommended`, and the gate runs at `-n info`.** `info-contact` and `info-license` exist only in `all` and hard mode, so disabling them "citing #35" is meaningful only on that base; the probe (60 rules) shows the syntax works on 0.36.2. With `-n info` an inform fails the gate, so "clean" means zero findings of any severity. Cost if wrong: a future vacuum release adding a rule to `all` fails `make verify` until the rule is fixed or listed; the exact version pin (ruling 3) makes that a deliberate upgrade step.
2. **Seven rules off, each with a reason in the ruleset file; everything else fixed.** Off: `info-contact`, `info-license` (issue #35 decides the publisher contact and license); `camel-case-properties` (the wire's JSON members are snake_case in every schema and every `internal/bus` tag; a rename is a protocol change); `oas3-missing-example` (139 examples; examples are what CATS (#30) builds requests from, so #30 decides whether and how to add them: **Eric should see this one**); `oas3-api-servers` (the document describes no deployment; every consumer takes the base URL, and `server.Spec()` clears `servers` at `server.go:68`); `description-duplication` (the shared bound texts of #34 repeat by design); `openapi-tags-alphabetical` (the tags follow spec section 3's order: discovery, health, sessions, channels, messages, memories, tasks, admin, auth); and the whole OWASP set stays out of base (hard mode only): `owasp-define-error-responses-429` contradicts #33's per-operation declaration (a 429 only where a limiter exists), `owasp-string-restricted` contradicts #34's rule of patterns only where the core has a character rule, `owasp-rate-limit` wants `X-RateLimit-*` headers the server does not send, `owasp-integer-limit` and `owasp-integer-format` want bounds on response integers (#34 bounded requests); the five remaining OWASP rules (`owasp-protection-global-*`, `owasp-no-additional`, `owasp-no-numeric-ids`, `owasp-jwt-best-practices`) are noted in the file as unassessed, not disabled, because they never run. Fixed: 57 summaries, 20 request body descriptions, 13 parameter descriptions, 67 schema and 1 parameter component descriptions, 9 tag descriptions, the two dual-tag operations (ruling 5).
3. **Exact version pin, one variable, two failure texts.** `VACUUM_VERSION := 0.36.2` and `VACUUM ?= vacuum` in the Makefile; `spec-lint` fails with `spec-lint: vacuum is not installed; run: go install github.com/daveshanley/vacuum@v0.36.2 (or brew install vacuum and pin 0.36.2)` when `$(VACUUM)` is not found, and with `spec-lint: vacuum X installed, want 0.36.2` on a different `vacuum version`. Rulesets drift by version, so a different version is not a pass. CI installs with `go install github.com/daveshanley/vacuum@v$VACUUM_VERSION` in every job that reaches `spec-lint` (four: `verify`, `gate-negative`, the no-Docker negative job at `ci.yml:133-147`, and `check-gates-selftest`, whose block 14 runs `ci-gate-negative.sh` and so `make verify`, and whose block 38 runs `make spec-lint` itself), because `scripts/ci-gate-negative.sh` greps the log for the Postgres text and a missing-vacuum failure would make those jobs red for the wrong reason. `go install github.com/daveshanley/vacuum@v0.36.2` was proven on 2026-11-07 (a scratch `GOBIN`; the binary prints `v0.36.2`), so no download fallback is planned. `windows.yml` does not run `verify` and gets nothing.
4. **The ruleset lives at `api/vacuum-ruleset.yaml`**, next to the document; the Arazzo document at `api/arazzo.yaml` (`sourceDescriptions[0].url: openapi.yaml`); the journeys doc at `docs/journeys.md` (the `openapi:arazzo` default input; `profile:journeys` emits its contract as a reply and never writes into the repository, so the controller writes the file: the fenced JSON block first, prose after). `.local/openapi/config.yaml` gets `arazzo_spec: api/arazzo.yaml`. `apis.yaml` is declined: nothing consumes it.
5. **Dual tags become `[channels]`.** `DELETE` and `PATCH /v1/channels/{channel}` are channel operations whose access rule is the channel ACL's `Admin` permission, not the administrator flag (`internal/core/access`); `admin` on them conflated the two. Cost if wrong: a doc renderer lists them under channels only.
6. **Summaries and descriptions are sourced, not invented.** A summary is one line in the imperative or noun form ("Open a session", "The health document as the caller's tier sees it"); a description states what the handler does with the field or body, taken from the `internal/bus` type's doc comment or the handler file named in the task. The reviewer checks each against source. No description states a limit the spec does not carry.
7. **The completeness test is a scan plus a probe, and says what it proves.** `TestNoRoutesOutsideTheDocument` (go/ast over the non-test files of `internal/server`, `internal/server/cmd` and `internal/client/localmode`) allows exactly one `http.NewServeMux` call and one `gen.HandlerWithOptions` call, both in `server.go`, and no `Handle`, `HandleFunc`, `HandlerFromMux` or `HandlerFromMuxWithBaseURL` call anywhere: the server has no route the document does not generate. `TestDeclaredMethodsRouted` sends every documented (method, path) through `server.New` and asserts the answer is not the router's refusal; `TestUndeclaredMethodsRefused` sends the other four of `GET POST PUT PATCH DELETE` on every documented path and asserts the router's refusal (404 `not_found`, detail from kin: `no matching operation was found` or `method not allowed`; the implementer pins the exact text from the first run). The spec side is `TestOperationTable`'s literal table of 57. Stated limit: a 400 from the validator proves the kin router matched, not that the handler ran; the handler's presence is the compile-time interface, and `generate-check` keeps the generated router equal to the YAML.
8. **`TestOperationShape` is the Go test for the issue's "operationId, summary, security, responses" line**, in `internal/gen/openapi31_test.go` beside `TestOperationTable`: every operation has a non-empty `operationId` and `summary`, exactly one tag that the top-level `tags` defines, at least one 2xx response, and every response key is a three-digit status (no `default`; #33's `TestStatusTable/references` already forbids it and pins the shared references). Security is already pinned by `TestOperationTable` (8 open, 49 protected, the health shape). Descriptions are vacuum's job and are not duplicated in Go.
9. **The runner's supported surface, exactly.** Document: `arazzo: 1.0.x`, `info`, exactly one `sourceDescriptions` entry of `type: openapi` whose `url` is a relative file path resolved against the Arazzo file and loaded with `openapi3.NewLoader()` (external refs off), `workflows`. Workflow: `workflowId`, `summary`, `description`, `inputs` (a JSON Schema object: `required` names must be present in the inputs the caller passes and every passed input must be a declared property; property schemas are not validated), `dependsOn` (check only: every named workflow must have completed in this `Runner`, else an `*OrderError` naming the missing prerequisite; the runner never runs it for you), `steps`, `outputs`. Step: `stepId`, `description`, `operationId` (the bare id; resolved against the loaded document, case-sensitive), `parameters` (`name`, `in: path|query|header`, `value`), `requestBody` (`contentType: application/json` or `application/x-www-form-urlencoded`, `payload`), `successCriteria` (`condition` only), `outputs`. Expressions: `$inputs.<name>`, `$steps.<stepId>.outputs.<name>`, `$statusCode`, `$response.body`, `$response.body#/<json-pointer>` (RFC 6901, `~0` `~1` unescaped), and any of them embedded in a string with `{...}` (the result is a string; a value that is exactly one expression keeps the resolved value's type). Condition grammar: `<lhs> == <literal>` or `<lhs> != <literal>` where lhs is `$statusCode` or `$response.body#/<pointer>` and literal is an integer, a double-quoted string, `true`, `false` or `null`; comparison is on JSON values (numbers compared as float64). Refused with `*UnsupportedError{Where, Feature}` (one test each): a second `sourceDescriptions` entry, a `type` other than `openapi`, an absolute or remote `url`, `operationPath`, a step `workflowId`, `onSuccess`, `onFailure`, `successActions`, `failureActions`, `components`, a `reference` parameter, `requestBody.replacements`, `in: cookie`, a criterion `type` or `context`, another `contentType`, the expressions `$url`, `$method`, `$request.*`, `$response.header.*`, `$sourceDescriptions.*`, `$workflows.*`, `$components.*`, an unknown key anywhere (`yaml.Decoder.KnownFields(true)`), an unknown `operationId`, an undefined `$steps` or `$inputs` reference, a missing required input, an unknown workflow id, a pointer that does not resolve. Decision 3 names the supported features; `dependsOn` as a check and the form content type are this ruling's two additions, because the `openapi:arazzo` skill emits `dependsOn` from the journeys' `depends_on` edges and the token endpoint is form-encoded.
10. **The bearer travels as an Arazzo header parameter**, `Authorization: "Bearer {$steps.token.outputs.access_token}"` or `"Bearer {$inputs.bearer}"`, never injected by the runner: the document then shows the dependency on the token exchange. The Go test mints the inputs that need keys (the JWK, the client assertion with `assertion.Sign`, audience `fx.serverURL()`) and chains workflow outputs into the next workflow's inputs in Go, so the runner stays small. **Eric should see this one** (the alternative is an `http.Client` that injects the bearer, hiding the auth dependency from the document).
11. **The bridges workflow asserts the documented refusal.** The e2e server has no Slack tokens, so `createBridge`, `listBridges`, `getBridge` and `removeBridge` answer 503 `unavailable` (not retryable) by CLAUDE.md's rule; the workflow's criteria are `$statusCode == 503` and `$response.body#/code == "unavailable"`. It shows the admin-side composition (administrator bearer, the channel exists first) and the documented answer, not a live bridge. Standing up `slackfake` behind the real binary would need a server flag the product does not have; see Open for Eric 1.
12. **Admin bootstrap is split at the listener.** The host commands (`server admin admins add`, `enrollment create`) have no HTTP operation and stay in Go (the e2e fixture already runs `enrollment create`; the test runs `admins add`). The workflow covers the API half: `register` with an enrollment token, `token`, `createScope`, `createAgentIdentity` with `-scope`, `createIdentityByEmail`, `listSigningKeys`, `adminStatus`. The journeys doc says so, so `openapi:arazzo` does not flag the journey as non-API-shaped.
13. **Runner fixtures are recorded request logs.** `internal/arazzotest/testdata/` holds a tiny OpenAPI document (`createThing`, `getThing`, `listThings`, `token` form-encoded), `good.arazzo.yaml`, one `refuse-<feature>.arazzo.yaml` per refusal, and `good.golden`: the exact request log (`METHOD path?query`, sorted headers of interest, body) the fake server recorded plus the workflow outputs, compared byte for byte, with `-update` regenerating it. The real document is not used: the runner's tests must not move when `api/openapi.yaml` does.
14. **Spec descriptions and `spec-lint` land before the gate**, in Tasks 1 to 3, because `openapi:arazzo` reads operation summaries when it maps journeys.

## Open for Eric

1. **The bridges journey's fixture.** Ruling 11 runs it against the e2e server and asserts the documented 503. The alternative is a second e2e fixture whose server is wired to `internal/slackapi/slackfake`, which needs a test-only server flag or an in-process server in `internal/e2e` (the fixture today is the built binary over TCP). That is a change to the e2e architecture; Task 7 proceeds on ruling 11 unless Eric asks for the fixture.

## Coverage of the acceptance criteria (what exists, what this plan adds)

| Criterion | Already covered by | This plan |
| --- | --- | --- |
| `openapi:init` records the spec; the verdict goes on the issue | — | controller step C1 |
| `vacuum lint` with a committed ruleset, clean or disabled with a reason, in CI | — | Tasks 1 to 3 (`api/vacuum-ruleset.yaml`, `make spec-lint` in `verify`, CI installs) |
| constraints the server enforces (required, enums, formats, bounds, `additionalProperties`) | `TestSpecBounds`, `TestValidatorRefusesOverBound`, `TestOverBoundRefused` (#34); `TestJSONRequestBodiesAreClosed` (`internal/gen`) | nothing |
| every operation has `operationId`, summary, security, every response | `TestOperationTable` (ids, security), `TestOperationErrorTable`, `TestStatusTable` (#33: error responses per operation, the shared references, `Retry-After`) | Task 2 writes the 57 summaries and `TestOperationShape` |
| routes vs operations, both directions | `var _ gen.StrictServerInterface = (*api)(nil)`; `generate-check` | Task 4 (`TestNoRoutesOutsideTheDocument`, `TestDeclaredMethodsRouted`, `TestUndeclaredMethodsRefused`) |
| response validation in the suites | `internal/respcheck` wired into the inproc Bus suite (`TestInprocResponseCheckWired`), `TestAuthEndToEnd`, `internal/server` and `internal/server/cmd` (`TestMain` checks `respcheck.Late()`), the e2e proxy; the CATS hookup is #30 | nothing (the Arazzo test runs through the e2e proxy, so its responses are validated too) |
| every `bus.Code` to a documented code and status; every documented code reachable | `TestStatusTable`, `TestOperationErrorTable` (the producing site of each code is in the #33 plan's per-operation table), `TestStatusForEveryCode`, `TestRateLimitedSites`, `bus.Codes()` | nothing |
| Arazzo workflows for the six journeys, each run against the e2e server | — | Task 5 (runner), controller steps C2 to C4, Task 7 (`TestArazzoWorkflows`) |
| gaps fixed in the spec or the server, with tests | — | Tasks 1 to 3 (text), Task 4 (test); no server behavior gap was found in the evidence runs: the lint findings are all documentation, and a gap Task 7's workflows surface is fixed there with a test |
| `make verify`, `ci.yml`, `windows.yml` green | — | Tasks 6 and 7 |

## Review Focus

1. A summary or description that states something the handler does not do (ruling 6): the reviewer samples ten per task against the named source file.
2. A ruleset entry turned off without a reason line, or a reason that is not true of this repository (e.g. "servers" when `server.Spec()` no longer clears them).
3. `spec-lint` passing because of `--fail-severity` left at `error`: the target's `-n info` is checked by selftest block 38 (an inform-level mutation fails it).
4. The route probe calling a path the router matches by accident (a sample path parameter containing `/`): sample values are single plain segments.
5. The runner accepting a feature decision 3 does not list: every `refuse-*.arazzo.yaml` has a test, and `TestRefusalCoverage` fails when a refusal in the runner's `unsupported` list has no fixture.
6. The m4 rows for `internal/arazzotest` present in `scripts/m4-exit-checks.sh` and mutated in block 38.
7. `git diff --stat internal/gen` after every spec task: `gen.go` comments only.
8. Task 7 chaining a bearer the document did not mint (ruling 10): every `Authorization` value in `api/arazzo.yaml` is an expression over a `token` step's output or a workflow input the Go test filled from another workflow's output.

---

## Controller step C1 (before Task 1): `openapi:init` and the verdict on the issue

The controller (not an implementer) runs the `openapi:init` skill at the repository root: accept `api/openapi.yaml` (marker `openapi-3.1.0`, verified by vacuum), decline `apis.yaml` (ruling 4), then edit `.local/openapi/config.yaml` so `arazzo_spec: api/arazzo.yaml`. `.local/` is already in `.gitignore`. Post the discovery script's verdict as a comment on issue #32 (`gh issue comment 32 --body-file <scratchpad file>`): the validator name and version, the verdict, and the stock-ruleset counts (0 errors, 389 warnings, 69 informs on `e65a651`), with a sentence that Tasks 1 to 3 bring the committed ruleset to zero.

---

### Task 1: The ruleset, `make spec-lint` (standalone) and the tag findings

**Files:**
- Create: `api/vacuum-ruleset.yaml`
- Modify: `Makefile` (`VACUUM_VERSION`, `VACUUM`, the `spec-lint` target, `.PHONY`; not yet in `verify`)
- Modify: `api/openapi.yaml` (tag descriptions, the two dual tags; nothing else)
- Modify: `CLAUDE.md` (the Commands list: one bullet for `make spec-lint`, written in its final form: the ruleset path, the pin, the two failure texts; Task 3 adds "part of `verify`")

**The ruleset** (`api/vacuum-ruleset.yaml`; comments are the reasons, one per disabled rule):

```yaml
# vacuum ruleset for api/openapi.yaml (issue #32; vacuum 0.36.2, pinned in the Makefile).
# `make spec-lint` runs it at --fail-severity info: any finding fails. A rule is off only with
# a reason here. The OWASP rules are not in this base (vacuum runs them only with --hard-mode);
# see the note at the end.
extends: [[spectral:oas, all]]
rules:
  info-contact: off            # issue #35 decides the publisher contact (Eric's decision, 2026-11-06)
  info-license: off            # issue #35 decides the license (Eric's decision, 2026-11-06)
  camel-case-properties: off   # the wire's JSON members are snake_case (every schema, every internal/bus tag); a rename is a protocol change
  oas3-missing-example: off    # examples are what CATS (#30) builds requests from; #30 decides whether and how to add them
  oas3-api-servers: off        # the document describes no deployment; every consumer takes a base URL and server.Spec() clears servers
  description-duplication: off # the shared bound texts of #34 repeat by design (same unit, same limit)
  openapi-tags-alphabetical: off # the tags follow spec section 3's order (discovery, health, sessions, channels, messages, memories, tasks, admin, auth)
# Not in this base (hard mode only), assessed on e65a651 and left out: owasp-define-error-responses-429
# (contradicts #33: a 429 only where a limiter exists), owasp-string-restricted (contradicts #34: a
# pattern only where the core has a character rule), owasp-rate-limit (X-RateLimit-* headers the
# server does not send), owasp-integer-limit and owasp-integer-format (bounds on response integers;
# #34 bounded requests). Unassessed because they never run here: owasp-protection-global-safe,
# owasp-protection-global-unsafe, owasp-protection-global-unsafe-strict, owasp-no-additional,
# owasp-no-numeric-ids, owasp-jwt-best-practices.
```

**The target** (Makefile; tabs, not spaces):

```make
VACUUM_VERSION := 0.36.2
VACUUM ?= vacuum

spec-lint:   ## vacuum lint of api/openapi.yaml with api/vacuum-ruleset.yaml at fail-severity info (part of verify; needs vacuum $(VACUUM_VERSION))
	@command -v $(VACUUM) >/dev/null 2>&1 || { echo "spec-lint: vacuum is not installed; run: go install github.com/daveshanley/vacuum@v$(VACUUM_VERSION) (or brew install vacuum and pin $(VACUUM_VERSION))"; exit 1; }
	@v="$$($(VACUUM) version 2>/dev/null | tr -d '[:space:]' | sed 's/^v//')"; [ "$$v" = "$(VACUUM_VERSION)" ] || { echo "spec-lint: vacuum $$v installed, want $(VACUUM_VERSION)"; exit 1; }
	$(VACUUM) lint -r api/vacuum-ruleset.yaml -n info -d -q -b --no-clip api/openapi.yaml
```

The Homebrew binary's `vacuum version` prints `0.36.2`; a `go install`ed one prints `v0.36.2` (both checked on 2026-11-07), hence the `sed 's/^v//'`. Add `spec-lint` to `.PHONY`.

**The tag fixes:** give each of the nine top-level `tags` entries a one-line `description` (discovery: the well-known documents and `/v1/discover`; health: `GET /v1/health`; sessions: open, close, receive, watch, peek and agent status; channels: channels, ACLs, subscriptions and tag subscriptions; messages: send, history and search; memories: memory documents and their revisions; tasks: task lists; admin: administrator operations (scopes, identities, bridges, signing keys, status, usage, reset); auth: registration, the token endpoint and the JWKS). Change `tags: [channels, admin]` at `api/openapi.yaml:491` and `:514` to `tags: [channels]` (ruling 5). Keep the tag order (ruling 2).

- [ ] **Step 1: Write the ruleset and the target; run the lint (expected: the three description rules remain)**

Run: `make spec-lint 2>&1 | tail -20`
Expected: exit 1; the rule table shows exactly `component-description 68`, `operation-description 66`, `oas3-parameter-description 13`, total 147, 0 errors, 0 informs; no `tag-description`, `operation-singular-tag` or `openapi-tags-alphabetical` line. A line naming any other rule means the ruleset or the tag edit is wrong.

- [ ] **Step 2: The failure texts**

Run: `make spec-lint VACUUM=/nonexistent/vacuum; echo "exit $?"`
Expected: `spec-lint: vacuum is not installed; run: go install github.com/daveshanley/vacuum@v0.36.2 (or brew install vacuum and pin 0.36.2)` and `exit 1`.

Run: `printf '#!/bin/sh\necho 0.39.2\n' > /tmp/fakevacuum && chmod +x /tmp/fakevacuum && make spec-lint VACUUM=/tmp/fakevacuum; echo "exit $?"; rm /tmp/fakevacuum`
Expected: `spec-lint: vacuum 0.39.2 installed, want 0.36.2` and `exit 1`.

- [ ] **Step 3: Regenerate; check gen changed only in comments; commit**

Run: `make generate && git diff --stat internal/gen && go test ./internal/gen/ ./internal/server/ 2>&1 | tail -3`
Expected: `gen.go` and `spec/spec.go` changed; `rg -n '^[-+]' <(git diff internal/gen/gen.go) | rg -v '^[-+]\s*//' | rg -v '^(---|\+\+\+)'` prints nothing (comment lines only); `ok` for both packages.

```bash
git add api/vacuum-ruleset.yaml api/openapi.yaml Makefile CLAUDE.md internal/gen
git commit -m "chore(spec): the vacuum ruleset, make spec-lint and the tag descriptions (issue #32)"
```

---

### Task 2: Operation summaries, request body and parameter descriptions, `TestOperationShape`

**Files:**
- Modify: `api/openapi.yaml` (57 `summary` lines, 20 `requestBody.description`, 13 parameter `description`)
- Modify: `internal/gen/openapi31_test.go` (add `TestOperationShape`)

**Summaries (ruling 6):** one line each, placed directly after `operationId:` (the selftest anchors of blocks 36 and 37 span the whole operation, so the position is for readability and block 38's mutation). Source for the meaning: the handler file of the aggregate in `internal/server` (`sessions.go`, `channels.go`, `messages.go`, `memories.go`, `tasks.go`, `admin*.go`, `auth_handlers.go`, `discovery.go`, `health.go`, `agentstatus.go`: `rg -n 'func \(a \*api\) <OperationId>' internal/server`) and the matching `bus.Bus` method's doc comment in `internal/bus`. Examples of the register (write all 57 in this voice): `wellKnown`: "The agentmesh well-known document: where to discover the API"; `openSession`: "Open a session for the caller's identity, resuming by token or offering cursors"; `receive`: "Receive the next batch of messages for a session, acknowledging the previous one"; `watch`: "Long-poll until the session has something to receive or the timeout passes"; `peek`: "Count what receive would deliver without delivering it"; `health`: "The health document as the caller's tier sees it"; `token`: "Exchange a client assertion or a subject token for a bearer (RFC 6749, RFC 8693)"; `register`: "Register an identity's public key, with an enrollment token where registration is by enrollment"; `adminReset`: "Delete everything in the store (an administrator's reset)"; `doneScope`: "Retire a scope, with or without its bridge".

**Request body descriptions (20):** `openSession`, `receive`, `setAgentStatus`, `createChannel`, `renameChannel`, `setACL`, `subscribe`, `subscribeTags`, `sendMessage`, `editMemory`, `createTask`, `updateTask`, `claimTask`, `token`, `register`, `createIdentityByEmail`, `createAgentIdentity`, `createScope`, `doneScope`, `createBridge`: one line stating what the body carries (e.g. `setACL`: "The complete ACL that replaces the channel's; an agent that is not an administrator cannot remove a protected entry's permission").

**Parameter descriptions (13; vacuum names them by line):** `after` and `include_own` on `watch` (`:217`, `:236`), `include_own` on `peek` (`:274`), `before` and `after` on `history` (`:796`, `:804`), `mode`, `since`, `until`, `thread` on `search` (`:880`, `:900`, `:908`, `:916`), `scope` on `adminReset` (`:1445`), `revoke_previous` on `rotateSigningKey` (`:1540`), and two more the implementer takes from `make spec-lint`'s output (the line numbers above are from `e65a651` and move as text is added; the output, not this plan, is the list). Each names the unit and the default (e.g. `after`: "Deliver only messages with a sequence number above this one; default: the session's cursor").

**`TestOperationShape`** (in `internal/gen/openapi31_test.go`, package `gen_test`, uses `loadDoc`): for every operation of `doc.Paths.Map()`, `t.Run(lowerFirst(op.OperationID), ...)`: `op.OperationID != ""`, `strings.TrimSpace(op.Summary) != ""`, `len(op.Tags) == 1` and the tag is in `doc.Tags` (by name), at least one response key in `200..299`, every response key matches `^[1-5][0-9]{2}$` (so `default` fails here too, with its own message). The final `t.Run("count")` asserts 57 operations were seen (the number `TestOperationTable` pins).

- [ ] **Step 1: Write `TestOperationShape`; run it (expected: 57 failures on `summary`)**

Run: `go test ./internal/gen/ -run TestOperationShape 2>&1 | rg -c 'summary'`
Expected: 57.

- [ ] **Step 2: Write the summaries and descriptions; regenerate; run the lint and the tests**

Run: `make generate && make spec-lint 2>&1 | tail -12`
Expected: exit 1; the rule table shows exactly `component-description 68`, total 68.

Run: `go test ./internal/gen/ ./internal/server/ 2>&1 | tail -3 && git diff --stat internal/gen`
Expected: `ok` for both; `gen.go` comment-only (the Step 3 check of Task 1).

- [ ] **Step 3: Commit**

```bash
git add api/openapi.yaml internal/gen
git commit -m "docs(spec): a summary on every operation, descriptions on request bodies and parameters, TestOperationShape (issue #32)"
```

---

### Task 3: Component descriptions, `spec-lint` into `verify`, CI installs vacuum

**Files:**
- Modify: `api/openapi.yaml` (67 schema component descriptions, 1 parameter component description)
- Modify: `Makefile` (`$(MAKE) spec-lint` in `verify`, after `$(MAKE) lint` and before `$(MAKE) tidy-check`; the `verify` help line gains "spec lint")
- Modify: `.github/workflows/ci.yml` (an `Install vacuum` step in the four jobs of ruling 3: `verify` (before `make verify`), `gate-negative`, the no-Docker negative job at `:133-147`, and `check-gates-selftest` (before `make check-gates-selftest`), each after `setup-go`)
- Modify: `CLAUDE.md` (the Done gate sentence names `spec-lint`)

**Component descriptions (ruling 6):** `make spec-lint` lists the 68 by line. Each is one sentence from the matching `internal/bus` type's doc comment (`rg -n '^type <Name> struct' -B 3 internal/bus/*.go`) or, for request schemas, the handler's input converter. Request schemas that are closed objects keep their `additionalProperties: false`; no member is added or renamed.

**The CI step** (identical in the four jobs; `go` is on PATH from `setup-go`, which also puts `$(go env GOPATH)/bin` on PATH; the explicit `GITHUB_PATH` line makes that independent of the action's behavior). The install was proven on 2026-11-07 (`GOBIN=<scratch> go install github.com/daveshanley/vacuum@v0.36.2`; the binary prints `v0.36.2`, which the Makefile's `sed` strips):

```yaml
      - name: Install vacuum (pinned; make spec-lint checks the version)
        run: |
          go install github.com/daveshanley/vacuum@v0.36.2
          echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"
```

The version appears in the workflow once per job and in the Makefile once; `scripts/m9-exit-checks.sh` does not pin tool versions outside `release/` (check with `rg -n 'golangci' scripts/m9-exit-checks.sh`: if it does pin the golangci version against `ci.yml`, add vacuum to the same check, else leave it).

- [ ] **Step 1: Write the descriptions; regenerate; the lint is clean**

Run: `make generate && make spec-lint; echo "exit $?"`
Expected: `Passed with 0 errors, 0 warnings and 0 informs`, `exit 0`.

- [ ] **Step 2: Wire `verify` and CI; lint the workflow**

Run: `make release-lint 2>&1 | tail -3` (actionlint and shellcheck; both installed locally, else say so and run `actionlint` through the pinned download script of `ci.yml:118-121` into the scratchpad)
Expected: no findings.

Run: `sed -n '/^verify:/,/verify: OK/p' Makefile | rg -n 'spec-lint'`
Expected: one line, between `lint` and `tidy-check`.

- [ ] **Step 3: Tests, gen check, commit**

Run: `go test ./internal/gen/ ./internal/server/ 2>&1 | tail -3 && git diff --stat internal/gen`
Expected: `ok`; `gen.go` comment-only.

```bash
git add api/openapi.yaml internal/gen Makefile .github/workflows/ci.yml CLAUDE.md
git commit -m "chore(verify): spec-lint joins the done gate; every component described; CI installs vacuum 0.36.2 (issue #32)"
```

---

### Task 4: Route completeness in both directions

**Files:**
- Create: `internal/server/routes_test.go` (package `server`, uses `env` from `testenv_test.go`)

**`TestNoRoutesOutsideTheDocument`** (ruling 7): `go/parser` with `parser.SkipObjectResolution` over every non-`_test.go` file of `internal/server`, `internal/server/cmd` and `internal/client/localmode` (paths relative to the package directory: `.`, `cmd`, `../client/localmode`); walk `ast.CallExpr`; a call whose `Fun` is `*ast.SelectorExpr` with `Sel.Name` in `{"Handle", "HandleFunc", "NewServeMux", "HandlerFromMux", "HandlerFromMuxWithBaseURL", "HandlerWithOptions"}` is a site keyed `<file>:<Sel.Name>`; the allowlist is the literal `map[string]int{"server.go:NewServeMux": 1, "server.go:HandlerWithOptions": 1}`; any other site, or a different count, fails with the position. (Method values and `http.Handle` package-level calls are selectors too, so they are caught.)

**`TestDeclaredMethodsRouted`:** `e := newEnv(t, envOptions{})`, `e.identity("root", true)`; for every `(method, path)` of `Spec().Paths.Map()` (the embedded document the server serves), substitute path parameters with single-segment samples (`{channel}`: `c1`, `{scope}`: `s1`, `{identity}`: `pat`, `{session}`: `sess1`, `{id}`: `1`), build the request with no body and no query (a JSON operation gets `Content-Type: application/json` and body `{}` so the validator reaches the schema instead of refusing the missing body; the token operation gets a form body `grant_type=client_credentials`), send through `e.rawAllowUnrouted("root", req)`, and assert the answer is not the router's refusal: status is not 405, and when it is 404 the problem `detail` does not contain `no matching operation was found` or `method not allowed` (decode the problem; for `token`, the body is the OAuth error object and any 4xx is routed). Subtest per operation (`lowerFirst(op.OperationID)`), and a final count of 57.

**`TestUndeclaredMethodsRefused`:** for every documented path and each of `GET POST PUT PATCH DELETE` not declared on it, the same request shape; assert status 404, problem code `not_found`, and detail containing the kin text (pin the exact strings from the first run: `TestValidatorOnRealDocument` shows `method not allowed` for a known path with the wrong method; a wholly unknown path gives `no matching operation was found`). Subtest per `(method, path)`.

All three run without Docker (`make test`).

- [ ] **Step 1: Write the three tests; run them**

Run: `go test ./internal/server/ -run 'TestNoRoutesOutsideTheDocument|TestDeclaredMethodsRouted|TestUndeclaredMethodsRefused' -v 2>&1 | rg -c -- '--- PASS'`
Expected: 57 declared + the undeclared count (the implementer prints and pins it: 43 paths times 5 methods minus 57 = 158) + 1 scan + the two count subtests.

- [ ] **Step 2: Prove each fires**

Temporarily (do not commit) add `_ = http.NewServeMux()` in `server.go` after the `mux :=` block: the scan reports `server.go:NewServeMux` count 2. Revert. Temporarily change one subtest's sample from `c1` to `a/b` and watch the declared probe fail on the "no matching operation" text (an encoded slash is fine; a raw one is a different route): revert.

- [ ] **Step 3: Lint, commit**

Run: `go vet ./internal/server/ && make fmt-check && make lint`

```bash
git add internal/server/routes_test.go
git commit -m "test(server): the document's operations are the server's routes, both directions (issue #32)"
```

---

### Task 5: `internal/arazzotest`, the test-only Arazzo runner

**Files:**
- Create: `internal/arazzotest/doc.go` (package comment: what it is for, what it supports, that it is test-only and kept out of both binaries by the m4 rule), `internal/arazzotest/document.go` (types and `Load`), `internal/arazzotest/expr.go` (runtime expressions, embedded `{}`), `internal/arazzotest/criteria.go` (the condition grammar), `internal/arazzotest/runner.go` (`Runner`, `Run`), `internal/arazzotest/errors.go` (`UnsupportedError`, `OrderError`, `CriteriaError`, `ResolveError`)
- Create: `internal/arazzotest/runner_test.go`, `internal/arazzotest/testdata/openapi.yaml`, `internal/arazzotest/testdata/good.arazzo.yaml`, `internal/arazzotest/testdata/good.golden`, `internal/arazzotest/testdata/refuse-<feature>.arazzo.yaml` (one per refusal of ruling 9)
- Modify: `scripts/m4-exit-checks.sh` (the two `check_deps` rows beside `respcheck` at `:73-74`; the header comment at `:20` names `arazzotest` too)
- Modify: `go.mod` (`gopkg.in/yaml.v3` becomes a direct requirement: `go mod tidy`)
- Modify: `.gitattributes` (add `internal/arazzotest/testdata/** text eol=lf`: `windows.yml` runs this package's tests on a `core.autocrlf=true` checkout, and `good.golden` is compared byte for byte)

**Windows:** the source description's `url` is resolved with `filepath.Join(filepath.Dir(arazzoPath), filepath.FromSlash(url))`, never `path.Join`, so `repo_test.go` (Task 7) passes on `windows.yml`.

**Interfaces:**

```go
// Load parses an Arazzo document, resolves its one source description against
// the file's directory and binds every step's operationId to a method and path
// template of that OpenAPI document.
func Load(path string) (*Document, error)

type Document struct {
    Arazzo    string
    Info      Info
    Source    Source      // the one sourceDescriptions entry
    Workflows []Workflow  // in document order
    OpenAPI   *openapi3.T // the loaded source
}

type Runner struct {
    Doc     *Document
    BaseURL string       // the server (the e2e validating proxy)
    Client  *http.Client // nil: a client with a 30 s timeout
    Log     func(format string, args ...any) // nil: silent; the e2e test passes t.Logf
    done    map[string]bool // workflows completed in this runner (dependsOn)
}

type Result struct {
    Outputs map[string]any  // the workflow's outputs
    Steps   []StepResult
}

type StepResult struct {
    StepID        string
    Method, URL   string
    Status        int
    Body          []byte
    Outputs       map[string]any
}

func (r *Runner) Run(ctx context.Context, workflowID string, inputs map[string]any) (Result, error)

type UnsupportedError struct{ Where, Feature string } // "workflows[0].steps[2]", "operationPath"
type OrderError struct{ Workflow, Needs string }
type CriteriaError struct{ Workflow, Step, Condition string; Status int; Body []byte }
type ResolveError struct{ Where, Expr string; Cause error }
```

`Load` decodes with `yaml.NewDecoder(f)` and `KnownFields(true)` into structs that declare every key the Arazzo 1.0 object defines, with the unsupported ones declared as `*yaml.Node` or `any` so that presence (not shape) is detected and refused with `UnsupportedError` (an unknown key is a decode error reported as `UnsupportedError{Feature: "unknown key <k>"}`); `x-` extensions are refused as unknown keys too (none are expected). The path template's `{name}` segments are filled from the step's `in: path` parameters, each value percent-encoded once with `url.PathEscape` (the document's path-parameter rule at `api/openapi.yaml:5-12`); a missing path parameter is a `ResolveError`. Query parameters are `url.Values`; headers `http.Header.Set`. A JSON payload is marshaled after expression substitution; a form payload must resolve to a flat object of strings. The response body is read whole; JSON is decoded for `$response.body` expressions only when a criterion or output needs it (a non-JSON body with a pointer expression is a `ResolveError`).

**Tests** (`runner_test.go`, package `arazzotest_test`):
- `TestGoodWorkflow`: an `httptest.Server` with a scripted handler (`POST /token` form → 200 `{"access_token":"tok"}`; `POST /things` requires `Authorization: Bearer tok` and body `{"name":"x","count":2}` → 201 `{"id":41,"name":"x"}`; `GET /things/41?verbose=true` → 200 `{"id":41,"state":"ok","tags":["a"]}`; `GET /things?limit=5` → 200 `{"items":[...]}`); records one line per request (`METHOD path?query | Authorization: ... | Content-Type: ... | body`). `good.arazzo.yaml` has a `login` workflow (form body, output `access_token`) and a `things` workflow (`dependsOn: [login]`, input `bearer` required, header `Authorization: "Bearer {$inputs.bearer}"`, a path parameter from `$steps.create.outputs.id`, a query literal, criteria `$statusCode == 201`, `$response.body#/state == "ok"`, `$response.body#/tags/0 == "a"`, `$response.body#/id != 0`, outputs). The test runs `login`, feeds its output into `things`, and compares the recorded log plus the JSON of both `Result.Outputs` with `testdata/good.golden` (`-update` flag rewrites it).
- `TestDependsOnIsCheckedNotRun`: running `things` first is an `*OrderError{Workflow: "things", Needs: "login"}` and the fake server saw no request.
- `TestCriteriaFailure`: the handler answers 500 on `POST /things`; `*CriteriaError` names the step `create`, the condition, status 500 and carries the body; later steps did not run.
- `TestRefusals`: a table of every `refuse-*.arazzo.yaml` → `Load` or `Run` returns `*UnsupportedError` with the expected `Feature`; `TestRefusalCoverage`: the set of `Feature` strings the runner can produce (an exported `Unsupported() []string` listing them) equals the set the fixtures cover, so a new refusal without a fixture, or a stale fixture, fails.
- `TestResolveErrors`: unknown operationId, undefined `$steps.x.outputs.y`, missing required input, undeclared input, a pointer that does not resolve, a non-JSON body with a pointer: each a `*ResolveError` naming the expression.
- `TestEmbeddedExpressions`: `"Bearer {$inputs.bearer}"` and a payload whose member is exactly `$steps.create.outputs.id` keeps the number type (the fake server asserts the JSON type).
- `TestPathEscaping`: a path parameter `a/b 100%` arrives as `a%2Fb%20100%25`.

- [ ] **Step 1: Write the fixtures and the tests; run them (expected: compile failures, then red)**

Run: `go test ./internal/arazzotest/ 2>&1 | tail -5`

- [ ] **Step 2: Implement; run; record the golden**

Run: `go test ./internal/arazzotest/ -update && go test ./internal/arazzotest/ -count=1 -v 2>&1 | rg -c -- '--- PASS'`
Expected: every test passes; `testdata/good.golden` exists and is committed; `go test ./internal/arazzotest/ -race` passes.

- [ ] **Step 3: The m4 rows; tidy; lint; commit**

Run: `go mod tidy && git diff --stat go.mod go.sum && bash scripts/m4-exit-checks.sh --deps-only && go vet ./... && make fmt-check && make lint`
Expected: `go.mod` moves `gopkg.in/yaml.v3` to the direct block; the m4 script passes; (`go.sum` may gain nothing).

```bash
git add internal/arazzotest scripts/m4-exit-checks.sh go.mod go.sum
git commit -m "test(arazzotest): a test-only Arazzo runner over the document, decision 3's features and nothing else (issue #32)"
```

---

### Task 6: Selftest block 38, the ADR addendum, CLAUDE.md, the pre-gate done gate

**Files:**
- Modify: `scripts/check-gates-selftest.sh` (a `block_spec_validation_fires` function, appended to the dispatch list after `block_spec_bounds_fire`; a helper `mutate_lint_block`)
- Modify: `docs/adr/0001-transport-and-api.md` (an addendum "Spec validation (issue #32)")
- Modify: `CLAUDE.md` (a Design bullet "Spec validation (issue #32)")
- Modify: `docs/superpowers/plans/2026-11-07-issue-32-spec-validation.md` (nothing: the controller fills Task 7's table after the gate)

**Block 38 mutations** (each reverts, as the existing blocks do):
1. `spec-lint-fires`: `mutate_lint_block` removes the `description:` line of the `health` tag in `api/openapi.yaml` (`mutate_file`), runs `make -C "$wt" spec-lint > log; rc=$?`, wants `rc != 0` and `tag-description` in the log.
2. `spec-lint-inform-fires`: `mutate_lint_block` turns `openapi-tags-alphabetical: off` into `openapi-tags-alphabetical: info` in `api/vacuum-ruleset.yaml` (the tag order is not alphabetical, so three informs fire), wants `rc != 0` and `openapi-tags-alphabetical` in the log: this proves `-n info` is load-bearing (Review Focus 3).
3. `spec-lint-hint`: runs `make -C "$wt" spec-lint VACUUM=/nonexistent/vacuum`, wants `rc != 0` and `vacuum is not installed; run: go install github.com/daveshanley/vacuum@v` in the log.
4. `summary-missing`: `mutate_spec_block` with scope `operationId: listChannels`, from the whole `      summary: <text>` line (the implementer copies it) to `''`, package `./internal/gen/`, run `'^TestOperationShape$'`, want `TestOperationShape/listChannels`.
5. `stray-route-site`: `mutate_unit_block` on `internal/server/server.go`, from `	validator := nethttpmiddleware.OapiRequestValidatorWithOptions(` to `$'	_ = http.NewServeMux()\n	validator := nethttpmiddleware.OapiRequestValidatorWithOptions('`, package `./internal/server/`, run `'^TestNoRoutesOutsideTheDocument$'`, want `TestNoRoutesOutsideTheDocument`.
6. `m4-arazzotest-rule-fires`: two `deps_probe` calls in the shape of block 21's `respcheck` lines (`scripts/check-gates-selftest.sh:318-319`): `probe_m4.go` in `.` and in `cmd/agentmesh-mcponly` importing `internal/arazzotest`, each wanting `deps_violation=<module>[/cmd/agentmesh-mcponly] imports <module>/internal/arazzotest` from `scripts/m4-exit-checks.sh --deps-only`.
7. `arazzo-refusal-fixture-missing`: `mutate_file` deletes `internal/arazzotest/testdata/refuse-operationPath.arazzo.yaml` (use `rm` in a small `mutate_rm_block` if `mutate_file` cannot delete; the block's revert is `git checkout`), run `./internal/arazzotest/` `'^TestRefusalCoverage$'`, want `TestRefusalCoverage`.

The Task 7 mutation (`arazzo-criteria-fire`) is added to this block in Task 7.

**ADR 0001 addendum "Spec validation (issue #32)":** Eric's three decisions labeled as his (2026-11-06), the rulings 1 to 14 of this plan labeled as the plan's, the ruleset path, the gate (`make spec-lint`, `-n info`, the pin), the two-direction test and its stated limit, the runner's supported surface and refusal rule, where `api/arazzo.yaml` and `docs/journeys.md` live, and that the production server validates requests only (decision 1).

**CLAUDE.md Design bullet:** "Spec validation (issue #32, Eric 2026-11-06, ADR 0001 addendum): `make spec-lint` runs vacuum 0.36.2 (`VACUUM_VERSION`, exact) with `api/vacuum-ruleset.yaml` (`all`, seven rules off with reasons) at fail-severity info, inside `verify`; `TestOperationShape` (`internal/gen`) pins operationId, summary, one defined tag and a 2xx per operation; `TestNoRoutesOutsideTheDocument`, `TestDeclaredMethodsRouted` and `TestUndeclaredMethodsRefused` (`internal/server/routes_test.go`) are the route completeness test; `internal/arazzotest` (test-only, kept out of both binaries by the m4 rule) runs `api/arazzo.yaml` (from `docs/journeys.md`, Eric's hand-tuned journeys) against the e2e server in `TestArazzoWorkflows`; it supports steps by operationId, path/query/header parameters, JSON and form bodies, `$inputs`, `$steps`, `$statusCode`, `$response.body#/ptr`, `==`/`!=` criteria, outputs and `dependsOn` as a check, and refuses every other Arazzo feature by name. Mutations: `scripts/check-gates-selftest.sh` block 38."

- [ ] **Step 1: Write the block, the ADR addendum and the bullet; rehearse each mutation by hand**

The selftest has no single-block mode (its tail is a plain list of `block_*` calls; `scripts/check-gates-selftest.sh:1405-1449`). Before Step 3, apply each of the seven mutations by hand in the checkout, run the named test or target, confirm the expected `FAIL`/exit and text, and revert (`git checkout -- <file>`), so Step 3's run is not the first time they are tried.

- [ ] **Step 2: Shell lint**

Run: `make release-lint 2>&1 | tail -3`
Expected: clean.

- [ ] **Step 3: The pre-gate done gate**

Run: `make verify 2>&1 | tee /tmp/issue32-verify.log | tail -5 && make check-gates-selftest 2>&1 | tee /tmp/issue32-selftest.log | tail -8`
Expected: `verify: OK`; the selftest's summary reports every block `ok`, block 38 included. Paste both tails into the task report.

```bash
git add scripts/check-gates-selftest.sh docs/adr/0001-transport-and-api.md CLAUDE.md
git commit -m "test(gates): block 38 proves spec-lint, the shape test, the route scan and the m4 row fire; ADR 0001 addendum (issue #32)"
```

---

## Human gate: controller steps C2 to C4

**C2 (controller): journeys.** Run the `profile:journeys` skill at the repository root (it invokes `profile:stack` and `profile:docs` itself when not handed their contracts). Write its contract into `docs/journeys.md`: a heading, one paragraph on provenance (the skill, the commit, the date), the fenced ```` ```json ```` block with the contract, then one section per journey (name, actor, narrative, entry point, depends_on, evidence). Make sure the six journeys of the issue are present, API-shaped and named as the issue names them: register and log in (`register` + `token`), send and receive with ack (`openSession`, `subscribe`, `sendMessage` from a second identity, `receive` twice, the second with `ack`), memories (`createChannel` with `kind: memory`, `sendMessage` into it (a memory is a message of a memory channel; `EditResult.memory_id` names it), `getMemory`, `editMemory`, `listMemoryRevisions`, `deleteMemory`), task claim and complete (`createTask`, `claimTask`, `updateTask` to completed, `getTask`), admin bootstrap (ruling 12), bridges (ruling 11). Journeys whose actor is a CLI or TUI user (`init`, `wait`, hooks, `tui`) stay in the doc flagged as non-API-shaped. Commit: `docs(journeys): the customer journeys from profile:journeys, for Eric to tune (issue #32)`.

**C3: STOP.** Tell Eric the doc is at `docs/journeys.md`, list the journeys in one line each, and wait. Eric edits the file by hand (decision 3). Nothing below runs until he says the journeys are final. Commit his edits as `docs(journeys): Eric's hand-tuned journeys (issue #32)` when he does not commit them himself.

**C4 (controller): Arazzo.** Run the `openapi:arazzo` skill with `docs/journeys.md`. At its mapping gate, check against ruling 9: every step binds by `operationId`; parameters are `path`, `query` or `header`; bodies are JSON or form; every criterion is `$statusCode == N` or `$response.body#/ptr == literal`/`!=`; outputs are `$response.body#/ptr` or `$statusCode`; `dependsOn` names only workflows in the file; the bearer is a header parameter (ruling 10); inputs that need keys are declared in `inputs` (`enrollment_token`, `identity`, `public_key_jwk`, `client_assertion`, `bearer`, `admin_bearer`, ...) so the Go test can fill them. Anything outside ruling 9 is edited at the gate, not after. The skill writes `api/arazzo.yaml` (from the config). Check it loads: a throwaway `go test` in the scratchpad is not possible from outside the module, so write `internal/arazzotest/repo_test.go` now (Task 7 lists it: `TestLoadRepositoryDocument` calls `Load("../../api/arazzo.yaml")`) and run `go test ./internal/arazzotest/ -run TestLoadRepositoryDocument`; a `*UnsupportedError` sends the document back to the skill's gate. Then fill Task 7's workflow table below (ids, inputs, chaining) from the file and dispatch Task 7.

---

### Task 7: `TestArazzoWorkflows` against the e2e server, the final mutation, the done gate

**Files:**
- Create: `internal/e2e/workflows_test.go` (`//go:build !windows`, package `e2e_test`; named so it sorts after `mcponly_test.go`: Go runs a package's tests in file-name order, and the package doc (`e2e_test.go:9-12`) relies on `TestSection24Sequence` running before anything has opened a session, so `arazzo_test.go` would break its display-name assertions)
- Create: `internal/arazzotest/repo_test.go` (`TestLoadRepositoryDocument`: `Load("../../api/arazzo.yaml")` succeeds and every workflow id of the table below exists)
- Modify: `scripts/check-gates-selftest.sh` (block 38 gains `arazzo-criteria-fire`)
- Modify: `CLAUDE.md` (the Commands list: `api/arazzo.yaml` and `docs/journeys.md` named in the `make test` or e2e bullet), `docs/adr/0001-transport-and-api.md` (one line: the workflows landed, the ids)
- Modify: `api/arazzo.yaml` only when a workflow needs a fix the runner's error names (and then the fix is the document's, never the runner's: a feature outside ruling 9 goes back to C4)

**The workflow table** (the controller fills this from `api/arazzo.yaml` before dispatch; the shape below is the contract):

| Order | workflowId | Inputs the test provides | Outputs chained forward |
| --- | --- | --- | --- |
| 1 | `<register-and-log-in>` | `enrollment_token` (from `run(fx.homeA, "server", "admin", "-sqlite", fx.sqlite, "enrollment", "create")`, parsed with `tokenRE`), `identity` (`arazzo-ann`), `public_key_jwk` (`keys.Generate(keys.EdDSA)`, `keys.KID`, `keys.ToJWK` marshaled to a JSON object), `client_assertion` (`assertion.Sign(assertion.Input{Identity, Audience: fx.serverURL(), Key, KID, Now: time.Now()})`), `client_assertion_type` (`assertion.Type`) if the document declares it as an input | `access_token` |
| 2 | `<send-and-receive-with-ack>` | `bearer` (from 1), `peer_bearer` (a second identity registered the same way in Go, or by running workflow 1 twice with different inputs: prefer the second run), channel name | — |
| 3 | `<memories>` | `bearer` | — |
| 4 | `<task-claim-and-complete>` | `bearer` | — |
| 5 | `<admin-bootstrap>` | an administrator's inputs: register a third identity (`arazzo-root`) through workflow 1, then `mustRun(t, fx.homeA, "server", "admin", "-sqlite", fx.sqlite, "admins", "add", "-identity", "arazzo-root")` (the host command refuses an unregistered name with "register it first": `internal/server/cmd/admin_test.go:79`; the flag is read from the identity row on every request, `internal/core/access/principal.go:42`, so the bearer minted before the flag is set still acts as an administrator), then its `access_token` as `admin_bearer`; `scope` and identity names unique to this test | `admin_bearer` reused by 6 |
| 6 | `<bridges>` | `admin_bearer`, a channel name | — |

The test runs them in this order in one `TestArazzoWorkflows` with `t.Run(workflowId, ...)` per workflow; a failure stops the sequence (`t.Fatal`), since later workflows depend on earlier outputs. `Runner{Doc, BaseURL: fx.serverURL(), Log: t.Logf}`: every request crosses the validating proxy, so `runMain`'s violation and `Skipped` checks cover these responses too. Each `StepResult` is logged on one line (`stepId method URL status`).

**The gate guards this test, so the counts stay:** the m6 script counts `TestSection24Sequence` steps and `TestExitCodeTable` cells by name; a new test in the package changes neither. The word check lists files, not the package.

**Block 38 mutation 8, `arazzo-criteria-fire`:** `mutate_unit_block` (the helper that takes a package and a `-run` pattern; `mutate_block` runs the Bus conformance suite only) on `api/arazzo.yaml`, from the first `$statusCode == 201` (the implementer picks a criterion whose step is in workflow 1 and quotes the whole line so the anchor is unique) to `$statusCode == 200`, package `./internal/e2e/`, run `'^TestArazzoWorkflows$'`, want `--- FAIL: TestArazzoWorkflows/<workflow 1 id>` and the text `criteria` in the log (`CriteriaError`'s message starts with `arazzo: criteria failed`). The e2e package builds the binary (about 30 s); the block's log is in `$tmp`.

- [ ] **Step 1: Write `TestLoadRepositoryDocument` and the e2e test; run the e2e package**

Run: `go test ./internal/e2e/ -run 'TestArazzoWorkflows' -count=1 -v 2>&1 | tee /tmp/issue32-arazzo.log | rg -- '--- (PASS|FAIL)|arazzo:'`
Expected: `--- PASS: TestArazzoWorkflows` with six passing subtests. A `CriteriaError` here is a finding: either the document's expectation is wrong (fix `api/arazzo.yaml`, say so in the report) or the server's answer is not what the document promises (that is a real gap: fix the server or the OpenAPI document with a test, as the issue requires, and report it as such).

- [ ] **Step 2: The mutation; the whole e2e package; m6 counts**

Run: `go test ./internal/e2e/ -count=1 -v > /tmp/issue32-e2e.log 2>&1; bash scripts/m6-exit-checks.sh /tmp/issue32-e2e.log | tail -6`
Expected: `sequence=13 exitcodes=11 fail=0 pkg_ok=1`.

- [ ] **Step 3: The done gate; commit**

Run: `make verify 2>&1 | tee /tmp/issue32-verify2.log | tail -5 && make check-gates-selftest 2>&1 | tee /tmp/issue32-selftest2.log | tail -8`
Expected: `verify: OK`; every block `ok`, block 38 with eight mutations. Paste both tails into the task report.

```bash
git add internal/e2e/workflows_test.go internal/arazzotest/repo_test.go api/arazzo.yaml scripts/check-gates-selftest.sh CLAUDE.md docs/adr/0001-transport-and-api.md
git commit -m "test(e2e): the Arazzo workflows of the six journeys run against the e2e server (issue #32)"
```

---

## Controller step C5 (after Task 7): local merge

The controller fast-forwards `main` to the branch, runs `make verify` on `main`, then deletes the branch and the SDD workspace. Nothing is pushed (Eric, 2026-11-07: commit and merge locally only), so `ci.yml` and `windows.yml` stay unverified and are reported as open. The issue comment (the ruleset path and the seven disabled rules, the counts before and after, the three Task 4 test names, the runner and the six workflow ids, the fixed gaps, the Open for Eric item) is drafted for Eric rather than posted. Close the issue only when Eric says so.
