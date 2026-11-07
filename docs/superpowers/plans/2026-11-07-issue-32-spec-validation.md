# Issue 32: Spec Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Tasks 1 to 6A run before the human gate; the controller steps and Task 7 run after it.

**Goal:** `api/openapi.yaml` lints clean under a committed vacuum ruleset that `make verify` runs (`make spec-lint`), every operation carries a summary, every documented operation is the one the server serves and nothing else is served (a two-direction test), the acceptance criteria already met by issues #29, #33 and #34 are named rather than re-implemented, and the main customer journeys exist as Arazzo workflows (`api/arazzo.yaml`) that a small test-only runner (`internal/arazzotest`) executes against the e2e server.

**Architecture:** Nothing new runs in production. The server's router is generated from the document (`gen.HandlerWithOptions`, `internal/server/server.go:102`) and `var _ gen.StrictServerInterface = (*api)(nil)` (`internal/server/api.go:39`) makes "every operation is served" a compile-time fact; no non-test code outside `server.New` registers a route (`rg -n '\.Handle\(|\.HandleFunc\(|NewServeMux\(' internal cmd --glob '!*_test.go'` finds only `internal/gen`, `internal/oidcclient` and `internal/oidctest`). The completeness test therefore pins that fact with a sites scan plus a method-level probe through `server.New`, instead of pretending to enumerate an `http.ServeMux`. Response validation is already `internal/respcheck`, wired into the inproc Bus suite, `TestAuthEndToEnd`, the `internal/server` and `internal/server/cmd` tests and the e2e validating proxy (issue #33); the code-to-status table is `TestStatusTable`/`TestOperationErrorTable` (issue #33); the request bounds are `TestSpecBounds` (issue #34). The lint is vacuum 0.36.2 over a ruleset that extends `all` and turns seven rules off, each with a reason in the file. The Arazzo runner is a test-only package (kept out of both binaries by the m4 rule, like `internal/respcheck`) that supports exactly the features of Eric's decision 3 and refuses everything else by name. The bridges journey runs against a live bridge (Eric's decision 4): a second e2e fixture starts the same server wiring in the test process through `cmd.RunWith` (the exported form of the `run` seam `internal/server/cmd/cmd_test.go:270,726` already injects a serving function through) with `internal/slackapi/slackfake` in `Config.Slack` where `cmd.Run` puts the slack-go adapter; the binary's `main` keeps calling `cmd.Run` (`main.go:35`), and no flag, setting, environment variable or build tag selects the fake, so the release binary carries no way to bypass real Slack.

**Tech Stack:** Go (`CGO_ENABLED=0`), kin-openapi v0.151.0 (`openapi3`), oapi-codegen v2.8.0 (`internal/gen`, never edited by hand), `gopkg.in/yaml.v3` v3.0.1 (already in the module graph, indirect today), vacuum 0.36.2 (Homebrew locally, `/opt/homebrew/bin/vacuum`; brew stable is already 0.39.2, so the pin is exact), bash gate scripts (`set -euo pipefail`, shellcheck-clean).

**Spec:** GitHub issue #32 (body) and Eric's decisions of 2026-11-06 (1: response validation in the test suites only; 2: `spec-lint` in `make verify`, fail-fast install hint, CI installs a pinned vacuum, the ruleset disables `info-license` and `info-contact` citing #35; 3: journeys from `profile:journeys`, Eric tunes them by hand, `openapi:arazzo` emits `arazzo.yaml`, a small test-only Go runner using kin-openapi runs them against the e2e server, supporting steps by operationId, runtime-expression parameters and bodies, success criteria on status and JSON pointer, and step outputs, refusing any other feature loudly, with its own tests); and Eric's decision 4 (2026-11-07): the bridges journey runs against a live bridge, through a second e2e fixture whose server is wired to `internal/slackapi/slackfake`; it replaces plan ruling 11 and closes the former Open for Eric 1. CLAUDE.md (the `api/openapi.yaml` and `make generate` rules, Decision 47 and the m4/m6/m7/m10 import rules, the pre-release rule), ADR 0001 (choices 3, 11, 13; the issue #29, #33 and #34 addenda), ADR 0007 (choice 6, the validator). Evidence on `e65a651` (2026-11-07, read-only runs, output in the scratchpad `issue32/`): `vacuum lint` with the stock recommended ruleset (55 rules) exits 0 with 0 errors, 389 warnings, 69 informs, quality 25/100: `oas3-missing-example` 139, `camel-case-properties` 102, `description-duplication` 69, `component-description` 68 (67 schemas, 1 parameter), `operation-description` 66 (46 operations with neither summary nor description, 20 request bodies without a description), `oas3-parameter-description` 13, `oas3-api-servers` 1. Hard mode (`-z`, OWASP included) exits 1 with 568 errors, 450 warnings, 79 informs: `owasp-rate-limit` 311, `owasp-string-restricted` 172, `owasp-integer-limit` 66, `owasp-define-error-responses-429` 47, `owasp-integer-format` 14, `owasp-protection-global-safe` 5, `owasp-protection-global-unsafe-strict` 2, `owasp-protection-global-unsafe` 2, `owasp-no-additional` 2, `owasp-no-numeric-ids` 1, `owasp-jwt-best-practices` 1, `info-license` 1, `info-contact` 1 (plus the recommended set). A probe ruleset extending `all` (60 rules) with the six rules of ruling 2 off and the three description rules off leaves 14 findings: `tag-description` 9, `openapi-tags-alphabetical` 3 (informs), `operation-singular-tag` 2 (`DELETE` and `PATCH /v1/channels/{channel}` carry `[channels, admin]`). The document has 57 operations, 57 `operationId`s, 0 `summary` members, 8 operation-level `security` members (the open operations), one global `bearerAuth` requirement, no `servers`. Default fail severity is `error`, so the stock run passes with 389 warnings: `-n info` is what makes the gate bite.

## Global Constraints

- **Eric's decisions (2026-11-06, issue #32), binding:** see Spec. The production server does not validate its responses; nothing in this plan adds a response validator to `server.New`.
- **Issue acceptance criteria, binding:** `openapi:init` records the spec and the validator's verdict goes on the issue; `vacuum lint` runs with a committed ruleset and is clean, or each remaining rule is disabled with a reason; every operation has `operationId`, a summary, its security and every response it can give; a test enumerates routes against operations in both directions; response validation in the suites (done: #33); every `bus.Code` maps to a documented code and status (done: #33); Arazzo workflows for register and log in, send and receive with ack, memories, task claim and complete, admin bootstrap, bridges, each run against the e2e server; every gap fixed in the spec (then `make generate`) or the server, with a test; #29's `TestWireRoundTrip` and `TestToolCoverage` stay green.
- **The protocol version stays `1.0.0`** (`info.version` and `version.Protocol` untouched; pre-release rule, Eric 2026-10-27). Every spec change here is documentation (summaries, descriptions, tags): no schema, path, member or status changes.
- **Never edit `internal/gen` by hand.** Every spec task ends with `make generate` and `git diff --stat internal/gen` showing `gen.go` changed only in comments and `spec/spec.go` in the embedded bytes. A generated type change means a task wrote something other than text: stop and report.
- **Coordination with #29, #33, #34:** `TestWireRoundTrip`, `TestToolCoverage`, `TestStatusTable`, `TestOperationErrorTable`, `TestSpecBounds` and the selftest blocks 34 to 37 run unchanged. A text edit that moves an anchor a `mutate_spec_block` call depends on (`scripts/check-gates-selftest.sh` blocks 36 and 37 anchor on `operationId: sendMessage`, `operationId: listChannels`, `    TooManyRequests:` and the bound lines) must keep that anchor unique in its span: summaries go on the line directly after `operationId:`, descriptions after `summary:`.
- **Import rules hold.** `internal/arazzotest` imports the standard library, kin-openapi `openapi3` and `gopkg.in/yaml.v3` only, never `internal/server`, `internal/gen`, `internal/core`, `internal/bus` or `internal/store`; the m4 rule (`scripts/m4-exit-checks.sh:73-74`) gains the rows `check_deps . internal/arazzotest` and `check_deps ./cmd/agentmesh-mcponly internal/arazzotest`, so neither binary links it. `internal/e2e` is `//go:build !windows` and already imports `internal/server`, `internal/respcheck`, `internal/auth/keys` and `internal/auth/token`; the Arazzo test adds `internal/arazzotest` and `internal/auth/assertion`. `internal/gen`'s test file imports nothing new. Task 6A adds `internal/server/cmd`, `internal/slackapi` and `internal/slackapi/slackfake` to `internal/e2e`'s imports: it is an all-test package (`e2e_test`) that no gate script lists (the m6 consumer group and the m7 `slack-consumers` list name other packages and read non-test imports, `scripts/m6-exit-checks.sh:20-22`, `scripts/m7-exit-checks.sh:221-224`; `slack-go-importers` is direct-only, so the transitive pull of slack-go through `server/cmd` into the test binary is not a hit; `slackfake`'s own allowlist is unchanged). The m6 consumer group, the m7 and m10 rules are untouched.
- **Shell:** every script change stays `set -euo pipefail` and shellcheck-clean (`make release-lint`). Never run `vacuum generate-ruleset` inside the checkout: it writes `ruleset-<name>.yaml` into the working directory.
- **Vacuum needs no network:** no remote `$ref`, `--ext-refs` off, the ruleset is a local file. The install does (`go install`): CI jobs that run `make verify` install it in a step; developers install it once.
- American English everywhere. Work lands on the branch `issue-32-spec-validation`, one commit per task in the `type(scope): subject` style, ending with the two attribution lines the session reminder gives. No task pushes.
- Done gate: `make verify` (needs Docker; a run that skips the Postgres suites is not a pass) and `make check-gates-selftest`; then `ci.yml` and `windows.yml` green on the pushed commit. Tasks 6, 6A and 7 each run both make targets and show their output.

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
11. **Superseded by Eric's decision 4 (2026-11-07).** The plan ruled that the bridges workflow asserts the documented 503 `unavailable` of a server without Slack tokens, because the e2e fixture is the built binary and standing `slackfake` behind it would need a server flag. Eric decided instead that the bridges journey runs against a live bridge: Task 6A builds the second e2e fixture (the Slack fake behind the server wiring, ruling 15) and Task 7's bridges workflows assert the live answers (rulings 16 and 17). The 503 stays covered by `internal/server/bridges_test.go:131` and `internal/cli/bridges_test.go:91`, and Task 6A's test keeps one control against the first fixture.
12. **Admin bootstrap is split at the listener.** The host commands (`server admin admins add`, `enrollment create`) have no HTTP operation and stay in Go (the e2e fixture already runs `enrollment create`; the test runs `admins add`). The workflow covers the API half: `register` with an enrollment token, `token`, `createScope`, `createAgentIdentity` with `-scope`, `createIdentityByEmail`, `listSigningKeys`, `adminStatus`. The journeys doc says so, so `openapi:arazzo` does not flag the journey as non-API-shaped.
13. **Runner fixtures are recorded request logs.** `internal/arazzotest/testdata/` holds a tiny OpenAPI document (`createThing`, `getThing`, `listThings`, `token` form-encoded), `good.arazzo.yaml`, one `refuse-<feature>.arazzo.yaml` per refusal, and `good.golden`: the exact request log (`METHOD path?query`, sorted headers of interest, body) the fake server recorded plus the workflow outputs, compared byte for byte, with `-update` regenerating it. The real document is not used: the runner's tests must not move when `api/openapi.yaml` does.
14. **Spec descriptions and `spec-lint` land before the gate**, in Tasks 1 to 3, because `openapi:arazzo` reads operation summaries when it maps journeys.
15. **The Slack fixture is the server wiring in the test process, entered through `cmd.RunWith`, with the fake in `Config.Slack`.** `slackfake.Fake` is an in-process double (no HTTP: `internal/slackapi/slackfake/fake.go:1-4`), and the test must hold it to add the Slack user (`AddUser`), inject a message (`Say`) and read what the bridge posted (`Channel(id).Posts`). The three designs considered: (a) a test-only flag or build tag in the binary: the fake would live in the server process, so the test would also need a control endpoint for those three calls (a second protocol), the e2e build would need the tag while `make test` runs `go test` untagged, and a gate would have to keep the tag out of `release/build-archive.sh`; (b) a hand-built `cmd.Config` in the test, as `TestServeSlackBridge` does (`internal/server/cmd/serve_test.go:448`): that path has no issuer, signing keys or bearer verifier, so the test would duplicate the ~150 lines of `run`'s wiring (`cmd.go:56-230`) and drift from it; (c) chosen: export the seam that already exists. `run(ctx, args, environ, stdout, stderr, serve)` takes the serving function; `RunWith` is that function exported, `Run` is unchanged and stays the binary's only entry (`main.go:35`). The fixture passes `func(ctx, c) error { c.Slack = fake; ...; return cmd.Serve(ctx, c) }`, so flags, settings, the store, the issuer, the signing keys and the bearer verifier are exactly the binary's. Safety: `RunWith` is reachable from Go code of this module only; no flag, setting, variable or build tag selects another serving function, so the release binary ships no backdoor and no gate-script check is needed (the reviewer confirms `rg -n 'RunWith\(' --glob '!*_test.go' .` finds only the definition). Nothing new runs in production.
16. **J9 is two workflows, because an Arazzo step is one request and the bridge is created inside the workflow.** The runner has no hook between steps (decision 3, ruling 9), and the Slack message can only be injected after `createBridge` has made the Slack channel. So `bridges` (channel in the scope with a named-only ACL that grants the administrator and the human read and write, `createBridge`, `listBridges`, `getBridge`, `sendMessage` into the channel: the outbound half) outputs `slack_channel_id` and the message `seq`; the Go test waits for the post to reach the fake, injects the Slack message and waits for it to land; then `bridges-inbound-remove` (`history` after `seq` with the inbound text and `sender_kind == "human"` as criteria, `removeBridge`, `getBridge` showing `archived`) asserts the inbound half through the API and removes the bridge. `dependsOn: [bridges]` links them. The alternative (one CRUD workflow, the round trip only in Task 6A's Go test) shows less of the journey through the API; the issue asks for workflows that show the journey.
17. **Fixture 2 is isolated, shares the validator, and the workflows that feed J9 run again against it.** Its own SQLite file, listener (`127.0.0.1:0`), `-registration enrollment` (explicit, since a loopback listener defaults to `open`), its own validating proxy over the same `respcheck.Checker` and violation log as fixture 1, so `runMain`'s two final checks cover both servers with one tally. Bearers do not cross fixtures and the runner's `dependsOn` check is per `Runner`, so Task 7 runs the register and admin-bootstrap workflows a second time against fixture 2 (a second `Runner`, identities and scope names of its own) before `bridges`. Selftest block 38 gains `slack-fixture-fires` (one more e2e package run, about 40 s) so the fixture's test is shown to depend on the bridge wiring.

## Open for Eric

None. The former item 1 (the bridges journey's fixture) is closed by Eric's decision 4 (2026-11-07): the second fixture, Task 6A.

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
| Arazzo workflows for the six journeys, each run against the e2e server | — | Task 5 (runner), Task 6A (the Slack-fake fixture the bridges journey runs on), controller steps C2 to C4, Task 7 (`TestArazzoWorkflows`) |
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
9. `cmd.RunWith` reachable from anything but Go code: `rg -n 'RunWith\(' --glob '!*_test.go' .` finds only its definition; `main.go:35` still calls `cmd.Run`; no flag, setting, variable or tag names the fake (ruling 15).
10. The bridges workflows passing without a bridge: no `503` or `unavailable` criterion in the two J9 workflows, `createBridge` wants `201` and `state == "live"`, and block 38's `slack-fixture-fires` and `arazzo-criteria-fire` both fail when the wiring or the criteria are wrong.

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

### Task 6A: The Slack-fake e2e fixture (`cmd.RunWith`, `slackFx`, `TestSlackBridgeFixture`), block 38 mutation 8

Eric's decision 4 (2026-11-07): the bridges journey runs against a live bridge. This task builds the fixture Task 7's two bridges workflows run on and proves it with a Go test that needs no Arazzo document, so it runs before the human gate. Design: ruling 15 (the seam), ruling 17 (isolation). Read `internal/e2e/e2e_test.go:150-305` (`runMain`, `startFixture`), `internal/server/cmd/cmd.go:39-62,196-230` (`Run`, `run`, the `Config` the flags produce), `internal/server/cmd/serve.go:131-165` (the bridge and its runner), `internal/slackapi/slackfake/fake.go` (`New`, `AddUser`, `Say`, `Channel`, `FindPrivateChannel`, `Calls`), `internal/slackbridge/create.go:70-96` and `inbound.go:138-340` (what a create and an inbound message require), `internal/core/scopes/acl.go:13-36` (`CheckBridgeACL`: a bridged channel grants read and write to named identities only) and `internal/core/access/decide.go:205-224` (a channel of scope `s` is named `s-<rest>`).

**Files:**
- Modify: `internal/server/cmd/cmd.go` (export `RunWith`; `Run` unchanged)
- Modify: `internal/server/cmd/cmd_test.go` (`TestRunWithInjectsServe`)
- Create: `internal/e2e/slack_test.go` (`//go:build !windows`, package `e2e_test`; the name sorts after `mcponly_test.go` and before Task 7's `workflows_test.go`, so `TestSection24Sequence` still runs first)
- Modify: `internal/e2e/e2e_test.go` (package doc: one paragraph on fixture 2; `runMain` starts it after fixture 1 and stops it after `m.Run`; a `slackFx` variable beside `fx`)
- Modify: `scripts/check-gates-selftest.sh` (block 38 mutation 8, `slack-fixture-fires`)
- Modify: `docs/adr/0001-transport-and-api.md` (decision 4 under Eric's decisions; ruling 11 marked superseded; rulings 15 and 17; the "Open for Eric" paragraph removed)
- Modify: `CLAUDE.md` (the Commands bullet that says the e2e test "builds the binary and runs a real server" also names the second, in-process fixture with the Slack fake, `cmd.RunWith`, and that `main` calls `cmd.Run`)

**`RunWith`** (`cmd.go`, next to `Run`):

```go
// RunWith is Run with the serving function injected. The e2e fixture of
// internal/e2e uses it to put the Slack fake (internal/slackapi/slackfake)
// in Config.Slack before Serve runs; the binary's main calls Run. It is
// reachable from Go code of this module only: no flag, setting, variable or
// build tag selects another serving function.
func RunWith(ctx context.Context, args []string, environ []string, stdout, stderr io.Writer, serve func(context.Context, Config) error) int {
	return run(ctx, args, environ, stdout, stderr, serve)
}
```

`TestRunWithInjectsServe`: `RunWith` with `-listen 127.0.0.1:0 -sqlite <tmp>` and a serve function that records `c.Slack == nil` and `c.Registration` and returns nil answers 0 and called the function once (the shape of `cmd_test.go:726`).

**The fixture** (`slack_test.go`): `type slackFixture struct { root, sqlite, home string; fake *slackfake.Fake; proxy *httptest.Server; proxyH atomic.Pointer[http.Handler]; cancel context.CancelFunc; done chan struct{}; code int; out, errb *testkit.LockedBuffer }` and `startSlackFixture(root string, check *respcheck.Checker, add func(error)) (*slackFixture, error)`:
1. `fake := slackfake.New(slackapi.Self{TeamID: "T1", UserID: "UBOT", BotID: "B1"})`. The team id matters: `otherTeam` (`inbound.go:149`) treats an empty team on either side as another workspace and drops the message.
2. The proxy as `startFixture` builds it (`e2e_test.go:230-238`), then `ctx, cancel := context.WithCancel(context.Background())`, `ready := make(chan net.Addr, 1)`, and in a goroutine: `code = cmd.RunWith(ctx, []string{"-listen", "127.0.0.1:0", "-registration", "enrollment", "-sqlite", sqlite, "-set", "session_retention_hours=1", "-set", "issuer=" + proxy.URL}, nil, out, errb, func(ctx context.Context, c cmd.Config) error { c.Slack = fake; c.SlackCfg.PostInterval = 100 * time.Millisecond; orig := c.Ready; c.Ready = func(a net.Addr) { ready <- a; orig(a) }; return cmd.Serve(ctx, c) })`, then `close(done)`. `environ` is nil: the in-process server reads no `AGENTMESH_SERVER_*` variable. The listening line still goes to `out` (for diagnostics); the address comes from `Ready`, not from parsing.
3. Wait for `ready` (30 s; `done` first means the server exited: return `errb`), then `proxyH.Store(check.Proxy(&url.URL{Scheme: "http", Host: addr.String()}, add))`. The `Checker` and `add` are fixture 1's (`fx.check`, `fx.violations.add`): one tally.
4. `home := root/home-slack` (`os.MkdirAll`, 0700). `token()`: `run(home, "server", "admin", "-sqlite", sqlite, "enrollment", "create")` parsed with `tokenRE`; the host command is a separate process over the same SQLite file, as fixture 1 already does with the binary's server (`e2e_test.go:277`).
5. `stop()`: `cancel()`, wait for `done` (70 s: `Serve`'s shutdown is bounded at 60 s, `serve.go:70`), return `code` (the in-process analog of fixture 1's SIGTERM exit check; -1 when the wait timed out); `proxy.Close()` after.

`runMain`: after `fx` is up, `slackFx, err = startSlackFixture(root, fx.check, fx.violations.add)`; on error print `slackFx.errb`, run `fx.stopServer()` and return 1. After `m.Run()`: `if c := slackFx.stop(); c != 0 { ... code = 1 }` beside fixture 1's check, before the violation and `Skipped` tallies. `TestMain`'s helper-child early return (`e2e_test.go:151-153`) is untouched, so the child processes start no server.

**`TestSlackBridgeFixture`** (every client step is the binary against `slackFx.serverURL()` with `-profile lab -identity root` in `slackFx.home`; host commands take `-sqlite slackFx.sqlite`; JSON is decoded with `decode`):
1. `register -profile lab -identity root -server <url> -enrollment-token <slackFx.token()>` (exit 0); `mustRun(t, slackFx.home, "server", "admin", "-sqlite", slackFx.sqlite, "admins", "add", "-identity", "root")`; `server admin -sqlite ... create-human ann@example.test` prints `<name> created` (`admin.go:301`): keep `<name>` as `human`.
2. `scopes create j9fx`; `channels create -scope j9fx j9fx-room`; `channels acl j9fx-room ...` granting `root` and `human` read and write and nothing else (the implementer takes the flag syntax from `internal/cli/channels.go`; an `everyone`, `humans` or `admins` write entry is refused at create, `acl.go:23-27`; the administrator posts through a named row, not the flag: `decide.go:328-331`).
3. `slackFx.fake.AddUser(slackapi.User{ID: "U1", TeamID: "T1", Email: "ann@example.test", DisplayName: "Ann"})` before the create, so the invite finds the user.
4. `bridges create -slack-name j9fx-room j9fx-room`: exit 0; `bridge.state == "live"`, `bridge.slack_channel_id` non-empty and equal to `fake.FindPrivateChannel(ctx, "j9fx-room").ID`; `not_invited` empty; `fake.Calls("CreatePrivateChannel") == 1`; `fake.Channel(id).Members` contains `U1`. Keep `id`.
5. `bridges list`: one bridge, channel `j9fx-room`; `bridges get j9fx-room`: `state == "live"`.
6. Outbound: `send j9fx-room "hello slack"` (exit 0); poll `fake.Channel(id).Posts` every 100 ms for up to 20 s until one post's text contains `hello slack` (the bridge decorates the text: `internal/slackbridge/format.go`; `Contains`, not equality).
7. Inbound: `fake.Say(id, "U1", "hello bus", "")`; poll `history j9fx-room` every 200 ms for up to 20 s until it holds a message with `sender == human`, `sender_kind == "human"` and `content == "hello bus"` (pin equality against `inbound.go`'s text handling on the first run; say so in the report if the bridge rewrites plain text).
8. `bridges remove j9fx-room`: exit 0; `fake.Channel(id).Archived`; `bridges get j9fx-room`: `state == "archived"` (`Get` returns the row in any state, `service.go:262-275`; `Remove` on an archived row is a no-op, `archive.go:49`).
9. Control (ties the difference to the wiring): `run(fx.homeA, "bridges", "list", "-profile", "lab", "-identity", "pat")` against fixture 1 exits 1 with `agentmesh: unavailable:` and `the Slack bridge is not configured` on stderr (`internal/cli/bridges_test.go:91`); and `slackFx.fake.Calls("AuthTest") >= 1`.

Timing: the runner takes the `slack-bridge` Store lock on start and delivers outbound posts every `PostInterval` (100 ms here, 1 s by default: `service.go:58-59`); `Say` queues the event and `RunSocket` drains the queue, so the order of step 7 is safe whenever the socket connects. If step 6 or 7 misses 20 s on the first run, the report says which, with the fake's `Calls` counts; do not raise the deadline without saying why.

**Block 38 mutation 8, `slack-fixture-fires`:** `mutate_unit_block slack-fixture-fires internal/server/cmd/serve.go` from `		bridges = br` to `		bridges = nil` (the runner still starts; the handlers see no bridge and answer `unavailable`), package `./internal/e2e/`, run `'^TestSlackBridgeFixture$'`, want `TestSlackBridgeFixture`, EXTRA `unavailable`. The anchor is checked for uniqueness by the helper; if `bridges = br` occurs more than once, anchor on the whole `		bridges = br\n	}` span. Cost: one e2e package run (the two binaries build again in the worktree; about 40 s).

**ADR 0001 addendum:** under "Eric's decisions" add "Decision 4 (2026-11-07): the bridges journey runs against a live bridge: a second e2e fixture starts the server wiring in the test process through `cmd.RunWith` with `internal/slackapi/slackfake` in `Config.Slack`; it replaces plan ruling 11." Mark ruling 11 "superseded by decision 4", add rulings 15 and 17 in the plan's words (the seam and why, no gate needed, the isolation), and delete the "Open for Eric" paragraph. **CLAUDE.md:** in the Commands bullet that describes the e2e test, after "runs a real server", add "and a second, in-process server with the Slack fake (`internal/e2e/slack_test.go`, `cmd.RunWith`: the exported `run` seam; the binary's `main` calls `cmd.Run`, and nothing but Go code selects the fake)".

- [ ] **Step 1: `RunWith` and its test**

Run: `go test ./internal/server/cmd/ -run 'TestRunWithInjectsServe|TestRun' -count=1 2>&1 | tail -3`
Expected: `ok`.

- [ ] **Step 2: The fixture and the test; the whole e2e package; the m6 counts**

Run: `go test ./internal/e2e/ -run 'TestSlackBridgeFixture' -count=1 -v 2>&1 | tee /tmp/issue32-slackfx.log | rg -- '--- (PASS|FAIL)|e2e:'`
Expected: `--- PASS: TestSlackBridgeFixture`, no `e2e:` line.
Run: `go test ./internal/e2e/ -count=1 -v > /tmp/issue32-e2e-6a.log 2>&1; bash scripts/m6-exit-checks.sh /tmp/issue32-e2e-6a.log | tail -6`
Expected: `sequence=13 exitcodes=11 fail=0 pkg_ok=1`, `words_ok=1` (the new file is not in the word-check list; the counts name tests, not the package).

- [ ] **Step 3: The import rules, the mutation by hand, shell lint**

Run: `bash scripts/m4-exit-checks.sh --deps-only && bash scripts/m6-exit-checks.sh --deps-only && bash scripts/m7-exit-checks.sh --deps-only 2>&1 | tail -3 && rg -n 'RunWith\(' --glob '!*_test.go' . && make release-lint 2>&1 | tail -3`
Expected: `deps_ok=1` from each; the `rg` finds only `internal/server/cmd/cmd.go`'s definition; shellcheck clean. Then apply mutation 8 by hand (`bridges = nil`), run the test, confirm `--- FAIL: TestSlackBridgeFixture` with `unavailable` in the log, and `git checkout -- internal/server/cmd/serve.go`.

- [ ] **Step 4: The done gate; commit**

Run: `make verify 2>&1 | tee /tmp/issue32-verify-6a.log | tail -5 && make check-gates-selftest 2>&1 | tee /tmp/issue32-selftest-6a.log | tail -8`
Expected: `verify: OK`; every block `ok`, block 38 with eight mutations (the seven of Task 6 plus `slack-fixture-fires`; `arazzo-criteria-fire` comes in Task 7). Paste both tails into the task report.

```bash
git add internal/server/cmd/cmd.go internal/server/cmd/cmd_test.go internal/e2e/slack_test.go internal/e2e/e2e_test.go scripts/check-gates-selftest.sh docs/adr/0001-transport-and-api.md CLAUDE.md
git commit -m "test(e2e): a second fixture runs the server in-process with the Slack fake; cmd.RunWith exports the serve seam (issue #32)"
```

---

## Human gate: controller steps C2 to C4

**C2 (controller): journeys.** Run the `profile:journeys` skill at the repository root (it invokes `profile:stack` and `profile:docs` itself when not handed their contracts). Write its contract into `docs/journeys.md`: a heading, one paragraph on provenance (the skill, the commit, the date), the fenced ```` ```json ```` block with the contract, then one section per journey (name, actor, narrative, entry point, depends_on, evidence). Make sure the six journeys of the issue are present, API-shaped and named as the issue names them: register and log in (`register` + `token`), send and receive with ack (`openSession`, `subscribe`, `sendMessage` from a second identity, `receive` twice, the second with `ack`), memories (`createChannel` with `kind: memory`, `sendMessage` into it (a memory is a message of a memory channel; `EditResult.memory_id` names it), `getMemory`, `editMemory`, `listMemoryRevisions`, `deleteMemory`), task claim and complete (`createTask`, `claimTask`, `updateTask` to completed, `getTask`), admin bootstrap (ruling 12), bridges (Eric's decision 4: a live bridge on Task 6A's fixture: an open scope, a channel in it with a named-only ACL that grants the administrator and a human write, `createBridge`, `listBridges`, `getBridge`, a message each way, `removeBridge`; two workflows, ruling 16). Journeys whose actor is a CLI or TUI user (`init`, `wait`, hooks, `tui`) stay in the doc flagged as non-API-shaped. Commit: `docs(journeys): the customer journeys from profile:journeys, for Eric to tune (issue #32)`.

*Status (2026-11-07):* C2 is done; `docs/journeys.md` is the draft of `a43f196` and Eric is hand-tuning it. J9 ("Slack bridge for a scoped channel", `docs/journeys.md:284-289`) is the bridges journey and still carries the 503 expectation of the superseded ruling 11 ("A workflow against a server without Slack should expect 503"). At C3 the controller tells Eric that J9 now runs on the live fixture and proposes this wording for his tuning: actor administrator; precondition an open scope, a channel in it named `<scope>-<rest>` (the scope-prefix rule, `internal/core/access/decide.go:205-224`) whose ACL names the administrator and a human with read and write (named identities only on a bridged channel, `internal/core/scopes/acl.go:13-18`; the human exists through `createIdentityByEmail` and has the Slack user's email); steps `createBridge` (201, `live`), `listBridges`, `getBridge`, `sendMessage` into the channel (reaches Slack), a Slack message from the human's Slack account (reaches the channel: `history` shows it with `sender_kind` `human`), `removeBridge` (204), `getBridge` (`archived`). Eric's text is final; the proposal is only to save him a trip through the code.

**C3: STOP.** Tell Eric the doc is at `docs/journeys.md`, list the journeys in one line each, and wait. Eric edits the file by hand (decision 3). Nothing below runs until he says the journeys are final. Commit his edits as `docs(journeys): Eric's hand-tuned journeys (issue #32)` when he does not commit them himself.

**C4 (controller): Arazzo.** Run the `openapi:arazzo` skill with `docs/journeys.md`. At its mapping gate, check against ruling 9: every step binds by `operationId`; parameters are `path`, `query` or `header`; bodies are JSON or form; every criterion is `$statusCode == N` or `$response.body#/ptr == literal`/`!=`; outputs are `$response.body#/ptr` or `$statusCode`; `dependsOn` names only workflows in the file; the bearer is a header parameter (ruling 10); inputs that need keys are declared in `inputs` (`enrollment_token`, `identity`, `public_key_jwk`, `client_assertion`, `bearer`, `admin_bearer`, ...) so the Go test can fill them. Anything outside ruling 9 is edited at the gate, not after. J9 maps to two workflows (ruling 16): `bridges` (inputs `admin_bearer`, `admin_identity`, `scope`, `channel`, `slack_name`, `human_identity`; steps `createChannel` with `scope` and the named-only `acl` that grants `admin_identity` and `human_identity` read and write (neither Read nor Write has an administrator-flag bypass, `internal/core/access/decide.go:325-331`, so the administrator posts and reads through its own row), `createBridge`, `listBridges`, `getBridge`, `sendMessage`; outputs `slack_channel_id`, `seq`) and `bridges-inbound-remove` (`dependsOn: [bridges]`; inputs `admin_bearer`, `channel`, `after`; steps `history` with query `after` and `count`, `removeBridge`, `getBridge`), and the admin-bootstrap workflow takes `human_email` as an input and outputs `human_identity` from `createIdentityByEmail` (`$response.body#/identity`), so the Go test can give the Slack fake's user that email. Criteria are literals (ruling 9), so the inbound text is a literal in the document that the Go test repeats. The skill writes `api/arazzo.yaml` (from the config). Check it loads: a throwaway `go test` in the scratchpad is not possible from outside the module, so write `internal/arazzotest/repo_test.go` now (Task 7 lists it: `TestLoadRepositoryDocument` calls `Load("../../api/arazzo.yaml")`) and run `go test ./internal/arazzotest/ -run TestLoadRepositoryDocument`; a `*UnsupportedError` sends the document back to the skill's gate. Then fill Task 7's workflow table below (ids, inputs, chaining) from the file and dispatch Task 7.

---

### Task 7: `TestArazzoWorkflows` against both e2e fixtures, the final mutations, the folded minors, the done gate

**Files:**
- Create: `internal/e2e/workflows_test.go` (`//go:build !windows`, package `e2e_test`; named so it sorts after `mcponly_test.go` and `slack_test.go`: Go runs a package's tests in file-name order, and the package doc (`e2e_test.go:9-12`) relies on `TestSection24Sequence` running before anything has opened a session, so `arazzo_test.go` would break its display-name assertions)
- Create: `internal/arazzotest/repo_test.go` (`TestLoadRepositoryDocument`: `Load("../../api/arazzo.yaml")` succeeds and every workflow id of the table below exists)
- Modify: `scripts/check-gates-selftest.sh` (block 38 gains `arazzo-criteria-fire`; the two EXTRA pins below)
- Modify: `CLAUDE.md` (the Commands list: `api/arazzo.yaml` and `docs/journeys.md` named in the e2e bullet; the Design bullet trimmed as below), `docs/adr/0001-transport-and-api.md` (ruling 16 and the seven workflow ids; the "Mutations" line names nine)
- Modify: `api/arazzo.yaml` only when a workflow needs a fix the runner's error names (and then the fix is the document's, never the runner's: a feature outside ruling 9 goes back to C4)

**The workflow table** (the controller fills the ids from `api/arazzo.yaml` before dispatch; the shape below is the contract). Rows 1 to 5 run against fixture 1 (`fx`), as before. Rows 6 to 9 run against fixture 2 (`slackFx`, Task 6A) in a second `Runner`: bearers do not cross fixtures and `dependsOn` is checked per `Runner` (ruling 17), so the register and admin-bootstrap workflows run again there with identities and names of their own.

| Order | Fixture | workflowId | Inputs the test provides | Outputs chained forward |
| --- | --- | --- | --- | --- |
| 1 | `fx` | `<register-and-log-in>` | `enrollment_token` (from `run(fx.homeA, "server", "admin", "-sqlite", fx.sqlite, "enrollment", "create")`, parsed with `tokenRE`), `identity` (`arazzo-ann`), `public_key_jwk` (`keys.Generate(keys.EdDSA)`, `keys.KID`, `keys.ToJWK` marshaled to a JSON object), `client_assertion` (`assertion.Sign(assertion.Input{Identity, Audience: fx.serverURL(), Key, KID, Now: time.Now()})`), `client_assertion_type` (`assertion.Type`) if the document declares it as an input | `access_token` |
| 2 | `fx` | `<send-and-receive-with-ack>` | `bearer` (from 1), `peer_bearer` (a second identity registered the same way in Go, or by running workflow 1 twice with different inputs: prefer the second run), channel name | — |
| 3 | `fx` | `<memories>` | `bearer` | — |
| 4 | `fx` | `<task-claim-and-complete>` | `bearer` | — |
| 5 | `fx` | `<admin-bootstrap>` | an administrator's inputs: register a third identity (`arazzo-root`) through workflow 1, then `mustRun(t, fx.homeA, "server", "admin", "-sqlite", fx.sqlite, "admins", "add", "-identity", "arazzo-root")` (the host command refuses an unregistered name with "register it first": `internal/server/cmd/admin_test.go:79`; the flag is read from the identity row on every request, `internal/core/access/principal.go:42`, so the bearer minted before the flag is set still acts as an administrator), then its `access_token` as `admin_bearer`; `scope`, `human_email` and identity names unique to this test | — |
| 6 | `slackFx` | `<register-and-log-in>` | as row 1 with `slackFx.token()`, `identity` `arazzo-j9-root`, audience `slackFx.serverURL()` | `access_token` |
| 7 | `slackFx` | `<admin-bootstrap>` | `mustRun(t, slackFx.home, "server", "admin", "-sqlite", slackFx.sqlite, "admins", "add", "-identity", "arazzo-j9-root")`, then `admin_bearer` (from 6), `scope` `j9wf` (Task 6A's `j9fx` lives in the same database; the prefixes `j9fx-` and `j9wf-` do not nest, `decide.go:225-249`), `human_email` `j9@example.test` | `admin_bearer`, `scope`, `human_identity` (from `createIdentityByEmail`) |
| 8 | `slackFx` | `bridges` | `admin_bearer`, `admin_identity` (`arazzo-j9-root`: the ACL must name it, since Read and Write have no administrator-flag bypass, `decide.go:325-331`), `scope` (from 7), `channel` `j9wf-room` (the scope-prefix rule: `decide.go:205-224`), `slack_name` `j9wf-room`, `human_identity` (from 7); before the run: `slackFx.fake.AddUser(slackapi.User{ID: "U2", TeamID: "T1", Email: "j9@example.test", DisplayName: "J9"})` so the create's invite finds the user | `slack_channel_id`, `seq` (of the outbound `sendMessage`) |
| 9 | `slackFx` | `bridges-inbound-remove` | `admin_bearer`, `channel`, `after` (= `seq` from 8); between 8 and 9 the Go test polls `slackFx.fake.Channel(slack_channel_id).Posts` (20 s) until a post contains the outbound text, calls `slackFx.fake.Say(slack_channel_id, "U2", "<the inbound literal of the document>", "")` and polls `history` with an `http.Get` through the proxy carrying `admin_bearer` (`arazzo-j9-root` is named in the channel's ACL; Task 6A's `root` is not, so the binary cannot be used here; 20 s) until the message has landed, so workflow 9's `history` criterion is deterministic | — |

The criteria of rows 8 and 9 are live (ruling 16): `createBridge` `$statusCode == 201` and `$response.body#/bridge/state == "live"`; `listBridges` and `getBridge` `200` with `state == "live"`; `sendMessage` `201`; `history` (query parameter `after` with `value: $inputs.after`, bare, so the integer keeps its type until it is written on the wire; `count` `1`) `200`, `$response.body#/0/content == "<the inbound literal>"` and `$response.body#/0/sender_kind == "human"` (the sender's name is server-derived, so the Go test checks `sender == human_identity` in its poll, not the document); `removeBridge` `204`; `getBridge` `200` and `state == "archived"`. No step of either workflow expects `503` or `unavailable`.

The test runs them in this order in one `TestArazzoWorkflows` with `t.Run(workflowId, ...)` for rows 1 to 5 and `t.Run("slack:"+workflowId, ...)` for rows 6 to 9; a failure stops the sequence (`t.Fatal`), since later workflows depend on earlier outputs. Two `Runner`s: `Runner{Doc, BaseURL: fx.serverURL(), Log: t.Logf}` and `Runner{Doc, BaseURL: slackFx.serverURL(), Log: t.Logf}`; every request crosses a validating proxy, so `runMain`'s violation and `Skipped` checks cover these responses too. Each `StepResult` is logged on one line (`stepId method URL status`).

**The gate guards this test, so the counts stay:** the m6 script counts `TestSection24Sequence` steps and `TestExitCodeTable` cells by name; a new test in the package changes neither. The word check lists files, not the package.

**Block 38 mutation 9, `arazzo-criteria-fire`:** `mutate_unit_block` (the helper that takes a package and a `-run` pattern; `mutate_block` runs the Bus conformance suite only) on `api/arazzo.yaml`, from the first `$statusCode == 201` (the implementer picks a criterion whose step is in workflow 1 and quotes the whole line so the anchor is unique) to `$statusCode == 200`, package `./internal/e2e/`, run `'^TestArazzoWorkflows$'`, want `--- FAIL: TestArazzoWorkflows/<workflow 1 id>` and the text `criteria` in the log (`CriteriaError`'s message starts with `arazzo: criteria failed`). The e2e package builds the binary (about 30 s); the block's log is in `$tmp`.

**Task 6 review minors, folded in here:**
1. Block 38 `arazzo-refusal-fixture-missing` (`scripts/check-gates-selftest.sh:1476`): add the EXTRA argument `refusals table names` (`mutate_rm_block LABEL FILE PKG RUN WANT [EXTRA]`), so the mutation is pinned to `TestRefusalCoverage`'s message and not only to its name.
2. Block 34 `wire-gen-type-unpaired` (`:1180`): add the EXTRA argument `generated type Extra is neither paired nor excepted` (`mutate_unit_block`'s eighth argument), pinning `TestWireRoundTrip/coverage`'s message.
3. CLAUDE.md Design bullet "Spec validation (issue #32 ...)" (`CLAUDE.md:53`): drop the `spec-lint` half, which the Commands bullet (`CLAUDE.md:15`) already carries, so it reads: "Spec validation (issue #32, Eric 2026-11-06 and 2026-11-07, ADR 0001 addendum): the lint gate is `make spec-lint` (Commands); `TestOperationShape` (`internal/gen`) pins operationId, summary, one defined tag and a 2xx per operation; `TestNoRoutesOutsideTheDocument`, `TestDeclaredMethodsRouted` and `TestUndeclaredMethodsRefused` (`internal/server/routes_test.go`) are the route completeness test; `internal/arazzotest` (test-only, kept out of both binaries by the m4 rule) runs the seven workflows of `api/arazzo.yaml` (from `docs/journeys.md`, Eric's hand-tuned journeys) in `TestArazzoWorkflows` (`internal/e2e`): five against the binary's server, the register, admin-bootstrap, `bridges` and `bridges-inbound-remove` workflows against the in-process server with the Slack fake (decision 4); it supports steps by operationId, path/query/header parameters, JSON and form bodies, `$inputs`, `$steps`, `$statusCode`, `$response.body#/ptr`, `==`/`!=` criteria, outputs and `dependsOn` as a check, and refuses every other Arazzo feature by name. Mutations: `scripts/check-gates-selftest.sh` block 38." Keep the ids as the document spells them.
4. The plan's Architecture paragraph said "eight rules off"; it says seven now (fixed in this amendment, nothing to do).

**ADR 0001 addendum:** add "Ruling 16: J9 is two workflows, `bridges` and `bridges-inbound-remove`, because an Arazzo step is one request and the Slack message is injected between them" to the rulings, list the seven workflow ids in the "Where things live" paragraph with which fixture runs each, and make the "Mutations" line read "block 38 (nine mutations)".

- [ ] **Step 1: Write `TestLoadRepositoryDocument` and the e2e test; run the e2e package**

Run: `go test ./internal/e2e/ -run 'TestArazzoWorkflows' -count=1 -v 2>&1 | tee /tmp/issue32-arazzo.log | rg -- '--- (PASS|FAIL)|arazzo:'`
Expected: `--- PASS: TestArazzoWorkflows` with nine passing subtests (five on `fx`, four `slack:` on `slackFx`). A `CriteriaError` here is a finding: either the document's expectation is wrong (fix `api/arazzo.yaml`, say so in the report) or the server's answer is not what the document promises (that is a real gap: fix the server or the OpenAPI document with a test, as the issue requires, and report it as such).

- [ ] **Step 2: The mutations and the EXTRA pins; the whole e2e package; m6 counts**

Apply mutation 9 by hand, confirm the failure text, revert. Run: `go test ./internal/e2e/ -count=1 -v > /tmp/issue32-e2e.log 2>&1; bash scripts/m6-exit-checks.sh /tmp/issue32-e2e.log | tail -6`
Expected: `sequence=13 exitcodes=11 fail=0 pkg_ok=1`.

- [ ] **Step 3: The done gate; commit**

Run: `make verify 2>&1 | tee /tmp/issue32-verify2.log | tail -5 && make check-gates-selftest 2>&1 | tee /tmp/issue32-selftest2.log | tail -8`
Expected: `verify: OK`; every block `ok`, block 38 with nine mutations. Paste both tails into the task report.

```bash
git add internal/e2e/workflows_test.go internal/arazzotest/repo_test.go api/arazzo.yaml scripts/check-gates-selftest.sh CLAUDE.md docs/adr/0001-transport-and-api.md
git commit -m "test(e2e): the Arazzo workflows of the six journeys run against both e2e fixtures (issue #32)"
```

---

## Controller step C5 (after Task 7): local merge

The controller fast-forwards `main` to the branch, runs `make verify` on `main`, then deletes the branch and the SDD workspace. Nothing is pushed (Eric, 2026-11-07: commit and merge locally only), so `ci.yml` and `windows.yml` stay unverified and are reported as open. The issue comment (the ruleset path and the seven disabled rules, the counts before and after, the three Task 4 test names, the runner and the seven workflow ids, the second fixture of Eric's decision 4, the fixed gaps; no open item) is drafted for Eric rather than posted. Close the issue only when Eric says so.
