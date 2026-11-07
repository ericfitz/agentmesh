# Issue 34: Spec Bounds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every request-side string, integer, number, array and map of `api/openapi.yaml` carries the bound the server enforces (`maxLength`, `minLength`, `pattern`, `minimum`, `maximum`, `format`, `maxItems`, `minItems`, `maxProperties`), each bound is a named Go constant or a setting's ceiling, a literal table test (`TestSpecBounds`) fails when the Go side and the spec disagree or when a bounded field has no row or a row has no field, requests one over each bound are refused with `validation` by the request validator (`TestValidatorRefusesOverBound`) and by the core alone (`TestOverBoundRefused` on the `local` transport), and `scripts/check-gates-selftest.sh` block 37 proves each check fires.

**Architecture:** No new validator: `internal/server/server.go:112` already runs kin-openapi's request validator on every request (ADR 0007 choice 6) and `limitBody` sits outside it, so the spec bounds become enforced on the wire the moment they are written; Decision 47 and the import rules are untouched. The production in-process path (`internal/client/localmode`, `localmode.go:131`) calls `server.New`, so it is validated too; the only bypass is `internal/bus/local` (`local.New` delegates straight to the core), which has no production user (`rg -l 'internal/bus/local"' internal cmd --glob '!*_test.go'` is empty) and is the Bus conformance suite's `local` transport. That is where the core's own refusals are proved. Every bound is backed by a Go constant in `internal/core/rules` (or `store`, `core`, `tasks`, `sessions`, `search`, `auth/assertion`, `auth/keys`, `slackapi`), the spec states it with `x-go-type` where a `format` or `enum` would otherwise change a generated Go type (spike below), and `TestSpecBounds` walks the embedded document (`server.Spec()`) exactly as `TestWireRoundTrip` and `TestToolCoverage` walk their artifacts: a literal table, a coverage pass, a staleness pass.

**Tech Stack:** Go (`CGO_ENABLED=0`), oapi-codegen v2.8.0 (`internal/gen`, never edited by hand), kin-openapi v0.151.0 (`openapi3`, `openapi3filter`), `nethttp-middleware` v1.2.0, bash gate scripts (`set -euo pipefail`, shellcheck-clean).

**Spec:** GitHub issue #34 (body) and Eric's decisions of 2026-11-06 (the limit rule (a), (b), (c), pre-approved); CLAUDE.md (the `api/openapi.yaml` and `make generate` rules, Decision 47, the m4/m6/m7/m10 import rules, the pre-release rule); ADR 0001 (choices 3, 11, 13, item 6), ADR 0007 (choice 6, the path-parameter facts, the body-read fact); the issue #33 plan for the table style. Evidence on `75ef974` (2026-11-07): the walker in the scratchpad (`specinv`, kin-openapi, request parameters and bodies, recursive) finds 193 request-side leaf fields of which 159 lack at least one bound (106 strings without `maxLength`, 32 integers without `maximum`, 30 without `minimum`, 3 without `format`, 15 arrays without `maxItems`, 5 maps without `maxProperties`, 1 number without either); after `$ref` dedupe (five shared parameters, the shared schemas) 112 distinct fields are unbounded (67 strings, 25 integers, 14 arrays, 5 maps, 1 number). Existing bounds: `thread` and `if_revision` carry `minimum: 1`; `unsubscribeTags` `pattern` carries `minItems: 1`; six distinct fields are enums (`adminReset` `scope`, `ACLEntry.permissions[]`, `CreateChannelRequest.kind`, `DoneScopeRequest.retire`, `search` `mode`, `SubscribeRequest.from`). The spec has no `maxLength`, `maxItems`, `maximum` or `maxProperties` anywhere. Validator probes (scratchpad `specinv/kinmax`, `specinv/pathspike`, kin-openapi v0.151.0 with the gorillamux router): `maxLength` counts code points for a body string and a query parameter (`q=%E6%97%A5%E6%9C%AC%E8%AA%9E`, three code points, passes `maxLength: 3`), but a path parameter is validated on its percent-encoded segment (`/h/%E6%97%A5%E6%9C%AC%E8%AA%9E` fails `maxLength: 3` with `maximum string length is 3`; `a%2Fb` is five characters): ruling 15.

## Global Constraints

- **Eric's decisions (2026-11-06, issue #34), binding:** (a) a field that is the same kind of thing as an existing Go limit reuses it (names follow `store.NameRule`, tags `rules.MaxTagLen`); (b) otherwise: free-form short strings 256 code points, opaque tokens 1024 bytes, metadata 32 keys of 64 code points with values of 1024 code points, request arrays 256 items, page counts the existing server maximum else 1000, sequence numbers `int64` with `minimum: 0`; (c) every new limit is a named Go constant, a row in the inventory (this plan, mirrored in `TestSpecBounds`) and a line in the ADR 0001 addendum labeled "Eric's decision of 2026-11-06". New limits land without asking; Eric may tighten any value afterwards.
- **Issue acceptance criteria, binding:** every request string, integer, array and map has a bound; a runtime setting's field is bounded at the setting's largest allowed value and its description names the setting; each bound states its unit and the server and the spec agree (rune counts where the rule is in runes); a test reads the Go constants and the spec and fails when they differ; requests just over each bound are refused with `validation` by the validator and by the core; patterns only where the core has a real character rule, never one that contradicts percent-encoded names.
- **The protocol version stays `1.0.0`** (`info.version` and `version.Protocol` untouched; pre-release rule of CLAUDE.md, Eric 2026-10-27): bounds change the protocol in place.
- **Never edit `internal/gen` by hand**: every spec change is followed by `make generate` in the same task, and every selftest spec mutation regenerates in the throwaway worktree (`mutate_spec_block`) before running the test, because the tests read the embedded document (`server.Spec()`), never the YAML.
- **No generated Go type changes.** Spike with the pinned generator (scratchpad `genspike`, 2026-11-07): `format: int32` turns a `*int` parameter or property into `*int32`, and an `enum` on a string generates a named string type (`HistoryParamsStatus2`, `PatchStatus2`); `x-go-type: int` beside `format: int32` keeps `*int`, and `x-go-type: string` beside an enum keeps `*string`, on parameters and on properties alike. Every spec task therefore ends with `git diff --stat internal/gen` showing `gen.go` changed only in comments (the descriptions) and `spec/spec.go` in the embedded bytes; `TestWireRoundTrip` and `TestToolCoverage` stay green with no table edit.
- **Units.** JSON Schema `maxLength` counts code points and kin-openapi does too (probe: `"日本語"` passes `maxLength: 3`, `"日本語x"` fails with `maximum string length is 3`). A rule the core counts in runes gets the exact number; a rule the core counts in bytes gets the same number as `maxLength` with a description saying "bytes": every byte count is at least the code-point count, so the validator admits everything the core admits and the core refuses the rest with `validation` (the spec is never stricter than the server). No rule is converted from bytes to runes except the task subject (ruling 3). A path parameter is the exception to both: kin validates the percent-encoded segment, so its `maxLength` is three times the byte bound (ruling 15).
- **The core refuses every bound the spec states**, so the `local` transport agrees with the wire: a clamp above the spec's `maximum` becomes a refusal (ruling 1), and a count of raw entries replaces count-after-dedupe (ruling 4). Inputs the core cannot represent (an integer above `int64`) need no core check (ruling 6).
- **`TestAccessRuleSites`** (`internal/core/access/sites_test.go`) is not touched: no task reads `Admin`, `Creator`, `Owner`, `Scope` or a `Kind` outside `access`. The new checks read lengths and counts only.
- **Import rules hold.** `internal/server` test files may import `internal/slackapi` and `internal/auth/...` (the m7 rule checks production imports, `scripts/m7-exit-checks.sh:15`); `internal/core/rules` keeps importing only `internal/bus`; `internal/bus/remote` gains nothing; `internal/respcheck` is unchanged.
- American English everywhere. Work lands on the branch `issue-34-spec-bounds`, one commit per task in the `type(scope): subject` style, ending with the two attribution lines the session reminder gives. No task pushes.
- Done gate: `make verify` (needs Docker; a run that skips the Postgres suites is not a pass) and `make check-gates-selftest`; then `ci.yml` and `windows.yml` green on the pushed commit. Task 9 runs the two make targets and shows their output.
- Shell: the gate script stays `set -euo pipefail`, shellcheck-clean (`make release-lint`).

## Rulings made by this plan (Eric may overrule)

1. **Clamp becomes refuse at the ceiling, clamp stays below it.** `receive` and `history` `count` are clamped to `receive_max_count` (`delivery/receive.go:127`, `messaging/history.go:44`), `search` `count` to `rules.SearchPageMax` (`search/service.go:173`), `watch` `timeout` to `watch_max_seconds` (`delivery/watch.go:28`). The spec states the setting's ceiling (`maximum: 10000`, `240`) or the constant (`1000`); the validator refuses above it, so the core must too. New constants in `internal/core/config.go`, used by `Config.Validate`'s bounds table and by the refusals: `ReceiveCountCeiling = 10000`, `WatchSecondsCeiling = 240`, `MessageKiBCeiling = 1024`. Above the ceiling the core answers `validation` ("count must be at most 10000"); between the configured value and the ceiling it still clamps (existing behavior, documented in the description: "above `receive_max_count` the server returns at most that many"). Tests that flip: `internal/core/search/query_test.go:29` ("count capped", 5000 clamped to 1000) becomes a refusal case; `internal/conformance/bus/history_test.go:105` (`ReceiveMaxCount = 5`) still clamps and is unchanged. Cost if wrong: a client that sent a huge count to mean "everything" gets 400 and must send the ceiling instead.
2. **Names stay bytes.** `store.NameRule` (`internal/store/names.go:32`) is 1 to 128 bytes and also names credential and token files through `FileNameRule`; 128 runes can be 512 bytes, above NAME_MAX. The literal becomes `store.MaxNameBytes = 128`; the spec says `maxLength: 128` with "bytes" in the description. Applies to channel, identity, scope, hint, ACL identity, email, owner, sender, cursor channel, receive channel, bridge channel and the `identity`, `channel`, `scope` path parameters.
3. **The task subject converts to runes.** `validateTaskSubject` (`internal/core/tasks/doc.go:70`) counts bytes ("subject must be 1-256 bytes") with no file or storage reason; it becomes `tasks.MaxSubjectRunes = 256` counted with `utf8.RuneCountInString`, so the spec's `maxLength: 256` is exact. The message becomes "subject must be 1-256 characters". Cost if wrong: a subject of 200 four-byte runes (800 bytes) is now accepted; nothing bounds the stored column.
4. **Raw counts, not counts after dedupe.** `rules.normalizeTagList` drops duplicates before comparing with `MaxTags`, and `tasks` dedupes `blocked_by` before `maxBlockers`; `maxItems` counts raw entries, so eleven tags with a duplicate pass the core and fail the validator. The core counts the raw list first (`len(tags) > MaxTags` before the loop; `len(t.BlockedBy) > MaxBlockers` before `dedupeIDs`). ACL `permissions` are not deduplicated at all; the core refuses more than `len(store.AllPermissions)` (3) entries per ACL entry. Cost if wrong: a client sending redundant entries above the cap is refused where it was tolerated.
5. **Core-owned enums stay strings.** `SetAgentStatusRequest.tag`, `TaskPatch.status` and the `listTasks` `status` query are validated by the core with their own messages (`rules.CheckStatusTag`: "unknown tag %q: one of idle, ..."; `tasks`: "status must be pending, in_progress, or completed"), and `internal/mcpserver/agentstatus_test.go:41` and `internal/cli/agentstatus_test.go:69` assert that text over the wire. A spec `enum` would make kin answer first with its own text. They get `maxLength: 256` (`rules.MaxLabelRunes`) and a description listing the values; no `enum`. The six existing enums are untouched, and the `TokenRequest` type fields stay strings: an enum there would turn the handler's `unsupported_grant_type` into the validator's `invalid_request`.
6. **`int64` fields are bounded by the type.** Every `format: int64` field gets `maximum: 9223372036854775807` (vacuum's `owasp-integer-limit` wants both ends) and `minimum: 0`, or `1` where the core already says so (`thread`, `if_revision`; `search` `thread` gains the same `minimum: 1` and core check). The core adds a non-negative check at each site (`rules.NonNegative(field, v)`), so a negative id answers `validation` instead of `not_found`; nothing can hand the core an integer above `int64`, so there is no core check for the maximum: kin admits `MaxInt64` (probe: `VisitJSON(int64(math.MaxInt64))` is nil; a JSON body decodes to `float64(2^63)` which equals the schema's `float64` maximum) and the strict handler's `json.Unmarshal` into `int64` refuses `9223372036854775808` with 400 `validation` (`RequestErrorHandlerFunc`), the query binder likewise. `TestInt64OverflowRefused` pins both facts.
7. **Resume token and search cursor get their real shape, not (b)'s 1024.** `resume_token` is `base64.RawURLEncoding` of 32 bytes (`sessions/service.go:60`, `resumeTokenBytes`): exactly 43 characters of `[A-Za-z0-9_-]`, so `minLength: 43`, `maxLength: 43`, `pattern: ^[A-Za-z0-9_-]{43}$` (`sessions.ResumeTokenLen`, `sessions.ResumeTokenPattern`; the core's "resume_token is malformed" already refuses everything else). `search` `cursor` is a decimal offset (`strconv.Atoi`): `pattern: ^[0-9]+$`, `maxLength: 19` (`rules.MaxSearchCursorLen`, the digits of `MaxInt64`; `Atoi` overflows at 20 and the core already answers "invalid cursor"). Rule (a) (same kind of thing as an existing Go rule) wins over (b).
8. **External JWTs are not opaque tokens.** `client_assertion`, `subject_token` and `actor_token` are JWTs; a corporate id_token routinely exceeds 1024 bytes. New `assertion.MaxTokenBytes = 16384` in `internal/auth/assertion`, checked by `assertion.Parse` and by the token handler before any parse (`invalid_request`); the other `TokenRequest` fields are `MaxOAuthFieldBytes = 1024` in `internal/server/oauth.go` (rule (b)), except `client_id`, an identity name (`store.MaxNameBytes`). The token endpoint has no in-process bypass, so the handler and `assertion.Parse` are its two layers, and its over-bound answer is the RFC 6749 body (`tokenRequestError`), not a problem. **Eric should see this one.**
9. **`search` `q` is 1024 code points** (`rules.MaxQueryRunes`): rule (b)'s 256 for short strings is too tight for a semantic query paragraph; 1024 keeps it under every other ceiling. **Eric should see this one.**
10. **Content fields are bounded by the envelope in bytes.** `SendRequest.content`, `EditMemoryRequest.content`, `TaskCreateRequest.description` and `TaskPatch.description` get `maxLength: 1048576` (`core.MessageKiBCeiling * 1024`) with a description naming `max_message_kib` (default 64 KiB, ceiling 1024 KiB) and "bytes": the core refuses by the whole envelope (`append.go:50`), which is at most the configured value, so it refuses everything the spec refuses. On the wire `limitBody` (`MaxMessageKiB*1024 + 1 MiB`) answers 413 first unless `max_message_kib` is at the ceiling; `TestValidatorRefusesOverBound` sets it there for the content probes.
11. **Metadata keys are core-only.** OpenAPI 3.0.3 has no `propertyNames`, so the 64-code-point key bound (`rules.MaxMetadataKeyRunes`) is enforced by the core and stated in the description; `maxProperties: 32` and the value `maxLength: 1024` are spec bounds. `TaskPatch.metadata` merges into the stored map (`update.go:66-81`): the patch and the merged result are both bounded by `rules.MaxMetadataKeys`.
12. **Response fields are out of scope**, with one consequence stated: shared schemas (`ACLEntry`, `JWK`) carry their bounds into responses, which `internal/respcheck` validates in every suite; stored names and permissions always pass, and `JWK` `maxProperties: 16` (`keys.MaxJWKMembers`) is above the server's own JWKS member count (`kty`, `crv`, `x`, `y`, `kid`, `alg`, `use`: 7). Metadata written before the cap cannot exist in a database this build creates (pre-release: recreate local data).
13. **`Idempotency-Key`, session ids, `ack` and `enrollment_token` are opaque tokens** (`rules.MaxTokenBytes = 1024`): the core refuses longer ones with `validation` at one site each (`core.CheckReceipt`, `sessions.Require`/`Owned`, `delivery.Receive`, `identities.Register`), where today an unknown token is `not_found`, ignored (`AckIgnored`) or `forbidden`.
14. **`NormalizeLine` counts before trimming.** `rules.NormalizeLine` trims and then counts runes, so a 200-rune subject padded with spaces passes the core and fails the validator (201 code points). The count moves before the trim so the two agree exactly; the message is unchanged.
15. **Path parameters are bounded on their percent-encoded form.** The validator's router is gorillamux with `UseEncodedPath()` (ADR 0007) and kin validates the route variable as given, so `ChannelParam`, `ScopeParam`, the `identity` path parameter and `SessionParam` get `maxLength: 3 * store.MaxNameBytes` (384) and `3 * rules.MaxTokenBytes` (3072): every byte encodes to at most three characters, so the validator admits every name the core admits (a 128-byte CJK name is 384 encoded characters) and the core still refuses above 128 decoded bytes. The description says "percent-encoded length; the server counts 128 decoded bytes". A `pattern` on a path parameter would have to match the encoded form and is never written (the issue's percent-encoded-names rule). Query and header parameters and body strings are validated decoded, so every other row keeps its decoded count.

## Review Focus

1. A bound written in the spec without a Go constant behind it (a literal in the YAML and in the table): `TestSpecBounds` cannot see it; the reviewer checks every table row's value is a constant or a `core`/`rules` ceiling, never a number.
2. A core check that counts the wrong unit (bytes where the row says runes): `TestOverBoundRefused/<field>_runes_accepted` sends `MaxLineRunes` two-byte runes and expects success on both transports.
3. A new spec bound without a probe: `TestValidatorRefusesOverBound/coverage` fails; a probe whose refusal comes from the core, not the validator (the detail lacks kin's phrase): the per-row subtest fails. Kin's phrases: `maximum string length is`, `minimum string length is`, `maximum number of items is`, `minimum number of items is`, `there must be at most`, `number must be at most`, `number must be at least`, `string doesn't match the regular expression`.
4. The over-bound body must stay under `limitBody`'s limit (ruling 10) or the probe sees 413.
5. `x-go-type` left off a `format: int32` or an `enum`: `git diff --stat internal/gen` shows a type change and `TestWireRoundTrip` or the converters fail to compile; the spec tasks print the stat.
6. The `local` transport is the only proof of the core (inproc hits the validator first): block 37's `mutate_block` calls run without `AGENTMESH_BUS_TRANSPORT`.
7. A path-parameter bound written as the decoded count (128 instead of 384): `TestValidatorCountsEncodedPath` fails on the 128-byte CJK name; a `pattern` on a path parameter: `TestSpecBounds/<key>` fails because no row carries one.
8. The e2e exit-code cells and the CLI texts: `rg -n 'not_found|validation' internal/e2e internal/cli --glob '*_test.go'` before Task 2 for any test sending a negative id or an over-long name expecting `not_found`.

## The inventory

### Limits the server enforces today, and the fields they bound

| Go limit (site) | Value, unit | Spec fields |
| --- | --- | --- |
| `store.NameRule` (`store/names.go:32`; literal 128 becomes `store.MaxNameBytes`) | 1 to 128 bytes, valid UTF-8, no NUL, no `/`, no control characters | `ChannelParam`, `ScopeParam`, `identity` path (`agentStatusHistory`, `resetCredential`) (these four: `maxLength: 384`, ruling 15), `OpenSessionRequest.hint`, `OfferedCursor.channel`, `ReceiveRequest.channels[]`, `CreateChannelRequest.name`, `.scope`, `RenameChannelRequest.name`, `ACLEntry.identity`, `CreateScopeRequest.name`, `CreateAgentIdentityRequest.name`, `.scope`, `CreateIdentityByEmailRequest.email`, `CreateBridgeRequest.channel`, `RegisterRequest.identity`, `TaskPatch.owner`, `listTasks` `owner`, `search` `channel`, `sender`, `TokenRequest.client_id` |
| `rules.MaxLineRunes` (`rules/status.go:12`), `MaxSubjectRunes` | 200 code points, one line | `SendRequest.subject`, `EditMemoryRequest.subject`, `SetAgentStatusRequest.text`, `.problem` |
| `rules.MaxTags`, `rules.MaxTagLen`, `tagRe` (`rules/tags.go`) | 10 items; 32 characters of `[a-z0-9-]` with one optional `:` | `SendRequest.tags`, `EditMemoryRequest.tags` (`maxItems: 10`; items `maxLength: 32`, `pattern: ^[A-Za-z0-9-]+(:[A-Za-z0-9-]+)?$`: the core lowercases first, so the spec pattern is the case-insensitive form) |
| `rules.NormalizeTagPatterns` (`tagPrefixRe`) | 10 items; a tag or a 1 to 32 character prefix plus `*` | `TagPatterns.patterns`, `history` `tags`, `search` `tags`, `unsubscribeTags` `pattern` (`maxItems: 10`; items `maxLength: 33` (`rules.MaxTagPatternLen`), `pattern: ^[A-Za-z0-9-]+(:[A-Za-z0-9-]+)?$\|^[A-Za-z0-9-]+(:[A-Za-z0-9-]*)?\*$`) |
| `rules.SearchPageMax` (`rules/vector.go:66`) | 1000 | `search` `count` (`maximum: 1000`; refusal above it: ruling 1) |
| `receive_max_count` (`core/config.go:162`: 1 to 10000; becomes `core.ReceiveCountCeiling`) | 10000 | `ReceiveRequest.count`, `history` `count` (`format: int32`, `x-go-type: int`, `minimum: 0`, `maximum: 10000`) |
| `watch_max_seconds` (`core/config.go:152`: 1 to 240; becomes `core.WatchSecondsCeiling`) | 240 s | `watch` `timeout` (`minimum: 0`, `maximum: 240`) |
| `max_message_kib` (`core/config.go:158`: 1 to 1024; `append.go:50`; becomes `core.MessageKiBCeiling`) | 1024 KiB per envelope | `SendRequest.content`, `EditMemoryRequest.content`, `TaskCreateRequest.description`, `TaskPatch.description` (`maxLength: 1048576`, bytes) |
| `limitBody` (`server/server.go:132`) | `max_message_kib*1024 + 1 MiB` per request body | no field; 413 `payload_too_large` on every operation with a body (ADR 0001 choice 11) |
| `validateTaskSubject` (`tasks/doc.go:70`; becomes `tasks.MaxSubjectRunes`, ruling 3) | 1 to 256 code points, no control characters | `TaskCreateRequest.subject`, `TaskPatch.subject` (`minLength: 1` on create) |
| `maxBlockers` (`tasks/doc.go:246`; becomes `tasks.MaxBlockers`) | 64 | `TaskCreateRequest.blocked_by`, `TaskPatch.add_blocked_by`, `.remove_blocked_by` |
| `store.ValidPermission` (`store/acl.go:32`; `store.AllPermissions` is new) | 3 permissions | `ACLEntry.permissions` (`maxItems: 3`, `minItems: 1`) |
| `resumeTokenBytes` (`sessions/service.go:26`; `sessions.ResumeTokenLen`, `ResumeTokenPattern` are new) | 43 characters of base64url | `OpenSessionRequest.resume_token` |
| `strconv.Atoi` of the cursor (`search/service.go:174`; `rules.MaxSearchCursorLen` is new) | 19 decimal digits | `search` `cursor` |
| `slackapi.ValidChannelName` (`slackapi/slackapi.go:182`; `slackapi.MaxChannelNameLen`, `ChannelNamePattern` are new) | 1 to 80 of `[a-z0-9_-]` | `CreateBridgeRequest.slack_name` |
| the core's `< 0` / `< 1` checks (`receive.go:122`, `watch.go:23,26`, `history.go:42,46`, `search/service.go:168`, `sessions/open.go:36`, `memories.go:180`) | non-negative, or at least 1 | `minimum: 0` on `count`, `timeout`, `after`, `OfferedCursor.seq`; `minimum: 1` on `thread`, `if_revision` |
| `assertion.MaxJTIBytes` (`auth/assertion.go:126`) | 256 bytes | no spec field (inside the JWT) |

### New limits (Eric's decision of 2026-11-06, rule (b); each a constant, a row, an ADR line)

| Constant | Value, unit | Spec fields | Core refusal site |
| --- | --- | --- | --- |
| `rules.MaxLabelRunes` | 256 code points | `SendRequest.type`, `EditMemoryRequest.type`, `SetAgentStatusRequest.tag`, `TaskPatch.status`, `listTasks` `status` | `messaging.Send`, `memories.Edit`, (`tag` and `status` are refused by their enum checks first; the length check precedes them so a 257-rune value says "at most 256 characters") |
| `rules.MaxTokenBytes` | 1024 bytes | `SessionParam` (`maxLength: 3072`, ruling 15), `SendRequest.session`, `ReceiveRequest.ack`, `IdempotencyKeyParam`, `RegisterRequest.enrollment_token` | `sessions.Require`/`Owned` (every session-scoped call), `delivery.Receive`, `core.CheckReceipt`, `identities.Register` |
| `rules.MaxMetadataKeys`, `MaxMetadataKeyRunes`, `MaxMetadataValueRunes` | 32 keys; 64 and 1024 code points | `SendRequest.metadata`, `EditMemoryRequest.metadata`, `TaskCreateRequest.metadata`, `TaskPatch.metadata` (`maxProperties: 32`; values `maxLength: 1024`; keys core-only, ruling 11) | `rules.CheckMetadata` from `messaging.Send`, `memories.Edit`, `tasks.Create`, `tasks.applyPatch` (patch and merged) |
| `rules.MaxArrayItems` | 256 items | `OpenSessionRequest.cursors`, `ReceiveRequest.channels`, `CreateChannelRequest.acl`, the `setACL` body | `sessions.Open`, `delivery.Receive`, `core.aclEntries` (`convert.go:80`) |
| `rules.MaxQueryRunes` (ruling 9) | 1024 code points | `search` `q` | `search.prepare` |
| `rules.MaxTagPatternLen` | 33 | the pattern items above | existing (`validTagPattern`) |
| `rules.MaxSearchCursorLen` (ruling 7) | 19 | `search` `cursor` | existing (`Atoi` overflow) |
| `core.ReceiveCountCeiling`, `WatchSecondsCeiling`, `MessageKiBCeiling` (ruling 1) | 10000; 240; 1024 | the setting-derived fields above | `delivery.Receive`, `messaging.History`, `delivery.Watch`; `search.prepare` uses `rules.SearchPageMax` |
| `tasks.MaxSubjectRunes`, `tasks.MaxBlockers` | 256; 64 | above | existing sites, raw counts (ruling 4) |
| `store.MaxNameBytes`, `store.AllPermissions` | 128; 3 | above | existing; `core.aclEntries` |
| `sessions.ResumeTokenLen`, `ResumeTokenPattern` | 43; `^[A-Za-z0-9_-]{43}$` | `OpenSessionRequest.resume_token` | existing (`validToken`) |
| `assertion.MaxTokenBytes` (ruling 8) | 16384 bytes | `TokenRequest.client_assertion`, `.subject_token`, `.actor_token` | `assertion.Parse`; the token handler |
| `server.MaxOAuthFieldBytes` (ruling 8) | 1024 bytes | `TokenRequest.grant_type`, `.client_assertion_type`, `.subject_token_type`, `.actor_token_type`, `.requested_token_type`, `.audience`, `.resource`, `.scope` | the token handler (`Token`, before the grant switch) |
| `keys.MaxJWKMembers` | 16 properties | `RegisterRequest.public_key_jwk` (`maxProperties: 16`) | the register handler before `keys.FromJWK` (`auth_handlers.go:161`) |
| `slackapi.MaxChannelNameLen`, `ChannelNamePattern` | 80; `^[a-z0-9_-]{1,80}$` | `CreateBridgeRequest.slack_name` | existing (`slackbridge/create.go:176`) |
| `int64` ranges (ruling 6) | `0` (or `1`) to `9223372036854775807` | `IdParam`, `OfferedCursor.seq`, `SendRequest.reply_to`, `EditMemoryRequest.if_revision`, `TaskCreateRequest.parent`, `.before`, `.after`, `.blocked_by[]`, `TaskPatch.parent`, `.before`, `.after`, `.leased_until`, `.add_blocked_by[]`, `.remove_blocked_by[]`, `ClaimTaskRequest.leased_until`, `history` `after`, `before`, `thread`, `search` `since`, `until`, `thread`, `watch` `after` | `rules.NonNegative` at each aggregate (Task 2) |

### Units, per category

| Category | Unit the core counts | Spec | Why |
| --- | --- | --- | --- |
| names | bytes (`store.NameRule`) | `maxLength: 128`, description "bytes" | file names (ruling 2); the spec is looser, never stricter |
| one-line text, labels, metadata values, query, task subject | code points | exact | the rules already count runes (`utf8.RuneCountInString`), or convert (ruling 3) |
| tags, patterns, resume token, cursor, Slack name | bytes = code points (ASCII by pattern) | exact | the pattern admits ASCII only |
| opaque tokens, JWTs, OAuth fields, content | bytes | same number, description "bytes" | tokens are compared or hashed as bytes; content is sized by the envelope |
| path parameters (`ChannelParam`, `ScopeParam`, `identity`, `SessionParam`) | decoded bytes (`store.NameRule`, `rules.MaxTokenBytes`) | three times the byte bound, description "percent-encoded length" | kin validates the encoded segment (ruling 15); the spec stays looser than the server |
| counts, seconds, ids | integers | `format: int32` + `x-go-type: int` for counts, `int64` for ids and seqs, `double` for `timeout` | the generated Go types stay |

---

### Task 1: The rule constants and helpers in `internal/core/rules`, `store`, `sessions`, `tasks`

**Files:**
- Modify: `internal/core/rules/tags.go` (raw count before dedupe; `MaxTagPatternLen`; `TagSpecPattern`, `TagPatternSpecPattern` string constants; a doc line that the spec patterns are the case-insensitive forms of `tagRe` and `tagPrefixRe`), `internal/core/rules/tags_test.go`
- Modify: `internal/core/rules/status.go` (`NormalizeLine` counts before trimming, ruling 14), `internal/core/rules/status_test.go`
- Create: `internal/core/rules/bounds.go` (`MaxLabelRunes`, `MaxTokenBytes`, `MaxMetadataKeys`, `MaxMetadataKeyRunes`, `MaxMetadataValueRunes`, `MaxArrayItems`, `MaxQueryRunes`, `MaxSearchCursorLen`; `CheckLabel(field, s string) error`, `CheckToken(field, s string) error`, `CheckMetadata(m map[string]string) error`, `CheckItems(field string, n int) error`, `NonNegative(field string, v int64) error`, `AtLeastOne(field string, v int64) error`; every error `bus.Errorf(bus.CodeValidation, false, ...)` naming the field, the limit and the unit, e.g. "type must be at most 256 characters", "ack must be at most 1024 bytes", "metadata has 33 keys, at most 32", "metadata key %q must be at most 64 characters", "cursors has 257 entries, at most 256", "after must not be negative"), `internal/core/rules/bounds_test.go`
- Modify: `internal/store/names.go` (`MaxNameBytes = 128`; `NameRule` uses it; message unchanged), `internal/store/acl.go` (`var AllPermissions = []Permission{PermRead, PermWrite, PermAdmin}`; `ValidPermission` ranges over it), `internal/store/names_test.go`
- Modify: `internal/core/sessions/service.go` (`ResumeTokenLen = 43`, `ResumeTokenPattern = "^[A-Za-z0-9_-]{43}$"`, a test that `validToken` and the pattern agree on a corpus: 43 valid, 42, 44, a `+`), `internal/core/sessions/service_test.go` (or the nearest existing test file)
- Modify: `internal/core/tasks/doc.go` (`MaxSubjectRunes = 256`, `MaxBlockers = 64` exported; `validateTaskSubject` counts runes, message "subject must be 1-256 characters"; the blocker count is checked on the raw list before `dedupeIDs`), `internal/core/tasks/doc_test.go` (or `service_test.go`)

**Interfaces:**
- `rules.TagSpecPattern = "^[A-Za-z0-9-]+(:[A-Za-z0-9-]+)?$"`, `rules.TagPatternSpecPattern = "^[A-Za-z0-9-]+(:[A-Za-z0-9-]+)?$|^[A-Za-z0-9-]+(:[A-Za-z0-9-]*)?\\*$"`.
- `TestTagSpecPatternsAgree`: for a corpus (`env`, `env:prod`, `ENV:Prod`, `env:`, `env:*`, `env*`, `*`, `:a`, `a:b:c`, `a b`, 32 and 33 characters, with and without `*`), `regexp.MustCompile(TagSpecPattern).MatchString(s) && len(s) <= MaxTagLen` equals `NormalizeTags([]string{s}) == nil`, and the pattern form likewise against `NormalizeTagPatterns` with `MaxTagPatternLen`.

- [ ] **Step 1: Write the failing tests**

`bounds_test.go`: `TestCheckLabel` (256 two-byte runes pass, 257 fail with "type must be at most 256 characters"), `TestCheckToken` (1024 bytes pass, 1025 fail, a 513-rune two-byte string fails: bytes), `TestCheckMetadata` (32 keys pass, 33 fail; a 64-rune key passes, 65 fails; a 1024-rune value passes, 1025 fails; nil passes), `TestCheckItems`, `TestNonNegative`, `TestAtLeastOne`. `tags_test.go`: `TestTagsRawCountBeforeDedupe` (`["a","a","b","c","d","e","f","g","h","i","j"]`, eleven entries with a duplicate, is refused with "at most 10 tags per message"; ten with a duplicate pass), `TestTagSpecPatternsAgree`. `status_test.go`: `TestNormalizeLineCountsBeforeTrim` (200 runes plus a trailing space is refused; 200 runes pass; 200 two-byte runes pass). `names_test.go`: `MaxNameBytes == 128`, `AllPermissions` has 3 members and `ValidPermission` agrees. tasks: `TestTaskSubjectRunes` (256 two-byte runes pass; 257 ASCII fail with "subject must be 1-256 characters"), `TestBlockersRawCount` (65 ids with a duplicate refused).

Run: `go test ./internal/core/rules/ ./internal/store/ ./internal/core/sessions/ ./internal/core/tasks/ 2>&1 | tail -20`
Expected: compile failures (undefined constants and helpers) and the two behavior tests red.

- [ ] **Step 2: Implement; run the packages**

Run: `go test ./internal/core/... ./internal/store/... 2>&1 | tail -8`
Expected: `ok` for every package; `search/query_test.go` is untouched here (Task 3 flips it).

- [ ] **Step 3: Vet, format, lint; commit**

Run: `go vet ./... && make fmt-check && make lint`

```bash
git add internal/core/rules internal/store internal/core/sessions internal/core/tasks
git commit -m "feat(rules): the bound constants, helpers and raw counts of issue #34"
```

---

### Task 2: The core refuses every bound (the `local` transport proof)

**Files:**
- Modify: `internal/core/sessions/open.go` (`len(in.Cursors) > rules.MaxArrayItems`; each cursor channel passes `store.NameRule`; `seq` through `rules.NonNegative`), `internal/core/sessions/service.go` (`Require` and `Owned`: `rules.CheckToken("session", id)` first)
- Modify: `internal/core/receipts.go` (`CheckReceipt`: `rules.CheckToken("Idempotency-Key", key)` when `key != ""`)
- Modify: `internal/core/delivery/receive.go` (`ack` token, `channels` count and names, `count > core.ReceiveCountCeiling`), `internal/core/delivery/watch.go` (`timeout > core.WatchSecondsCeiling`: "timeout must be at most 240 seconds"; `after` through `NonNegative`), `internal/core/config.go` (the three ceilings; `Validate`'s table uses them)
- Modify: `internal/core/messaging/send.go` (`rules.CheckLabel("type", in.Type)`, `rules.CheckMetadata(in.Metadata)`, `rules.CheckToken("session", in.Session)`, `rules.NonNegative("reply_to", in.ReplyTo)`), `internal/core/messaging/history.go` (`count > ReceiveCountCeiling`; `after`, `before` through `NonNegative`)
- Modify: `internal/core/memories/memories.go` (`Edit`: `type` label, metadata; tags and `if_revision` unchanged; `Get`, `Revisions`, `Edit`, `Delete`: `rules.NonNegative("id", id)` before the Store read, lines 22, 57, 175, 292)
- Modify: `internal/core/tasks/create.go`, `update.go`, `read.go`, `doc.go` (metadata on create; patch and merged on update; `parent`, `before`, `after`, `leased_until`, every blocker id and the path id through `NonNegative`; `owner` through `store.NameRule`; `status` through `CheckLabel` before the enum check; `listTasks` `owner`, `status` likewise)
- Modify: `internal/core/convert.go` (`aclEntries`: `len(in) > rules.MaxArrayItems`; `len(e.Permissions) > len(store.AllPermissions)`: "at most 3 permissions per ACL entry")
- Modify: `internal/core/search/service.go` (`rules.CheckLabel`-style check of `q` with `MaxQueryRunes`: "query must be at most 1024 characters"; `channel` and `sender` through `store.NameRule` when set; `count > rules.SearchPageMax` refused: "count must be at most 1000"; `since`, `until` through `NonNegative`; `thread` through `AtLeastOne`), `internal/core/search/query_test.go:29` (the "count capped" row expects `validation`)
- Modify: `internal/core/statuses/statuses.go` (`tag` through `CheckLabel` before `CheckStatusTag`; `History`'s identity through `store.NameRule`), `internal/core/identities/register.go` (`rules.CheckToken("enrollment_token", in.EnrollmentToken)`), `internal/core/identities/admin.go` (reset: the identity through `NameRule` before the lookup, if not already)
- Create: `internal/conformance/bus/bounds_test.go` (`TestOverBoundRefused`, `TestRuneCountsAgree`)

**Interfaces:** `core.ReceiveCountCeiling = 10000`, `core.WatchSecondsCeiling = 240`, `core.MessageKiBCeiling = 1024` (`internal/core/config.go`, next to the bounds table, which reads them).

- [ ] **Step 1: Write `TestOverBoundRefused` first**

One table, each case `{name, call func(ctx, bus.Bus) error, text string}` expecting a `*bus.Error` with code `validation` on both transports; `text` (the core's own wording, e.g. "at most 200 characters") is asserted only when the harness transport is `local`, because on inproc the validator answers first with kin's text once Task 4 lands (`open_resume_token_shape`: core "resume_token is malformed", kin "maximum string length is 43"). The harness runs it on both transports (`local` is the core alone). Cases (the name is the subtest; the input is one over the bound, everything else valid):
`session_id_bytes` (`Receive` with a 1025-byte session), `open_cursors_items` (257 cursors), `open_cursor_channel_bytes` (129-byte name), `open_cursor_seq_negative`, `open_resume_token_shape` (44 characters), `receive_ack_bytes`, `receive_channels_items`, `receive_count_ceiling` (10001), `watch_timeout_ceiling` (241), `watch_after_negative`, `send_subject_runes` (201), `send_subject_padded` (200 runes plus a space, ruling 14), `send_type_runes` (257), `send_metadata_keys` (33), `send_metadata_key_runes` (65), `send_metadata_value_runes` (1025), `send_tags_items` (11), `send_tags_duplicates` (11 with a duplicate, ruling 4), `send_tag_len` (33), `send_reply_to_negative`, `send_session_bytes`, `history_count_ceiling`, `history_after_negative`, `history_tags_items`, `history_pattern_len` (34), `search_query_runes` (1025), `search_count_ceiling` (1001), `search_cursor_len` (20 digits), `search_since_negative`, `search_thread_zero`, `search_channel_bytes`, `edit_memory_type_runes`, `edit_memory_metadata_keys`, `edit_memory_subject_runes`, `memory_id_negative`, `task_subject_runes` (257), `task_subject_empty`, `task_description_envelope` (content above the harness's `max_message_kib`: the existing envelope refusal), `task_metadata_keys` (create), `task_patch_metadata_merged` (16 keys stored, patch of 17 new keys: merged 33), `task_blockers_items` (65), `task_blockers_duplicates`, `task_parent_negative`, `task_id_negative` (`GetTask` with -1), `task_leased_until_negative`, `task_owner_bytes`, `task_status_runes`, `list_tasks_owner_bytes`, `create_channel_acl_items` (257), `acl_permissions_items` (4 entries, `read` repeated), `acl_identity_bytes`, `create_channel_name_bytes`, `rename_name_bytes`, `subscribe_tags_items`, `subscribe_tags_pattern_len`, `status_text_runes`, `status_problem_runes`, `status_tag_runes` (257, message names 256), `status_history_identity_bytes`, `idempotency_key_bytes` (`CreateChannel` with a 1025-byte key).
`TestRuneCountsAgree`: `Send` with a subject of 200 two-byte runes (400 bytes), a `type` of 256 two-byte runes, metadata values of 1024 two-byte runes, and `CreateTask` with a subject of 256 two-byte runes each succeed on both transports (the validator counts code points, the core counts runes: agreement at the boundary).

Run: `go test -count=1 ./internal/conformance/bus/ -run 'TestOverBoundRefused|TestRuneCountsAgree' 2>&1 | tail -30`
Expected: compile failure (`ReceiveCountCeiling` undefined) or red cases naming `not_found`, `AckIgnored`-style success, or clamping.

- [ ] **Step 2: Implement the sites**

Keep each check before the Store read of its aggregate, after authentication where the code already orders it that way (a bound refusal does not leak existence: it fires on the input alone, so ordering before the access check is safe and is what `sessions/open.go:22` already does for `hint`).

Run: `go test ./internal/core/... && go test -count=1 ./internal/conformance/bus/ -run 'TestOverBoundRefused|TestRuneCountsAgree' && AGENTMESH_BUS_TRANSPORT=inproc go test -count=1 ./internal/conformance/bus/ -run 'TestOverBoundRefused|TestRuneCountsAgree' 2>&1 | tail -5`
Expected: `ok` three times (on inproc the validator has no bounds yet, so the core answers there too).

- [ ] **Step 3: The whole net**

Run: `make test && go test -count=1 ./internal/conformance/bus/ 2>&1 | tail -5`
Expected: `ok`; the e2e suite (`internal/e2e`) is green: Review Focus 7 names what to look at if a cell flips.

- [ ] **Step 4: Vet, format, lint; commit**

```bash
git add internal/core internal/conformance/bus/bounds_test.go
git commit -m "feat(core): refuse every request bound in the core, ceilings for the clamped settings (issue #34)"
```

---

### Task 3: The auth, token, JWK and Slack constants

**Files:**
- Modify: `internal/auth/assertion/assertion.go` (`MaxTokenBytes = 16 << 10`; `Parse` refuses a longer `raw` with `malformed("assertion is %d bytes, at most %d")`), `internal/auth/assertion/assertion_test.go`
- Modify: `internal/auth/keys/keys.go` (`MaxJWKMembers = 16`; `CheckJWKMembers(n int) error`), `internal/auth/keys/keys_test.go`
- Modify: `internal/server/oauth.go` (`MaxOAuthFieldBytes = 1024`; `checkTokenFormBounds(b *gen.TokenRequest) (string, bool)` naming the first field over its bound), `internal/server/auth_handlers.go` (`Token` calls it before the grant switch and answers `invalid_request` "<field> exceeds <n> bytes"; the register handler checks `len(jwk) > keys.MaxJWKMembers` before `keys.FromJWK` and answers `validation`), `internal/server/oauth_test.go`, `internal/server/auth_test.go`
- Modify: `internal/slackapi/slackapi.go` (`MaxChannelNameLen = 80`, `ChannelNamePattern = "^[a-z0-9_-]{1,80}$"`; `ValidChannelName` unchanged in behavior), `internal/slackapi/slackapi_test.go` (`TestChannelNamePatternAgrees`: the compiled pattern and `ValidChannelName` agree on a corpus)

- [ ] **Step 1: Tests first**

`TestParseRefusesOversizeToken` (16385 bytes: malformed, message names the limit; 16384 of a syntactically valid but unsigned token fails later than the size check), `TestCheckJWKMembers`, `TestTokenFormBounds` (a `client_assertion` of 16385 bytes answers 400 `invalid_request` over `env.raw`; an `audience` of 1025 bytes likewise; `client_id` of 129 bytes likewise), `TestRegisterRefusesWideJWK` (a JWK with 17 members answers 400 `validation`).

Run: `go test ./internal/auth/... ./internal/server/ ./internal/slackapi/ -run 'TestParseRefusesOversizeToken|TestCheckJWKMembers|TestTokenFormBounds|TestRegisterRefusesWideJWK|TestChannelNamePatternAgrees' 2>&1 | tail -10`
Expected: compile failures, then red.

- [ ] **Step 2: Implement; run the packages and the m7 rules**

Run: `go test ./internal/auth/... ./internal/server/... ./internal/slackapi/... ./internal/slackbridge/... && bash scripts/m7-exit-checks.sh --deps-only && bash scripts/m5-exit-checks.sh --deps-only`
Expected: `ok`; both scripts print their pass lines.

- [ ] **Step 3: Commit**

```bash
git add internal/auth internal/server/oauth.go internal/server/auth_handlers.go internal/server/oauth_test.go internal/server/auth_test.go internal/slackapi
git commit -m "feat(auth): size ceilings for JWT inputs, OAuth form fields, JWK members and Slack names (issue #34)"
```

---

### Task 4: The spec bounds, `make generate`, `TestSpecBounds`

**Files:**
- Modify: `api/openapi.yaml` (every field of the inventory; descriptions name the unit, the constant's meaning and the setting where one applies; `x-go-type: int` on the three `count` fields with `format: int32`; no enum added; the `IdempotencyKeyParam` description keeps its Decision 66 sentence)
- Regenerate: `internal/gen/gen.go`, `internal/gen/spec/spec.go` (`make generate`)
- Create: `internal/server/spec_bounds_test.go` (`TestSpecBounds`; the walker from the scratchpad program, moved in: parameters of the path item and the operation, request body schemas, recursive through `properties`, `items`, `additionalProperties`, `allOf`/`oneOf`/`anyOf`, keyed `parameters/<Name>` for a `$ref` parameter, `schemas/<Name><.path>` for a `$ref` schema (walked once), `operations/<opId>/<in>/<name>` for an inline parameter and `operations/<opId>/body<.path>` for an inline body)

**Interfaces:**

```go
type unit string // "code points", "bytes", "percent-encoded", "items", "keys", "n", "seconds"

type bound struct {
	MaxLength *int     // the spec's maxLength
	MinLength int
	Pattern   string
	Min, Max  *float64 // the spec's minimum and maximum
	Format    string   // "int32", "int64", "double"
	MaxItems  *int
	MinItems  int
	MaxProps  *int
	Unit      unit     // what the server counts; the description must contain the word
	Setting   string   // the setting whose ceiling this is; the description must name it
	Source    string   // the Go constant or site, for the reader
}

// bounds is the literal table: one row per bounded request field, keyed as the walker keys it.
var bounds = map[string]bound{
	"parameters/SessionParam":       {MaxLength: n(3 * rules.MaxTokenBytes), Unit: encoded, Source: "rules.MaxTokenBytes; sessions.Require; ruling 15"},
	"parameters/ChannelParam":       {MaxLength: n(3 * store.MaxNameBytes), Unit: encoded, Source: "store.NameRule; ruling 15"},
	"parameters/IdParam":            {Format: "int64", Min: f(0), Max: f(math.MaxInt64), Unit: nUnit, Source: "rules.NonNegative; the type"},
	"schemas/SendRequest.subject":   {MaxLength: n(rules.MaxLineRunes), Unit: codePoints, Source: "rules.NormalizeSubject"},
	"schemas/SendRequest.content":   {MaxLength: n(core.MessageKiBCeiling * 1024), Unit: bytes, Setting: "max_message_kib", Source: "core.Append envelope"},
	"schemas/SendRequest.metadata":  {MaxProps: n(rules.MaxMetadataKeys), Unit: keys, Source: "rules.CheckMetadata"},
	"schemas/SendRequest.metadata.<key>": {MaxLength: n(rules.MaxMetadataValueRunes), Unit: codePoints, Source: "rules.CheckMetadata"},
	"schemas/SendRequest.tags":      {MaxItems: n(rules.MaxTags), Unit: items, Source: "rules.NormalizeTags"},
	"schemas/SendRequest.tags[]":    {MaxLength: n(rules.MaxTagLen), Pattern: rules.TagSpecPattern, Unit: codePoints, Source: "rules.NormalizeTags"},
	"schemas/ReceiveRequest.count":  {Format: "int32", Min: f(0), Max: f(core.ReceiveCountCeiling), Unit: nUnit, Setting: "receive_max_count", Source: "core.ReceiveCountCeiling"},
	"operations/watch/query/timeout": {Format: "double", Min: f(0), Max: f(core.WatchSecondsCeiling), Unit: seconds, Setting: "watch_max_seconds", Source: "core.WatchSecondsCeiling"},
	// ... every row of the inventory
}
```

Subtests: `TestSpecBounds/<key>` for each walked bounded-kind leaf (a non-enum string, an integer, a number, an array, a map): the row must exist ("unlisted field") and each of its members must equal the spec's (nil against present and present against absent both fail, naming the keyword), the description must contain the unit word and the setting name when set; `TestSpecBounds/coverage` fails on any bounded-kind leaf without a row; `TestSpecBounds/stale` fails on any row whose key the walk did not visit; `TestSpecBounds/int32_types` asserts that every `format: int32` carries `x-go-type: int` (read from `Extensions`) so the generated types stay; `TestSpecBounds/enums` asserts no new `enum` beyond the eight (ruling 5). `TestValidatorCountsCodePoints` sends a `search` with `channel` of 128 three-byte code points (384 bytes, decoded by the query binder) through `env.raw` and expects the validator to pass it (the core's `validation` from `NameRule` follows, without kin's phrase); `TestValidatorCountsEncodedPath` sends `getACL` for a channel of 128 three-byte code points (384 bytes, 1152 encoded characters) and expects kin's `maximum string length is 384` (the encoded form is what it sees, ruling 15), then a 128-byte CJK name (384 encoded characters) and expects the validator to pass it. `TestInt64OverflowRefused`: `9223372036854775808` as `reply_to` answers 400 `validation`; `9223372036854775807` reaches the core (any non-400 answer, or the core's own text).

- [ ] **Step 1: Write the test with the full table, run it against the unchanged spec**

Run: `go test ./internal/server/ -run 'TestSpecBounds' 2>&1 | rg -c 'spec lacks'`
Expected: a count in the hundreds (every row reports the missing keyword), `coverage` green (nothing is bounded yet) and `stale` green.

- [ ] **Step 2: Write the bounds into the spec; regenerate**

Run: `make generate && git diff --stat internal/gen && go test ./internal/server/ -run 'TestSpecBounds|TestValidatorCountsCodePoints|TestValidatorCountsEncodedPath|TestInt64OverflowRefused' 2>&1 | tail -5 && bash scripts/m7-exit-checks.sh --deps-only && bash scripts/m4-exit-checks.sh --deps-only`
Expected: `gen.go` differs in comment lines only (`git diff internal/gen/gen.go | rg '^[-+]' | rg -v '^[-+]\s*//' | rg -v '^(\+\+\+|---)'` prints nothing), `spec/spec.go` differs; the tests pass.

- [ ] **Step 3: The regression net**

Run: `make test && make test-conformance 2>&1 | tail -5`
Expected: `ok`; `TestWireRoundTrip` and `TestToolCoverage` unchanged and green; the inproc suite's `TestOverBoundRefused` now meets the validator first and still sees `validation`.

- [ ] **Step 4: Commit**

```bash
git add api/openapi.yaml internal/gen internal/server/spec_bounds_test.go
git commit -m "feat(api): every request field carries its bound, TestSpecBounds pins it to the Go constants (issue #34)"
```

---

### Task 5: `TestValidatorRefusesOverBound`

**Files:**
- Create: `internal/server/bounds_refuse_test.go`
- Uses: `envOptions.cfg` (`internal/server/testenv_test.go:13`, `func(*core.Config)`) to set `MaxMessageKiB = core.MessageKiBCeiling` for the content probes (ruling 10); no change to the env

**Interfaces:**

```go
// probe says how to send one field of one operation: the operation, a valid base request
// (path with every parameter filled, query, headers, body as map[string]any) and the JSON
// pointer or parameter the over-bound value replaces. The value is derived from the bounds
// row of the same key: MaxLength+1 of "a" (or 2-byte runes for code-point rows), MaxItems+1
// valid items, MaxProps+1 keys, Max+1 for an int32 or double, "a b" for a pattern.
type probe struct {
	op     string
	base   request
	target string // "path:channel", "query:count", "header:Idempotency-Key", "body:/subject"
}

var probes = map[string]probe{ /* one per key of bounds, or an entry in probeExceptions */ }

var probeExceptions = map[string]string{
	"parameters/IdParam": "int64 maximum: TestInt64OverflowRefused (the decoder refuses, not the validator)",
	// every int64 row, same reason; metadata keys (core-only, ruling 11)
}
```

The first probe written is `schemas/SendRequest.subject`, run alone to confirm that the flattened `err.Error()` `nethttp-middleware` hands `ErrorHandlerWithOpts` (`server.go:124`) carries kin's leaf phrase in the problem's `detail` (the path spike shows `parameter "channel" in path has an error: maximum string length is 3`; a body error reads `request body has an error: doesn't match schema: Error at "/subject": maximum string length is 200`); if the middleware truncated it, the assertion would move to the status and `title` alone and the plan would say so. Each subtest `TestValidatorRefusesOverBound/<key>` sends the mutated request through `env.raw` and expects 400 (`application/problem+json`, code `validation`; for `token` the RFC 6749 body with `invalid_request`) whose `detail` contains one of kin's phrases (Review Focus 3), which proves the validator and not the core refused; `coverage` fails on a bounds row with neither a probe nor an exception; `stale` fails on a probe or exception without a row. The probes for `content`, `description` run under `MaxMessageKiB = core.MessageKiBCeiling` so `limitBody` admits 1 MiB + 1 byte (ruling 10).

- [ ] **Step 1: Write it; run**

Run: `go test ./internal/server/ -run 'TestValidatorRefusesOverBound' 2>&1 | tail -10`
Expected: `ok`; the `-v` log lists one subtest per row plus `coverage` and `stale`.

- [ ] **Step 2: Commit**

```bash
git add internal/server/bounds_refuse_test.go
git commit -m "test(server): the validator refuses one over every bound (issue #34)"
```

---

### Task 6: Selftest block 37

**Files:**
- Modify: `scripts/check-gates-selftest.sh` (`block_spec_bounds_fire` after `block_error_responses_fire`, in the function list and the call list; the header comment names issue #34 and the three tests; mutations 1 to 8, 11 and 12 are Docker-free, 9 and 10 run the conformance suite under `dbtest.ForEachEngine` and need Docker like blocks 9 to 11)

Mutations (12; anchors are scoped so each occurs once):
1. `spec-bound-removed`: `mutate_spec_block` scope `    SendRequest:`, from the subject's `          maxLength: 200` to `` → `./internal/server/ '^TestSpecBounds$' TestSpecBounds/schemas/SendRequest.subject`, extra `spec lacks maxLength`.
2. `spec-bound-changed`: same scope, `maxLength: 200` → `maxLength: 201` → the same subtest.
3. `go-constant-changed`: `mutate_unit_block` on `internal/core/rules/status.go`, `const MaxLineRunes = 200` → `201`, `./internal/server/ '^TestSpecBounds$' TestSpecBounds/schemas/SendRequest.subject`.
4. `spec-field-unlisted`: scope `    SendRequest:`, anchor `      properties:\n        subject:` (unchanged by Task 4) → `      properties:\n        extra:\n          type: string\n          maxLength: 5\n        subject:` → `TestSpecBounds/coverage`, extra `unlisted field schemas/SendRequest.extra`. Every spec anchor of this block is written against the post-Task-4 text of the file.
5. `table-row-stale`: `mutate_unit_block` on `internal/server/spec_bounds_test.go`, `var bounds = map[string]bound{` → the same plus `\n\t"schemas/SendRequest.nope": {MaxLength: n(1), Unit: bytes},` → `TestSpecBounds/stale`.
6. `spec-pattern-dropped`: scope `    SendRequest:`, remove the tags items' `          pattern:` line → `TestSpecBounds/schemas/SendRequest.tags[]`.
7. `ceiling-constant-changed`: `internal/core/config.go`, `ReceiveCountCeiling = 10000` → `10001` → `TestSpecBounds/schemas/ReceiveRequest.count`.
8. `description-unit-missing`: scope `    SendRequest:`, the subject's description loses the words `code points` → the same subtest, extra `description does not name the unit`.
9. `core-check-removed`: `mutate_block` (local transport) on `internal/core/rules/status.go`, `if utf8.RuneCountInString(s) > MaxLineRunes {` → `if utf8.RuneCountInString(s) > MaxLineRunes*4 {` (still compiles: `utf8` stays used) → `TestOverBoundRefused`, wants `--- FAIL: TestOverBoundRefused/send_subject_runes`.
10. `tags-dedupe-restored`: `mutate_block` on `internal/core/rules/tags.go`, the raw count line → removed → `TestOverBoundRefused`, wants `--- FAIL: TestOverBoundRefused/send_tags_duplicates`.
11. `validator-bound-loosened`: `mutate_spec_block` scope `    SendRequest:`, subject `maxLength: 200` → `maxLength: 100000` → `./internal/server/ '^TestValidatorRefusesOverBound$' TestValidatorRefusesOverBound/schemas/SendRequest.subject` (the core refuses with its own text; the subtest wants kin's phrase).
12. `probe-missing`: `mutate_unit_block` on `internal/server/bounds_refuse_test.go`, the `"schemas/SendRequest.subject":` probe line → removed → `TestValidatorRefusesOverBound/coverage`.

- [ ] **Step 1: Add the block; run it alone**

The script has no single-block switch (every block runs, minutes). Run: `make check-gates-selftest 2>&1 | tee /tmp/selftest-34-dev.log | rg 'selftest: (ok|problem)' | tail -14`
Expected: twelve `selftest: ok <label>` lines for the block 37 labels and no `problem` line; `shellcheck scripts/check-gates-selftest.sh` clean.

- [ ] **Step 2: Commit**

```bash
git add scripts/check-gates-selftest.sh
git commit -m "test(gates): selftest block 37, the spec bound checks fire (issue #34)"
```

---

### Task 7: Docs

**Files:**
- Modify: `CLAUDE.md` (the Design bullet after "Protocol client checks (issue #29 ...)": one sentence: "Request bounds (issue #34, Eric's decision of 2026-11-06): every request field of `api/openapi.yaml` carries the bound a named Go constant enforces (`internal/core/rules/bounds.go`, `store.MaxNameBytes`, the `core` ceilings); `TestSpecBounds` (`internal/server/spec_bounds_test.go`) holds the literal table keyed by schema or parameter, `TestValidatorRefusesOverBound` proves the validator and `TestOverBoundRefused` (`internal/conformance/bus`, the `local` transport) the core; mutations: `scripts/check-gates-selftest.sh` block 37.")
- Modify: `docs/adr/0001-transport-and-api.md` (addendum "Request bounds addendum (Eric's decision of 2026-11-06; issue #34)": the rule (a), (b), (c); one line per new constant of the inventory's second table with its value and unit; rulings 1 to 14 as plan rulings; the units table)
- Modify: `docs/adr/0007-openapi-code-generator.md` (one line under the protocol client checks addendum: `x-go-type` keeps the generated types when a bound needs `format: int32`; kin counts code points; the validator enforces every bound before the handler)
- Modify: `docs/ops/configuration.md` (the `watch_max_seconds`, `max_message_kib`, `receive_max_count` rows: "The ceiling is the spec's `maximum` for `timeout` / `maxLength` of content fields / `maximum` of `count`; above the configured value and below the ceiling the server clamps"), keeping the row shape `settingRow` parses (`internal/server/config/docs_test.go`)
- The issue: list the new limits (the second inventory table) in a comment for Eric's record (the controller posts it; Definition of Done E: no private names in it).

- [ ] **Step 1: Write; check**

Run: `go test ./internal/server/config/ -run 'Docs|Configuration' && rg -n 'agentbus2|github.com/ericfitz' docs/adr/0001-transport-and-api.md | head -3`
Expected: `ok`; every claim in the addendum is checked against the files of Tasks 1 to 5 (the reviewer spot-checks three constants).

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md docs/adr/0001-transport-and-api.md docs/adr/0007-openapi-code-generator.md docs/ops/configuration.md
git commit -m "docs: request bounds addendum, CLAUDE.md and the configuration ceilings (issue #34)"
```

---

### Task 8: `internal/mcpserver` and CLI texts (scoped follow-through)

**Files:**
- Modify: `internal/mcpserver/inputs.go` only where a `jsonschema` description names a limit that changed (the three `count` descriptions gain "at most 10000" / "at most 1000"); no bound keywords are added to the tool schemas (out of scope; the server answers `validation`).
- Modify: `internal/cli/help.go` / `internal/mcpcli/help.go` only if a help line states a bound that changed (`rg -n '256 bytes|1-256|at most' internal/cli internal/mcpcli internal/mcpserver`).

- [ ] **Step 1: Search, edit, run**

Run: `rg -n '1-256 bytes|256 bytes' internal docs --glob '!internal/gen/**'; go test ./internal/mcpserver/ ./internal/cli/ ./internal/mcpcli/ 2>&1 | tail -3`
Expected: no stale "256 bytes" text for the task subject; `ok`.

- [ ] **Step 2: Commit** (skip if nothing changed)

```bash
git add internal/mcpserver internal/cli internal/mcpcli
git commit -m "docs(mcp): count and subject limits in the tool and help text (issue #34)"
```

---

### Task 9: Done gate

- [ ] **Step 1: `make verify`**

Run: `make verify 2>&1 | tee /tmp/verify-34.log | tail -15`
Expected: every step passes, the Postgres suites included (a skip is not a pass); `check-gates` green.

- [ ] **Step 2: `make check-gates-selftest`**

Run: `make check-gates-selftest 2>&1 | tee /tmp/selftest-34.log | rg -c 'selftest: ok'`
Expected: the previous count plus 12; no `selftest: problem` line.

- [ ] **Step 3: Report**

Show both tails, the number of bounds rows, probes and conformance cases, and the second inventory table (the new limits) for Eric's record. Nothing is pushed.

## What Eric should see

1. Ruling 8: JWT inputs get a 16 KiB ceiling (`assertion.MaxTokenBytes`) instead of rule (b)'s 1024 bytes for opaque tokens, because corporate id_tokens exceed 1 KiB.
2. Ruling 9: `search` `q` gets 1024 code points, not rule (b)'s 256 for short strings.
3. Ruling 1: counts and timeouts above the setting's ceiling are refused where they were clamped (`search` above 1000, `receive`/`history` above 10000, `watch` above 240 s).
4. Rulings 3, 4, 14: the task subject counts code points (was bytes); tags, blockers and permissions are counted raw (before dedupe); the one-line rule counts before trimming.
5. Ruling 7: `resume_token` is pinned to its exact 43-character shape and the search cursor to 19 digits, tighter than rule (b).
6. Ruling 6: a negative id or sequence number answers `validation` where it answered `not_found`.
7. Ruling 12: response fields get no bounds of their own in this issue; shared schemas carry theirs into `respcheck`.
8. Ruling 15: path parameters are bounded on the percent-encoded segment (384 and 3072), because that is what the validator sees; the server still counts decoded bytes.
