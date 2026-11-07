# Issue 29: Protocol Drift Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make it hard for any client of the protocol to diverge from `api/openapi.yaml`: the four consumer packages obtain a `Bus` only from `internal/client` (an import rule under `make verify`), every generated wire type that crosses the wire round-trips through the client and server converters with no field dropped (`TestWireRoundTrip`), and every MCP tool's use of the Bus is recorded member by member (`TestToolCoverage`), each check with a mutation proof in `scripts/check-gates-selftest.sh`.

**Architecture:** Decision 47 stands: tool schemas stay hand-written and consumers keep using `internal/bus` domain types. The layering is enforced by checks instead. The import rule extends the Milestone 6 consumer group (`scripts/m6-exit-checks.sh`, direct imports of non-test code) to the four packages and the full forbidden list, and `make verify` runs it; `scripts/m10-exit-checks.sh` keeps only the `internal/cli` ban that is specific to the MCP-only binary. The converter test lives in `internal/server` (package `server`, a test file importing `internal/bus/remote`, as `peek_test.go`, `channels_test.go`, `sessions_test.go` and `agentstatus_test.go` already do): every inline wire mapping on both sides becomes a named converter, the client's request builders return the generated `gen.<Op>RequestObject` (the one generated struct bundling an operation's path, query, header and body), and a reflection harness fills every member, runs each pair both ways (`gen -> bus -> gen` and `bus -> gen -> bus`) and names every member that comes back zero or changed. The tool table is a literal in `internal/mcpserver/coverage_test.go` checked by a syntactic walk of the tool handlers (the model is `internal/core/access/sites_test.go`).

**Tech Stack:** Go (`CGO_ENABLED=0`), `go/ast` and `reflect` in tests, oapi-codegen output in `internal/gen` (never edited by hand), bash gate scripts (`scripts/*.sh`, shellcheck-clean).

**Spec:** GitHub issue #29 (`gh issue view 29 --comments`: the body and Eric's decision comment of 2026-11-06, "no open decisions"), ADR 0001 item 12 and its Consequences line, ADR 0007 Consequences. Checked on `b3b4f4c`: none of the four packages imports a forbidden package today, and the named converters that exist (`Message`, `Task`, `TaskSummary`, `ACLEntry`, `Health`, `Usage`, `ChannelInfo`, `Scope`, `Bridge`, `SigningKey`, `AgentStatus`, `Status`, `Session`, `ReceiveResult`, `Identity`) drop no field in either direction; the inline mappings are what the test will expose.

## Global Constraints

- Decision 47 is unchanged: hand-written MCP tool schemas, consumers use `internal/bus` domain types, `internal/bus/remote` wraps the generated client. No schema is generated from the spec and no tool shape has to match the API.
- The ADR addenda (Task 9) record Eric's decision of 2026-11-06 (issue #29); nothing else in ADR 0001 or 0007 changes. The plan's own rulings are listed under "Rulings made by this plan" and are not Eric's decisions.
- Import rules are on the direct imports of non-test code (`go list -f '{{.Imports}}'`, as m6 does; m4 uses `go list -deps` without `-test`). A `_test.go` file may import across these lines, and `internal/server` tests already import `internal/bus/remote`. Task 9 adds "(non-test code)" to the Decision 47 sentence in `CLAUDE.md`. `internal/cli` importing `internal/client/localmode` is allowed (not on the forbidden list): do not "fix" it.
- American English everywhere (code, comments, docs, commit messages).
- Done gate: `make verify` (needs Docker; a run that skips the Postgres suites is not a pass), then `ci.yml` and `windows.yml` green on the pushed commit, `release-check`, `gates-selftest` and `release-lint` jobs included. Each task runs the `go test`, `go vet`, `make fmt-check` and `make lint` commands it names; Task 9 runs `make verify` and `make check-gates-selftest`. No task pushes.
- Never edit `internal/gen` by hand. A mutation of `internal/gen/gen.go` happens only inside the selftest's throwaway worktree (as block 3 does).
- Until the first release (Eric, 2026-10-25): no compatibility shims, no deprecation paths. The converter extraction is a pure refactor: the wire bytes do not change. The handler idioms that keep required arrays non-null (`make([]gen.X, 0, n)` in `OpenSession`, `Receive`; `chans == nil -> []string{}` in `Watch`; `capabilityStrings` never nil) and the "absent, never null" optional members (`optStr`, `strPtr`, `int64Ptr`, `slicePtr`, `mapPtr`) move into the converters unchanged. The inproc Bus conformance suite (`AGENTMESH_BUS_TRANSPORT=inproc`) is the regression net; the hand tests `TestTaskConvertReclaimedMark` and `TestTaskWireReclaimedMark` stay (they pin the nil-for-zero behavior the filler cannot see).
- `TestAccessRuleSites` (`internal/core/access/sites_test.go`) keys its allowlist by "file func". Extracting a handler's wire copy into a converter moves the site: the entry moves to the new function with the same count and the same "wire copy (kind N)" comment; counts move, never grow. The moves are listed per task; block 29 of the selftest mutates no `internal/server` site. Commit `b3b4f4c` restored an inline `ListTasks` mapping to avoid such a move for a small change; for this issue the moves are the point (ruling 4).
- The protocol version stays `1.0.0`; `api/openapi.yaml` is not touched by this plan.
- Work lands on the branch `issue-29-protocol-drift`; one commit per task in the `type(scope): subject` style, ending with the two attribution lines the session reminder gives.
- Shell: the gate scripts stay `set -euo pipefail`, shellcheck-clean (`make release-lint` runs `shellcheck -x release/*.sh scripts/*.sh`), with the `deps_violation=<pkg> imports <imp>` output contract the selftest greps.

## Rulings made by this plan (Eric may overrule)

1. **Where the import rule lives.** The m6 consumer group becomes the four packages with the full forbidden list, and `make verify` runs `bash scripts/m6-exit-checks.sh --deps-only` beside the m10 line. m10's direct rule (b) narrows to `internal/cli` (its MCP-only-specific ban), so `internal/mcpcli`'s gen/store rows are not checked twice; `cmd/agentmesh-mcponly` imports only `internal/mcpcli`, so nothing is lost.
2. **Test placement and exports.** `TestWireRoundTrip` is an internal test of `internal/server` importing `internal/bus/remote`; the client's converters are exported (`remote.FromGen<Model>`, `remote.<Op>Request`), the server's stay unexported. The alternative (a test in `internal/bus/remote` importing `internal/server`) pulls the core and a Store engine into the client's test binary for nothing.
3. **Request pairs are keyed by the generated `<Op>RequestObject`.** The client's request builder returns `gen.<Op>RequestObject` and the server's input converter consumes it, so path, query and header members are covered without an exception per input type. The client method passes the object's members to the generated call (`r.Session, &r.Params, *r.Body`).
4. **Allowlist moves.** Extraction moves `TestAccessRuleSites` entries (same counts); listed per task.
5. **Enum values are a literal table** (`enumValues`, keyed by Go type string or by member path) with a staleness check, not parsed from `gen.go`: the bus side has enums too, and the client validators pin the values.
6. **The tool walk is syntactic**, like `sites_test.go`: a Bus call is a call whose method name is a `bus.Bus` method and whose receiver is the identifier `b` or a selector ending in `.Bus`; the walk follows calls into this package's own functions and `*server` methods. Aliasing the Bus (`x := c.Bus`) is refused by the test.
7. **`Woke` needs no exception**: `FromGenWake` sets `Woke: true` (a 200 is a wake); the 204 path stays in the method.

## Review Focus

1. A request whose body is optional on the wire (`Receive`, `OpenSession`: `if b := req.Body; b != nil`) with no body: the filler always fills `Body`, so the nil path is tested by hand in Task 3 (`TestRequestConvertersNilBody`).
2. A member whose zero value is meaningful (`HasDetails`, `Deleted`, `Resumed`, `Session` empty): the filler sets non-zero, so "absent, never null" for zero stays pinned by the existing hand tests and by `TestRequestConvertersNilBody`'s zero-input case (Task 3).
3. An oapi-codegen upgrade that changes the `defines model for` doc comments: the enumeration would see nothing and pass vacuously. Task 7's `coverage` subtest asserts a floor of 120 enumerated struct types.
4. A tool handler that reaches the Bus through an alias (`bb := c.Bus`) or a helper in another package: the walk would miss it. Task 8's `aliases` subtest fails on any assignment or value spec whose right side is a `.Bus` selector, and the `calls` subtest fails on two `FuncDecl`s sharing a name (the by-name index would be ambiguous).
5. A converter that validates a value the filler produced (an enum, `Health.Store.Engine`): the trip errors and the test names the member; the fix is an `enumValues` entry, never a loosened validator. Task 2's `enumValues` staleness check (every entry consulted) keeps the table honest.

---

### Task 1: The consumer import rule under `make verify`

**Files:**
- Modify: `scripts/m6-exit-checks.sh` (header comment lines 20 to 39; `import_check`, the consumer `check_group` call)
- Modify: `scripts/m10-exit-checks.sh` (header comment of `(b)`; the direct rule's ERE)
- Modify: `Makefile` (`verify` target: add `bash scripts/m6-exit-checks.sh --deps-only` right after the m10 line)
- Modify: `scripts/check-gates-selftest.sh` (block 23 `block_m6_exit_script_fires`, block 33 `block_m10_deps_rule_fires`)

**Interfaces:**
- Produces: m6 consumer group `./internal/mcpserver ./internal/mcpcli ./internal/cli ./internal/tui`, forbidden ERE `^$MOD/internal/(core|server|store|gen)(/|\$)|^$MOD/internal/bus/local\$`; m10 rule (b) ERE `^$MOD/internal/cli(/|\$)` over `./internal/mcpcli` and `$BIN`; output lines unchanged in form.

- [ ] **Step 1: Confirm the clean tree passes both scripts today**

Run: `bash scripts/m6-exit-checks.sh --deps-only && bash scripts/m10-exit-checks.sh --deps-only`
Expected: `deps_ok=1` from m6; `deps_ok=1` and `modules=13` from m10.

- [ ] **Step 2: Widen the m6 consumer group**

In `import_check`, replace the consumer `check_group` call with:

```bash
	check_group './internal/mcpserver ./internal/mcpcli ./internal/cli ./internal/tui' \
		"^$MOD/internal/(core|server|store|gen)(/|\$)|^$MOD/internal/bus/local\$"
```

Rewrite the header's consumer-group paragraph: the four packages obtain a Bus only from `internal/client` (`client.Open`, `Conn`) and must not import `internal/core/...`, `internal/server/...`, `internal/store/...`, `internal/gen/...` or `internal/bus/local` (issue #29; `internal/tui` is also allowlisted by m8; `internal/mcpcli`'s `internal/cli` ban is m10's). Note that `--deps-only` now runs inside `make verify`.

- [ ] **Step 3: Narrow m10's direct rule**

In `scripts/m10-exit-checks.sh` change the `(b)` grep to `"^$MOD/internal/cli(/|\$)"` and its header comment to: `(b) direct: the imports of ./internal/mcpcli and ./cmd/agentmesh-mcponly that are internal/cli/... print deps_violation=<pkg> imports <imp> [rule direct]; the gen, store, core, server and bus/local bans on internal/mcpcli are scripts/m6-exit-checks.sh's consumer group (issue #29)`.

- [ ] **Step 4: Add the m6 run to `verify`**

In `Makefile`, after `bash scripts/m10-exit-checks.sh --deps-only` add `bash scripts/m6-exit-checks.sh --deps-only`. Update the `verify` help comment to name "the m6 and m10 dependency rules".

- [ ] **Step 5: Prove each forbidden family fires, by hand**

For each row, create the probe, run the script, check the exit and line, and remove the probe (`deps_probe` in the selftest does the same):

| probe file | import | script | expected line |
| --- | --- | --- | --- |
| `internal/mcpserver/probe.go` | `internal/bus/local` | m6 | `deps_violation=$MOD/internal/mcpserver imports $MOD/internal/bus/local` |
| `internal/mcpserver/probe.go` | `internal/core/channels` | m6 | `... imports $MOD/internal/core/channels` |
| `internal/mcpserver/probe.go` | `internal/server` | m6 | `... imports $MOD/internal/server` |
| `internal/mcpcli/probe.go` | `internal/core/notify` | m6 | `deps_violation=$MOD/internal/mcpcli imports $MOD/internal/core/notify` |
| `internal/mcpcli/probe.go` | `internal/server/config` | m6 | `... imports $MOD/internal/server/config` |
| `internal/mcpcli/probe.go` | `internal/cli` | m10 | `deps_violation=$MOD/internal/mcpcli imports $MOD/internal/cli [rule direct]` |
| `internal/cli/probe.go` | `internal/bus/local` | m6 | `deps_violation=$MOD/internal/cli imports $MOD/internal/bus/local` |
| `internal/cli/probe.go` | `internal/core` | m6 | `... imports $MOD/internal/core` |
| `internal/cli/probe.go` | `internal/server` | m6 | `... imports $MOD/internal/server` |
| `internal/tui/probe.go` | `internal/gen` | m6 | `deps_violation=$MOD/internal/tui imports $MOD/internal/gen` |
| `internal/tui/probe.go` | `internal/store/sqlite` | m6 | `... imports $MOD/internal/store/sqlite` |
| `internal/tui/probe.go` | `internal/bus/local` | m6 | `... imports $MOD/internal/bus/local` |

Probe content: `package <pkg>` and `import _ "github.com/ericfitz/agentmesh/<import>"`. Expected: exit 1 and the line each time; the clean tree exits 0 afterwards.

- [ ] **Step 6: Add the selftest probes**

In block 23 (`block_m6_exit_script_fires`), after the existing seven `deps_probe` lines, add the twelve m6 rows of Step 5 (`deps_probe "$label" <file> "$m/<import>" "<expected line>" m6-exit-checks.sh`; use file names `probe_m6.go`). Update the block's header comment. In block 33, change the `[rule direct]` probe at the `internal/mcpcli/probe_m10.go` + `$m/internal/store` line to `$m/internal/cli` with want `deps_violation=$m/internal/mcpcli imports $m/internal/cli [rule direct]`; the `internal/core/notify` probe that expects m10 exit 0 stays (the direct ban on it is m6's, proved by the new m6 row). Update block 33's comment.

- [ ] **Step 7: Lint the scripts and run the gate**

Run: `shellcheck -x scripts/m6-exit-checks.sh scripts/m10-exit-checks.sh scripts/check-gates-selftest.sh` (if shellcheck is installed; CI's `release-lint` runs it), then `bash scripts/m6-exit-checks.sh --deps-only && bash scripts/m10-exit-checks.sh --deps-only`.
Expected: no shellcheck findings; `deps_ok=1` from both.

- [ ] **Step 8: Commit**

```bash
git add scripts/m6-exit-checks.sh scripts/m10-exit-checks.sh Makefile scripts/check-gates-selftest.sh
git commit -m "chore(gates): consumer packages get a Bus only from internal/client (issue #29)"
```

---

### Task 2: The round-trip harness over the converters that already exist

**Files:**
- Create: `internal/server/wire_roundtrip_test.go` (package `server`)
- Modify: `internal/bus/remote/convert.go`, `channels.go`, `usage.go`, `scopes.go`, `signingkeys.go`, `agentstatus.go`, `tasks.go` (export the `fromGen*` converters and their callers; `toGenACLEntry` stays unexported, it is the client's own helper)
- Modify: `internal/server/channels.go` (extract `aclEntryToGen`), `internal/server/tasks.go` (extract `taskSummaryToGen` from `ListTasks`)
- Modify: `internal/core/access/sites_test.go` (`"internal/server/tasks.go ListTasks": {"Owner": 2}` becomes `{"Owner": 1}` plus `"internal/server/tasks.go taskSummaryToGen": {"Owner": 1}`, comment "wire copy of the summary's owner (kind N)")

**Interfaces:**
- Produces (client, exported, signatures unchanged but for the name): `remote.FromGenMessage(gen.Message) (bus.Message, error)`, `remote.FromGenACLEntry(gen.ACLEntry) bus.ACLEntry`, `remote.FromGenTask(gen.Task) bus.Task`, `remote.FromGenTaskSummary(gen.TaskSummary) bus.TaskSummary`, `remote.FromGenTaskResult(gen.TaskUpdateResult) bus.TaskUpdateResult`, `remote.FromGenHealth(gen.Health) (bus.Health, error)`, `remote.FromGenUsage(gen.Usage) (bus.Usage, error)`, `remote.FromGenChannelInfo(gen.ChannelInfo) bus.ChannelInfo`, `remote.FromGenScope(gen.Scope) (bus.Scope, error)`, `remote.FromGenBridge(gen.Bridge) (bus.Bridge, error)`, `remote.FromGenSigningKey(gen.SigningKey) (bus.SigningKey, error)`, `remote.FromGenAgentStatus(gen.AgentStatus) bus.AgentStatus`.
- Produces (server): `aclEntryToGen(bus.ACLEntry) gen.ACLEntry` (used by `channelACLToGen`), `taskSummaryToGen(bus.TaskSummary) gen.TaskSummary` (used by `ListTasks`).
- Produces (harness, in the test file, used by Tasks 3 to 7):

```go
type pair struct {
	name    string       // the generated type's name: the subtest name
	gen     reflect.Type // the generated struct (or ScopeList-style wrapper)
	bus     reflect.Type // the domain struct, slice or scalar
	genTrip func(reflect.Value) (reflect.Value, error) // gen -> bus -> gen
	busTrip func(reflect.Value) (reflect.Value, error) // bus -> gen -> bus
}
func pairOf[G, B any](name string, fromGen func(G) (B, error), toGen func(B) (G, error)) pair
func ok[I, O any](f func(I) O) func(I) (O, error) // adapts a converter that cannot fail
var pairs = []pair{ ... }                           // one literal; later tasks append
type exception struct { Fields []string; Reason string }
var exceptions = map[string]exception{}            // filled in Task 7; keys "gen:<Pair>.<path>", "bus:<Pair>.<path>" or a type name
var enumValues = map[string]any{ ... }             // keyed by reflect.Type.String() ("gen.MessageSenderKind", "bus.PressureTier", "time.Duration") or by member path ("Health.Store.Engine")
func fill(t *testing.T, v reflect.Value, path string, c *counter, used map[string]bool)
func diff(path string, want, got reflect.Value) []string // "path: want X, got Y"
```

- [ ] **Step 1: Write the harness and the first pairs**

`fill` sets every member non-zero: bool `true`; integers and floats a fresh value from `c` (start at 1001, increment per leaf, so a swapped member shows as "changed"); `string` the path; a named string type `enumValues[type]` when present else the path; `time.Duration` from `enumValues`; a pointer is allocated and filled; a slice gets one filled element (`path[0]`); a map one entry keyed `path.k`; a struct fills every exported field (`path.Field`); any other kind is `t.Fatalf("unsupported kind at %s")`. A member path is looked up in `enumValues` before the type. Every consulted key is recorded in `used`.

`diff` walks both values in parallel (same Go type): a nil/non-nil pointer mismatch, a length mismatch, a missing map key or a leaf where `!reflect.DeepEqual` is one line.

`TestWireRoundTrip` runs `t.Run(p.name)` per pair: fill a `gen` value, `genTrip`, diff; fill a `bus` value, `busTrip`, diff; a trip error is `t.Fatalf` naming the pair and side; each diff line whose key `"<side>:<line path>"` is in `exceptions` marks that entry used, any other is `t.Errorf`. After the pairs, `t.Run("enums")` fails for every `enumValues` key never consulted. (Task 7 adds `coverage` and `exceptions`.)

The first pairs (the server side's existing functions; the client's renamed):

```go
pairOf("Message", remote.FromGenMessage, ok(toGenMessage)),
pairOf("ACLEntry", ok(remote.FromGenACLEntry), ok(aclEntryToGen)),
pairOf("Task", ok(remote.FromGenTask), ok(taskToGen)),
pairOf("TaskSummary", ok(remote.FromGenTaskSummary), ok(taskSummaryToGen)),
pairOf("TaskUpdateResult", ok(remote.FromGenTaskResult), ok(taskResultToGen)),
pairOf("Health", remote.FromGenHealth, ok(healthToGen)),
pairOf("Usage", remote.FromGenUsage, ok(usageToGen)),
pairOf("ChannelInfo", ok(remote.FromGenChannelInfo), ok(channelInfoToGen)),
pairOf("Scope", remote.FromGenScope, ok(scopeToGen)),
pairOf("Bridge", remote.FromGenBridge, ok(bridgeToGen)),
pairOf("SigningKey", remote.FromGenSigningKey, ok(signingKeyToGen)),
pairOf("AgentStatus", ok(remote.FromGenAgentStatus), ok(genAgentStatus)),
```

`enumValues` starts with the values the client validators accept (`fromGenIdentityKind`; `ValidHealthStatus`, `ValidHealthTier`, `ValidEmbeddingState`, `ValidMaintenanceLock`, `ValidPressureTier` in `internal/bus`; the `Valid()` methods of the signing-key enums; the `switch` in `FromGenScope` and `FromGenBridge`; the `sqlite|postgres` engine check in `FromGenHealth`): `gen.MessageSenderKind`, `bus.IdentityKind`, `gen.HealthStatus`, `bus.HealthStatus`, `gen.HealthTier`, `bus.HealthTier`, `gen.HealthStoreEngine`, `Health.Store.Engine` (the bus side's plain string), `gen.HealthEmbeddingsState`, `bus.EmbeddingState`, `gen.HealthMaintenanceLock`, `bus.MaintenanceLock`, `gen.UsageTier`, `bus.PressureTier`, `gen.ScopeState`, `bus.ScopeState`, `gen.ScopeRetire`, `bus.RetireMode`, `gen.BridgeState`, `bus.BridgeState`, `gen.SigningKeyState`, `gen.SigningKeyProvider`, `gen.SigningKeyAlgorithm`, `SigningKey.State`, `SigningKey.Provider`, `SigningKey.Algorithm` (bus side plain strings), `time.Duration` (`3 * time.Second`). Read each validator for its values; remove any entry the `enums` subtest reports unused.

- [ ] **Step 2: Run the test and expect the rename failures**

Run: `go test ./internal/server/ -run '^TestWireRoundTrip$' -v 2>&1 | tail -20`
Expected: compile failure naming `remote.FromGenMessage` (undefined) until Step 3.

- [ ] **Step 3: Export the client converters; extract the two server converters; move the allowlist entry**

Rename each `fromGen*` listed under Interfaces and every caller in `internal/bus/remote` (non-test and test files). `aclEntryToGen` is the loop body of `channelACLToGen`; `taskSummaryToGen` is the loop body of `ListTasks` (the `HasDetails` pointer rule included). Update `sites_test.go` as listed.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/server/ ./internal/bus/remote/ ./internal/core/access/ -run 'TestWireRoundTrip|TestTaskConvertReclaimedMark|TestTaskWireReclaimedMark|TestAccessRuleSites' -v 2>&1 | rg -- '^(---|ok|FAIL|\s+---)' `
Expected: every `TestWireRoundTrip/<pair>` leaf PASS, `TestWireRoundTrip/enums` PASS, the three other tests PASS. A diff line at this step is a converter bug in a function the plan read as complete: fix the converter, report it in the commit message.

- [ ] **Step 5: Vet, format, lint, the packages' full tests**

Run: `go vet ./internal/server/ ./internal/bus/remote/ && make fmt-check && make lint && go test ./internal/server/ ./internal/bus/remote/ ./internal/core/access/`
Expected: clean; `ok` for the three packages.

- [ ] **Step 6: Commit**

```bash
git add internal/server/wire_roundtrip_test.go internal/server/channels.go internal/server/tasks.go internal/bus/remote internal/core/access/sites_test.go
git commit -m "test(server): wire round-trip harness over the client and server converters (issue #29)"
```

---

### Task 3: Sessions, receive, watch, peek, identities and agent status

**Files:**
- Modify: `internal/server/sessions.go` (`OpenSession`, `CloseSession`, `Receive`, `Watch`, `ListIdentities`), `internal/server/peek.go`, `internal/server/agentstatus.go` (`SetAgentStatus`, `ListAgentStatuses`; rename `genAgentStatus` to `agentStatusToGen`)
- Modify: `internal/bus/remote/sessions.go`, `peek.go`, `agentstatus.go`
- Modify: `internal/server/wire_roundtrip_test.go` (append pairs; `enumValues` entries the trips demand, such as `gen.RejectedCursorReason` if a validator exists, else none)
- Create: `internal/server/convert_requests_test.go` (`TestRequestConvertersNilBody`)
- Modify: `internal/core/access/sites_test.go`: `"internal/server/sessions.go ListIdentities": {"Admin": 1}` moves to `"internal/server/sessions.go identityToGen": {"Admin": 1}` (same comment)

**Interfaces:**
- Produces (server, unexported): `openSessionInput(gen.OpenSessionRequestObject) bus.OpenSessionInput`, `sessionToGen(bus.Session) gen.Session`, `closeSessionInput(gen.CloseSessionRequestObject) bus.CloseSessionInput`, `receiveInput(gen.ReceiveRequestObject) bus.ReceiveInput`, `receiveResultToGen(bus.ReceiveResult) gen.ReceiveResult`, `watchInput(gen.WatchRequestObject) (bus.WatchInput, error)` (the `watchTimeout` validation), `wakeToGen(bus.WatchResult) gen.Wake`, `peekInput(gen.PeekRequestObject) bus.PeekInput`, `peekToGen(bus.PeekResult) gen.Peek`, `identityToGen(bus.IdentityInfo) gen.Identity`, `setAgentStatusInput(gen.SetAgentStatusRequestObject) bus.SetAgentStatusInput`, `agentStatusToGen(bus.AgentStatus) gen.AgentStatus`, `agentStatusEntryToGen(bus.AgentStatusEntry) gen.AgentStatusEntry`.
- Produces (client, exported): `remote.OpenSessionRequest(bus.OpenSessionInput) gen.OpenSessionRequestObject`, `remote.FromGenSession(gen.Session) bus.Session`, `remote.CloseSessionRequest(bus.CloseSessionInput) gen.CloseSessionRequestObject`, `remote.ReceiveRequest(bus.ReceiveInput) gen.ReceiveRequestObject`, `remote.FromGenReceiveResult(gen.ReceiveResult) (bus.ReceiveResult, error)`, `remote.WatchRequest(bus.WatchInput) gen.WatchRequestObject`, `remote.FromGenWake(gen.Wake) bus.WatchResult` (`Woke: true`), `remote.PeekRequest(bus.PeekInput) gen.PeekRequestObject`, `remote.FromGenPeek(gen.Peek) bus.PeekResult`, `remote.FromGenIdentity(gen.Identity) (bus.IdentityInfo, error)`, `remote.SetAgentStatusRequest(bus.SetAgentStatusInput) gen.SetAgentStatusRequestObject`, `remote.FromGenAgentStatusEntry(gen.AgentStatusEntry) (bus.AgentStatusEntry, error)`.
- A request builder always sets `Body` (non-nil) when the operation has one; the client method passes `*r.Body`, `&r.Params`, `r.Session` to the generated call. The client's guards (`Close` with an empty session, `SetAgentStatus` with an empty session) stay in the methods, before the builder.

- [ ] **Step 1: Append the pairs to `pairs`**

```go
pairOf("OpenSessionRequestObject", ok(openSessionInput), ok(remote.OpenSessionRequest)),
pairOf("Session", ok(remote.FromGenSession), ok(sessionToGen)),
pairOf("CloseSessionRequestObject", ok(closeSessionInput), ok(remote.CloseSessionRequest)),
pairOf("ReceiveRequestObject", ok(receiveInput), ok(remote.ReceiveRequest)),
pairOf("ReceiveResult", remote.FromGenReceiveResult, ok(receiveResultToGen)),
pairOf("WatchRequestObject", watchInput, ok(remote.WatchRequest)),
pairOf("Wake", ok(remote.FromGenWake), ok(wakeToGen)),
pairOf("PeekRequestObject", ok(peekInput), ok(remote.PeekRequest)),
pairOf("Peek", ok(remote.FromGenPeek), ok(peekToGen)),
pairOf("Identity", remote.FromGenIdentity, ok(identityToGen)),
pairOf("SetAgentStatusRequestObject", ok(setAgentStatusInput), ok(remote.SetAgentStatusRequest)),
pairOf("AgentStatusEntry", remote.FromGenAgentStatusEntry, ok(agentStatusEntryToGen)),
```

For a request pair the "fromGen" argument is the server's input converter and the "toGen" argument the client's builder (the generic parameters read `G = gen.<Op>RequestObject`, `B = bus.<Input>`). Task 2's `AgentStatus` pair changes to `ok(agentStatusToGen)` with the rename.

- [ ] **Step 2: Write `TestRequestConvertersNilBody`**

```go
func TestRequestConvertersNilBody(t *testing.T) {
	if got := receiveInput(gen.ReceiveRequestObject{Session: "s"}); got.Session != "s" || got.Ack != "" || got.Count != 0 || got.Channels != nil || got.IncludeOwn { t.Fatalf("receiveInput nil body = %+v", got) }
	if got := openSessionInput(gen.OpenSessionRequestObject{}); len(got.Cursors) != 0 || got.Hint != "" || got.ResumeToken != "" { t.Fatalf("openSessionInput nil body = %+v", got) }
	g := sessionToGen(bus.Session{})
	if g.Pending == nil || g.RejectedCursors == nil { t.Fatal("sessionToGen: required arrays must be [] not null") }
	r := receiveResultToGen(bus.ReceiveResult{})
	if r.Messages == nil || r.Gaps == nil || r.Notice != nil || r.Instruction != nil { t.Fatalf("receiveResultToGen zero = %+v", r) }
	if w := wakeToGen(bus.WatchResult{Woke: true}); w.Channels == nil { t.Fatal("wakeToGen: channels must be [] not null") }
}
```

Task 5 appends the required-body cases.

- [ ] **Step 3: Run; expect compile failures**

Run: `go test ./internal/server/ -run 'TestWireRoundTrip|TestRequestConvertersNilBody' 2>&1 | head`
Expected: undefined converters.

- [ ] **Step 4: Extract the converters on both sides**

Each handler becomes: convert the request, call the service, convert the result, wrap in the `gen.<Op>2xxJSONResponse`; the error paths are unchanged. Each client method becomes: guard, build the request object, call the generated client with its members, `errorOf`/`unparsable` as today, convert the response. Move the allowlist entry.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/server/ ./internal/bus/remote/ ./internal/core/access/ -run 'TestWireRoundTrip|TestRequestConvertersNilBody|TestAccessRuleSites' -v 2>&1 | rg -- '^(---|ok|FAIL|\s+---)'`
Expected: every leaf PASS. A `WatchRequestObject` diff on `Timeout` means the `time.Duration` entry is not a whole number of seconds; a diff elsewhere is a dropped member: fix the converter. No one-sided member is expected in this task; if one is real (the other side has it under no name), stop and report it for Task 7's exceptions table instead of loosening the test.

- [ ] **Step 6: Full packages, vet, format, lint**

Run: `go test ./internal/server/ ./internal/bus/remote/ ./internal/mcpserver/ ./internal/core/access/ && go vet ./internal/server/ ./internal/bus/remote/ && make fmt-check && make lint`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add internal/server/sessions.go internal/server/peek.go internal/server/agentstatus.go internal/bus/remote/sessions.go internal/bus/remote/peek.go internal/bus/remote/agentstatus.go internal/server/wire_roundtrip_test.go internal/server/convert_requests_test.go internal/core/access/sites_test.go
git commit -m "refactor(wire): named converters for sessions, delivery, peek, identities and status (issue #29)"
```

---

### Task 4: Channels, subscriptions, messages and search

**Files:**
- Modify: `internal/server/channels.go` (`ListChannels`, `CreateChannel`, `DeleteChannel`, `RenameChannel`, `SetACL`, `Subscribe`, `Unsubscribe`, `SubscribeTags`, `UnsubscribeTags`), `internal/server/messages.go` (`SendMessage`, `History`, `Search`)
- Modify: `internal/bus/remote/channels.go`, `internal/bus/remote/messages.go`
- Modify: `internal/server/wire_roundtrip_test.go` (append pairs)
- Modify: `internal/core/access/sites_test.go`: `"internal/server/channels.go CreateChannel": {"Scope": 3}` moves to `"internal/server/channels.go createChannelInput": {"Scope": 3}` (same comment; confirm the count with the test, it moves, never grows)

**Interfaces:**
- Produces (server): `channelToGen(bus.Channel) gen.Channel`, `createChannelInput(gen.CreateChannelRequestObject) (bus.CreateChannelInput, error)` (the existing nil-body validation, if any, moves in), `deleteChannelInput`, `renameChannelInput`, `setACLInput`, `subscribeInput`, `unsubscribeInput`, `subscribeTagsInput(gen.SubscribeTagsRequestObject) bus.TagSubscribeInput`, `unsubscribeTagsInput(gen.UnsubscribeTagsRequestObject) bus.TagSubscribeInput`, `sendInput(gen.SendMessageRequestObject) (bus.SendInput, error)`, `sendResultToGen(bus.SendResult) gen.SendResult`, `historyInput(gen.HistoryRequestObject) bus.HistoryInput`, `searchInput(gen.SearchRequestObject) bus.SearchInput`, `searchResultToGen(bus.SearchResult) gen.SearchResult` (hits through `toGenMessage`).
- Produces (client): `remote.CreateChannelRequest`, `remote.FromGenChannel(gen.Channel) bus.Channel`, `remote.DeleteChannelRequest`, `remote.RenameChannelRequest`, `remote.SetACLRequest`, `remote.SubscribeRequest`, `remote.UnsubscribeRequest`, `remote.SubscribeTagsRequest(bus.TagSubscribeInput) gen.SubscribeTagsRequestObject`, `remote.UnsubscribeTagsRequest(bus.TagSubscribeInput) gen.UnsubscribeTagsRequestObject`, `remote.SendMessageRequest(bus.SendInput) gen.SendMessageRequestObject`, `remote.FromGenSendResult`, `remote.HistoryRequest`, `remote.SearchRequest`, `remote.FromGenSearchResult(gen.SearchResult) (bus.SearchResult, error)`. The `UnsubscribeTags` empty-pattern guard and `Send`'s empty-channel guard stay in the methods; `queryTags` stays as the builders' helper.

- [ ] **Step 1: Append the pairs**

```go
pairOf("CreateChannelRequestObject", createChannelInput, ok(remote.CreateChannelRequest)),
pairOf("Channel", ok(remote.FromGenChannel), ok(channelToGen)),
pairOf("DeleteChannelRequestObject", ok(deleteChannelInput), ok(remote.DeleteChannelRequest)),
pairOf("RenameChannelRequestObject", ok(renameChannelInput), ok(remote.RenameChannelRequest)),
pairOf("SetACLRequestObject", ok(setACLInput), ok(remote.SetACLRequest)),
pairOf("SubscribeRequestObject", ok(subscribeInput), ok(remote.SubscribeRequest)),
pairOf("UnsubscribeRequestObject", ok(unsubscribeInput), ok(remote.UnsubscribeRequest)),
pairOf("SubscribeTagsRequestObject", ok(subscribeTagsInput), ok(remote.SubscribeTagsRequest)),
pairOf("UnsubscribeTagsRequestObject", ok(unsubscribeTagsInput), ok(remote.UnsubscribeTagsRequest)),
pairOf("SendMessageRequestObject", sendInput, ok(remote.SendMessageRequest)),
pairOf("SendResult", ok(remote.FromGenSendResult), ok(sendResultToGen)),
pairOf("HistoryRequestObject", ok(historyInput), ok(remote.HistoryRequest)),
pairOf("SearchRequestObject", ok(searchInput), ok(remote.SearchRequest)),
pairOf("SearchResult", remote.FromGenSearchResult, ok(searchResultToGen)),
```

A converter the current handler writes without a nil-body check is `ok(...)`; one with the check returns `(bus.X, error)`. Match the code, do not add checks.

- [ ] **Step 2: Run; expect compile failures** (`go test ./internal/server/ -run '^TestWireRoundTrip$' 2>&1 | head`)

- [ ] **Step 3: Extract on both sides; move the allowlist entry**

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/server/ ./internal/bus/remote/ ./internal/core/access/ -run 'TestWireRoundTrip|TestAccessRuleSites' -v 2>&1 | rg -- '^(---|ok|FAIL|\s+---)'`
Expected: every leaf PASS (a `gen.SubscribeRequestFrom` or `gen.SearchParamsMode` diff means a validator the plan did not see: add the `enumValues` entry).

- [ ] **Step 5: Full packages, vet, format, lint**

Run: `go test ./internal/server/ ./internal/bus/remote/ ./internal/mcpserver/ ./internal/core/access/ && go vet ./internal/server/ ./internal/bus/remote/ && make fmt-check && make lint`

- [ ] **Step 6: Commit**

```bash
git add internal/server/channels.go internal/server/messages.go internal/bus/remote/channels.go internal/bus/remote/messages.go internal/server/wire_roundtrip_test.go internal/core/access/sites_test.go
git commit -m "refactor(wire): named converters for channels, subscriptions, messages and search (issue #29)"
```

---

### Task 5: Memories and tasks

**Files:**
- Modify: `internal/server/memories.go` (`EditMemory`, `DeleteMemory`), `internal/server/tasks.go` (`CreateTask`, `ListTasks`, `UpdateTask`, `ClaimTask`, `ReleaseTask`)
- Modify: `internal/bus/remote/memories.go`, `internal/bus/remote/tasks.go`
- Modify: `internal/server/wire_roundtrip_test.go` (append pairs), `internal/server/convert_requests_test.go` (required-body cases)
- Modify: `internal/core/access/sites_test.go`: `"internal/server/tasks.go ListTasks": {"Owner": 1}` moves to `"internal/server/tasks.go listTasksInput": {"Owner": 1}`; `"internal/server/tasks.go UpdateTask": {"Owner": 1}` moves to `"internal/server/tasks.go updateTaskInput": {"Owner": 1}` (same comments)

**Interfaces:**
- Produces (server): `editMemoryInput(gen.EditMemoryRequestObject) (bus.EditMemoryInput, error)`, `editResultToGen(bus.EditResult) gen.EditResult`, `deleteMemoryInput(gen.DeleteMemoryRequestObject) bus.DeleteMemoryInput`, `createTaskInput(gen.CreateTaskRequestObject) (bus.TaskCreateInput, error)` (the `request body is required` validation moves in), `listTasksInput(gen.ListTasksRequestObject) bus.TaskListInput`, `updateTaskInput(gen.UpdateTaskRequestObject) (bus.TaskPatch, error)`, `claimTaskInput(gen.ClaimTaskRequestObject) bus.TaskClaimInput`, `releaseTaskInput(gen.ReleaseTaskRequestObject) bus.TaskReleaseInput`.
- Produces (client): `remote.EditMemoryRequest`, `remote.FromGenEditResult`, `remote.DeleteMemoryRequest`, `remote.CreateTaskRequest`, `remote.ListTasksRequest`, `remote.UpdateTaskRequest(bus.TaskPatch) gen.UpdateTaskRequestObject`, `remote.ClaimTaskRequest`, `remote.ReleaseTaskRequest`.
- `EditMemoryInput`'s pointer members keep their omit-versus-clear meaning: a nil pointer stays absent on the wire, an empty value is sent.

- [ ] **Step 1: Append the pairs**

```go
pairOf("EditMemoryRequestObject", editMemoryInput, ok(remote.EditMemoryRequest)),
pairOf("EditResult", ok(remote.FromGenEditResult), ok(editResultToGen)),
pairOf("DeleteMemoryRequestObject", ok(deleteMemoryInput), ok(remote.DeleteMemoryRequest)),
pairOf("CreateTaskRequestObject", createTaskInput, ok(remote.CreateTaskRequest)),
pairOf("ListTasksRequestObject", ok(listTasksInput), ok(remote.ListTasksRequest)),
pairOf("UpdateTaskRequestObject", updateTaskInput, ok(remote.UpdateTaskRequest)),
pairOf("ClaimTaskRequestObject", ok(claimTaskInput), ok(remote.ClaimTaskRequest)),
pairOf("ReleaseTaskRequestObject", ok(releaseTaskInput), ok(remote.ReleaseTaskRequest)),
```

- [ ] **Step 2: Append to `TestRequestConvertersNilBody`**: `createTaskInput(gen.CreateTaskRequestObject{Channel: "c"})` and `updateTaskInput(gen.UpdateTaskRequestObject{Id: 1})` return a `*bus.Error` with `Code == bus.CodeValidation` and the message `the request body is required`; `editMemoryInput(gen.EditMemoryRequestObject{Id: 1, Body: &gen.EditMemoryRequest{}})` returns an input whose `Subject`, `Content`, `Type`, `Metadata` are nil and `Tags` nil.

- [ ] **Step 3: Run; expect compile failures**

- [ ] **Step 4: Extract on both sides; move the two allowlist entries**

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/server/ ./internal/bus/remote/ ./internal/core/access/ -run 'TestWireRoundTrip|TestRequestConvertersNilBody|TestAccessRuleSites|TestTaskConvertReclaimedMark|TestTaskWireReclaimedMark' -v 2>&1 | rg -- '^(---|ok|FAIL|\s+---)'`
Expected: every leaf PASS.

- [ ] **Step 6: Full packages, vet, format, lint**

Run: `go test ./internal/server/ ./internal/bus/remote/ ./internal/mcpserver/ ./internal/core/access/ && go vet ./internal/server/ ./internal/bus/remote/ && make fmt-check && make lint`

- [ ] **Step 7: Commit**

```bash
git add internal/server/memories.go internal/server/tasks.go internal/bus/remote/memories.go internal/bus/remote/tasks.go internal/server/wire_roundtrip_test.go internal/server/convert_requests_test.go internal/core/access/sites_test.go
git commit -m "refactor(wire): named converters for memories and tasks (issue #29)"
```

---

### Task 6: Admin, scopes, bridges and signing keys

**Files:**
- Modify: `internal/server/admin.go` (`AdminStatus`), `admin_auth.go` (`AdminReset`, `ResetCredential`, `CreateIdentityByEmail`), `scopes.go` (`CreateScope`, `ListScopes`, `DoneScope`, `CreateAgentIdentity`), `bridges.go` (`CreateBridge`, `ListBridges`, `RemoveBridge`), `signing_keys.go` (`ListSigningKeys`, `RotateSigningKey`)
- Modify: `internal/bus/remote/admin.go`, `admin_identities.go`, `scopes.go`, `signingkeys.go`
- Modify: `internal/server/wire_roundtrip_test.go` (append pairs; `enumValues` for `gen.AdminResetParamsScope`/`bus.ResetScope` and `gen.DoneScopeRequestRetire` only if a converter validates them)
- Modify: `internal/core/access/sites_test.go`: `"internal/server/admin_auth.go AdminReset": {"Scope": 2}` moves to `adminResetInput`; `"internal/server/scopes.go DoneScope": {"Scope": 1}` moves to `doneScopeInput`; `"internal/server/scopes.go CreateAgentIdentity": {"Scope": 6}` splits into `createAgentIdentityInput` and `agentIdentityToGen` with counts that sum to 6 (the test reports the exact split); `GetScope` stays (a path parameter, no converter).

**Interfaces:**
- Produces (server): `statusToGen(bus.Status) gen.Status`, `adminResetInput(gen.AdminResetRequestObject) bus.ResetInput`, `resetCredentialInput(gen.ResetCredentialRequestObject) bus.ResetCredentialInput`, `credentialResetToGen(bus.ResetCredentialResult) gen.CredentialReset`, `createIdentityByEmailInput(gen.CreateIdentityByEmailRequestObject) bus.CreateIdentityByEmailInput`, `humanIdentityToGen(bus.CreateIdentityByEmailResult) gen.HumanIdentity`, `createScopeInput`, `doneScopeInput`, `scopeListToGen([]bus.Scope) gen.ScopeList`, `createAgentIdentityInput(gen.CreateAgentIdentityRequestObject) bus.CreateAgentIdentityInput`, `agentIdentityToGen(bus.AgentIdentity) gen.AgentIdentity`, `createBridgeInput`, `bridgeCreatedToGen(bus.BridgeCreated) gen.BridgeCreated`, `bridgeListToGen([]bus.Bridge) gen.BridgeList`, `removeBridgeInput(gen.RemoveBridgeRequestObject) bus.RemoveBridgeInput`, `signingKeyListToGen([]bus.SigningKey) gen.SigningKeyList`, `rotateSigningKeyInput`, `signingKeyRotationToGen(bus.SigningKeyRotation) gen.SigningKeyRotation`.
- Produces (client): `remote.FromGenStatus(gen.Status) bus.Status`, `remote.AdminResetRequest`, `remote.ResetCredentialRequest`, `remote.FromGenCredentialReset`, `remote.CreateIdentityByEmailRequest`, `remote.FromGenHumanIdentity`, `remote.CreateScopeRequest`, `remote.DoneScopeRequest`, `remote.FromGenScopeList(gen.ScopeList) ([]bus.Scope, error)`, `remote.CreateAgentIdentityRequest`, `remote.FromGenAgentIdentity`, `remote.CreateBridgeRequest`, `remote.FromGenBridgeCreated(gen.BridgeCreated) (bus.BridgeCreated, error)`, `remote.FromGenBridgeList(gen.BridgeList) ([]bus.Bridge, error)`, `remote.RemoveBridgeRequest`, `remote.FromGenSigningKeyList(gen.SigningKeyList) ([]bus.SigningKey, error)`, `remote.RotateSigningKeyRequest`, `remote.FromGenSigningKeyRotation(gen.SigningKeyRotation) (bus.SigningKeyRotation, error)`. The `unavailable` answers for an unconfigured bridge or key service stay in the handlers.

- [ ] **Step 1: Append the pairs** (same shape as Tasks 3 to 5; the bus side of `ScopeList`, `BridgeList` and `SigningKeyList` is a slice, which `fill` and `diff` handle): `Status`, `AdminResetRequestObject`, `ResetCredentialRequestObject`, `CredentialReset`, `CreateIdentityByEmailRequestObject`, `HumanIdentity`, `CreateScopeRequestObject`, `DoneScopeRequestObject`, `ScopeList`, `CreateAgentIdentityRequestObject`, `AgentIdentity`, `CreateBridgeRequestObject`, `BridgeCreated`, `BridgeList`, `RemoveBridgeRequestObject`, `SigningKeyList`, `RotateSigningKeyRequestObject`, `SigningKeyRotation`.

- [ ] **Step 2: Run; expect compile failures**

- [ ] **Step 3: Extract on both sides; move the allowlist entries**

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/server/ ./internal/bus/remote/ ./internal/core/access/ -run 'TestWireRoundTrip|TestAccessRuleSites' -v 2>&1 | rg -- '^(---|ok|FAIL|\s+---)'`
Expected: every leaf PASS. `SigningKeyRotation.Previous` is a pointer on the wire and a value on the bus: if the diff shows `Previous` on the gen trip only when nil, that is the zero case the filler never produces (no exception needed); if it shows with a filled value, the converter drops it.

- [ ] **Step 5: Full packages, vet, format, lint**

Run: `go test ./internal/server/ ./internal/bus/remote/ ./internal/mcpserver/ ./internal/cli/ ./internal/core/access/ && go vet ./internal/server/ ./internal/bus/remote/ && make fmt-check && make lint`

- [ ] **Step 6: Commit**

```bash
git add internal/server/admin.go internal/server/admin_auth.go internal/server/scopes.go internal/server/bridges.go internal/server/signing_keys.go internal/bus/remote/admin.go internal/bus/remote/admin_identities.go internal/bus/remote/scopes.go internal/bus/remote/signingkeys.go internal/server/wire_roundtrip_test.go internal/core/access/sites_test.go
git commit -m "refactor(wire): named converters for admin, scopes, bridges and signing keys (issue #29)"
```

---

### Task 7: Enumerate the generated types, the exceptions table, and the selftest block

**Files:**
- Modify: `internal/server/wire_roundtrip_test.go` (`coverage` and `exceptions` subtests; the `exceptions` literal)
- Modify: `scripts/check-gates-selftest.sh` (new block 34 `wire-roundtrip-fires`, called after `block_m10_deps_rule_fires`)

**Interfaces:**
- Produces: `genStructs(t) map[string][]string` (name to exported field names) parsed from `internal/gen/gen.go` with `go/parser`: every `*ast.TypeSpec` whose type is `*ast.StructType` and whose name ends in `RequestObject`, or whose `GenDecl`/`TypeSpec` doc contains `defines model for` or `defines parameters for`. `reachable(types ...reflect.Type) map[string]bool`: the named struct types of package `gen` reachable through fields, pointers, slices and maps.

- [ ] **Step 1: Write the `exceptions` literal**

Whole-type entries (`Fields` is the exact exported field list today; `Reason` says who consumes the type instead of the Bus):

| type | reason |
| --- | --- |
| `Problem` | errors cross as RFC 9457 problems: `WriteProblem` writes, `errorOf` reads (`TestErrorOf`, `TestProblem*`) |
| `Discovery`, `AuthMethod`, `WellKnown`, `AuthorizationServerMetadata`, `JWK`, `JWKS`, `AccessToken`, `Registration`, `RegisterRequest`, `RegisterRequestObject`, `TokenRequestObject` and its body struct | discovery and authentication: consumed by `internal/client` (registration, `login`), `internal/credential` and `internal/oidcclient`, not the Bus |
| `GetTaskRequestObject`, `GetMemoryRequestObject`, `ListMemoryRevisionsRequestObject` (`Id`), `GetScopeRequestObject` (`Scope`), `GetBridgeRequestObject`, `GetACLRequestObject` (`Channel`), `AgentStatusHistoryRequestObject` (`Identity`) | the path parameter alone; the Bus method takes it as a scalar and the client passes it as given (Decision 80) |

A request object with no fields (`ListChannelsRequestObject`, `HealthRequestObject`, ...) is covered without an entry. Member-level entries (`gen:<Pair>.<path>` or `bus:<Pair>.<path>`) are added only for a diff Tasks 3 to 6 left red as intended; none is expected.

- [ ] **Step 2: Write the `coverage` subtest**

`t.Run("coverage")`: `structs := genStructs(t)`; fail when `len(structs) < 120` ("the generator's doc comments changed; the enumeration is blind"); `covered := reachable(every pairs[i].gen) ∪ reachable(reflect types of the whole-type exceptions)`; a struct with zero fields is covered; `t.Errorf("generated type %s is neither paired nor excepted", name)` for each other name, sorted.

- [ ] **Step 3: Write the `exceptions` subtest**

`t.Run("exceptions")` runs last: a whole-type entry whose name is not in `structs`, or whose `Fields` differ from the parsed list (order-insensitive), is `t.Errorf("stale exception %s")`; a member-level entry no pair's diff consumed is `t.Errorf("exception %s matches nothing")`.

- [ ] **Step 4: Run**

Run: `go test ./internal/server/ -run '^TestWireRoundTrip$' -v 2>&1 | rg -- '^(---|ok|FAIL|\s+---)|neither|stale|matches nothing'`
Expected: `coverage` and `exceptions` PASS. Each "neither paired nor excepted" name is either a pair Tasks 3 to 6 missed (add it, with its converters, in this task) or a non-Bus type for the table with a reason; a `*JSONBody` alias that is not a struct does not appear.

- [ ] **Step 5: Add selftest block 34**

Four `mutate_unit_block` calls, package `./internal/server/`, run `'^TestWireRoundTrip$'`; verify each anchor is exactly once with `grep -cF` first:

1. `wire-gen-field-unmapped`: `internal/gen/gen.go`, FROM `type Session struct {`, TO `type Session struct {`$'\n\t'`Extra *string `json:"extra,omitempty"``, WANT `TestWireRoundTrip/Session`.
2. `wire-converter-line-dropped`: `internal/server/convert.go`, FROM `ReplyTo: m.ReplyTo, MemoryId: m.MemoryID, Revision: m.Revision,`, TO `ReplyTo: m.ReplyTo, Revision: m.Revision,`, WANT `TestWireRoundTrip/Message`.
3. `wire-gen-type-unpaired`: `internal/gen/gen.go`, FROM `// Problem defines model for Problem.`, TO `// Extra defines model for Extra.`$'\n'`type Extra struct {`$'\n\t'`A string`$'\n'`}`$'\n\n'`// Problem defines model for Problem.`, WANT `TestWireRoundTrip/coverage`.
4. `wire-exception-stale`: `internal/server/wire_roundtrip_test.go`, FROM `var exceptions = map[string]exception{`, TO the same plus `$'\n\t'"gen:Session.Nope": {Reason: "stale"},`, WANT `TestWireRoundTrip/exceptions`.

Block comment: Docker-free; mutating `internal/gen/gen.go` in the worktree is the same move as block 3. Add `block_wire_roundtrip_fires` to the call list after `block_m10_deps_rule_fires`.

- [ ] **Step 6: Prove the block by hand once**

Apply mutation 2 in the working tree, run `go test ./internal/server/ -run '^TestWireRoundTrip$' 2>&1 | rg 'FAIL: TestWireRoundTrip/Message|MemoryId|MemoryID'`, expect the FAIL line naming `Message.MemoryId`; `git checkout -- internal/server/convert.go`. Run `shellcheck -x scripts/check-gates-selftest.sh` if installed.

- [ ] **Step 7: Commit**

```bash
git add internal/server/wire_roundtrip_test.go scripts/check-gates-selftest.sh
git commit -m "test(server): every generated wire type is paired or excepted; selftest block 34 (issue #29)"
```

---

### Task 8: The tool coverage table

**Files:**
- Create: `internal/mcpserver/coverage_test.go` (package `mcpserver`)
- Modify: `scripts/check-gates-selftest.sh` (block 35 `tool-coverage-fires`, after block 34)

**Interfaces:**
- Produces: `TestToolCoverage` with subtests `tools`, `calls`, `members`, `aliases`; the literals `toolCalls map[string][]string` (tool to Bus methods) and `busMembers map[string]map[string]string` (bus type name to member to `"used"` or `"hidden: <reason>"`).

- [ ] **Step 1: Write the tables**

`toolCalls` as read on `b3b4f4c` (the walk of Step 3 is authoritative: correct the table to it and say so in the commit message; a `withSession` caller inherits `Open` through `resumeLapsed`):

```go
"register": {"Open", "Identities"}, "close_session": {"Close"},
"create_channel": {"CreateChannel"}, "list_channels": {"ListChannels"}, "delete_channel": {"DeleteChannel"},
"rename_channel": {"RenameChannel"}, "get_acl": {"ACL"}, "set_acl": {"SetACL"},
"subscribe": {"Subscribe", "SubscribeTags"}, "unsubscribe": {"Unsubscribe", "UnsubscribeTags"},
"send": {"Send", "Open"}, "receive": {"Receive", "Watch", "Open"}, "history": {"History"}, "search": {"Search"},
"get_memory": {"GetMemory"}, "edit_memory": {"Edit"}, "delete_memory": {"Delete"},
"discover": {"Identities"}, "set_status": {"SetAgentStatus", "Open"}, "health": {"Health"},
"task_create": {"Create"}, "task_claim": {"Claim"}, "task_release": {"Release"},
"task_update": {"Update"}, "task_get": {"GetTask"}, "task_list": {"List"},
```

`busMembers`: one entry per bus struct type reachable from the inputs and results of the methods named above (the `members` subtest lists the missing ones); for each exported member, `"used"` when some tool's input or output carries it (the `*In` types in `inputs.go`, the `*Out` types and the bus values returned verbatim such as `messagesOut`, `task_get`, `task_list`), else `"hidden: <reason>"` where the reason names the tool output that omits it and, when the handler or the tool description says why, that why (example: `ChannelInfo.Scope`: `hidden: create_channel's channelInfoOut has no scope; a scoped agent's channels carry the scope as the name prefix`). Record facts; do not invent intent. An embedded struct (`ChannelInfo.Channel`, `SearchHit.Message`) is a member named by its type and its own members are listed under its own type.

- [ ] **Step 2: Write the test**

`parseMCPServer(t) (files []*ast.File, fset)`: every non-test `.go` file of this package directory. `funcIndex`: `FuncDecl` by bare name over all files; two decls with one name is `t.Fatalf` (`aliases`-style precondition in `calls`). `tools`: every `mcp.AddTool(srv, &mcp.Tool{Name: "<lit>", ...}, handler)` call; the set of names must equal the keys of `toolCalls` (missing or extra named). `calls`: for each tool, walk the handler (a `FuncLit`, or a selector such as `s.register` resolved through `funcIndex`) with `ast.Inspect`; a `CallExpr` whose `Fun` is a `SelectorExpr` with `Sel.Name` in the `bus.Bus` method set (from `reflect.TypeOf((*bus.Bus)(nil)).Elem()`) and `X` an `Ident` named `b` or a `SelectorExpr` with `Sel.Name == "Bus"` is a Bus call; a `CallExpr` whose `Fun` is an `Ident` or a `SelectorExpr` whose `Sel.Name` is in `funcIndex` is followed (visited set); the found set must equal the table's (sorted; name the tool, the missing and the extra). `members`: from the union of the table's methods, collect the reachable bus struct types of each method's inputs (all `In` but `context.Context`) and results (`Out(0)` unless `error`); every collected type must have a `busMembers` entry whose keys equal its exported field names, each value `"used"` or prefixed `"hidden: "`; an entry for a type not collected is stale. `aliases`: any `AssignStmt` or `ValueSpec` in the walked files whose right side (or a `UnaryExpr` of it) is a `SelectorExpr` with `Sel.Name == "Bus"` fails with `alias the Bus and the walk goes blind: call through c.Bus or the b parameter`.

- [ ] **Step 3: Run**

Run: `go test ./internal/mcpserver/ -run '^TestToolCoverage$' -v 2>&1 | rg -- '^(---|ok|FAIL|\s+---)|calls|member|stale'`
Expected: four leaves PASS after the tables are corrected to the walk's output and the collected member set.

- [ ] **Step 4: Add selftest block 35**

Three `mutate_unit_block` calls, package `./internal/mcpserver/`, run `'^TestToolCoverage$'` (anchors verified once with `grep -cF`):

1. `tool-bus-member-unlisted`: `internal/bus/sessions.go`, FROM `type PeekInput struct {`, TO the same plus `$'\n\t'Extra string`, WANT `TestToolCoverage/members`.
2. `tool-call-unlisted`: `internal/mcpserver/server.go`, FROM `h, err := b.Health(ctx)`, TO `h, err := b.Health(ctx)`$'\n\t\t\t\t'`_, _ = b.Status(ctx)`, WANT `TestToolCoverage/calls`.
3. `tool-member-entry-stale`: `internal/mcpserver/coverage_test.go`, FROM `"PeekInput": {`, TO `"PeekInput": {"Nope": "used",`, WANT `TestToolCoverage/members`.

Add `block_tool_coverage_fires` to the call list after `block_wire_roundtrip_fires`.

- [ ] **Step 5: Vet, format, lint; prove mutation 2 by hand** (apply it, run the test, expect `--- FAIL: TestToolCoverage/calls` naming `health` and `Status`, revert with `git checkout -- internal/mcpserver/server.go`)

Run: `go vet ./internal/mcpserver/ && make fmt-check && make lint && go test ./internal/mcpserver/`

- [ ] **Step 6: Commit**

```bash
git add internal/mcpserver/coverage_test.go scripts/check-gates-selftest.sh
git commit -m "test(mcpserver): the tool coverage table over the Bus; selftest block 35 (issue #29)"
```

---

### Task 9: Records, CLAUDE.md, the done gate and the selftest

**Files:**
- Modify: `docs/adr/0001-transport-and-api.md` (new section at the end), `docs/adr/0007-openapi-code-generator.md` (new section at the end)
- Modify: `CLAUDE.md` (Commands: the `make verify` line; Design: the Decision 47 line, the Milestone 6 import rule line, the `internal/client` paragraph's m10 sentence, a new bullet for the two tests)
- Modify: `scripts/m6-exit-checks.sh`, `scripts/m10-exit-checks.sh` headers if Task 1 left anything stale

- [ ] **Step 1: ADR 0001 addendum**

Append `## Protocol client checks addendum (Eric's decision, 2026-11-06; issue #29)`: item 12 stands (hand-written tool schemas, domain types behind the `Bus`), and the Consequences line "the hand-written MCP tool schemas must be kept in step with the OpenAPI schema by hand" is superseded by three checks: the consumer import rule (`scripts/m6-exit-checks.sh` consumer group of `internal/mcpserver`, `internal/mcpcli`, `internal/cli`, `internal/tui`: no `internal/core/...`, `internal/server/...`, `internal/store/...`, `internal/gen/...` or `internal/bus/local`; a Bus comes from `internal/client`; under `make verify`), `TestWireRoundTrip` (`internal/server`: every generated wire type is paired with a domain type and round-trips through `internal/bus/remote` and `internal/server` with every member intact, the client's request builders returning `gen.<Op>RequestObject`; one exceptions table with reasons and a staleness check), and `TestToolCoverage` (`internal/mcpserver`: the literal table of the 26 tools' Bus methods and of every member as used or hidden with a reason). Name the selftest blocks (23, 33, 34, 35). State that tool shapes stay free.

- [ ] **Step 2: ADR 0007 addendum**

Append `## Protocol client checks addendum (Eric's decision, 2026-11-06; issue #29)`: the Consequences line "kept in step with the OpenAPI document by hand, whichever generator is chosen" is superseded as recorded in ADR 0001's addendum of the same date; the generator choice is unaffected.

- [ ] **Step 3: CLAUDE.md**

- Commands, `make verify` line: add "the m6 consumer import rule" beside "the m10 dependency rule".
- Design, Decision 47 line: "(non-test code; a `_test.go` file may import across these lines, as `internal/server`'s tests import `internal/bus/remote`)".
- Design, Milestone 6 import rule line: the consumer group is `internal/mcpserver`, `internal/mcpcli`, `internal/cli` and `internal/tui`, which do not import `internal/core/...`, `internal/server/...`, `internal/store/...`, `internal/gen/...` or `internal/bus/local` and obtain a Bus only from `internal/client` (issue #29; `--deps-only` runs under `make verify`).
- Design, `internal/client` paragraph: `internal/mcpcli` "(imports no `internal/cli`; m10)" and the consumer rule reference.
- Design, new bullet after the `api/openapi.yaml` line: "Protocol client checks (issue #29, Eric 2026-11-06, ADR 0001 addendum): `TestWireRoundTrip` (`internal/server/wire_roundtrip_test.go`) pairs every generated struct of `internal/gen` that crosses the wire with its `internal/bus` type (request pairs on `gen.<Op>RequestObject`, which the client's exported `remote.<Op>Request` builders return and the server's `<op>Input` converters consume; responses on `remote.FromGen<Model>` and `<model>ToGen`), fills every member and runs both directions; intended one-sided members and non-Bus types live in its one `exceptions` table, each with a reason, and a stale entry fails. `TestToolCoverage` (`internal/mcpserver/coverage_test.go`) holds the literal table of the 26 tools' Bus methods and of every Bus input and result member as `used` or `hidden: <reason>`; a new member, an unlisted call or a stale entry fails. Mutations: `scripts/check-gates-selftest.sh` blocks 34 and 35."

- [ ] **Step 4: Check every claim against the tree**

Run: `rg -n 'TestWireRoundTrip|TestToolCoverage|block_wire_roundtrip_fires|block_tool_coverage_fires' internal scripts CLAUDE.md docs/adr | wc -l` and read the four edited documents once for private names or stale paths.
Expected: every name the documents cite exists in the tree.

- [ ] **Step 5: The done gate**

Run: `make verify 2>&1 | tail -5`
Expected: `verify: OK` (the Postgres suites ran; a skipped suite is not a pass).

- [ ] **Step 6: The selftest and the script lint**

Run: `make check-gates-selftest 2>&1 | rg 'selftest: (ok|FAIL)|check-gates-selftest'` (minutes; Docker) and `make release-lint`.
Expected: `selftest: ok` for every block including `m6-exit-script-fires`, `m10-deps-rule-fires`, `wire-gen-field-unmapped`, `wire-converter-line-dropped`, `wire-gen-type-unpaired`, `wire-exception-stale`, `tool-bus-member-unlisted`, `tool-call-unlisted`, `tool-member-entry-stale`, then `check-gates-selftest: OK`; no actionlint or shellcheck finding.

- [ ] **Step 7: Commit**

```bash
git add docs/adr/0001-transport-and-api.md docs/adr/0007-openapi-code-generator.md CLAUDE.md scripts/m6-exit-checks.sh scripts/m10-exit-checks.sh
git commit -m "docs: protocol client checks addenda (ADR 0001, 0007) and the CLAUDE.md rules (issue #29)"
```

Then report completion and wait for Eric's word on the push (`ci.yml` and `windows.yml` must be green on the pushed commit).
