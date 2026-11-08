# Issue 30: CATS Fuzzing Campaign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Task 7 is a **controller phase**: the main session runs it with the `cats:*` skills and appends the fix tasks (Task 8.N) it produces; no implementer is dispatched for Task 7 itself.

**Goal:** CATS (`/opt/homebrew/bin/cats`, version 15.4.0) fuzzes the 57 operations of `api/openapi.yaml` against a throwaway native `agentmesh server -sqlite` on loopback as a repeatable campaign: one command (`bash scripts/cats-harness.sh run`) builds, starts, seeds, mints an agent and an administrator bearer, fuzzes, collects and stops; the cats plugin's skills (`cats:init`, `cats:run`, `cats:analyze`, `cats:fp`, `cats:report`) drive the same server through hooks for the triaged campaign; every finding is a fixed bug, a fixed spec gap or a recorded false positive; and a tracked pre-commit hook (`.githooks/pre-commit`) re-fuzzes the paths a non-documentation spec change touches and blocks the commit on any finding that is not a recorded false positive.

**Architecture:** Three pieces, all tracked. (1) `tools/catscheck`, a Go `package main` with its own tests: `changed-paths OLD NEW` (the normalizer that strips `description`, `summary`, `example`, `examples` and `externalDocs` by position, the per-path diff, and the widening to every path whose `$ref` closure reaches a changed component), `normalize FILE` (debug output) and `classify --rules FILE REPORT_DIR` (a port of the plugin's false-positive rule vocabulary over CATS's `Test*.json`, first match wins, a rule never suppresses a 5xx). (2) `scripts/cats-harness.sh`, bash, with the subcommands `up`, `seed`, `token`, `headers`, `run`, `down`, `status` over one state directory, plus its self-test with a fake `cats`. (3) `.githooks/pre-commit`, a two-line shim to `scripts/cats-precommit.sh`, which exports the staged tree, regenerates and compares `internal/gen`, runs the harness on the changed paths and classifies the report. The plugin's results database and the controller's triage live in `.local/cats/` (git-ignored); the rules file is `api/cats-false-positives.yaml` (tracked). No CI job runs CATS (Eric's decision 2); the self-tests use the fake `cats`, and `make check-gates-selftest` block 40 runs both of them once unmutated and then under mutation, so CI exercises the harness and the hook without Java.

**Tech Stack:** Go 1.27 (`CGO_ENABLED=0`; `gopkg.in/yaml.v3 v3.0.1` is already a direct dependency), bash (`set -euo pipefail`, shellcheck-clean under `make release-lint`), `jq` (`/opt/homebrew/bin/jq`, used by the harness; the hook and selftests fail fast when it is missing), CATS 15.4.0 (`cats -c -s --headers --refData --paths --skipPaths -o --noEnvFile --no-checkUpdate --maxRequestsPerMinute`; `cats smoke`), the cats plugin 0.1.2 (`/Users/efitz/.claude/plugins/cache/efitz-skills/cats/0.1.2`; its config contract is `catslib/config.py`, its run pipeline `catslib/runner.py`, its rule engine `catslib/rules.py`, its record shape `catslib/parse.py:record_from_json`).

**Spec:** GitHub issue #30 (body and acceptance criteria); Eric's decisions of 2026-11-06 (scratchpad `decisions/30.md`, transcribed under Global Constraints); CLAUDE.md (Commands, Design, the pre-release rule, Definition of Done A to F); ADR 0001 (the #33 error responses addendum: 11 shared responses, `TestStatusTable`), ADR 0002 (registration, enrollment tokens, the token endpoint), `docs/ops/admin-bootstrap.md` (the host commands). Evidence on branch `issue-30-cats` at `5d26dfe`; probes of 2026-11-08 in the scratchpad (`probe-cats/run.sh` to `run4.sh`, their logs).

## Probes (2026-11-08, CATS 15.4.0 against a scratch server built from 5d26dfe)

| Probe | Result the plan relies on |
|---|---|
| `cats list -p -c api/openapi.yaml` | 43 paths, 57 operations; templated paths are spelled `/v1/channels/{channel}` and `-p` accepts them (`-p '/v1/channels/{channel}/acl'` fuzzed `/v1/channels/cats-fixture/acl`) |
| `cats --dryRun` over the whole spec | 15,133 tests over 57 operations; the largest are `/v1/tasks/{id}` PATCH 863, `/v1/search` GET 606, `/v1/sessions/{session}/status` POST 553 |
| `/v1/channels` + `/v1/discover`, full fuzz | 658 tests in 4 s (`cats-summary-report.json`: `totalTests`, `success`, `warnings`, `errors`, `qualityGatePassed`, `runStatus`); CATS exits 1 on its default quality gate ("fail on any error"); the report directory holds `Test<N>.json` per test, `cats-summary-report.json`, `index.html` and assets; the `Authorization` request header is stored masked as `$$Authorization`; no bearer appears in the report or the server log |
| Bearer by `-H 'Authorization=Bearer $$CATS_BEARER'` (environment, `.env`, `${}`) | every protected call 401: the `$$VAR` substitution did not take; the `--headers` YAML file does (`all:` plus per-path keys) |
| Per-path headers | `all:` agent bearer and `/v1/admin/status:` administrator bearer: `GET /v1/admin/status` 200, `GET /v1/admin/usage` (agent) 403; one headers file can carry both identities |
| refData | per-path path parameters are filled (`channel: cats-fixture`, `session: <id>`); nested array members by `acl[*]#identity` (CATS `JsonUtils` turns `#` into `.`; `$[*]#field` addresses a root array); `cats_remove_field` is the documented value that removes a member (`FilesArguments.java`, `ServiceCaller.java`); `--urlParams identity:cats-agent` fills a path parameter globally |
| `watch_max_seconds=1` | `/v1/sessions/{session}/watch` answers 204 in 1.0 s; its 263 tests cost about 5 min; the default 50 s would cost hours |
| `cats smoke` | one request per operation with a diagnostic table and `Verdict: READY`; it lists `register` and `token` as unresolved (`enrollment_token`; `actor_token`, `subject_token`, `client_id`), so their HappyPath can never be 2xx |
| Clusters seen (two paths) | `UnsupportedAcceptHeaders` expects 406, gets 200; `UnsupportedContentTypesHeaders` expects 415, gets 400; `NonRestHttpMethods`/`CustomHttpMethods`/`HttpMethods` expect 405, get 404 problem+json; `DummyTransferEncodingHeaders` gets 501 `text/plain` from Go's `net/http` before any handler (CATS scores it `success`); `LargeNumberOfRandomAlphanumericHeaders` gets 431 `text/plain` (`success`); `BypassAuthentication` 401 flagged as "error details leak: [unauthorized]" with `detail` `security requirements failed: no identity`; `GET /v1/admin/status` 200 flagged "leak: [notice]"; HappyPath `POST /v1/channels` as the agent 403 (the generated `scope` member is administrator-only) and 404 as the administrator (random scope) |
| Plugin pipeline | `execute()` runs `preflight` (spec, port-forward, `cats` on PATH, rules file, **server health**) before `pre_run`, so the server must be up before `/cats:run`; hooks run `shell=True` with the repo root as cwd and receive `CATS_SERVER`, `CATS_SPEC`, `CATS_RESULTS_DIR`, `CATS_REPORT_DIR`, `CATS_RUN_ID`, `CATS_IDENTITY`; `token_cmd` must print the bearer and nothing else; the plugin writes its own `all:`-only headers file under `results_dir` at 0600 and deletes it; `parse --report DIR` ingests any CATS report directory; `classify` suppresses only `error` and `warn` records and refuses a rule that matches a 5xx unless `allow_suppressing_5xx: true` |
| Server facts | `agentmesh server -listen 127.0.0.1:0` prints `agentmesh server listening on 127.0.0.1:<port> (sqlite, registration open, issuer http://127.0.0.1:<port>, kid <kid>)`; host commands run against the live SQLite file (the e2e fixture does it); `create-identity NAME`, `admins add -identity NAME`, `enrollment create -identity NAME` (prints `token: abe_...`); `agentmesh register -profile cats -identity NAME -server URL [-enrollment-token T]` creates the profile; `login` caches the bearer at `<data dir>/tokens/cats/<identity>.json` (0600, member `access_token`); the only rate limiter is the send limiter (`send_messages_per_second` 1 to 10000, `send_kib_per_second` 64 to 65536; six `core.RateLimited` sites all name it); `token_lifetime_seconds` ceiling 86400; `channel_creation` default `open`; `watch_max_seconds` 1 to `WatchSecondsCeiling` |

## Global Constraints

- **Eric's decisions (2026-11-06, issue #30), binding:** (1) the target is a native `agentmesh server -sqlite <tmpdir>` built from the tree, on a loopback port, seeded by the setup script; no Docker. (2) No CI job runs CATS; it runs locally only. (3) A tracked pre-commit hook in `.githooks/`, enabled with `git config core.hooksPath .githooks` and documented, compares the staged `api/openapi.yaml` with HEAD after stripping `description`, `summary`, `example`, `examples` and `externalDocs` (a normalizer with its own tests); on a non-documentation change it runs CATS on the changed paths only (`--paths`), widened to every path that references a changed schema, and blocks the commit on any finding that is not a recorded false positive; a documentation-only diff passes at once; `--no-verify` remains the bypass.
- **Issue acceptance criteria, binding:** `cats:init` bootstraps `.local/cats/config.yaml` and the committed rules file; the campaign registers its own agent and administrator identities and gets bearers for both by a repository script (bash, `set -euo pipefail`, absolute paths), never a manual step, and never Eric's running stack; one command runs the whole campaign from a clean state and survives a second run and a start over a failed run's leftovers; the harness has its own test against recorded output; every finding is triaged with `cats:analyze` into a real bug, a spec gap or a false positive; real bugs and spec gaps are fixed, one commit per root cause, each with a test that reproduced the bug before the fix; every false positive is recorded with `cats:fp` with its reason; for every operation: no 5xx except the documented 503, every error `application/problem+json` with `code` and `retryable` (the token endpoint's RFC 6749 body excepted), no answer contradicting the documented responses, no secret, token or stack trace in any answer; `docs/` gets a page on running the campaign and reading the results; `make verify` green; `ci.yml` and `windows.yml` green on the pushed commit.
- **Repository code never calls the plugin's scripts by path** (`cats_tool.py` is the controller's, through the skills); the harness and the hook call the `cats` CLI on `PATH` (`CATS_BIN` overrides it, for the fake). The harness never passes `--showSecrets` and always passes `--noEnvFile` (CATS auto-loads `./.env`, which in this repository is the operator's compose secrets) and `--no-checkUpdate`, and always passes `-o` into a directory it owns (a `cats` run without `-o` writes `./cats-report` into the repository).
- **Bearers never reach stdout, a log, a commit or a file outside the harness directory**, with one exception: `scripts/cats-harness.sh token <admin|agent>` prints the bearer alone on stdout because the plugin's `token_cmd` contract requires it; nothing else prints it, no `set -x` anywhere, and the selftest greps the server log, the harness output and the report for `Bearer ey` and `abe_`. The bearer caches (`<harness dir>/data/tokens/cats/*.json`) and the headers file (`<harness dir>/headers.yml`) are written at 0600 inside the harness directory (mode 0700) and removed by `down` and by the `run` trap. The CATS report masks `Authorization` on its own (probe); the harness checks that the report contains no `Bearer ey` anyway.
- **`.local/` is git-ignored**, so `.local/cats/config.yaml` (machine-local, plugin-owned) and `.local/cats/results/` (databases, reports, the seeded `refdata.yml` and `fixtures.json`) are never committed; the committed artifacts are `api/cats-false-positives.yaml`, `tools/catscheck/`, `scripts/cats-*.sh`, `scripts/testdata/cats-*`, `.githooks/pre-commit`, the docs, the ADR, the Makefile and CLAUDE.md lines. No `.gitignore` edit is needed (`.local/` is already listed).
- **The protocol version stays `1.0.0`** (`info.version`, `version.Protocol`, `api/arazzo.yaml`): spec fixes from the campaign change the wire in place (CLAUDE.md, Eric 2026-10-27); no migration, shim or compatibility branch.
- **Never edit `internal/gen` by hand**; every spec fix runs `make generate` and commits the regenerated files with the spec.
- **Every fix task reproduces first** (Definition of Done A and B): a Go test that sends the CATS request shape and fails on the current answer is committed in the same commit as the fix, and the task searches for every other instance of the pattern (`rg`) and fixes or lists them. Unknown inputs, states, enum values, rule fields and rule operators are rejected, with a test.
- **Stateful scripts say what happens on a second run, on overlap and over leftovers** (Definition of Done D): Task 4 states it for `up`, `seed`, `run` and `down`; Task 6 for the hook; the selftests exercise the second run and the leftovers.
- **Shell (Definition of Done F):** every script is `#!/usr/bin/env bash`, `set -euo pipefail`, absolute paths from `ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"`, arrays for lists, shellcheck-clean; `make release-lint` gains `.githooks/pre-commit` and `scripts/testdata/cats-fake/cats`.
- **Import and gate rules hold.** `tools/catscheck` imports the standard library and `gopkg.in/yaml.v3` only (no `internal/...`, no kin-openapi: the normalizer works on the YAML tree, not the parsed document); nothing imports it. `scripts/m4-exit-checks.sh`, `m6`, `m7`, `m10` are untouched. `make test` (`go list ./...` minus conformance) and `windows.yml` (`go test` of the unit packages) pick the package up on their own, so its tests use `filepath` and `t.TempDir()`, never bash or `/tmp`.
- **Staging:** `git add` names files; never `git add -A`. `replay.env.example` (untracked in the root at the start of this branch) is not this plan's and is never staged. No task pushes. Work lands on `issue-30-cats`, one commit per task in the `type(scope): subject` style, ending with the two attribution lines the session reminder gives.
- **American English everywhere.** `UPPER_SNAKE_CASE` rule ids, `kebab-case` script and fixture names, `snake_case` YAML keys (the plugin's convention).
- **Done gate:** `make verify` (needs Docker; a run that skips the Postgres suites is not a pass), `make check-gates-selftest`, `make release-lint`, `make cats-selftest`; then `ci.yml` and `windows.yml` green on the pushed commit. Task 11 runs the four make targets and shows their output.

## Rulings made by this plan (Eric may overrule; not his decisions)

- **Ruling 1: the normalizer, the path widener and the rule classifier are one Go program, `tools/catscheck`, with `go test`** — Go is the repository's language, `gopkg.in/yaml.v3` is already a direct dependency, `make test`, `make lint` and `windows.yml` cover it for free, and a Sonnet implementer writes table-driven Go tests reliably; a bash or Python normalizer would need its own test runner and a YAML parser that is not on every machine — cost if wrong: a 400-line Go tool and `go run` (about 1 s cached) at each spec commit; the hook is slower by that second.
- **Ruling 2: the normalizer strips by position, not by key name** — three schemas (`Task`, `TaskCreateRequest`, `TaskPatch`) have a *property named* `description`, so a global key strip would erase a real member and turn a schema change into "documentation-only"; the walker deletes the five keys from a mapping only when that mapping was not reached through a name-map key (`properties`, `patternProperties`, `paths`, `responses`, `headers`, `links`, `callbacks`, `encoding`, `variables`, `mapping`, `securitySchemes`, `requestBodies`, `schemas`, `parameters` under `components`) — cost if wrong: a documentation edit of a property named like a stripped key runs the hook's campaign needlessly (safe direction).
- **Ruling 3: `changed-paths` widens through `$ref` closures and treats `openapi`, `servers`, `security` and unknown top-level keys as "every path"; `info` and `tags` as documentation** — a changed shared response, parameter, request body or schema reaches a path only through `$ref`, so the closure is the exact set; a top-level security or server change has no path of its own and affects every request — cost if wrong: an unreferenced component change (spec-lint's business) runs nothing; a top-level change runs the whole campaign in the hook (about 10 min).
- **Ruling 4: `classify` ports the plugin's vocabulary exactly (`catslib/rules.py`: 14 scalar fields, `json_body.<path>`, `request_header.<name>`, `json_body`, `request_headers`; the 11 operators with their case rules; `when` AND, `any_of` OR, both ANDed; first enabled match wins; only `error` and `warn`; a 5xx match is refused) and rejects every unknown key, field and operator with exit 2** — the hook must honor the same rules file `cats:fp` writes, and two engines that disagree would let a commit through or block it wrongly; regexes are RE2 (Go) where the plugin uses Python `re`, so rules keep to the common subset — cost if wrong: a rule written for one engine mismatches in the other; the committed-rules test (ruling 6) and the controller's cross-check (Task 7 step 9) catch it.
- **Ruling 5: the rules file is `api/cats-false-positives.yaml`** — it describes the API's answers and sits beside `api/openapi.yaml`, `api/arazzo.yaml` and `api/vacuum-ruleset.yaml`; the plugin's default `test/cats/false-positives.yaml` would create a `test/` tree for one file — cost if wrong: a path in `.local/cats/config.yaml` and the docs.
- **Ruling 6: every committed rule names its response codes explicitly (`response_code` with `equals` or `in`), none of them in 500 to 599 (CATS's transport pseudo-codes 953 and 999 are allowed, as the plugin's own rail allows them), and `TestCommittedRules` (`tools/catscheck`) enforces both over the committed file** — the 5xx rail is the issue's first acceptance criterion and the plugin enforces it at classify time only; a static check keeps a 5xx rule from ever being committed, and explicit codes keep rules narrow — cost if wrong: a rule that legitimately spans codes needs `in: [...]` spelled out.
- **Ruling 7: one harness directory, `${TMPDIR:-/tmp}/agentmesh-cats-$(id -u)` (override `--dir`), mode 0700, holds the built binary, the SQLite file, the server log, the pid and url files, the config and data dirs and the headers file; `down` removes it whole** — one place to clean, one place for the bearers, no bearer file outside it; a fixed name lets `up`, `seed`, `token` and `down` find each other across the plugin's separate hook processes — cost if wrong: two campaigns cannot run at once on one machine (by design; `up` refuses while a live pid is recorded).
- **Ruling 8: `up` refuses when the recorded pid is alive (exit 3, names the pid and `down`), tears down a dead or stale directory and starts afresh; `run` always calls `down` first; `down` kills only a pid whose command line contains `<harness dir>/agentmesh server`** — a second `run` from scratch and a start over a failed run's leftovers are acceptance criteria; refusing a live server protects a campaign in progress; matching the command line keeps `down` from killing an unrelated process that reused the pid — cost if wrong: a stuck server needs a manual `down`.
- **Ruling 9: the plugin flow uses a fixed loopback port, `127.0.0.1:8430`, and the controller runs `up --port 8430` before `/cats:run`; the standalone `run` and the hook use a free port (`-listen 127.0.0.1:0`, the port read from the listening line)** — the plugin probes `health_url` in preflight before any hook runs, so its `pre_run` cannot start the server, and `server:` in `config.yaml` is static; 8430 avoids 8420 (the spec's `servers` placeholder and the likely developer port) — cost if wrong: a busy 8430 fails `up` with the bind error; `--port` picks another and `config.yaml` follows.
- **Ruling 10: the campaign runs with tuned settings: `send_messages_per_second=10000`, `send_kib_per_second=65536` (the bounds' maxima; the only limiter), `token_lifetime_seconds=86400` (the ceiling; no refresh during a run), `session_lease_seconds=86400` (ruling 25: the default 90 s lease, renewed only by `open`, `receive` and `watch`, would turn the seeded sessions into 410 `session_lapsed` answers a minute and a half into the run), `watch_max_seconds=1` (a `watch` costs 1 s instead of 50), `maintenance_interval_seconds=3600` (no maintenance tick mid-run, as the e2e fixture does)** — the issue says to tune limits rather than count 429s; `watch` would otherwise dominate the run — cost if wrong: a `watch` finding tied to a long timeout is not reproduced here (the e2e long-poll tests cover it).
- **Ruling 11: the identities are `cats-admin` (created keyless by the host command, flagged with `admins add`, claimed with a bound enrollment token) and `cats-agent` (self-registered: loopback defaults to `open` registration); profile `cats`; the harness never uses Eric's config dir (it sets `AGENTMESH_CONFIG_DIR` and `AGENTMESH_DATA_DIR` into the harness directory)** — this is the documented bootstrap (`admin-bootstrap.md`, "Alternatively run `create-identity NAME` and `admins add`"), needs no interactive step, and `login` leaves the bearer where `token` reads it — cost if wrong: none known; the probe ran exactly this sequence.
- **Ruling 12: the standalone `run` fuzzes both identities in one pass: the headers file has `all:` the agent bearer and each `/v1/admin/...` path the administrator bearer, so every operation is fuzzed past 401 and 403 as the identity meant to call it; the plugin flow (one bearer per run, `all:` only) runs twice: `default_identity: admin` over every path, then `--identity agent` over the non-admin paths** — per-path headers work (probe); the hook wants one run; the plugin's `write_headers_file` writes `all:` only — cost if wrong: the two flows produce different clusters for `/v1/admin/*` as the agent (403s), which the agent pass excludes by path.
- **Ruling 13: the seed creates fixtures with decoys for the anchors CATS can destroy, and the three self-sabotaging operations are skipped and fuzzed alone**: skipped: `/v1/admin/reset` (`scope=everything` deletes `cats-agent` and every token), `/v1/admin/signing-keys/rotate` (`revoke_previous=true` invalidates both bearers), `/v1/admin/identities/{identity}/reset-credential` (removes the identity's key); the three are fuzzed alone in Task 7 Step 2b (`--paths` wins over the skip list, ruling 16), so every operation is still fuzzed; `/v1/admin/bridges` and `/v1/admin/bridges/{channel}` are also skipped, pending Open item 6 (no Slack bridge is wired in the campaign server, every call is the documented 503 `unavailable`, and fuzzing them would force a 5xx false-positive rule; the Slack fake is selectable from Go only, `cmd.RunWith`); decoys: `/v1/channels/{channel}` → `cats-ordinary-decoy`, `/v1/sessions/{session}` → the decoy session, `/v1/memories/{id}` → the decoy memory, `/v1/tasks/{id}` → the decoy task, `/v1/admin/scopes/{scope}/done` → `cats-scope-decoy`; two more sacrificial channels (Tasks 8.1 and 8.4): `cats-acl` takes the fuzzed `PUT /v1/channels/{channel}/acl` (which rewrites an ACL and may drop the agent's own admin), so `cats-ordinary` stays usable for the nested paths, and it is seeded with the agent's entry alone (CATS cannot send two different entries in the root-array body, and an agent may not take a permission from `cats-admin`'s entry, ADR 0011; the administrator keeps admin through the flag), while `cats-sub` takes `DELETE /v1/channels/{channel}/subscription` (CATS mangles a path parameter with `?` and `#`, so that request reaches `DELETE /v1/channels/cats-sub`); every other seeded channel names both identities, re-applied on every seed; the nested paths use the real fixtures — this is the plugin's own model (`cats.fixtures`, `anchor_path`, `decoyed`) and CATS fuzzes per operation, so a consumed decoy never kills a nested path — cost if wrong: a dead fixture is caught by the plugin's fixture gate (run invalid, exit 3) and the harness's post-run fixture check, not silently.
- **Ruling 14: the harness `run` exits 0 when CATS completed (CATS exit 0 or 1: 1 is its default quality gate on any error), 2 on usage, 3 when the server did not start or the seed failed, 4 when CATS exited with another code or wrote no `cats-summary-report.json`; it prints one summary line from `cats-summary-report.json` and `report=<dir>`; findings are the classifier's business** — the hook needs "ran" separated from "found something"; CATS's own gate is not the repository's rule — cost if wrong: none; the codes are documented in the script's usage.
- **Ruling 15: the hook fuzzes the staged tree: `git checkout-index -a -f --prefix=<tmp>/tree/`, then `make generate` there and `diff -r` of `internal/gen` against the export (a difference fails the commit: "run make generate and stage internal/gen"), then the harness with `--repo <tmp>/tree`** — the server embeds `internal/gen/spec`; building from the working tree or with stale generated code would fuzz a server that validates against another spec than the one being committed; `git stash` is forbidden (CLAUDE.md) — cost if wrong: about 10 s of regeneration per spec commit.
- **Ruling 16 (as amended by ruling 24): a destructive skipped path is fuzzed alone, in its own `run --paths <path> --no-skip` on a fresh server, where destroying the campaign's data at the end costs nothing; the hook does this for each such path in the widened list and runs the rest together** — a destructive path still gets coverage when it changes, and a `servers` or `Problem` change that widens to every path no longer floods the main run with 401s or 503s — cost if wrong: a hook run on `/v1/admin/signing-keys/rotate` may see 401s after `revoke_previous` hits; they are findings on that path's own run and the controller's analysis explains them.
- **Ruling 17: the hook fails closed when `cats`, `jq` or `go` is missing (exit 1 with the install line `brew install endava/tap/cats`) and names `git commit --no-verify` as the bypass** — a silent skip would turn the gate off on a machine without CATS without anyone noticing; Eric's decision keeps `--no-verify` as the bypass — cost if wrong: a contributor without Java bypasses explicitly.
- **Ruling 18: the docs page is `docs/cats.md`** (beside `docs/tui.md` and `docs/release.md`; `docs/ops/` is the operator's entry point and this is a developer's tool) **and the record is a new ADR 0018, "API fuzzing with CATS"** (three decisions of Eric's, the rulings, the transport exception of Open item 1; ADR 0001 gets a one-line pointer in its error-responses addendum) — fuzzing is its own topic with its own tooling, and ADR 0001 is already the longest record — cost if wrong: a file move.
- **Ruling 19: the hook's gate is the classifier's verdict over `error` and `warn` records only (CATS `success` records are never findings), and "a finding" is any such record no enabled rule matches** — this is what "recorded false positive" means in the plugin and keeps one definition for `cats:analyze` and the hook — cost if wrong: a `success`-scored answer that violates an acceptance criterion (the probe's 501 is one) is the controller phase's SQL check, not the hook's.
- **Ruling 20: the selftests (`scripts/cats-harness-selftest.sh`, `scripts/cats-precommit-selftest.sh`) run the real server (seconds, no Docker) against the fake `cats` (`scripts/testdata/cats-fake/cats`: records its argv, checks the headers file for `all:` and the admin paths with no bearer on stdout, writes a canned `cats-summary-report.json` and three `Test*.json`, exits 1) and compare against recorded expectations with the directory, port and random ids tokenized; `--real` additionally runs the installed `cats` on `/v1/discover` and `/v1/channels`** — Definition of Done C wants the harness tested against recorded output before Eric is asked to run it; the fake keeps CI (block 40) free of Java — cost if wrong: a CATS flag rename is caught only by `--real` or by the controller's first run.

Rulings 21 to 31 come from the pre-flight scan of 2026-11-08 (`.superpowers/sdd/2026-11-08-issue-30-cats-campaign/progress.md`), accepted by the controller; the three tree claims they rest on were re-verified (`session_lease_seconds` default 90 and bounds 1 to 86400 at `internal/core/config.go:110,165`, the 410 `session_lapsed` at `internal/core/sessions/service.go:116`; `gen.Task.Description` is `*string` at `internal/gen/gen.go:1594` with `optStr` at `internal/server/tasks.go:27` and `deref`/`strPtr` at `internal/bus/remote/convert.go:111,122`; the `release-lint` glob is `release/*.sh scripts/*.sh` plus `install.sh`, so only the fake and the shim need adding).

- **Ruling 21: `changed-paths` exits 10 only when at least one path is affected; documents that differ with no affected path exit 0 with stderr `catscheck: no path is affected`; a missing or empty input file is the empty mapping `{}`; a non-empty non-mapping is exit 2** — the hook turns exit 10 into `--paths`, so an empty list must never ride on exit 10, and a first commit or a newly added spec needs no special case in the hook — cost if wrong: an unreferenced component change skips the hook's campaign (spec-lint's job anyway).
- **Ruling 22: Task 1's `required_change_is_a_change` fixture is an inline request-schema change on one path; `schema_change_widens` (a shared schema) is Task 2's test** — Task 1 has no `$ref` widening, so a shared-schema fixture could not pass there — cost if wrong: none; both tests exist after Task 2.
- **Ruling 23: every task that produces a block 40 anchor pins the literal in its own text** (`"summary", ` and `"properties":` in `normalize.go` (gofmt aligns the map values, so the anchor is the key alone); `var widen = true` in `paths.go`; `if _, ok := operators[op]; !ok {` and `if code >= 500 && code < 600 {` in `rules.go`; `exit 0 # documentation-only` and `exit 1 # findings` in `scripts/cats-precommit.sh`) — implementers read only their task; an unpinned anchor makes Task 10 guess — cost if wrong: Task 10 adjusts an anchor to the file as written and says so.
- **Ruling 24: `run --paths LIST` subtracts `SKIP_PATHS` from the list (printing `skipped: <path> (use --no-skip)`) unless `--no-skip`; the three destructive paths run only as one-path `run --paths P --no-skip`; the hook partitions its widened list into the non-skipped paths (one run), each destructive path (its own run with `--no-skip`) and the bridges paths (dropped with a notice, Open item 6)** — a `Problem`, `servers` or `security` change widens to every path, and one run over all of them would flood with 401s once `reset` or `rotate` revoked the credential and with 503s on bridges, blocking every such commit — cost if wrong: a hook commit touching every path runs up to four campaigns (about 12 min).
- **Ruling 25: `-set session_lease_seconds=86400` is part of `SERVER_SETS`** — the default lease is 90 s and only `open`, `receive` and `watch` renew it, so the seeded sessions would answer 410 `session_lapsed` for most of a 10-minute run and the post-run fixture check would report the session dead; the probes were seconds long and never saw it — cost if wrong: a lapse-related finding is not reproduced by the campaign (the sessions tests cover it).
- **Ruling 26: the hook selftest's staged spec edit is type-neutral: `maxLength: 256` added under `Task.properties.subject`** — adding `description` to `Task.required` turns `gen.Task.Description` from `*string` into `string` and breaks `internal/server/tasks.go` and `internal/bus/remote/convert.go`, so the exported tree would not build and the cases would never reach the fake; the closure is still the four task paths — cost if wrong: if oapi-codegen ever folds `maxLength` into the type, another neutral edit (a `description` beside a new `x-` extension) replaces it.
- **Ruling 27: the hook selftest copies the files under test (`scripts/cats-precommit.sh`, `scripts/cats-harness.sh`, `.githooks/pre-commit`, `scripts/testdata/cats-fake/`, `tools/catscheck/`) from its own `$ROOT` into its throwaway worktree of HEAD before running** — a worktree of HEAD holds neither the uncommitted scripts of Task 6 Step 1 nor block 40's mutations of `$wt`, so without the copy nothing under test would run — cost if wrong: none; the copy is a `cp -R` of five paths.
- **Ruling 28: block 40 runs both selftests once unmutated as its baseline before the mutations, and every repository script uses `grep -E`, never `rg`** — the architecture promised the selftests run in CI, and a mutation-only block never runs the harness selftest at all; `rg` is not guaranteed on the ubuntu runner and no repository script uses it — cost if wrong: block 40 takes about a minute longer.
- **Ruling 29: the hook runs `go run ./tools/catscheck` and `scripts/cats-harness.sh` from the exported index tree (`cd "$tmp/tree"`), never from the working tree** — the staged tree is the only source (ruling 15); otherwise the normalizer, the classifier and the harness could differ from what is being committed, and Review Focus 5 would fail its own check — cost if wrong: `go run` compiles the tool in the export (cached by the Go build cache; about 1 s).
- **Ruling 30: the fake `cats`'s records carry the fuzzer name `FakeCatsFuzzer`, which no real fuzzer has and no committed rule may name (`TestCommittedRules` fails a rule whose `fuzzer` condition names it)** — a rule recorded in Task 7 could otherwise match the fake's `HappyPath` or `NonRestHttpMethods` record and silently change the pre-commit selftest's case 3 — cost if wrong: none.
- **Ruling 31: harness hygiene: `check_dir` validates the directory (not a symlink, owned by the user, absent or empty or carrying the marker `.agentmesh-cats`) before any `rm -rf`, in `up`, `run` and `down`; `down` removes only a marked directory; the seed's task and memory writes carry fixed idempotency keys so a second seed returns the first ids; `run` checks `cats`, `jq` and `go` before tearing anything down; `admin-paths` and `skip-paths` print the two hard-coded lists so the selftest compares `ADMIN_PATHS` with the spec and the hook reads `SKIP_PATHS` from one place; the enrollment token on `register`'s argv is accepted (single-use, bound, consumed within a second)** — each closes a self-consistency defect the scan found (an unchecked `--dir` deleted by `up`, duplicated fixtures in the plugin flow, a `cats` check after `down`, a list that could drift) — cost if wrong: two small subcommands and a marker file.

## Open for Eric (each with the default this plan executes)

1. **The transport-layer answers Go's `net/http` gives before any handler: 501 `text/plain` on an unknown `Transfer-Encoding` (`DummyTransferEncodingHeaders`) and 431 `text/plain` on oversized headers (`LargeNumberOfRandomAlphanumericHeaders`).** The 501 is a 5xx that is not the documented 503 and neither is problem+json. Default: accept them as the documented exception beside 503 (ADR 0018, `docs/cats.md`, the acceptance query excludes code 501 only when the fuzzer is `DummyTransferEncodingHeaders` and the body is empty); no rule is needed (CATS scores both `success`). Alternative: a `ConnState`/`http.Server` wrapper cannot intercept them; only a proxy in front could, which this server does not have.
2. **Three content-negotiation and method clusters (seen on two paths; expected on all): unknown methods answer 404 (CATS expects 405; `TestUndeclaredMethodsRouted`/`TestUndeclaredMethodsRefused` pin 404), unsupported `Accept` answers 200 (expects 406; the server does no content negotiation), unsupported `Content-Type` answers 400 (expects 415).** Each "fix" is a 12th shared response and a `TestStatusTable` row (a wire change, allowed pre-release) or a recorded false positive citing the router and the absence of negotiation. Default: false-positive rules (`UNKNOWN_METHOD_404`, `ACCEPT_NOT_NEGOTIATED_200`, `CONTENT_TYPE_400`), each with its `why`; the controller presents the three clusters with counts before recording them, and Eric may pick the 405/406/415 responses instead (one fix task each).
3. **The agent pass (ruling 12) as a standing part of the triaged campaign.** Default: yes, two plugin runs per campaign; `docs/cats.md` documents both.
4. **CATS's error-leak keywords (`unauthorized`, `notice`, ...) on correct answers.** Default: a rule per keyword cluster after reading the body; `security requirements failed: no identity` (the validator's internal error text in a 401 `detail`) is presented as a real-bug candidate, not a false positive.
5. **The hook's cost: `make generate` plus a build plus 1 to 10 min of fuzzing per spec commit.** Default: accept (Eric's decision 3 chose the hook); the hook prints the path count and the estimated test count from `cats --dryRun` before fuzzing.
6. **The two bridges paths (`/v1/admin/bridges`, `/v1/admin/bridges/{channel}`, four operations) are not fuzzed**, which narrows "for every operation": the campaign server has no Slack bridge, every call answers the documented 503 `unavailable`, and the Slack fake is wired from Go only (`cmd.RunWith`, the e2e fixture). Default: skip them and say so in `docs/cats.md` and ADR 0018. Alternative: a `-slack-fake` seam in the binary for the harness, a design change Eric would have to approve (it puts test code behind a production flag).

## Review Focus

1. **Bearer hygiene:** every reviewer greps the task's scripts for `echo`, `printf`, `set -x`, `cat` or `jq` of a token cache or headers file outside `token` and `headers`, and reads the selftest's grep of the server log, the harness output and the report for `Bearer ey` and `abe_`.
2. **The normalizer's name-map list (ruling 2)** against the spec: `yq '.. | select(has("properties")) | .properties | keys | .[]' api/openapi.yaml | sort | uniq -c | rg -w 'description|summary|example|examples|externalDocs'` must list only `description` (3), and `TestNormalize/property_named_description_kept` must use `Task`.
3. **The classifier against `rules.py`:** compare operator by operator (`equals` is type-sensitive: `response_code` is an int, `result` a string; `in` on a list; `exists` treats JSON `null` as absent; the case-insensitive operators lower both sides; `any_text` is `result_reason + " " + result_details`; `json_body.<path>` splits on `.`; `request_header.<name>` compares names case-insensitively; a bare list on a scalar field is a load error). A missing field is `_MISSING` and `not_equals` matches it.
4. **Idempotency and leftovers (ruling 8):** the reviewer reads `up` for the live-pid refusal, the dead-pid cleanup and the symlink/ownership check of the directory, and `down` for the command-line match; the selftest has a case for each.
5. **The hook's staged-tree rule (ruling 15):** nothing in `scripts/cats-precommit.sh` reads the working tree's `api/openapi.yaml` or builds from `$ROOT`; the export is the only source.
6. **No plugin path in repository code:** `rg -n 'cats_tool|CLAUDE_PLUGIN_ROOT|efitz-skills' scripts/ tools/ .githooks/ Makefile docs/cats.md` finds only the documentation sentence that names the skills.
7. **Fix tasks (Task 8.N):** the reproducing test is committed with the fix and failed before it (the commit message quotes the failing line); the touchpoint checklist of the template is ticked in the task's report.

## Layout

| Path | Task | Tracked |
|---|---|---|
| `tools/catscheck/main.go`, `normalize.go`, `paths.go`, `rules.go`, `record.go`, their `_test.go`, `testdata/` | 1, 2, 3 | yes |
| `api/cats-false-positives.yaml` | 3, 7 | yes |
| `scripts/cats-harness.sh` | 4 | yes |
| `scripts/testdata/cats-fake/cats`, `scripts/testdata/cats-harness/expected-*.txt` | 5 | yes |
| `scripts/cats-harness-selftest.sh`, Makefile target `cats-selftest`, `release-lint` glob | 5, 6 | yes |
| `.githooks/pre-commit`, `scripts/cats-precommit.sh`, `scripts/cats-precommit-selftest.sh` | 6 | yes |
| `.local/cats/config.yaml`, `.local/cats/results/` | 7 | no (git-ignored) |
| `docs/cats.md`, `docs/adr/0018-api-fuzzing-with-cats.md`, `docs/adr/README.md`, `docs/adr/0001-transport-and-api.md` (pointer), CLAUDE.md | 9 | yes |
| `scripts/check-gates-selftest.sh` block 40 | 10 | yes |

---

### Task 1: `tools/catscheck`: the normalizer and `changed-paths` over paths

**Files:**
- Create: `tools/catscheck/main.go` (subcommand dispatch: `normalize FILE`, `changed-paths OLD NEW`, `classify --rules FILE REPORT_DIR`; `classify` is a stub that exits 2 with `not implemented` until Task 3; usage on stderr, exit 2)
- Create: `tools/catscheck/normalize.go` (`Normalize(doc *yaml.Node) *yaml.Node`, `canonical(node) []byte`)
- Create: `tools/catscheck/paths.go` (`ChangedPaths(old, new *yaml.Node) (paths []string, docOnly bool, err error)`; Task 2 adds the `$ref` widening)
- Create: `tools/catscheck/normalize_test.go`, `tools/catscheck/paths_test.go`
- Create: `tools/catscheck/testdata/spec-min.yaml` (a 60-line OpenAPI document with two paths, one shared schema `Thing` with a property named `description`, one shared response, one parameter; the tests derive variants from it in code, so one file is enough)

**Behavior (pinned):**
- `normalize FILE` prints the normalized document as canonical YAML (keys sorted, flow style off) and exits 0; a parse error exits 2 with `catscheck: FILE: <yaml error>`.
- `changed-paths OLD NEW` (ruling 21): both parsed; a **missing or empty file is the empty mapping `{}`** (so a first commit or a newly added spec lists every path of the other side); a non-empty document that is not a mapping, or a YAML parse error, exits 2 with `catscheck: FILE: <reason>`. Exit **0 with no stdout** when the normalized documents are equal (documentation-only, or no change). Exit **10** with one path per line (sorted, the OpenAPI template spelling, `/v1/channels/{channel}`) when at least one path is affected. When the documents differ but no path is affected (an unreferenced component changed), exit **0** with stderr `catscheck: no path is affected` and no stdout. A path present in only one document is a changed path. A difference outside `paths` and `components`: `info` or `tags` → ignored (documentation; a tag rename shows in the operations' `tags` lists anyway); `openapi`, `servers`, `security`, `webhooks` or any other key → every path of `NEW` (or of `OLD` when `NEW` has none).
- Stripping is by position (ruling 2). `strip(node, keysAreNames)`: for a mapping, when `!keysAreNames` delete the keys `description`, `summary`, `example`, `examples`, `externalDocs`; then recurse into each remaining value with `keysAreNames = key ∈ nameMapKeys`; for a sequence recurse into each element with `false`; scalars unchanged. `nameMapKeys = {properties, patternProperties, paths, responses, headers, links, callbacks, encoding, variables, mapping, securitySchemes, requestBodies, schemas, parameters}` as a literal set with a comment on each. (`parameters` under an operation is a sequence, so the set entry only affects `components.parameters`; `components` itself is reached with `false`, its section keys are fixed words.)
- Canonical form: re-encode with `yaml.v3` after sorting mapping keys recursively (the comparison is `bytes.Equal` of the canonical encodings of the subtrees).

**Tests (`go test ./tools/catscheck/`), subtest names pinned for block 40:**
- `TestNormalize/strips_operation_description` (an operation `description` is gone), `TestNormalize/strips_schema_example` (a schema-level `example` is gone), `TestNormalize/strips_components_examples` (the whole `components.examples` section is gone), `TestNormalize/property_named_description_kept` (`Thing.properties.description` survives with its `type`), `TestNormalize/response_description_stripped` (the `description` inside a response object is gone while the status key stays), `TestNormalize/idempotent` (normalize twice equals once), `TestNormalize/extensions_kept` (`x-foo` survives).
- `TestChangedPaths/documentation_only` (OLD = `spec-min.yaml`; NEW = the same with every `description`, `summary`, `example` and `externalDocs` edited or added: exit 0, no paths; this is the mutation block 40 uses), `TestChangedPaths/required_change_is_a_change` (ruling 22: NEW adds a member to the `required` list of an **inline** request schema of one path, so Task 1 resolves it without `$ref` widening; exactly that path is listed), `TestChangedPaths/path_added`, `TestChangedPaths/path_removed`, `TestChangedPaths/servers_change_is_every_path`, `TestChangedPaths/info_change_is_documentation`, `TestChangedPaths/unparsable_is_error` (a non-mapping document: exit 2), `TestChangedPaths/missing_file_is_empty` (OLD absent: every NEW path listed), `TestChangedPaths/empty_file_is_empty` (an empty OLD file: the same), `TestChangedPaths/unreferenced_component_is_no_path` (in Task 1 every component change is "no path" until Task 2 widens: exit 0, empty stdout, stderr `catscheck: no path is affected`).
- The command-level test `TestMainChangedPaths` runs the dispatcher in-process (`run(args, stdout, stderr) int`) and pins the exit codes 0 (equal; and differ-but-no-path with the stderr line), 10 and 2 and the output format.

**Anchors (exact, once in the file; block 40 mutates them; ruling 23):** in `normalize.go` the stripped keys are a string slice literal `var strippedKeys = []string{"description", "summary", "example", "examples", "externalDocs"}` (one line; the anchor is `"summary", `) and the name maps a `var nameMapKeys = map[string]bool{` literal with one entry per line, each `"<key>": true,` (the anchor is `"properties":`, the key alone, because gofmt aligns the values; the mutation deletes that line).

- [ ] **Step 1: Write the tests (red), then `normalize.go`, `paths.go` and `main.go` (green)**

Run: `go test ./tools/catscheck/ -run 'TestNormalize|TestChangedPaths|TestMainChangedPaths' -v 2>&1 | tail -25`
Expected: every listed subtest `--- PASS`.

- [ ] **Step 2: Probe against the real spec**

Run: `go run ./tools/catscheck changed-paths api/openapi.yaml api/openapi.yaml; echo "exit $?"` → exit 0, no output. Then copy the spec to the scratchpad, change one `description:` line of `listChannels` and run again → exit 0. Then add `maxLength: 256` to `Task.properties.subject` (a shared schema) → in Task 1 exit 0 with `catscheck: no path is affected` on stderr; after Task 2 exit 10 listing `/v1/channels/{channel}/tasks`, `/v1/tasks/{id}`, `/v1/tasks/{id}/claim`, `/v1/tasks/{id}/release` (record both in the Task 2 commit message).

- [ ] **Step 3: Lint and commit**

Run: `make lint vet fmt-check` (clean) and `go build ./...`.

```bash
git add tools/catscheck/
git commit -m "tools(catscheck): the spec normalizer and changed-paths over paths (issue #30)"
```

---

### Task 2: `changed-paths` widens through `$ref` closures

**Files:**
- Modify: `tools/catscheck/paths.go` (`refClosure(doc, pathItem) set[string]` following `$ref` strings of the form `#/components/<section>/<name>` recursively, cycle-safe; a `$ref` to another document or a malformed one is an error, exit 2)
- Modify: `tools/catscheck/paths_test.go`

**Behavior:** a path is changed when its normalized path item differs between OLD and NEW, **or** when any component in the closure of its NEW path item (or OLD, for a removed path) has a different normalized value between the documents (a component present in one document only counts as different). Components not reachable from any path are ignored. The closure follows `$ref` inside schemas (`properties`, `items`, `allOf`, `oneOf`, `anyOf`, `additionalProperties`, `not`), responses (`content.*.schema`, `headers`), parameters, request bodies and headers, by walking every node of the referenced component and collecting every `$ref` scalar.

**Tests (pinned):** `TestChangedPaths/schema_change_widens` (change `Thing.type` of a property: both paths that reference `Thing`, directly or through the shared response, are listed; this is the block 40 mutation), `TestChangedPaths/nested_ref_widens` (a schema referenced only by another schema), `TestChangedPaths/unreferenced_component_is_no_path` (kept from Task 1, now with a component no path reaches: exit 0, stderr `catscheck: no path is affected`, no stdout; ruling 21), `TestChangedPaths/ref_cycle_terminates`, `TestChangedPaths/external_ref_is_error` (exit 2).

**Anchor (exact, once in `paths.go`; ruling 23):** the widening is behind one package-level toggle written exactly as `var widen = true // block 40 flips this to false` and read as `if widen {` around the closure step; block 40 mutates `var widen = true` to `var widen = false` (the file still compiles and `schema_change_widens` fails).

- [ ] **Step 1: Tests red, implementation green; rerun the Task 1 Step 2 probe** (the `maxLength: 256` edit of `Task.properties.subject` now lists exactly `/v1/channels/{channel}/tasks`, `/v1/tasks/{id}`, `/v1/tasks/{id}/claim`, `/v1/tasks/{id}/release`: verified on 5d26dfe by `rg -n 'components/schemas/Task' api/openapi.yaml`, lines 1789 and 1917 directly, 1998, 2077 and 2145 through `TaskUpdateResult`, whose line 4687 references `Task`; `Problem` changes list every path that declares a problem response, which is all 57 operations' paths minus the three `.well-known` ones: record the count).

- [ ] **Step 2: Commit**

```bash
git add tools/catscheck/paths.go tools/catscheck/paths_test.go
git commit -m "tools(catscheck): changed-paths widens to every path whose \$ref closure reaches a changed component (issue #30)"
```

---

### Task 3: `classify`: the rule engine over `Test*.json`, and the committed rules file

**Files:**
- Create: `tools/catscheck/record.go` (`Record` with the fields of `parse.py:record_from_json`: `result` (lowercased), `response_code` (int; 0 when absent or unparsable), `fuzzer`, `path`, `contract_path`, `method` (`request.httpMethod`), `url`, `scenario`, `result_reason`, `result_details`, `response_body` (the JSON re-serialization of `response.jsonBody`, `""` when absent), `response_content_type`, `request_body` (`request.payload` as a string), `json_body` (`any`), `request_headers` (`map[string]string` from `request.headers` `[{key,value}]`, names lowercased); `LoadReport(dir) ([]Record, error)` reads every `Test*.json` sorted by number and skips a file missing `testId`, `scenario`, `result`, `fuzzer`, `path`, `request` or `response` with a warning on stderr, like `parse.py:_REQUIRED_FIELDS`)
- Create: `tools/catscheck/rules.go` (`LoadRules(path) ([]Rule, error)`: `version: 1`, `rules:` list; keys `id`, `why`, `when`, `any_of`, `enabled` (default true), `tags`; at least one of `when`/`any_of`; non-empty blocks; the 14 scalar fields, the two prefixes and the two bare fields; the 11 operators; list operands for `in`, `contains_any`, `contains_all`, `starts_with_any`; a bare list on a scalar field is an error; unknown anything is an error naming the rule id and the key; `Match(rule, rec) bool`; `Classify(rules, rec) (fp bool, ruleID string, violation string)` with the 5xx refusal: a matching rule on `response_code` 500 to 599 is a violation, never a suppression)
- Create: `tools/catscheck/classify.go` (`classify --rules FILE [--max-lines N] REPORT_DIR`, flags before the positional as Go's `flag` requires: loads both; for every `error`/`warn` record not suppressed prints one TSV line `<result>\t<method>\t<path>\t<response_code>\t<fuzzer>\t<result_reason>` (capped at `N`, default 40, then `... and K more`), then a summary line `catscheck: <tests> tests, <errors> error, <warn> warn, <suppressed> suppressed by <rules used> rule(s), <findings> finding(s)`; a violation prints `catscheck: rule <ID> matched a <code> response and was refused` and counts as a finding; exit 0 when findings are 0, 1 otherwise, 2 on a load error)
- Create: `tools/catscheck/rules_test.go`, `tools/catscheck/classify_test.go`
- Create: `tools/catscheck/testdata/report/` with six scrubbed `Test*.json` taken from a real run (Step 1 says how): an `error` 400 problem+json (`HappyPath`), a `warn` 404 (`NonRestHttpMethods`), a `success` 200, an `error` 401 "leak" (`BypassAuthentication`), a `success` 501 `text/plain` (`DummyTransferEncodingHeaders`), and a hand-edited `error` 503 problem+json (copy of the 400 with the code changed) for the 5xx rail, plus `testdata/report-malformed/` holding one valid record and one `Test2.json` that is `{"result": "error"}` (missing the required members) for `TestLoadReport/skips_malformed_file`; plus `testdata/rules/` with `valid.yaml`, `unknown-operator.yaml`, `unknown-field.yaml`, `unknown-key.yaml` (a rule with `reason:` instead of `why:`), `bare-list.yaml`, `no-condition.yaml`, `five-xx.yaml`
- Create: `api/cats-false-positives.yaml`: the plugin's `INITIAL_RULES_YAML` text verbatim (`config.py`: the header comment, `version: 1`, `RATE_LIMIT_429` and `CONNECTION_ERROR_999`), so `cats:init` finds it and never overwrites it (it "never overwrites an existing rules file")
- Create: `tools/catscheck/committed_rules_test.go` (`TestCommittedRules`: loads `../../api/cats-false-positives.yaml` through `LoadRules`; every rule constrains `response_code` with `equals` or `in` and no code is in 500 to 599 (ruling 6; the starter `CONNECTION_ERROR_999` passes); ids are unique `UPPER_SNAKE_CASE`; `why` is non-empty; no rule's `fuzzer` condition names `FakeCatsFuzzer` (ruling 30; Task 5's fake uses that name); the file loads with no unknown key)

**Semantics to port exactly (`rules.py` lines 194 to 320):** `field_value`: `any_text` is `result_reason + " " + result_details` (never missing); `json_body.<a>.<b>` walks maps only (a non-map or missing key is missing); `request_header.<name>` compares lowercased names; other names read the record field or missing. `_apply`: `exists` is present-and-not-null equals the operand; `equals`/`not_equals`/`in` compare values as decoded (ints with ints, strings with strings; missing is `not_equals` everything and `in` nothing); the seven text operators lowercase `fmt.Sprint(actual)` (missing and null become `""`) and the operand; `matches` is `regexp.MustCompile("(?i)" + expr)` with `FindStringIndex` (search, not full match), an invalid regex is a load error. A bare scalar condition is `equals` (so the starter rules' `when: {response_code: 429}` counts as an explicit `equals` for `TestCommittedRules`). A block matches when every condition does; a rule matches when `when` matches (if present) and at least one `any_of` block matches (if present); evaluation in file order; the first enabled match wins.

**Anchors (exact, once in `rules.go`; ruling 23):** the operator check is written `if _, ok := operators[op]; !ok {` (`operators` is a `map[string]bool` literal of the 11 names) and the 5xx rail `if code >= 500 && code < 600 {`; block 40 mutates each to `if false {`.

**Tests (pinned):** `TestLoadRules/valid`, `TestLoadRules/unknown_operator_rejected`, `TestLoadRules/unknown_field_rejected`, `TestLoadRules/bare_list_rejected`, `TestLoadRules/no_condition_rejected`, `TestLoadRules/unknown_key_rejected`; `TestMatch/<operator>` one per operator including case rules and the missing-field cases above; `TestClassify/first_match_wins`, `TestClassify/success_never_classified`, `TestClassify/disabled_rule_skipped`, `TestClassify/rule_never_suppresses_5xx` (the 503 record and `five-xx.yaml`: violation, exit 1; this is the block 40 mutation), `TestClassify/any_text_contains`, `TestClassify/json_body_path`, `TestClassify/request_header_case_insensitive`; `TestLoadReport/skips_malformed_file`; `TestMainClassify/exit_codes` (0 with a rules file covering the error records, 1 with the starter file, 2 with a bad rules file); `TestCommittedRules`.

- [ ] **Step 1: Record the fixtures**

Until Task 4 lands, the recording uses the probe script's sequence by hand: build `agentmesh` into the scratchpad, start `agentmesh server -listen 127.0.0.1:0 -sqlite <scratch>/s.sqlite`, create and register `cats-admin` as in `docs/ops/admin-bootstrap.md`, `login`, write a 0600 headers file `all: {Authorization: Bearer <token>}` from the cache's `access_token`, run `cats -c api/openapi.yaml -s <url> --headers=<file> -o <scratch>/report --no-checkUpdate --noEnvFile -p /v1/channels,/v1/discover`, delete the headers file, stop the server. Pick the six files by `jq '.result, .response.responseCode, .fuzzer'`, copy them renamed `Test1.json` to `Test6.json`, and confirm with `rg -l 'eyJ|abe_' tools/catscheck/testdata/report/` that none carries a token (the `Authorization` value is already `$$Authorization`). Record the chosen files and their origin in the commit message.

- [ ] **Step 2: Tests red, implementation green**

Run: `go test ./tools/catscheck/ 2>&1 | tail -5` → `ok`. Then: `go run ./tools/catscheck classify --rules api/cats-false-positives.yaml tools/catscheck/testdata/report; echo "exit $?"` → the error and warn lines, the summary, exit 1.

- [ ] **Step 3: Commit**

```bash
git add tools/catscheck/ api/cats-false-positives.yaml
git commit -m "tools(catscheck): classify ports the cats plugin's false-positive rules over Test*.json; the committed rules file (issue #30)"
```

---

### Task 4: `scripts/cats-harness.sh`: up, seed, token, headers, run, down, status

**Files:**
- Create: `scripts/cats-harness.sh`
- Modify: `Makefile` (`cats-run: ## One CATS campaign against a throwaway server (needs cats and Java; not part of verify)` → `bash scripts/cats-harness.sh run`; `cats-run` added to `.PHONY`)

**Interface (pinned; `usage` prints it; every option before the subcommand's positional arguments):**

```
scripts/cats-harness.sh up     [--dir DIR] [--port N] [--repo DIR]
scripts/cats-harness.sh seed   [--dir DIR] [--out DIR] [--identity admin|agent]
scripts/cats-harness.sh token  [--dir DIR] <admin|agent>
scripts/cats-harness.sh headers [--dir DIR] [--out FILE]
scripts/cats-harness.sh run    [--dir DIR] [--port N] [--repo DIR] [--out DIR] [--paths LIST] [--no-skip]
scripts/cats-harness.sh down   [--dir DIR]
scripts/cats-harness.sh status [--dir DIR]
scripts/cats-harness.sh admin-paths
scripts/cats-harness.sh skip-paths
```

`admin-paths` prints `ADMIN_PATHS` one per line and nothing else (the selftest compares it with the spec); `skip-paths` prints `SKIP_PATHS` one per line and nothing else (the hook partitions with it, so the list lives in one place). `down` prints `cleaned leftovers (pid <N> dead)` when it finds a pid file whose process is gone, and nothing when the pid is alive and killed normally or when no directory exists.

Defaults: `--dir` `${CATS_HARNESS_DIR:-${TMPDIR:-/tmp}/agentmesh-cats-$(id -u)}`; `--port` `0` (free; the listening line gives it); `--repo` the script's own repository root; `seed --out` the harness dir; `seed --identity` `${CATS_IDENTITY:-agent}` (the plugin exports `CATS_IDENTITY` to its hooks); `run --out` `$ROOT/.local/cats/results/run-$(date -u +%Y%m%dT%H%M%SZ)`; `CATS_BIN` `${CATS_BIN:-cats}`. Exit codes: 0 ok; 1 a check failed (a bearer in a log, a dead fixture); 2 usage or a missing tool (`cats`, `jq`, `go`); 3 the server did not start, a live server is recorded (`up`), or the seed failed; 4 CATS exited with a code other than 0 or 1 or wrote no `cats-summary-report.json`.

**Constants (pinned, with a comment naming ruling 10 and 13):** `PROFILE=cats`, `ADMIN=cats-admin`, `AGENT=cats-agent`; `SERVER_SETS=(-set send_messages_per_second=10000 -set send_kib_per_second=65536 -set token_lifetime_seconds=86400 -set session_lease_seconds=86400 -set watch_max_seconds=1 -set maintenance_interval_seconds=3600)` (ruling 25: the default lease is 90 s and only `open`, `receive` and `watch` renew it, so the seeded sessions would answer 410 `session_lapsed` for most of a run; `session_lease_seconds` is bounded 1 to 86400, `internal/core/config.go:165`); `SKIP_PATHS=(/v1/admin/reset /v1/admin/signing-keys/rotate '/v1/admin/identities/{identity}/reset-credential' /v1/admin/bridges '/v1/admin/bridges/{channel}')`; `ADMIN_PATHS` = the 13 paths under `/v1/admin/` (from `cats list -p`; the headers file keys); `LISTEN_RE='agentmesh server listening on ([^ ]+) \('` (the e2e fixture's); `TOKEN_RE='^token: (abe_[^ ]+)$'`.

**`up`:** fail fast on missing `go` or `jq`; **validate the directory before anything is removed** (ruling 31; the same `check_dir` function runs first in `up`, `run` and `down`): `$DIR` must be absent, or a directory that is not a symlink (`[ ! -L "$DIR" ]`), owned by the user (`[ -O "$DIR" ]`) and either empty or containing the marker file `.agentmesh-cats`; anything else exits 2 naming the path (`cats-harness: refusing <dir>: not a harness directory`). Then refuse (exit 3, message names the pid and `down`) when `$DIR/server.pid` names a live process whose command line contains `$DIR/agentmesh server` (`ps -o command= -p PID`); otherwise `rm -rf "$DIR"` (only after `check_dir` passed), `mkdir -m 700 "$DIR"`, `touch "$DIR/.agentmesh-cats"`; `umask 077` for the whole script; `CGO_ENABLED=0 go build -trimpath -o "$DIR/agentmesh" .` from `--repo`; `export AGENTMESH_CONFIG_DIR="$DIR/config" AGENTMESH_DATA_DIR="$DIR/data"`; host commands on `$DIR/server.sqlite`: `create-identity cats-admin`, `admins add -identity cats-admin`, `enrollment create -identity cats-admin -expires 24h -uses 1` captured into a variable through `TOKEN_RE` (never echoed); start `"$DIR/agentmesh" server -listen 127.0.0.1:$PORT -sqlite "$DIR/server.sqlite" "${SERVER_SETS[@]}" >"$DIR/server.log" 2>&1 &`, write `server.pid`; wait up to 30 s for `LISTEN_RE` in the log (0.2 s polls), else print the log tail and exit 3; write `server.url` (`http://<addr>`); `register -profile cats -identity cats-admin -server URL -enrollment-token <var>` and `register -profile cats -identity cats-agent -server URL` (registration is `open` on loopback), both with stdout to the log file `$DIR/harness.log`; `login` for both; print exactly `dir=$DIR` and `server=$URL`. The script never prints the enrollment token or a bearer; `set -x` is forbidden. The enrollment token does pass on `register`'s argv (`-enrollment-token`; the CLI has no file form), visible in `ps` to the same user for under a second: accepted (ruling 31) because it is single-use, bound to `cats-admin`, consumed at once and useless against any other server; the header comment says so.

**`seed`:** requires a live `up` (exit 3 otherwise); runs the CLI as `cats-admin` with the profile; idempotent (ruling 31): a conflict on an existing channel or scope is accepted (the CLI's `conflict` error exit 1 is caught per command and the existing object is read back by `channels list`, `scopes list`); the task and memory writes carry fixed idempotency keys (`tasks create -key cats-seed-task-fixture`, `-key cats-seed-task-decoy`; `send -key cats-seed-memory-fixture`, `-key cats-seed-memory-decoy`), so a second `seed` (the plugin flow seeds on every run) returns the first ids instead of duplicating; the two sessions are reopened each time (a fresh session per run is fine: `refdata.yml` is rewritten); creates channels `cats-ordinary`, `cats-ordinary-decoy` (ordinary), `cats-tasks` (`-kind tasks`), `cats-memory` (`-kind memory`), each with `-acl '[{"identity":"cats-agent","permissions":["read","write","admin"]}]'`; tasks `Fixture task` and `Decoy task` in `cats-tasks` (ids from the JSON `id`); memories by `send cats-memory 'Fixture memory'` and `send cats-memory 'Decoy memory'` (ids from `memory_id`); scopes `cats-scope`, `cats-scope-decoy`; two sessions **as `--identity`** (`session open -identity <who> -hint cats-primary`, `-hint cats-decoy`; the `session` member), so `/v1/sessions/{session}/...` belongs to the identity that fuzzes. Writes, to `--out`: `seed.json` (every id by name), `refdata.yml` and `fixtures.json`.

`refdata.yml` (exact keys; `<...>` are the seeded values; the `scope` line of `/v1/channels` is `cats_remove_field` for the agent identity and `cats-scope` for the administrator, because `scope` on a channel is administrator-only):

```yaml
/v1/channels:
  acl[*]#identity: cats-agent
  acl[*]#permissions: [read, write, admin]
  scope: <cats_remove_field | cats-scope>
/v1/channels/{channel}:
  channel: cats-ordinary-decoy
/v1/channels/{channel}/acl:
  channel: cats-ordinary
  $[*]#identity: cats-agent
  $[*]#permissions: [read, write, admin]
/v1/channels/{channel}/subscription:
  channel: cats-ordinary
/v1/channels/{channel}/messages:
  channel: cats-ordinary
  reply_to: cats_remove_field
/v1/channels/{channel}/tasks:
  channel: cats-tasks
/v1/tasks/{id}:
  id: <decoy task id>
/v1/tasks/{id}/claim:
  id: <task id>
/v1/tasks/{id}/release:
  id: <task id>
/v1/memories/{id}:
  id: <decoy memory id>
/v1/memories/{id}/revisions:
  id: <memory id>
/v1/sessions/{session}:
  session: <decoy session>
/v1/sessions/{session}/peek:
  session: <primary session>
/v1/sessions/{session}/receive:
  session: <primary session>
/v1/sessions/{session}/watch:
  session: <primary session>
/v1/sessions/{session}/status:
  session: <primary session>
/v1/identities/{identity}/statuses:
  identity: cats-agent
/v1/admin/scopes/{scope}:
  scope: cats-scope
/v1/admin/scopes/{scope}/done:
  scope: cats-scope-decoy
  retire: normal
/v1/admin/identities:
  scope: cats-scope
```

`fixtures.json` (the plugin's manifest shape, `runner.py:load_fixtures`; `verify_url` is a GET the fuzzing identity may make): `{"fixtures": [{"key": "channel", "id": "cats-ordinary", "verify_url": "<url>/v1/channels/cats-ordinary/acl", "anchor_path": "/v1/channels/{channel}", "decoyed": true}, {"key": "tasks-channel", "id": "cats-tasks", "verify_url": "<url>/v1/channels/cats-tasks/tasks", "anchor_path": "/v1/channels/{channel}", "decoyed": true}, {"key": "task", "id": "<task id>", "verify_url": "<url>/v1/tasks/<task id>", "anchor_path": "/v1/tasks/{id}", "decoyed": true}, {"key": "memory", "id": "<memory id>", "verify_url": "<url>/v1/memories/<memory id>", "anchor_path": "/v1/memories/{id}", "decoyed": true}, {"key": "session", "id": "<primary session>", "verify_url": "<url>/v1/sessions/<primary session>/peek", "anchor_path": "/v1/sessions/{session}", "decoyed": true}, {"key": "scope", "id": "cats-scope", "verify_url": "<url>/v1/admin/scopes/cats-scope", "anchor_path": "/v1/admin/scopes/{scope}/done", "decoyed": true}]}` (the `scope` entry's verify is administrator-only; `seed --identity agent` omits it).

**`token <admin|agent>`:** `login -profile cats -identity <name>` with stdout and stderr to `$DIR/harness.log` (refreshes a bearer near expiry), then `jq -r .access_token "$DIR/data/tokens/cats/<name>.json"` is the only stdout; exit 3 when `up` is not live.

**`headers [--out FILE]`:** writes (0600, default `$DIR/headers.yml`) `all:` with the agent bearer and one key per `ADMIN_PATHS` entry with the administrator bearer, reading the caches with `jq` into variables; prints the file path only.

**`run`:** first the tool check (`$CATS_BIN`, `jq`, `go` on `PATH` or executable; exit 2 naming the missing one, before anything is torn down) and `check_dir`; then `down` (leftovers, ruling 8); `up`; `seed --identity agent`; `headers`; the path list (ruling 24): with `--paths LIST`, every entry that is in `SKIP_PATHS` is removed from the list and printed as `skipped: <path> (use --no-skip)` unless `--no-skip` is given; an empty list after the subtraction exits 0 with `nothing to fuzz`; without `--paths`, `--skipPaths=<SKIP_PATHS joined by ,>` is passed unless `--no-skip`; optional smoke: `"$CATS_BIN" smoke -c "$REPO/api/openapi.yaml" -s "$URL" --headers="$DIR/headers.yml" --no-checkUpdate --noEnvFile -o "$OUT/smoke"` with the summary line kept in `$OUT/smoke.txt` (its exit code is not checked; the fake writes a one-line table); then the campaign: `"$CATS_BIN" -c "$REPO/api/openapi.yaml" -s "$URL" --headers="$DIR/headers.yml" --refData="$DIR/refdata.yml" -o "$OUT/report" --maxRequestsPerMinute=10000 --no-checkUpdate --noEnvFile --printExecutionStatistics` plus `--skipPaths=<SKIP_PATHS joined by ,>` unless `--paths` or `--no-skip` is given, plus `--paths=<LIST>` when given (ruling 16); stdout and stderr to `$OUT/cats.log`; the exit code recorded; the headers file removed at once (also by the `EXIT` trap); post-run fixture check: every `verify_url` of `fixtures.json` is fetched with the agent bearer (`curl -s -o /dev/null -w '%{http_code}'`) and a non-2xx prints `fixture <key> died (HTTP <code>)` and sets the exit to 1 after the summary; bearer check: `leaks=$(grep -l -E 'Bearer ey|abe_[A-Za-z0-9_-]{20,}' "$DIR/server.log" "$OUT/cats.log" 2>/dev/null || true); leaks+=$(grep -rl -E 'Bearer ey' "$OUT/report" 2>/dev/null || true)`; a non-empty `$leaks` prints `bearer leaked into: <files>` and sets the exit to 1 (`grep -c` is not used: it prints counts and exits 1 on no match, which `set -e` would misread); summary: from `$OUT/report/cats-summary-report.json` with `jq -r '"tests=\(.totalTests) success=\(.success) warnings=\(.warnings) errors=\(.errors) status=\(.runStatus)"'`, then `report=$OUT/report`; CATS exit not in {0, 1} or no summary file → exit 4 with the last 20 lines of `cats.log`; `down` last (trap). Exit 0 otherwise (ruling 14).

**`down`:** if `server.pid` exists and the pid is alive with the matching command line, `kill -TERM`, wait up to 5 s, then `kill -KILL`; then `rm -rf "$DIR"` (which removes the bearer caches); silent when nothing exists. **`status`:** prints `dir=`, `server=` (or `none`), `pid=<pid> alive|dead|none`.

**Definition of Done D statement (goes in the script header):** second `up` → exit 3 while alive; `up` over a dead pid or a stale directory → cleaned and restarted; `run` twice → each run tears down what the previous left; two overlapping `run`s on one machine → the second's `down` kills the first's server (the directory is shared by design; use `--dir` for a second campaign); `seed` twice → the same fixtures, re-read; `down` twice → the second is a no-op.

- [ ] **Step 1: Write the script; shellcheck it; run it for real**

Run: `shellcheck -x scripts/cats-harness.sh` (clean). Then `bash scripts/cats-harness.sh up && bash scripts/cats-harness.sh status && bash scripts/cats-harness.sh seed && bash scripts/cats-harness.sh token agent | wc -c && bash scripts/cats-harness.sh up; echo "second up exit $?"; bash scripts/cats-harness.sh down` → `dir=`/`server=` lines, a status line, a byte count above 100 (the bearer's length, not the bearer), `second up exit 3`, and nothing left under the directory.

- [ ] **Step 2: A real campaign on two paths, then the fixture and HappyPath check**

Run: `bash scripts/cats-harness.sh run --paths '/v1/channels,/v1/channels/{channel}/acl,/v1/sessions/{session}/peek,/v1/tasks/{id}/claim' | tee /tmp/cats-run.txt` → `tests=... errors=...`, `report=...`, exit 0. Then `go run ./tools/catscheck classify --rules api/cats-false-positives.yaml <report>` and read the HappyPath lines: every `HappyPath` record on these paths must be `success` (the refData is right) before the task is done; iterate on `refdata.yml` (the `cats_remove_field` line, the ACL members) until it is, and record the final HappyPath count in the commit message. Then the full run once: `bash scripts/cats-harness.sh run` → about 10 min; record `tests=`, `errors=`, `warnings=` and the elapsed time in the commit message (they are the baseline Task 7 starts from).

- [ ] **Step 3: Second run and leftovers by hand**

`bash scripts/cats-harness.sh up; kill -9 "$(cat "${TMPDIR:-/tmp}/agentmesh-cats-$(id -u)/server.pid")"; bash scripts/cats-harness.sh run --paths /v1/discover; echo "exit $?"` → the dead pid is cleaned, the run completes, exit 0.

- [ ] **Step 4: Commit**

```bash
git add scripts/cats-harness.sh Makefile
git commit -m "scripts(cats): the campaign harness: build, start, seed, bearers, cats, collect, stop (issue #30)"
```

---

### Task 5: The harness selftest against recorded output, with a fake `cats`

**Files:**
- Create: `scripts/testdata/cats-fake/cats` (bash, executable; `set -euo pipefail`): appends its arguments, one per line, to `$CATS_FAKE_LOG` (required); for `smoke` writes `Summary: fake` to stdout and exits 0; otherwise parses `--headers=` and `-o` from the arguments, asserts the headers file exists, is mode 0600 and has an `all:` key and an `/v1/admin/status:` key (prints `fake-cats: FAIL <reason>` and exits 9 otherwise), never prints a header value, writes to the `-o` directory `cats-summary-report.json` (`{"totalTests":"3","success":"1","warnings":"1","errors":"1","runStatus":"COMPLETED","qualityGatePassed":false}`) and three `Test*.json` copied from `scripts/testdata/cats-fake/report/` (the Task 3 fixtures: the 400 error, the 404 warn, the 200 success, paths adjusted to `/v1/channels`, and every `fuzzer` member set to `FakeCatsFuzzer`, a name no real fuzzer and no committed rule ever carries: ruling 30), and exits 1 (CATS's quality gate)
- Create: `scripts/testdata/cats-fake/report/Test1.json`, `Test2.json`, `Test3.json`
- Create: `scripts/testdata/cats-harness/expected-argv.txt` (the recorded fake argv with `<DIR>`, `<URL>`, `<OUT>` and `<REPO>` tokens), `expected-refdata.yml` (with `<SESSION>`, `<DECOY_SESSION>`, `<TASK>`, `<DECOY_TASK>`, `<MEMORY>`, `<DECOY_MEMORY>` tokens), `expected-fixtures-keys.txt` (the `key` list)
- Create: `scripts/cats-harness-selftest.sh` (`[--real]`)
- Modify: `Makefile` (`cats-selftest: ## The harness selftest with the fake cats (no Java; block 40 of check-gates-selftest runs it once unmutated and under mutation)` → `bash scripts/cats-harness-selftest.sh`; `cats-selftest` added to `.PHONY`; Task 6 appends `&& bash scripts/cats-precommit-selftest.sh` to it; the `release-lint` shellcheck line gains `scripts/testdata/cats-fake/cats` here and `.githooks/pre-commit` in Task 6)

**The selftest** uses its own `--dir` under `$(mktemp -d)` (never the default directory, so a developer's campaign is untouched), `CATS_BIN=$ROOT/scripts/testdata/cats-fake/cats`, `CATS_FAKE_LOG` in the temp dir, prints `cats-harness-selftest: ok <case>` or `cats-harness-selftest: FAIL <case>: <why>` per case and exits 1 if any failed (every case runs). Cases (names pinned):
1. `run-completes`: `run --out <tmp>/out` exits 0 and prints `tests=3 success=1 warnings=1 errors=1 status=COMPLETED` and `report=`.
2. `argv-recorded`: the fake's argv, after tokenizing the directory, URL, out and repo paths, equals `expected-argv.txt` (so a flag rename or a lost `--noEnvFile` fails).
3. `refdata-recorded`: `refdata.yml` with ids tokenized equals `expected-refdata.yml`; `fixtures.json` keys equal `expected-fixtures-keys.txt`.
4. `token-prints-one-line`: after `up`, `token agent` prints exactly one line matching `^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`; `token nobody` exits 2.
5. `no-bearer-leaks`: `grep -q -E 'Bearer ey|abe_[A-Za-z0-9_-]{20,}' <tmp>/out/cats.log <dir>/harness.log <dir>/server.log` finds nothing, and the harness's own stdout from cases 1 and 4 (captured) contains no `eyJ` except the `token` line. (Scripts use `grep -E`, never `rg`: ruling 28.)
6. `headers-file-removed`: after `run` the headers file `<dir>/headers.yml` does not exist (the mode check itself is the fake's: it exits 9 on a wrong mode or a missing key, and case 1 would then see exit 4 from `run`, so case 6 is not a repeat of case 1).
7. `second-up-refused`: `up` then `up` exits 3 with `down` in the message.
8. `leftovers-cleaned`: `up`, read `<dir>/server.pid` as `old`, `kill -9 "$old"`, then `run --paths /v1/discover` exits 0 and its output contains the line `cleaned leftovers (pid <old> dead)` that `down` prints when it finds a dead pid file (Task 4), proving the stale state was seen and replaced rather than ignored.
9. `down-removes-dir`: after `down` the directory does not exist; `down` again exits 0.
10. `skip-paths-vs-paths`: the argv of a `run` has `--skipPaths=/v1/admin/reset,...` (the five entries in order); the argv of `run --paths /v1/discover` has `--paths=/v1/discover` and no `--skipPaths=`; `run --paths /v1/discover,/v1/admin/reset` prints `skipped: /v1/admin/reset (use --no-skip)` and passes `--paths=/v1/discover`; `run --paths /v1/admin/reset --no-skip` passes `--paths=/v1/admin/reset`; `run --paths /v1/admin/reset` exits 0 with `nothing to fuzz` and the fake is not invoked (ruling 24).
11. `cats-not-found`: `CATS_BIN=/nonexistent run` exits 2 naming `cats`, before any server is started (no `server.pid` appears).
12. `shellcheck`: `shellcheck -x scripts/cats-harness.sh scripts/cats-harness-selftest.sh scripts/testdata/cats-fake/cats` is clean.
13. `server-argv`: the server's command line (`ps -o command= -p "$(cat <dir>/server.pid)"` while up) contains each of the six `SERVER_SETS` pairs, `session_lease_seconds=86400` among them (ruling 25), and `-listen 127.0.0.1:`.
14. `admin-paths-match-spec`: the `ADMIN_PATHS` list the harness prints with `scripts/cats-harness.sh admin-paths` (a seventh subcommand: one path per line, nothing else) equals `yq '.paths | keys | .[] | select(startswith("/v1/admin/"))' api/openapi.yaml | sort` (13 lines today), so the hard-coded list cannot drift from the spec (`yq` is on this machine at `/opt/homebrew/bin/yq`; the case is skipped with `ok admin-paths-match-spec (yq absent)` when it is not).
15. `dir-guard`: `up --dir <tmp>/not-mine` where that path is a non-empty directory without the marker exits 2 with `not a harness directory` and the directory's file survives; `down --dir` on it exits 2 the same way (ruling 31).
`--real` adds `real-campaign`: `CATS_BIN=cats run --paths /v1/discover,/v1/channels` exits 0 with `tests=` above 500 (needs Java; never in CI).

Hand-written assertions beside the recorded files (so a wrong recording cannot pass): `expected-argv.txt` must contain `--noEnvFile`, `--no-checkUpdate`, `-o <OUT>/report`, `--headers=<DIR>/headers.yml`, `--refData=<DIR>/refdata.yml` and must not contain `--showSecrets` or `Bearer`; the selftest asserts these literals itself before comparing the whole file.

- [ ] **Step 1: Write the fake, the selftest and the expectations; record**

The expectation files are recorded by running the selftest once with `CATS_HARNESS_RECORD=1`, which writes them instead of comparing (and prints what it wrote); the second run compares. Run: `bash scripts/cats-harness-selftest.sh` → twelve `ok` lines, exit 0; `bash scripts/cats-harness-selftest.sh --real` → thirteen.

- [ ] **Step 2: `make cats-selftest` and `make release-lint` green; commit**

```bash
git add scripts/cats-harness-selftest.sh scripts/testdata/cats-fake scripts/testdata/cats-harness Makefile
git commit -m "test(cats): the harness selftest against recorded output with a fake cats (issue #30)"
```

---

### Task 6: The pre-commit hook

**Files:**
- Create: `.githooks/pre-commit` (executable): `#!/usr/bin/env bash` / `exec bash "$(git rev-parse --show-toplevel)/scripts/cats-precommit.sh" "$@"`
- Create: `scripts/cats-precommit.sh`
- Create: `scripts/cats-precommit-selftest.sh`
- Modify: `Makefile` (`cats-selftest` runs both selftests; `release-lint` shellchecks `.githooks/pre-commit`)

**`scripts/cats-precommit.sh` (pinned):**
1. `ROOT="$(git rev-parse --show-toplevel)"`; if `git diff --cached --name-only -- api/openapi.yaml` is empty → exit 0 silently.
2. Fail closed (ruling 17): `cats`, `jq`, `go` on `PATH` (`CATS_BIN` honored), else `cats-precommit: <tool> is not installed (brew install endava/tap/cats); commit with --no-verify to bypass` and exit 1.
3. `tmp=$(mktemp -d)`, `trap` removes it and runs `scripts/cats-harness.sh down --dir "$tmp/harness"`.
4. Export the index first (ruling 15 and 29): `git checkout-index -a -f --prefix="$tmp/tree/"`; everything below runs from `$tmp/tree` (`cd "$tmp/tree"`), so the normalizer, the classifier and the harness are the staged copies, never the working tree's. Then `git -C "$ROOT" show HEAD:api/openapi.yaml >"$tmp/old.yaml" 2>/dev/null || : >"$tmp/old.yaml"` (no HEAD, or the spec newly added: an empty file, which `changed-paths` reads as `{}` by ruling 21, so every staged path is changed; no special case in the hook) and `cp "$tmp/tree/api/openapi.yaml" "$tmp/new.yaml"`.
5. `go run ./tools/catscheck changed-paths "$tmp/old.yaml" "$tmp/new.yaml" >"$tmp/paths.txt"`; exit 0 → print `cats-precommit: documentation-only change to api/openapi.yaml; skipping CATS` (or, when the tool's stderr says `no path is affected`, `cats-precommit: no path is affected by the api/openapi.yaml change; skipping CATS`) and `exit 0 # documentation-only` (that literal line, once in the file: the block 40 anchor); exit 10 → continue with the paths in `$tmp/paths.txt` (at least one line is guaranteed); anything else → print the tool's stderr and exit 1.
6. Generated-code freshness (ruling 15): `cp -R "$tmp/tree/internal/gen" "$tmp/gen-staged"`; `make generate >/dev/null` (in `$tmp/tree`); `diff -rq "$tmp/gen-staged" "$tmp/tree/internal/gen"`; a difference prints `cats-precommit: internal/gen is stale for the staged api/openapi.yaml; run make generate and stage internal/gen` and exits 1 (the comparison is against the staged copy, never HEAD or the working tree).
7. Partition the paths (ruling 24; the harness's `SKIP_PATHS` is the one list, read with `bash scripts/cats-harness.sh skip-paths`, an eighth subcommand that prints it one per line): bridges paths (`/v1/admin/bridges`, `/v1/admin/bridges/{channel}`) are dropped with `cats-precommit: not fuzzing <path> (no Slack bridge in the campaign server; ADR 0018)`; each of the other three skipped paths that is in the list gets its own run `bash scripts/cats-harness.sh run --dir "$tmp/harness" --repo "$tmp/tree" --out "$tmp/out-<n>" --paths "<path>" --no-skip`; the remaining paths run together: `cats-precommit: fuzzing <N> changed path(s): <list>`, `bash scripts/cats-harness.sh run --dir "$tmp/harness" --repo "$tmp/tree" --out "$tmp/out" --paths "<comma list>"`. A non-zero harness exit prints its message and exits 1. If nothing is left to fuzz after the drops, print `cats-precommit: only bridges paths changed; nothing to fuzz` and exit 0.
8. For every report directory produced: `go run ./tools/catscheck classify --rules api/cats-false-positives.yaml "<out>/report"` (the rules file is the staged copy, since the cwd is `$tmp/tree`); all exit 0 → `cats-precommit: no finding; <summary line(s)>` and exit 0; any exit 1 → the findings (already printed), then `cats-precommit: <K> finding(s) not covered by api/cats-false-positives.yaml; fix them or record false positives with /cats:fp (git commit --no-verify bypasses this hook)` and `exit 1 # findings` (that literal line, once in the file: the block 40 anchor); exit 2 → the error and exit 1.

Definition of Done D for the hook: it owns a fresh `--dir` under `mktemp -d`, so it never collides with a campaign in progress and a second commit after a failed hook starts clean; the trap tears its server down on every exit path.

**`scripts/cats-precommit-selftest.sh`** creates a throwaway worktree of HEAD (`git worktree add --detach "$tmp/wt" HEAD`, removed by the trap with `git worktree remove --force`), then **copies the files under test from its own `$ROOT` into the worktree** (ruling 27): `scripts/cats-precommit.sh`, `scripts/cats-harness.sh`, `.githooks/pre-commit`, `scripts/testdata/cats-fake/` and `tools/catscheck/` (`cp -R`, overwriting), so the selftest exercises the working copy (uncommitted in Task 6 Step 1, mutated in block 40) and not whatever HEAD holds; it commits nothing. It sets `CATS_BIN` to the worktree's fake and `CATS_FAKE_LOG`, and runs `bash "$tmp/wt/scripts/cats-precommit.sh"` with the worktree as cwd after staging an edit (every case restores with `git -C "$tmp/wt" checkout -- . && git -C "$tmp/wt" reset -q`, then re-copies the files under test). It prints `cats-precommit-selftest: ok|FAIL <case>` lines and exits 1 on any failure. Cases (pinned):
1. `no-spec-change`: stage an edit to `README.md`: exit 0, no output, the fake not invoked.
2. `doc-only-skips`: stage a `description:` edit of `listChannels`: exit 0, output contains `documentation-only`, the fake not invoked (`CATS_FAKE_LOG` absent). This is the block 40 mutation target.
3. `change-runs-widened-paths`: stage the **type-neutral** edit `maxLength: 256` added under `Task.properties.subject` (ruling 26; it changes no Go type, so the exported tree still builds; `Task.required` gaining `description` would turn `gen.Task.Description` from `*string` into `string` and break `internal/server/tasks.go` and `internal/bus/remote/convert.go`) **and** the regenerated `internal/gen` (`make generate` in the worktree, `git add internal/gen`; the embedded spec changes, so there is something to stage): the output contains `fuzzing 4 changed path(s)` and the fake's argv has `--paths=/v1/channels/{channel}/tasks,/v1/tasks/{id},/v1/tasks/{id}/claim,/v1/tasks/{id}/release` (the closure verified in Task 2 Step 1); exit 1 (the fake's report carries an unrecorded error) and the output contains `finding(s) not covered`.
4. `recorded-fp-passes`: same staging plus a rule appended to the worktree's `api/cats-false-positives.yaml`, `- id: FAKE_CATS_SELFTEST` / `why: the fake cats's records; selftest only` / `when: {fuzzer: FakeCatsFuzzer, response_code: {in: [400, 404]}}` (ruling 30: no committed rule may carry this name; the selftest asserts the committed file does not match the fake's records before this case), staged: exit 0 and `no finding`.
5. `stale-gen-blocks`: the `maxLength` edit staged without regenerating: exit 1 and `internal/gen is stale`.
6. `missing-cats-fails-closed`: `CATS_BIN=/nonexistent` with the Task case 3 staging: exit 1 and `is not installed`.
7. `shellcheck`: clean over `.githooks/pre-commit`, `scripts/cats-precommit.sh`, `scripts/cats-precommit-selftest.sh`.

- [ ] **Step 1: Write the hook, the shim and the selftest; run**

Run: `bash scripts/cats-precommit-selftest.sh` → seven `ok` lines (the selftest copies the uncommitted scripts into its worktree, so it passes before this task's commit). `make cats-selftest` → both selftests ok. `make release-lint` → clean.

- [ ] **Step 2: Enable and try it once for real in this repository**

Run `bash scripts/cats-precommit.sh` directly (not through git) with a `description:` edit of the spec staged → `documentation-only`; `git reset -q && git checkout -- api/openapi.yaml`. Then with `Task.required` edited and `make generate` staged → it fuzzes the four task paths with the real `cats` (about 2 min) and reports; restore. Record both outputs in the commit message. **Do not set `core.hooksPath` yet:** the Task 8.N spec fixes would each trigger a campaign at commit time and a fix for one cluster could be blocked by another cluster on the same path before its rule is recorded; Task 11 enables the hook once the campaign is clean.

- [ ] **Step 3: Commit**

```bash
git add .githooks/pre-commit scripts/cats-precommit.sh scripts/cats-precommit-selftest.sh Makefile
git commit -m "hooks: pre-commit fuzzes the paths a non-documentation spec change touches (issue #30, decision 3)"
```

---

### Task 7 (controller phase): `cats:init`, the first full campaign, triage

**Run by the main session, not an implementer.** Nothing here is committed except what the sub-steps say. The findings cannot be known in advance; this task defines how they become Tasks 8.1 to 8.N (fixes) and rules in `api/cats-false-positives.yaml` (false positives), and what the campaign must show before Task 9 starts.

- [ ] **Step 1: Start the plugin-flow server and bootstrap the plugin**

`bash scripts/cats-harness.sh up --port 8430` (ruling 9). Then invoke `cats:init` with `--spec api/openapi.yaml --server http://127.0.0.1:8430 --health-url http://127.0.0.1:8430/v1/discover --results-dir .local/cats/results --rules api/cats-false-positives.yaml`; it finds the committed rules file and leaves it. Edit `.local/cats/config.yaml` to exactly this (the skill's walk-through asks about `token_cmd`, `seed`, `pre_run`; these are the answers):

```yaml
version: 1
spec: api/openapi.yaml
server: http://127.0.0.1:8430
health_url: http://127.0.0.1:8430/v1/discover
results_dir: .local/cats/results
false_positives: api/cats-false-positives.yaml
# true: Step 3's raw-report secret scan and Step 6's catscheck cross-check read report-<run>/;
# keep_runs still bounds the disk.
retain_raw_report: true
allow_suppressing_5xx: false
allow_port_forward: false
max_connection_error_pct: 1.0
max_unauthenticated_pct: 5.0
keep_runs: 5
identities:
  admin:
    token_cmd: "bash scripts/cats-harness.sh token admin"
  agent:
    token_cmd: "bash scripts/cats-harness.sh token agent"
default_identity: admin
auth:
  header: Authorization
  template: "Bearer {token}"
hooks:
  # The server is started before /cats:run by `bash scripts/cats-harness.sh up --port 8430`
  # (the plugin probes health_url in preflight, before any hook runs; ruling 9).
  pre_run: ""
  seed: "bash scripts/cats-harness.sh seed --out .local/cats/results"
  post_run: ""
cats:
  http_methods: [POST, PUT, GET, DELETE, PATCH]
  max_requests_per_minute: 10000
  ref_data: .local/cats/results/refdata.yml
  fixtures: .local/cats/results/fixtures.json
  skip_field_format: []
  skip_field: []
  skip_fuzzers: []
  skip_fuzzers_for_extension: []
  skip_paths: [/v1/admin/reset, /v1/admin/signing-keys/rotate, "/v1/admin/identities/{identity}/reset-credential", /v1/admin/bridges, "/v1/admin/bridges/{channel}"]
  headers: {}
  extra_args: ["--printExecutionStatistics", "--no-checkUpdate", "--noEnvFile"]
```

`doctor` must show four checks passing. The seed hook receives `CATS_IDENTITY` from the plugin, so the sessions belong to the run's identity (Task 4).

- [ ] **Step 2: The administrator pass, then the agent pass**

`cats:run` (default identity `admin`, every path minus the skips; about 10 min). Then `cats:run --identity agent --path <every path from cats list -p that does not start with /v1/admin/ and is not skipped, comma-separated>`. Each run must be valid (not exit 3); a `RUN INVALID` is diagnosed with the skill's cliff queries before anything else (a dead fixture names the anchor to decoy; the seed's decoys are Task 4's and a fix there is a small follow-up commit `fix(cats): ...`).

- [ ] **Step 2b: The three skipped operations, each alone on a fresh server** (ruling 13; every operation is fuzzed): for each of `/v1/admin/reset`, `/v1/admin/signing-keys/rotate` and `/v1/admin/identities/{identity}/reset-credential` run `bash scripts/cats-harness.sh run --paths '<that path>' --no-skip` (the standalone flow: `run` tears the previous server down and starts a fresh one; without `--no-skip` the path would be subtracted as skipped and the run would print `nothing to fuzz`, ruling 24; the administrator bearer applies on `/v1/admin/` paths) followed by `go run ./tools/catscheck classify --rules api/cats-false-positives.yaml <report>`. The plugin flow is not used here on purpose: `reset` with `scope=everything` and `rotate` with `revoke_previous=true` revoke the campaign's own credential partway, which trips the plugin's credential gate; alone, the 401s after that point are the expected tail of the run and the controller reads the findings before the cliff. Triage these three reports with `cats:analyze` over a database made by `cats_tool.py parse --report <report>` through the `cats:report` skill, like the two passes. The reports are kept under `.local/cats/results/` for Step 3's raw scan.

- [ ] **Step 3: Acceptance queries on each run's database** (through `cats:report`, `--db latest` after the admin pass and `--db <the agent run's file>` after the agent pass; both must end empty or explained)

```sql
-- Q1: 5xx other than the documented 503 and the net/http 501 (Open item 1)
SELECT path, http_method, response_code, fuzzer, COUNT(*) AS n FROM test_results_view
WHERE response_code >= 500 AND response_code <> 503
  AND NOT (response_code = 501 AND fuzzer = 'DummyTransferEncodingHeaders')
GROUP BY 1, 2, 3, 4 ORDER BY n DESC;
-- Q1b: every 503 is on a bridges path or `store unreachable` (none expected: bridges are skipped)
SELECT path, http_method, COUNT(*) FROM test_results_view WHERE response_code = 503 GROUP BY 1, 2;
-- Q2: an error answer that is not problem+json, or lacks code or retryable (bodies are stored for error and warn)
SELECT v.path, v.http_method, v.response_code, r.response_content_type, COUNT(*) AS n
FROM test_results_view v JOIN tests t ON t.test_id = v.test_id JOIN responses r ON r.test_id = t.id
WHERE v.response_code >= 400 AND v.response_code NOT IN (431, 501, 953, 999)
  AND v.path NOT LIKE '/v1/auth/token%'
  AND (r.response_content_type NOT LIKE 'application/problem+json%'
       OR (r.response_body IS NOT NULL AND (json_extract(r.response_body, '$.code') IS NULL OR json_extract(r.response_body, '$.retryable') IS NULL)))
GROUP BY 1, 2, 3, 4 ORDER BY n DESC;
-- Q3: nothing contradicts the documented responses: the true positives must be empty once rules and fixes are in
SELECT path, http_method, response_code, fuzzer, result_reason, COUNT(*) AS n FROM true_positives_view
GROUP BY 1, 2, 3, 4, 5 ORDER BY response_code DESC, n DESC;
-- Q4: no token, key or stack trace in a stored body
SELECT v.test_id, v.path, v.response_code FROM test_results_view v JOIN tests t ON t.test_id = v.test_id JOIN responses r ON r.test_id = t.id
WHERE r.response_body LIKE '%eyJ%' OR r.response_body LIKE '%abe_%' OR r.response_body LIKE '%goroutine %' OR r.response_body LIKE '%.go:%' OR r.response_body LIKE '%BEGIN PRIVATE KEY%';
```

Q4 covers error and warn bodies only (the database stores no `success` body), so the raw report is also scanned before `retain_raw_report: false` deletes it: `cats:run` with `retain_raw_report: true` for the first campaign, then `for f in .local/cats/results/report-<run>/Test*.json; do jq -r 'select((.response.jsonBody // "") | tostring | test("eyJ[A-Za-z0-9_-]{20,}|abe_[A-Za-z0-9_-]{20,}|goroutine [0-9]+|\\.go:[0-9]+")) | .testId' "$f"; done` must print nothing.

- [ ] **Step 4: Triage with `cats:analyze`** (per run). Every cluster `(path, fuzzer, response_code)` gets exactly one disposition with its evidence, in the skill's order: every 5xx first (real bug, no exception but Open item 1), then real bugs, spec gaps, false-positive candidates. Open items 2 and 4 are presented to Eric with their counts at this point, one question at a time, each with the default; execution continues on the default if he has not answered.

- [ ] **Step 5: Append fix tasks.** For every real bug and spec gap root cause, append a task to this plan under "Tasks 8.N (appended by the controller)" using the template below, in severity order, and dispatch it to an implementer as usual (implementer, task review, then the next). One root cause per task; a cluster that spans operations through one handler or one shared component is one task.

- [ ] **Step 6: Record false positives with `cats:fp add`,** one at a time, always through the skill's dry-run (`classify --db latest --dry-run --rules <scratch>`), never by editing the file first; each rule has an `UPPER_SNAKE_CASE` id, a `why` that cites the spec line, the ADR, the router test or the fuzzer's definition, and an explicit `response_code` (ruling 6); after each round, `go test ./tools/catscheck/ -run TestCommittedRules` and `go run ./tools/catscheck classify --rules api/cats-false-positives.yaml .local/cats/results/report-<run>` (with `retain_raw_report: true`) must agree with the plugin's `true_positives_view` count for that run (the cross-check of ruling 4; a disagreement is a bug in `tools/catscheck` and a fix task). Commit per round: `git add api/cats-false-positives.yaml && git commit -m "test(cats): record <N> false positives from the <admin|agent> pass (issue #30)"` listing the ids in the body.

- [ ] **Step 7: Loop.** After the fix tasks of a round land: `bash scripts/cats-harness.sh down && bash scripts/cats-harness.sh up --port 8430`, both `cats:run`s again, Steps 3 to 6 again, until Q1, Q2 and Q4 are empty, Q3 is empty, and both runs are valid. Then `bash scripts/cats-harness.sh down`. Record the final run ids, totals and the number of rules in the handoff for Task 9.

- [ ] **Step 8: Two more checks for the record:** `bash scripts/cats-harness.sh run` (the standalone flow, both identities in one pass) exits 0 and `go run ./tools/catscheck classify --rules api/cats-false-positives.yaml <report>` exits 0; `make cats-selftest` is still green (the fake's records carry the fuzzer name `FakeCatsFuzzer`, ruling 30, so no rule recorded in Step 6 can match them and the pre-commit selftest's case 3 keeps its meaning; `TestCommittedRules` also fails any committed rule whose `fuzzer` condition names `FakeCatsFuzzer`).

**Fix task template (Task 8.N):**

```
### Task 8.N: <root cause in one line> (<path(s)>, <fuzzer(s)>, <code>)

**Disposition:** real bug | spec gap. **Evidence:** <the cats:analyze line: spec quote or response excerpt>.
**Files:** Modify: <handler or core file>; <api/openapi.yaml and `make generate` when the spec changes>; Create/Modify: <test file>.

- [ ] Step 1: Reproduce: write `Test<Name>` in <package> sending the CATS request shape (method, path, headers, body from the example test's `request`), asserting the documented answer; run it; it fails with <the current answer>. Quote the failing line in the commit message.
- [ ] Step 2: Fix. Touchpoints to check and tick in the report: `api/openapi.yaml` + `make generate` (protocol stays 1.0.0); `TestStatusTable` / `TestOperationErrorTable` (a new status or code); `TestWireRoundTrip` and the converters (a new member, issue #29); `TestToolCoverage` (a new Bus member); `TestSpecBounds` (a new request field); `TestSpecDescriptions` / `TestSpecExamples` (a new response needs a description and an example); `api/arazzo.yaml` (a changed success body); `TestAccessRuleSites` (no new flag read outside access).
- [ ] Step 3: Search for the pattern elsewhere (`rg`); fix or list the other instances in the report (Definition of Done B).
- [ ] Step 4: `go test ./internal/server/ ./internal/gen/ ./internal/e2e/ ./tools/catscheck/` green; `bash scripts/cats-harness.sh run --paths '<paths>'` and `go run ./tools/catscheck classify --rules api/cats-false-positives.yaml <report>` show the cluster gone.
- [ ] Step 5: Commit: `fix(<scope>): <subject> (issue #30, CATS <fuzzer>)`, or `fix(spec): ...` for a spec gap.
```

---

### Tasks 8.N (appended by the controller during Task 7)

TRIAGE=`.superpowers/sdd/2026-11-08-issue-30-cats-campaign/task-7-triage.md` (git-ignored; the first campaign of 2026-11-08: admin 20261108T141137Z, agent 20261108T141502Z, three Step 2b runs; every run valid; catscheck agrees with the plugin on all six).

Controller rulings on the triage (2026-11-08; Eric may overrule):
- Ruling 32: RB1, RB2 and RB3 are real bugs and are fixed (RB3 is Open item 4's real-bug candidate; the `[forbidden]` and `[notice]` keyword clusters are false-positive rules after reading the bodies).
- Ruling 33: SG1 to SG5 are spec gaps fixed in the spec; SG5 marks `q` `required: true` (the spec follows the server, no behavior change).
- Ruling 34: FP16 (missing security response headers) is recorded as a false-positive rule, and a small header middleware is Open item 7 for Eric; adding headers is outside the issue's acceptance criteria.
- Ruling 35: CATS pseudo-code 954 (read timeout) is treated like 953 and 999: excluded from Q1, allowed in rules (it is above 599, so ruling 6 permits it).
- Ruling 36: the Step 3 and Step 2 text is corrected as the triage's section 6 found: the raw scan reads `.response.jsonBody`; Q4 escapes `_` (`LIKE '%abe\_%' ESCAPE '\'`) and treats `enrollment_token` in the documented `createAgentIdentity` 200 body as expected; Q2 excludes HEAD answers and net/http's own `text/plain` 400s; the agent pass covers every path of `cats list -p -c api/openapi.yaml` not under `/v1/admin/` (30 paths, the three `/.well-known/*` included).

Open item 7 (Eric): a response-header middleware (`X-Content-Type-Options: nosniff`, `Cache-Control: no-store`) instead of rule FP16. Default: the rule.

### Task 8.1: harness fixes from the first campaign (`scripts/cats-harness.sh`, its selftest)

**Disposition:** harness defect. **Evidence:** TRIAGE section 6, items a, e, f, g.
- a: the seed writes `verify_url` as a path (`/v1/...`), as the plugin joins it onto `server` (`catslib/runner.py:144`); the harness's own post-run fixture check prefixes the server URL. `.local/cats/seed-wrap.sh` then becomes unnecessary (the controller removes it from `.local/cats/config.yaml`).
- e: `acl_both` on all six seeded channels, so the administrator pass reaches messages and subscription; the agent pass's loss of `admin` on `cats-acl` after its own `PUT .../acl` is a recorded rule (Task 7 Step 6), not a harness change.
- f: `seed` re-creates any decoy that is gone (a deleted memory gets a new id, a removed channel is re-created) and writes the live ids into the refData and `fixtures.json`; a second `seed` with every decoy alive keeps the same ids.
- g: `SERVER_SETS` adds `signing_key_rotation_cooldown_seconds=1`; the seed registers a throwaway identity `cats-victim` (key in the harness directory) and the refData maps `/v1/admin/identities/{identity}/reset-credential` `identity` to it.
- Selftest cases for a (path form), f (a deleted decoy is re-created, an alive one keeps its id) and g (the setting and the refData entry); the recorded expectations follow.
- Gates: both selftests twice, shellcheck, `make release-lint`, `make lint`. Commit `fix(cats): harness follows the first campaign (issue #30)`.

### Task 8.2: server error answers (RB2, RB3, RB1; `internal/server/server.go`)

**Disposition:** real bugs. **Evidence:** TRIAGE section 3 items 1 to 3 (repro shapes there). One commit per root cause, in this order, each with a reproducing test that failed before the fix (Definition of Done A and B):
- RB2: the validation `detail` names the JSON pointer and the reason only; never the schema, never the submitted value. Test: no `detail` of a refused request contains `Schema:`, `Value:` or the submitted value (table over a body field, a query parameter and a path parameter). Search for the other places that format a kin error.
- RB3: a missing or invalid bearer on a protected operation answers 401 with a fixed detail (`a bearer token is required`); `authErrorFrom` errors keep their text.
- RB1: a JSON request body must be exactly one JSON value (trailing data, a second value: 400 `validation`); the token endpoint keeps its RFC 6749 body. Test over the triage's two shapes.
- Touchpoints: `TestStatusTable`, the respcheck-wired tests, the e2e. Gates: `go test ./internal/server/... ./internal/e2e/`, `make lint`, `make verify`.

### Task 8.3: spec gaps SG1 to SG5 (`api/openapi.yaml`, `make generate`)

**Disposition:** spec gaps. **Evidence:** TRIAGE section 3 items 4 to 8. One commit per gap: SG1 quote `"off"` (and add a `TestOperationShape`-style guard that no enum member is a YAML 1.1 boolean word); SG2 `enum` on `SetAgentStatusRequest.tag` (the seven settable tags; `TestSpecBounds` row; the core list is the source); SG3 `minProperties: 1` on `EditMemoryRequest`; SG4 a real Ed25519 `JWK` example whose `kid` is its RFC 7638 thumbprint, the rule stated in the description, and a test that the example registers (the e2e replay already replays `register`; check it); SG5 `q` `required: true` on `search`. Each passes `TestSpecDescriptions`, `TestSpecExamples`, `TestWireRoundTrip`, `TestToolCoverage` and `TestRequestExamples`; the protocol stays 1.0.0. Gates: `make generate-check`, `make spec-lint`, `make lint`, `make verify`.

---

### Task 9: Docs, CLAUDE.md, ADR 0018

**Files:**
- Create: `docs/cats.md`
- Create: `docs/adr/0018-api-fuzzing-with-cats.md`
- Modify: `docs/adr/README.md` (row `| [0018](0018-api-fuzzing-with-cats.md) | API fuzzing with CATS | Accepted (Eric, 2026-11-06; decisions 1 to 3) |`)
- Modify: `docs/adr/0001-transport-and-api.md` (one sentence at the end of "Error responses declared per operation (issue #33)": the answers are fuzzed by CATS, ADR 0018, which records the transport-layer exception)
- Modify: `CLAUDE.md` (Commands: one bullet for `scripts/cats-harness.sh` (the subcommands, the exit codes, `make cats-run`, `make cats-selftest`), the hook (`git config core.hooksPath .githooks`; what it does; `--no-verify`), `tools/catscheck` (the three subcommands and exit codes); Design: one bullet "CATS fuzzing (issue #30, ADR 0018, Eric 2026-11-06): native SQLite target, no CI job, the pre-commit hook; the rules file `api/cats-false-positives.yaml`; the plugin's config in `.local/cats/`; the controller runs the `cats:*` skills; repository code calls `cats` directly")
- Modify: `README.md` only if it already lists the `docs/` pages (check with `rg -n 'docs/tui.md' README.md`): add `docs/cats.md` to that list; otherwise ADR 0018 is the one link to the page. `docs/ops/README.md` is untouched (it is the operator's index; the campaign is a developer's tool).

**`docs/cats.md` sections (every number checked against the final run's output, Definition of Done E):** What is fuzzed and why (the validator, the 57 operations, what CATS tests behind it); Prerequisites (`brew install endava/tap/cats`, Java, `jq`); The one command (`bash scripts/cats-harness.sh run`, what it prints, where the report is, the exit codes, `--paths`, `--dir`); The triaged campaign with the plugin (`up --port 8430`, `cats:init` with the config above, the two `cats:run`s, `cats:analyze`, `cats:fp`, `cats:report`, `down`; the validity gates); Reading the results (the four acceptance queries, `true_positives_view`, the rules file and how to add a rule); The pre-commit hook (enable, what it checks, the doc-only fast path, the staged-tree rule, the cost, `--no-verify`); The exceptions (the net/http 501 and 431; the skipped paths and why; bridges); The selftests (`make cats-selftest`, `--real`); What a campaign leaves behind (nothing outside `.local/cats/` and the harness directory, which `down` removes).

**ADR 0018 (sections: Context, Decision (Eric's three decisions, labeled, with the date), Plan rulings (1 to 31 of this plan, one line each, labeled not Eric's), Execution rulings (what Task 7 decided: Open items 1 to 6 with Eric's answer or the default taken, labeled accordingly), Consequences, Alternatives considered (Docker target; a CI job; a post-commit or pre-push hook; a Python normalizer; CATS's own `--ignoreResponseCodes` instead of the plugin's rules file)).**

- [ ] **Step 1: Write; check every command in `docs/cats.md` by running it** (the `run` and `status` lines, the queries against the final database, the hook's two messages).

- [ ] **Step 2: Commit**

```bash
git add docs/cats.md docs/adr/0018-api-fuzzing-with-cats.md docs/adr/README.md docs/adr/0001-transport-and-api.md CLAUDE.md
git commit -m "docs: the CATS campaign page, ADR 0018 and the CLAUDE.md lines (issue #30)"
```

---

### Task 10: Selftest block 40

**Files:**
- Modify: `scripts/check-gates-selftest.sh` (`block_cats_gates_fire` after `block_spec_examples_fire` in the definitions and the call list; the header comment names issue #30, `tools/catscheck`, the hook and the fake)

Mutations (7; anchors are written against the files as Tasks 1 to 6 leave them and must occur exactly once in their file; `mutate_unit_block` for the Go ones; the two hook ones use `mutate_file` plus a run of `scripts/cats-precommit-selftest.sh` in the worktree with the fake, grepping for the `FAIL <case>` line):
1. `catscheck-summary-not-stripped`: `tools/catscheck/normalize.go`, the stripped-key literal `"summary",` removed → `./tools/catscheck/ '^TestChangedPaths$' TestChangedPaths/documentation_only`.
2. `catscheck-property-named-description-stripped`: `normalize.go`, the line holding `"properties":` (the name-map entry) removed → `'^TestNormalize$' TestNormalize/property_named_description_kept`.
3. `catscheck-ref-widening-off`: `paths.go`, `var widen = true` → `var widen = false` (the Task 2 anchor; the file compiles) → `'^TestChangedPaths$' TestChangedPaths/schema_change_widens`.
4. `catscheck-5xx-rule-accepted`: `rules.go`, `if code >= 500 && code < 600 {` → `if false {` → `'^TestClassify$' TestClassify/rule_never_suppresses_5xx`.
5. `catscheck-unknown-operator-accepted`: `rules.go`, the operator check (pin in Task 3: `if _, ok := operators[op]; !ok {` → `if false {`) → `'^TestLoadRules$' TestLoadRules/unknown_operator_rejected`.
6. `precommit-doc-only-fast-path-gone`: `scripts/cats-precommit.sh`, `exit 0 # documentation-only` (the Task 6 anchor) → `: # documentation-only` (`mutate_file`), then `bash "$wt/scripts/cats-precommit-selftest.sh"` run from `$wt` → its log contains `cats-precommit-selftest: FAIL doc-only-skips` (the selftest copies `$wt`'s mutated script into its own nested worktree, ruling 27, so the mutation is what runs).
7. `precommit-findings-not-blocking`: `scripts/cats-precommit.sh`, `exit 1 # findings` (the Task 6 anchor) → `exit 0 # findings`, same run → the log contains `cats-precommit-selftest: FAIL change-runs-widened-paths`.

Before the mutations, the block runs both selftests once unmutated as the baseline (ruling 28): `bash "$wt/scripts/cats-harness-selftest.sh"` and `bash "$wt/scripts/cats-precommit-selftest.sh"` must exit 0 with no `FAIL` line (labels `cats-harness-selftest-baseline`, `cats-precommit-selftest-baseline`), so the fake, the harness and the hook are exercised in CI even when no mutation fires. The block needs no Java: the selftests set `CATS_BIN` to the fake themselves. The baseline and mutations 6 and 7 each build the server in a worktree (about 1 min each).

- [ ] **Step 1: Add the block; run the selftest**

The script has no single-block switch. Run: `make check-gates-selftest 2>&1 | tee /tmp/selftest-30-dev.log | rg 'selftest: (ok|problem)' | tail -10` → seven `selftest: ok <label>` lines for block 40 and no `problem`; `shellcheck scripts/check-gates-selftest.sh` clean.

- [ ] **Step 2: Commit**

```bash
git add scripts/check-gates-selftest.sh
git commit -m "test(gates): selftest block 40, the catscheck and pre-commit gates fire (issue #30)"
```

---

### Task 11: Done gate

- [ ] **Step 1:** `make verify` (Docker up; the Postgres suites run) → every step passes; paste the final lines.
- [ ] **Step 2:** `make check-gates-selftest` → `check-gates-selftest: OK` (block 40 included).
- [ ] **Step 3:** `make release-lint` → clean (the new scripts, the shim and the fake are in the glob).
- [ ] **Step 4:** `make cats-selftest` → both selftests ok; `bash scripts/cats-harness-selftest.sh --real` ok (local only).
- [ ] **Step 5:** `git status --porcelain` shows only `replay.env.example` (untracked, not this plan's) and nothing under `.local/` is tracked (`git ls-files .local` empty); `ls cats-report 2>/dev/null` finds nothing in the repository root.
- [ ] **Step 5b:** Enable the hook on this machine now that the campaign is clean: `git config core.hooksPath .githooks` (local config, not a tracked file; Task 6 Step 2 deferred it), then confirm `git config --get core.hooksPath` prints `.githooks`.
- [ ] **Step 6:** Report completion with the four outputs, the final campaign numbers (run ids, totals, rules count, fix tasks landed) and stop; Eric decides on push.

## What Eric should see

- `bash scripts/cats-harness.sh run` prints `dir=`, `server=`, a `tests=... errors=...` line and `report=...`, and leaves nothing behind but the report under `.local/cats/results/`.
- `git config core.hooksPath .githooks`, then a documentation edit of `api/openapi.yaml` commits at once with `documentation-only`; a `required:` edit regenerates, fuzzes the widened paths and either commits with `no finding` or lists what blocked it.
- `/cats:report` on the final database answers the four acceptance queries empty, and `api/cats-false-positives.yaml` explains every suppressed cluster in its `why`.
- The Open items answered or defaulted, labeled as such, in ADR 0018.

Round 2 (2026-11-08, `.superpowers/sdd/2026-11-08-issue-30-cats-campaign/task-7-round2.md`): 40 rules recorded (9c4c45a, 04b56a7, 642682a, 9cf4581); Q1, Q1b, Q2 empty; Q3 holds SG6 and SG7 only. Controller rulings:
- Ruling 37: SG6 is a spec gap: `JWK` gets `required: [kty]` (RFC 7517 section 4.1; the server already refuses a key without it).
- Ruling 38: SG7 (`TaskPatch` with `delete` plus another member answers 400) is a recorded false-positive rule citing the `TaskPatch` description; a `oneOf` would turn the generated Go type into a union for one prose rule — cost if wrong: Eric prefers the schema form (Open item 9).
- Ruling 39: the harness's report leak scan looks for the campaign's own bearers and credentials (the exact minted values, matched with `grep -F -f` from a 0600 file inside the harness directory, never printed), not for token-shaped patterns: the spec's example tokens and the documented `enrollment_token` in `createAgentIdentity` answers are expected content.

Open item 9 (Eric): SG7 as a `oneOf` in `TaskPatch` instead of rule. Default: the rule.

### Task 8.4: harness follow-ups from round 2 (`scripts/cats-harness.sh`, its selftest)

**Disposition:** harness defect. **Evidence:** round-2 report section 6 and Step 8.
- Ruling 39's leak scan (the selftest's leak cases plant the real minted bearer's value, and a planted spec-example JWT must not fire).
- `seed` re-applies `acl_both` to `cats-acl` on every run (an earlier pass may have emptied it), and the refData for `PUT /v1/channels/{channel}/acl` sends both entries (`acl[*]`), so the agent's PUT can succeed.
- The refData for `POST /v1/channels/{channel}/tasks` removes `parent` (`cats_remove_field`) so its HappyPath can succeed.
- Implementation findings (real cats 15.4.0): CATS cannot send two different entries in the root-array body of the ACL PUT (a refData key such as `identity` sets every entry alike; `acl[*]` applies only to a named field such as `POST /v1/channels`' `acl`), and an agent may not take a permission from `cats-admin`'s entry, so `cats-acl` is seeded with the agent's entry alone and the refData is `identity: cats-agent`, `permissions[*]: admin` (the happy path answers 204 and the agent keeps admin). The other seeded channels get `acl_both` re-applied on every seed. createTask's refData removes `parent`, `blocked_by`, `before` and `after` (random ids and the mutually exclusive pair both answer 400). The leak scan is `grep -F -f` over `$DIR/leak.secrets`.
- Gates: both selftests twice, shellcheck, `make release-lint`, `make lint`. Commit `fix(cats): harness follows round 2 (issue #30)`.

### Task 8.5: SG6 (`api/openapi.yaml` `JWK.required: [kty]`, `make generate`)

One commit `fix(spec): JWK requires kty (issue #30, CATS OnlyRequiredFields)` with a reproducing test (a register request whose JWK lacks `kty` is refused by the validator), the issue #29/#34/#35 checks green, protocol 1.0.0.

### Task 8.6: enforce the no-500 rule in the test layers (Eric 2026-11-08: "A: enforce in #30")

**Decision (Eric):** the no-500 rule (ADR 0001 addendum, CLAUDE.md): a 500 seen in any test is a must-fix bug. **Files:** `internal/respcheck` (the in-process and inproc Bus response check), the e2e validating proxy (`internal/e2e`), `scripts/check-gates-selftest.sh` block 40 (a mutation).
- respcheck and the e2e proxy record every 500 answer and fail the test (the same `Late()`/`TestMain` path respcheck already uses), naming the method, path and problem detail. A test that deliberately provokes a 500 (if any exists today) must say so through one explicit, listed exception with a reason; a stale exception fails.
- The CATS acceptance Q1 already fails any 5xx but 503 and the transport 501; `TestCommittedRules` already refuses any 5xx rule; keep both, and cite the rule in their messages.
- Any 500 this guard exposes in the existing suites is a must-fix bug: list them in the report; each becomes its own fix task (Task 8.7 and up) before the branch merges.
- Gates: `make verify`; block 40 gets a mutation that makes a handler answer 500 and expects the guard's failure text.

Final campaign (2026-11-08, `task-7-final.md`): every run valid; Q1, Q1b, Q2 empty; 44 rules; Q3 holds one cluster, SG8.
- Ruling 40: SG8 (register 400 `unsupported key type/format` once `JWK` declared only `kty`) is a spec gap Task 8.5 created: `JWK` declares the members the server accepts as properties: `kty` with `enum` of the supported key types, `crv` with `enum` of the supported curves, `x`, `y` (EC only) and `kid`, each with its bound and description, while `additionalProperties: true` and `x-go-type: map[string]interface{}` stay; the example stays the real Ed25519 key. The server's accepted set (`internal/auth/keys`) is the source; the descriptions say which members each key type needs.
- Ruling 41: the getMemory description states that the id may name a task row too (served by design, `internal/server/memories.go` Get), a documentation fix.

### Task 8.7: SG8 and the getMemory description (`api/openapi.yaml`, `make generate`)

One commit `fix(spec): JWK declares the accepted key members (issue #30, CATS HappyPath)` with a reproducing test (a register request built from the schema's own properties, as CATS builds it, e.g. `{"kty":"OKP","crv":"Ed25519","x":<example x>}` with the right kid, registers; `{"kty":"zzz"}` is refused by the validator with the enum, not by go-jose), and one `docs(spec): ...` commit for ruling 41. Then `bash scripts/cats-harness.sh run --paths /v1/auth/register` and `go run ./tools/catscheck classify --rules api/cats-false-positives.yaml <report>` exit 0 (SG8 gone), then `down`. Bounds rows, `propertyCount`, the issue #29/#34/#35 checks follow; protocol 1.0.0.

Task 8.6 (7277aa1) found four 500s in the existing suites; under the no-500 rule each is a must-fix bug:

### Task 8.8: the token endpoint answers 500 when the store is down (`internal/server/oauth.go`)

`TestTokenServerError`: `POST /v1/auth/token` with the store closed answers 500 `server_error`. A store outage is RFC 6749's `temporarily_unavailable` with 503 and `Retry-After` (the same outage answers 503 `unavailable` everywhere else, `docs/ops/health.md`). Fix the mapping, change the test to assert the 503 body, declare 503 on `token` in `api/openapi.yaml` if it is not declared (`make generate`, `TestOperationErrorTable`), and search for every other place that maps an unclassified store error to a 500. One commit `fix(server): token endpoint answers 503 temporarily_unavailable on a store outage (issue #30, no-500 rule)`.

### Task 8.9: an injected serialization failure answers 500 (inproc `Send`, `CreateTask`)

`TestInspectSendRetriedTxInspectsOnce`, `TestSendChargesOncePerCommit`, `TestTaskChargesOncePerCommit` (`internal/conformance/bus`, inproc, SQLite): the write answers 500 with detail `: could not serialize access (SQLSTATE 40001)`. Root-cause first (superpowers:systematic-debugging): why the retried transaction's serialization error reaches the handler unclassified on the inproc path but not on the local one; a serialization failure that survives the retries is a retryable `unavailable` (503, `Retry-After`) or must not surface at all if the retry is meant to absorb it. Fix at the root (the classification in `internal/core` or the store engines, not the handler), with the three tests green under respcheck and a test that pins the classification. One commit per root cause.

