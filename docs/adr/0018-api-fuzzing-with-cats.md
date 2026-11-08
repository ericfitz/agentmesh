# ADR 0018: API fuzzing with CATS

Status: Accepted (Eric, 2026-11-06; decisions 1 to 3). The no-500 enforcement is Eric's decision of 2026-11-08.

## Context

The server validates every request against the embedded `api/openapi.yaml` and every answer is a declared status (ADR 0001 addenda). Tests prove what the authors thought of. Issue #30 adds a repeatable fuzzing campaign with CATS (Endava's REST API fuzzer, version 15.4.0), so that for every operation: no 5xx other than the documented 503, every error is `application/problem+json` with `code` and `retryable` (the token endpoint's RFC 6749 body excepted), no answer contradicts the documented responses, and no secret, token or stack trace appears in any answer. The page for the developer who runs it is `docs/cats.md`.

## Decision (Eric, 2026-11-06, human-made)

1. The target is a native `agentmesh server -sqlite <tmpdir>` built from the tree, on a loopback port, seeded by a setup script; no Docker.
2. No CI job runs CATS; it runs locally only.
3. A tracked pre-commit hook in `.githooks/`, enabled with `git config core.hooksPath .githooks` and documented, compares the staged `api/openapi.yaml` with HEAD after stripping `description`, `summary`, `example`, `examples` and `externalDocs` (a normalizer with its own tests). On a non-documentation change it runs CATS on the changed paths only (`--paths`), widened to every path that references a changed schema, and blocks the commit on any finding that is not a recorded false positive. A documentation-only diff passes at once. `--no-verify` remains the bypass.

## No-500 rule and its enforcement

Eric's decisions of 2026-11-08 (human-made): the no-500 rule, recorded in the ADR 0001 addendum "No-500 rule" (a 500 seen in any test is a must-fix bug, never an accepted answer, a false-positive rule or a documented case), and enforcing it inside issue #30 (he chose option A, enforce in #30).

The enforcement below is plan work, not Eric's decisions (he may overrule it): the guard design, the exception table and the fixes.

- `internal/respcheck` fails any 500 answer, naming the method, path, operation and detail (`respcheck: no-500 rule (Eric 2026-11-08, ADR 0001): ...`). It reaches the in-process server tests, the inproc Bus suite and the e2e validating proxy. An explicit exception table (`Exceptions`, empty) needs a reason per entry, and a stale entry fails (`TestRespcheckExceptionsNotStale`).
- `tools/catscheck classify` refuses any rule that matches a 5xx answer, and `TestCommittedRules` refuses to commit one.
- The campaign's acceptance query Q1 (`docs/cats.md`) fails any 5xx other than the 503 and the transport 501.
- The guard exposed four failing tests in the existing suites, with two root causes, each fixed at its root: an unclassified closed or unreachable store handle (`TestTokenServerError`; the sqlstore now classifies it as retryable, so it answers 503, and the token endpoint answers 503 `temporarily_unavailable` with a fixed description), and a test fixture that injected a Postgres serialization error into SQLite, where nothing classifies it (three Bus suite tests; the fixture now injects the store's own retry-exhausted error, which answers 503).
- `scripts/check-gates-selftest.sh` block 40 mutates the guard and expects the failure text above.

## Plan rulings (made by the plan; Eric may overrule; not his decisions)

1. One Go program, `tools/catscheck`, holds the normalizer, the path widener and the classifier, with `go test`.
2. The normalizer strips by position, not by key name (three schemas have a property named `description`).
3. `changed-paths` widens through `$ref` closures; `openapi`, `servers`, `security` and unknown top-level keys mean every path; `info` and `tags` are documentation.
4. `classify` ports the cats plugin's rule vocabulary exactly and rejects every unknown key, field and operator with exit 2 (regexes are RE2).
5. The rules file is `api/cats-false-positives.yaml`, beside the other `api/` files.
6. Every committed rule names its response codes explicitly and none is in 500 to 599 (the transport pseudo-codes 953, 954 and 999 are allowed); `TestCommittedRules` enforces both.
7. One harness directory, `${TMPDIR:-/tmp}/agentmesh-cats-$(id -u)` (mode 0700, marker file), holds everything; `down` removes it whole.
8. `up` refuses a live pid (exit 3), cleans a dead or stale directory; `run` always downs first; `down` kills only a pid whose command line is the harness's own binary.
9. The plugin flow uses the fixed port 8430; the standalone `run` and the hook use a free port.
10. The server runs with tuned settings (limiter maxima, 86400 s tokens, 1 s `watch`, 3600 s maintenance interval).
11. The identities are `cats-admin` (keyless host-created, enrollment-claimed) and `cats-agent` (self-registered), profile `cats`, never Eric's config directory.
12. The standalone `run` fuzzes both identities in one pass (per-path headers); the plugin flow runs twice (administrator over every path, then the agent over the non-admin paths).
13. The seed creates decoys for the anchors CATS can destroy and sacrificial channels (`cats-acl`, `cats-sub`); the three self-sabotaging operations and the bridges are skipped and fuzzed alone (bridges not at all, Open item 6).
14. Harness exit codes: 0 ran, 1 a check failed, 2 usage, 3 server or seed, 4 CATS failed or wrote no summary.
15. The hook fuzzes the staged tree (an index export, `make generate` checked against the staged `internal/gen`), never the working tree.
16. A skipped destructive path is fuzzed alone on a fresh server with `--no-skip`.
17. The hook fails closed when `cats`, `jq`, `go` or `curl` is missing, naming `--no-verify`.
18. The page is `docs/cats.md`; the record is this ADR.
19. The gate is the classifier's verdict over `error` and `warn` records; a finding is one that no enabled rule matches.
20. The selftests run the real server against a fake `cats` and compare with recorded output.
21. `changed-paths` exits 10 only when a path is affected; an empty or missing input is the empty mapping.
22. Task 1's required-change fixture is inline; the shared-schema test is Task 2's.
23. Every task that produces a block 40 anchor pins the literal in its own text.
24. `run --paths` subtracts the skip list unless `--no-skip`; the hook partitions its list into the main run, one run per destructive path and the dropped bridges.
25. `session_lease_seconds=86400` joins the server settings (the 90 s lease would lapse the seeded sessions).
26. The hook selftest's staged spec edit is type-neutral (`maxLength: 256` on `Task.properties.subject`).
27. The hook selftest copies the files under test into its throwaway worktree of HEAD.
28. Block 40 runs both selftests unmutated as its baseline, and every repository script uses `grep -E`, never `rg`.
29. The hook runs `catscheck` and the harness from the exported tree.
30. The fake `cats` writes the fuzzer name `FakeCatsFuzzer`, which no committed rule may name.
31. Harness hygiene: `check_dir` before every `rm -rf`, fixed idempotency keys in the seed, `admin-paths` and `skip-paths` as the single lists, the enrollment token on `register`'s argv accepted.
32. RB1 (trailing JSON), RB2 (validation detail echoed the schema and the value) and RB3 (401 detail leaked the validator's text) are real bugs and are fixed.
33. SG1 to SG5 are spec gaps fixed in the spec (`q` becomes required, following the server).
34. Missing security response headers are a recorded false-positive rule, not a header middleware (Open item 7).
35. The CATS pseudo-code 954 (read timeout) is treated like 953 and 999.
36. The raw-report scan reads `.response.jsonBody`; Q4 escapes `_` and expects the documented `enrollment_token`; Q2 excludes HEAD answers and net/http's own `text/plain` 400s; the agent pass covers the 30 paths not under `/v1/admin/`.
37. SG6: `JWK` requires `kty` (RFC 7517 section 4.1).
38. SG7 (`TaskPatch` `delete` with another member answers 400) is a recorded false-positive rule, not a `oneOf` (Open item 9).
39. The harness's leak scan looks for the campaign's own minted secrets with `grep -F -f`, never for token-shaped patterns.
40. SG8: `JWK` declares the members the server accepts (`kty` and `crv` as enums, `x`, `y`, `kid`), keeping `additionalProperties: true`.
41. The `getMemory` description states that the id may name a task row (served by design; it already said so after issue #35).

## Execution rulings (Open items; each defaulted because no answer from Eric was recorded; Eric may overrule)

1. Open item 1, the net/http answers before any handler (501 `text/plain` on an unknown `Transfer-Encoding`, 431 on oversized headers): accepted as a documented exception beside 503. The acceptance query excludes 501 only for `DummyTransferEncodingHeaders`; no rule is needed (CATS scores both `success`).
2. Open item 2, content negotiation and methods (404 for an unknown method, 200 for an unsupported `Accept`, 400 for an unsupported `Content-Type`): false-positive rules `UNKNOWN_METHOD_404`, `ACCEPT_NOT_NEGOTIATED` and `CONTENT_TYPE_NOT_CHECKED`, each with its reason.
3. Open item 3, the agent pass: yes, two plugin runs per campaign.
4. Open item 4, error-leak keywords: a rule per keyword cluster after reading the bodies; the validator text in a 401 `detail` was a real bug (RB3) and is fixed.
5. Open item 5, the hook's cost: accepted. The hook prints the path count and the path names before fuzzing, not a test estimate (no `cats --dryRun` call).
6. Open item 6, the bridges paths (four operations): not fuzzed; the campaign server has no Slack bridge and every call is the documented 503. They are the one narrowing of "for every operation".
7. Open item 7, a response-header middleware instead of a rule: the rule `SECURITY_HEADERS_JSON_API`.
8. Open item 8, the 500 `detail` is the raw `err.Error()` (`internal/server/problem.go`): unchanged; a fixed detail with a logged cause would change the error contract.
9. Open item 9, SG7 as a `oneOf` instead of a rule: the rule `TASK_PATCH_DELETE_EXCLUSIVE_400`.

## Consequences

- Every spec change that is not documentation costs a build, `make generate` and an estimated 1 to 10 minutes of fuzzing at commit time (a plan estimate, not a measurement; more when the change widens to every path); `--no-verify` is the bypass, and the hook fails closed on a machine without `cats`.
- The rules file records every suppressed cluster with a reason and an explicit code; adding a rule is a reviewed edit.
- A change in CATS's behavior shows up in the selftests only through `--real`; the fake covers the harness and the hook, and block 40 of `scripts/check-gates-selftest.sh` mutates the gates.
- The campaign does not run in CI, so a regression is found at the next spec commit or the next manual run.
- The 501 and 431 transport answers are outside the problem+json rule; a proxy in front of the server could change that and this server has none.

## Alternatives considered

- A Docker target: heavier, and the native binary is the thing under test (Decision 1).
- A CI job: rejected by Eric (Decision 2).
- A post-commit or pre-push hook: the pre-commit hook blocks before the change lands (Decision 3).
- A Python normalizer: Go is the repository's language, and `go test`, `make lint` and `windows.yml` cover the tool for free (ruling 1).
- CATS's own `--ignoreResponseCodes` instead of the plugin's rules file: it ignores a code everywhere, while a rule names the path, fuzzer and body and carries a reason.
