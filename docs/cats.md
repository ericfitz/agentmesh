# API fuzzing with CATS

A repeatable fuzzing campaign for the HTTP API (issue #30, ADR 0018). It is a developer's tool, not an operator's: it builds a throwaway server from the tree, fuzzes it and removes it. It does not touch a running agentmesh server, your config directory or your data directory.

## What is fuzzed and why

`api/openapi.yaml` declares 57 operations, and the server validates every request and every answer against it. [CATS](https://github.com/Endava/cats) (version 15.4.0) reads the same document and sends each operation thousands of malformed, boundary and hostile requests. The campaign holds that for every operation (the two bridges paths excepted, see The exceptions):

- no 5xx other than the documented 503 (and the net/http transport 501; a 500 is a must-fix bug, ADR 0001 "No-500 rule");
- every error is `application/problem+json` with `code` and `retryable` (the token endpoint's RFC 6749 body excepted);
- no answer contradicts the documented responses;
- no token, key or stack trace in any answer.

CATS scores each test `success`, `warn` or `error`. A finding is an `error` or `warn` record that no rule in `api/cats-false-positives.yaml` explains. Every finding is a fixed bug, a fixed spec gap or a recorded false positive with its reason.

## Prerequisites

- `cats` on `PATH`: `brew install endava/tap/cats` (it needs Java). `CATS_BIN` names another executable.
- `jq`, `go` and `curl`.
- bash 4.4 or newer for the pre-commit hook (macOS ships 3.2; put Homebrew's bash first on `PATH`).

The harness checks these first and names what is missing (exit 2).

## The one command

```
bash scripts/cats-harness.sh run
```

`make cats-run` is the same. It builds the binary, starts a server on a free loopback port over a temporary SQLite file, seeds two identities (`cats-admin`, `cats-agent`) and fixtures, mints a bearer for each, runs CATS over every operation except the skipped ones, checks that the seeded fixtures are still alive and that no minted secret leaked into the server log, the CATS log or the report, stops the server and removes the harness directory. It prints two lines:

```
tests=13799 success=8790 warnings=1450 errors=3559 status=COMPLETED
report=/path/to/repository/.local/cats/results/run-20261108T180340Z/report
```

A run takes a few minutes (each plugin pass took about 2 min 20 s of CATS time in the last campaign). The standalone run fuzzes both identities in one pass: the agent bearer everywhere and the administrator bearer on `/v1/admin/*`. Judge the report with the classifier:

```
go run ./tools/catscheck classify --rules api/cats-false-positives.yaml <report>
```

It prints one line per finding and a last line of the form `catscheck: <N> tests, <E> error, <W> warn, <S> suppressed by <R> rule(s), <F> finding(s)` (the Step 8 run of the last campaign read `13799 tests, 3559 error, 1450 warn, 4998 suppressed by 33 rule(s), 11 finding(s)`); exit 0 means no finding, 1 means findings, 2 means a usage or file error.

Exit codes of the harness: 0 CATS completed (its own exit 0 or 1; findings are the classifier's business); 1 a check failed (a dead fixture, a minted secret found in the log or report); 2 usage, a missing tool or a refused directory; 3 the server did not start, a live server is already recorded (`up`), or the seed failed; 4 CATS exited with another code or wrote no `cats-summary-report.json`.

Options of `run`:

- `--paths LIST` fuzzes only the comma-separated spec paths (for example `--paths '/v1/channels,/v1/tasks/{id}'`). The skipped paths are subtracted with a `skipped: <path> (use --no-skip)` line; with nothing left it prints `nothing to fuzz` and exits 0.
- `--no-skip` includes the skipped paths. Use it only with `--paths` and one destructive path, as in The exceptions; it also skips the post-run fixture check, because such a run destroys its own fixtures.
- `--dir DIR` is the harness directory (default `${TMPDIR:-/tmp}/agentmesh-cats-<uid>`; also `CATS_HARNESS_DIR`). Two commands on one directory do not overlap: the second exits 3 while the first holds the lock. Use `--dir` for a second campaign.
- `CATS_SMOKE=1` (environment) runs `cats smoke` before the campaign (off by default; its result goes to `smoke.txt` beside the report); `CATS_IDENTITY` is the default of `seed --identity` (`admin` or `agent`, default `agent`; the plugin sets it so the seeded sessions belong to the run's identity).
- `--out DIR` is where the report goes (default `.local/cats/results/run-<UTC stamp>`); `--port N` and `--repo DIR` (the tree to build and fuzz) complete the list.

The other subcommands: `up`, `seed`, `token <admin|agent>`, `headers`, `down` and `status` (they are what the plugin flow calls), `admin-paths` and `skip-paths` (print the two hard-coded lists). `status` prints `dir=`, `server=` and `pid=` lines. A second `run` tears down what the first left; a start over a failed run's leftovers cleans them; `down` twice is a no-op.

## The triaged campaign with the plugin

Triage is the controller's job: the `cats:*` skills of the cats plugin (`cats:init`, `cats:run`, `cats:analyze`, `cats:fp`, `cats:report`) drive the same server through hooks. Repository code never calls the plugin's scripts; the harness and the hook call the `cats` CLI.

1. `bash scripts/cats-harness.sh up --port 8430` (the plugin probes `health_url` before any hook runs, so the server must already be up; 8430 avoids the spec's placeholder 8420).
2. `cats:init` with `--spec api/openapi.yaml --server http://127.0.0.1:8430 --health-url http://127.0.0.1:8430/v1/discover --results-dir .local/cats/results --rules api/cats-false-positives.yaml`, then edit `.local/cats/config.yaml` (git-ignored) so that:
   - `identities.admin.token_cmd` is `bash scripts/cats-harness.sh token admin` and `identities.agent.token_cmd` is `bash scripts/cats-harness.sh token agent`, `default_identity: admin`, `auth.template: "Bearer {token}"`;
   - `hooks.seed` is `bash scripts/cats-harness.sh seed --out .local/cats/results`, `hooks.pre_run` and `hooks.post_run` are empty;
   - `cats.ref_data` is `.local/cats/results/refdata.yml`, `cats.fixtures` is `.local/cats/results/fixtures.json`, `cats.skip_paths` lists the five skipped paths (`bash scripts/cats-harness.sh skip-paths`), `cats.extra_args` is `["--printExecutionStatistics", "--no-checkUpdate", "--noEnvFile"]`, `max_requests_per_minute: 10000`;
   - `retain_raw_report: true` (the raw scan and the classifier cross-check read the report), `allow_suppressing_5xx: false`, `max_connection_error_pct: 1.0`, `max_unauthenticated_pct: 5.0`.
   `doctor` must show its checks passing.
3. Two `cats:run`s: the administrator over every path except the skipped, then `cats:run --identity agent --path <every path of cats list -p -c api/openapi.yaml that is not under /v1/admin/>` (30 paths; the three `/.well-known/*` are included). Open item 3 of ADR 0018: the agent pass is a standing part of the campaign.
4. `cats:analyze` clusters the findings by (path, fuzzer, response code) and gives each one disposition: a real bug (every 5xx first), a spec gap or a false-positive candidate. Fix the first two, one commit per root cause, each with a test that failed before the fix. `cats:fp` records the third (below). `cats:report` answers questions from the SQLite database.
5. The skipped operations are fuzzed alone: `bash scripts/cats-harness.sh run --paths '<path>' --no-skip` on each of the three destructive paths, then classify each report.
6. `bash scripts/cats-harness.sh down`.

Validity gates (the plugin checks all three after every completed run and prints `RUN INVALID`, exit 3, naming each failed gate): transport, more than `max_connection_error_pct` of the tests failed with a connection error (the pseudo-codes 953 and 999); credential, more than `max_unauthenticated_pct` got a 401 that no rule explains (the campaign lost its bearer partway); fixture, a seeded fixture of `cats.fixtures` no longer exists at the end (the campaign deleted its own test data, so every path nested under it ran against a 404; the fixture file's `verify_url` is a path joined onto the server). Diagnose an invalid run before reading its findings. The standalone `run` makes the same fixture check itself (`fixture <key> died (HTTP <code>)`, exit 1).

Last full campaign (2026-11-08, before the JWK members of Task 8.7; `.superpowers/` records are not tracked): the administrator pass ran 13819 tests (3669 errors, 1450 warnings; 5108 explained by rules, 11 findings), the agent pass 11946 tests (11 findings), the standalone run 13799 tests (11 findings, harness exit 0) and the three destructive paths 94, 94 and 138 tests (no finding). All 11 findings were one spec gap, `POST /v1/auth/register` with a JWK that carried only `kty`; Task 8.7 fixed it (the schema declares the accepted members) and a run over `/v1/auth/register` afterwards fuzzed 917 tests with no finding. The rules file holds 46 rules.

## Reading the results

The plugin's database (`.local/cats/results/cats-results-<stamp>.db`; `--db latest`) has `test_results_view`, `true_positives_view` (the findings after the rules), `tests` and `responses`. The acceptance queries; each must return no rows (Q4 returns only the documented `enrollment_token` of `POST /v1/admin/identities`):

```sql
-- Q1: a 5xx other than the documented 503 and the net/http 501 (the pseudo-codes 953, 954, 999 are CATS's own)
SELECT path, http_method, response_code, fuzzer, COUNT(*) AS n FROM test_results_view
WHERE response_code BETWEEN 500 AND 599 AND response_code <> 503
  AND NOT (response_code = 501 AND fuzzer = 'DummyTransferEncodingHeaders')
GROUP BY 1, 2, 3, 4 ORDER BY n DESC;
-- Q1b: every 503 (none expected: the bridges are skipped)
SELECT path, http_method, COUNT(*) FROM test_results_view WHERE response_code = 503 GROUP BY 1, 2;
-- Q2: an error answer that is not problem+json, or lacks code or retryable
-- (HEAD answers have no body; net/http's own text/plain 400s ran no handler)
SELECT v.path, v.http_method, v.response_code, r.response_content_type, COUNT(*) AS n
FROM test_results_view v JOIN tests t ON t.test_id = v.test_id JOIN responses r ON r.test_id = t.id
WHERE v.response_code >= 400 AND v.response_code NOT IN (431, 501, 953, 954, 999)
  AND v.http_method <> 'HEAD' AND v.path NOT LIKE '/v1/auth/token%'
  AND NOT (v.response_code = 400 AND r.response_content_type LIKE 'text/plain%')
  AND (r.response_content_type NOT LIKE 'application/problem+json%'
       OR (r.response_body IS NOT NULL AND (json_extract(r.response_body, '$.code') IS NULL OR json_extract(r.response_body, '$.retryable') IS NULL)))
GROUP BY 1, 2, 3, 4 ORDER BY n DESC;
-- Q3: nothing contradicts the documented responses (the findings once rules and fixes are in)
SELECT path, http_method, response_code, fuzzer, result_reason, COUNT(*) AS n FROM true_positives_view
GROUP BY 1, 2, 3, 4, 5 ORDER BY response_code DESC, n DESC;
-- Q4: no token, key or stack trace in a stored body (the underscore is escaped: it is a wildcard)
SELECT v.test_id, v.path, v.response_code FROM test_results_view v JOIN tests t ON t.test_id = v.test_id JOIN responses r ON r.test_id = t.id
WHERE r.response_body LIKE '%eyJ%' OR r.response_body LIKE '%abe\_%' ESCAPE '\' OR r.response_body LIKE '%goroutine %'
   OR r.response_body LIKE '%.go:%' OR r.response_body LIKE '%BEGIN PRIVATE KEY%';
```

The database stores bodies for error and warn records only, so also scan the raw report (kept with `retain_raw_report: true`): `for f in <report>/Test*.json; do jq -r 'select((.response.jsonBody // "") | tostring | test("eyJ[A-Za-z0-9_-]{20,}|abe_[A-Za-z0-9_-]{20,}|goroutine [0-9]+|\\.go:[0-9]+")) | .testId' "$f"; done` must print nothing but the `enrollment_token` tests of `POST /v1/admin/identities`. The harness's own scan (every `run`) is stricter on one point: it looks for the campaign's exact minted secrets and finds none.

### The rules file

`api/cats-false-positives.yaml` is `version: 1` and a list of rules, evaluated in file order; the first enabled match wins and its id is recorded. Only `error` and `warn` records are classified. A rule:

```yaml
  - id: UPPER_SNAKE_CASE_ID_404
    why: "The reason, citing the spec line, the ADR, the router test or the fuzzer's definition."
    when: {response_code: 404, fuzzer: RandomResources, method: GET, path: {in: [/v1/tasks/{id}]}}
```

`when` is an AND of conditions; `any_of` is an OR; both may appear and are ANDed. Fields: `result`, `response_code`, `fuzzer`, `path`, `contract_path`, `method`, `url`, `scenario`, `result_reason`, `result_details`, `any_text`, `response_body`, `response_content_type`, `request_body`, `json_body.<dotted.path>`, `request_header.<name>`. Operators: `equals` (a bare scalar), `in`, `not_equals`, `contains`, `contains_any`, `contains_all`, `starts_with`, `starts_with_any`, `ends_with`, `matches`, `exists`. The classifier rejects an unknown key, field or operator (exit 2). Regular expressions are RE2 in the classifier and Python `re` in the plugin; keep to the common subset.

Rules for adding one: every rule names its response codes explicitly (`response_code` with `equals` or `in`); none may match 500 to 599 (a 5xx is never a false positive); no rule may name the fuzzer `FakeCatsFuzzer`; and `TestCommittedRules` (`go test ./tools/catscheck/ -run TestCommittedRules`) enforces all three. Add a rule through `cats:fp` (the plugin's own `classify --dry-run` against the database, not an option of `tools/catscheck`, runs first), then check that `go run ./tools/catscheck classify` agrees with the plugin's `true_positives_view` count for the same run.

## The pre-commit hook

Enable it once per clone: `git config core.hooksPath .githooks`. `.githooks/pre-commit` runs `scripts/cats-precommit.sh`:

1. No staged change to `api/openapi.yaml`: it exits 0 silently. A staged deletion of the spec is refused.
2. It exports the staged tree (`git checkout-index`) into a temporary directory and runs everything from there, never from the working tree (the staged tree is the only source). `git stash` is never used.
3. `tools/catscheck changed-paths` compares HEAD's spec with the staged one after stripping `description`, `summary`, `example`, `examples` and `externalDocs` by position (a property named `description` is kept). A documentation-only change prints `cats-precommit: documentation-only change to api/openapi.yaml; skipping CATS` and the commit goes through at once; a difference that reaches no path prints `no path is affected ... skipping CATS`.
4. Otherwise it checks that `internal/gen` is fresh for the staged spec (`make generate` in the export; a difference fails with `run make generate and stage internal/gen`), widens the changed paths through `$ref` (a changed shared schema, parameter or response reaches every path that references it; a change to `servers`, `security` or `openapi` reaches every path), and runs the harness: the non-skipped paths in one run, each skipped destructive path in its own run with `--no-skip`; the bridges paths are dropped with a notice.
5. It classifies each report. With no finding it prints `cats-precommit: no finding; <summary>` and the commit goes through. With findings it prints them, keeps the reports in `.local/cats/precommit/<stamp>/`, and fails the commit; fix the cause or record false positives with `cats:fp`.

Cost: a spec change that is not documentation pays a build, `make generate` and an estimated 1 to 10 minutes of fuzzing (a change that widens to every path runs up to four campaigns, an estimated 12 minutes; these are plan estimates, not measurements). The hook fails closed when `cats`, `jq`, `go` or `curl` is missing, naming `brew install endava/tap/cats`. `git commit --no-verify` bypasses the hook entirely.

## The exceptions

- Go's net/http answers before any handler: 501 `text/plain` on an unknown `Transfer-Encoding` (`DummyTransferEncodingHeaders`), 431 on oversized headers (`LargeNumberOfRandomAlphanumericHeaders`), and `text/plain` 400s after a malformed `Content-Length`. They are not problem+json and the 501 is a 5xx that is not the 503. CATS scores them `success`; the acceptance queries exclude them as above. A proxy in front of the server could change them and this server has none (ADR 0018, Open item 1).
- Skipped paths, fuzzed alone with `run --paths '<path>' --no-skip`: `/v1/admin/reset` (`scope=everything` deletes `cats-agent` and every token), `/v1/admin/signing-keys/rotate` (`revoke_previous=true` invalidates both bearers) and `/v1/admin/identities/{identity}/reset-credential` (removes the identity's key). Their 401s after the credential is gone are the expected tail of the run; read the findings before the cliff.
- Bridges (`/v1/admin/bridges`, `/v1/admin/bridges/{channel}`; four operations) are not fuzzed: the campaign server has no Slack bridge, every call answers the documented 503 `unavailable`, and the Slack fake is wired from Go only. This narrows "every operation" (ADR 0018, Open item 6).
- Sacrificial fixtures: decoys for the paths whose fuzzing deletes their anchor (`cats-ordinary-decoy`, a decoy session, memory and task, `cats-scope-decoy`), and the channels `cats-acl` and `cats-sub`. Each `seed` re-creates any decoy that is gone.
- Missing security response headers (`X-Content-Type-Options`, `Cache-Control`) are a recorded rule, `SECURITY_HEADERS_JSON_API`, not a middleware (Open item 7).

## The selftests

`make cats-selftest` runs `scripts/cats-harness-selftest.sh` and `scripts/cats-precommit-selftest.sh`. They run the real server against a fake `cats` (`scripts/testdata/cats-fake/cats`, no Java) and compare with recorded expectations in `scripts/testdata/cats-harness/`. `bash scripts/cats-harness-selftest.sh --real` also runs the installed `cats` on `/v1/discover` and `/v1/channels` (needs Java; never in CI); `--record` rewrites the expectation files and then exits 1. Block 40 of `scripts/check-gates-selftest.sh` runs both selftests unmutated and then mutates the gates (the normalizer, the path widener, the rule classifier, the hook's two exits and the no-500 guard), so `make check-gates-selftest` proves each one fires.

## What a campaign leaves behind

Nothing outside `.local/cats/` (git-ignored: `config.yaml`, `results/` with the databases, reports, `refdata.yml` and `fixtures.json`, and `precommit/`) and the harness directory, which `down` (and the `run` trap) removes whole, including the SQLite file, the server log and every bearer cache. `scripts/cats-harness.sh status` after a run shows `server=none`. A `cats` run without `-o` would write `./cats-report` into the repository; the harness always passes `-o` and never passes `--showSecrets`.
