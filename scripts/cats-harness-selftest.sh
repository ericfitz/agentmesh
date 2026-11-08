#!/usr/bin/env bash
# cats-harness-selftest.sh: tests scripts/cats-harness.sh against recorded output
# (issue #30, Definition of Done C). It runs the real server with a fake `cats`
# (scripts/testdata/cats-fake/cats) in its own temporary --dir, never the
# default directory. Every case runs; the exit code is 1 when any failed.
#
#   scripts/cats-harness-selftest.sh [--real] [--record]
#
# --record writes the expectation files in scripts/testdata/cats-harness/ instead
# of comparing against them, and the run then exits 1 (a recording is not a
# pass). Only the flag does it: the environment never rewrites expectations.
# --real adds real-campaign (the installed cats; needs Java; never in CI).
#
# State (Definition of Done D): everything lives under one mktemp directory that
# the EXIT trap removes after running `down` on each harness directory in it and
# killing any server still started from it; a second run starts from nothing.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
HARNESS=$ROOT/scripts/cats-harness.sh
FAKE=$ROOT/scripts/testdata/cats-fake/cats
EXPECT=$ROOT/scripts/testdata/cats-harness
RECORD=0
REAL=0
for arg in "$@"; do
  case "$arg" in
    --real) REAL=1 ;;
    --record) RECORD=1 ;;
    *) echo "usage: $0 [--real] [--record]" >&2; exit 2 ;;
  esac
done
if [ -n "${CATS_HARNESS_RECORD:-}" ]; then
  echo "cats-harness-selftest: CATS_HARNESS_RECORD is ignored; use --record" >&2
fi

unset CATS_HARNESS_DIR CATS_SMOKE CATS_IDENTITY CATS_FAKE_SLEEP CATS_FAKE_PLANT CATS_FAKE_WATCH \
  AGENTMESH_PROFILE AGENTMESH_IDENTITY AGENTMESH_SERVER AGENTMESH_CREDENTIAL \
  AGENTMESH_CONFIG_DIR AGENTMESH_DATA_DIR

TMP=$(mktemp -d "${TMPDIR:-/tmp}/cats-selftest.XXXXXX")
TMP=$(cd "$TMP" && pwd -P)
mkdir "$TMP/cap"
export CATS_BIN=$FAKE
export CATS_FAKE_LOG=$TMP/fake.log
BG=
D=$TMP/h # the main harness directory

cleanup() {
  local rc=$? stray=0
  trap - EXIT INT TERM
  if [ -n "$BG" ]; then
    kill "$BG" 2>/dev/null || true
    wait "$BG" 2>/dev/null || true
  fi
  if [ -d "$TMP" ]; then
    local d pid
    for d in "$TMP"/*/; do
      [ -f "${d}.agentmesh-cats" ] || continue
      echo "cats-harness-selftest: FAIL cleanup: ${d%/} was left behind" >&2
      stray=1
      bash "$HARNESS" down --dir "${d%/}" >/dev/null 2>&1 || true
    done
    for pid in $(pgrep -f "$TMP/[^ ]*/agentmesh server" 2>/dev/null || true); do
      echo "cats-harness-selftest: FAIL cleanup: a stray server (pid $pid) had to be killed" >&2
      stray=1
      kill -KILL "$pid" 2>/dev/null || true
    done
    rm -rf "$TMP"
  fi
  if [ "$stray" -eq 1 ] && [ "$rc" -eq 0 ]; then rc=1; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------- helpers

CASE=
CASE_FAIL=0
FAILED=()
RUNS=0
RECORDED=0

fail() { # fail WHY: records a failure of the current case
  echo "cats-harness-selftest: FAIL $CASE: $*"
  CASE_FAIL=1
}

run_case() { # run_case NAME FUNCTION
  CASE=$1
  CASE_FAIL=0
  RUNS=$((RUNS + 1))
  "$2" || true
  if [ "$CASE_FAIL" -eq 0 ]; then
    echo "cats-harness-selftest: ok $CASE"
  else
    FAILED+=("$CASE")
  fi
}

RC=0
# h NAME ARGS...: runs the harness, stdout and stderr to $TMP/cap/NAME.{out,err}, exit code in RC.
h() {
  local name=$1
  shift
  RC=0
  bash "$HARNESS" "$@" >"$TMP/cap/$name.out" 2>"$TMP/cap/$name.err" || RC=$?
  echo "$RC" >"$TMP/cap/$name.rc"
}
out_of() { cat "$TMP/cap/$1.out"; }
err_of() { cat "$TMP/cap/$1.err"; }

expect_rc() { # expect_rc WANT WHAT
  [ "$RC" -eq "$1" ] || fail "$2: exit $RC, want $1 (stderr: $(head -c 300 "$TMP/cap/${3:-x}.err" 2>/dev/null | tr '\n' ' '))"
}
contains() { # contains NAME FILE-SUFFIX NEEDLE (fixed string)
  grep -q -F -e "$3" "$TMP/cap/$1.$2" || fail "$1.$2 lacks '$3'"
}
log_has_line() { grep -q -x -F -e "$1" "$CATS_FAKE_LOG" 2>/dev/null; }
alive() { kill -0 "$1" 2>/dev/null; }

tokenize() { # tokenize OUT_DIR: stdin to stdout, paths and the port replaced by tokens
  sed -e "s|$1|<OUT>|g" -e "s|$D|<DIR>|g" -e "s|$ROOT|<REPO>|g" \
    -E -e 's#http://127\.0\.0\.1:[0-9]+#<URL>#g'
}

compare() { # compare ACTUAL_FILE EXPECTED_NAME
  if [ "$RECORD" = 1 ]; then
    cp "$1" "$EXPECT/$2"
    echo "cats-harness-selftest: recorded $EXPECT/$2"
    RECORDED=1
    return 0
  fi
  if ! diff -u "$EXPECT/$2" "$1" >"$TMP/diff.txt" 2>&1; then
    fail "$2 differs: $(head -n 12 "$TMP/diff.txt" | tr '\n' '|')"
  fi
}

wait_for() { # wait_for SECONDS CMD...: polls every 0.2 s
  local n=$(($1 * 5)) i
  shift
  for ((i = 0; i < n; i++)); do
    "$@" && return 0
    sleep 0.2
  done
  return 1
}

# ---------------------------------------------------------------- cases

# Cases 1, 2, 5 (part), 6 share one run.
OUT1=$TMP/out
case_run_completes() {
  : >"$CATS_FAKE_LOG"
  CATS_FAKE_WATCH=$TMP/watch1.txt h run1 run --dir "$D" --out "$OUT1"
  expect_rc 0 "run" run1
  contains run1 out 'tests=3 success=1 warnings=1 errors=1 status=COMPLETED'
  contains run1 out 'report='
  cp "$CATS_FAKE_LOG" "$TMP/argv-run1.txt"
  # The server is dead after run (not merely its directory gone).
  if pgrep -f "$D/agentmesh server" >/dev/null 2>&1; then fail "a server of $D still runs after run"; fi
}

case_argv_recorded() {
  local a=$TMP/argv-tokenized.txt joined
  tokenize "$OUT1" <"$TMP/argv-run1.txt" >"$a"
  joined=$(tr '\n' ' ' <"$a")
  local want
  for want in '--noEnvFile' '--no-checkUpdate' '-o <OUT>/report ' '--headers=<DIR>/headers.yml' \
    '--refData=<DIR>/refdata.yml' '-c <REPO>/api/openapi.yaml '; do
    case "$joined" in *"$want"*) ;; *) fail "argv lacks '$want'" ;; esac
  done
  case "$joined" in *--showSecrets* | *Bearer*) fail "argv has --showSecrets or Bearer" ;; esac
  compare "$a" expected-argv.txt
}

# ids are replaced by section: a value counts only when it is the seeded one.
tokenize_refdata() { # tokenize_refdata SEED_JSON REFDATA
  local sj=$1
  awk -v ses="$(jq -r .session "$sj")" -v sesd="$(jq -r .session_decoy "$sj")" \
    -v task="$(jq -r .task "$sj")" -v taskd="$(jq -r .task_decoy "$sj")" -v taskp="$(jq -r .task_parent "$sj")" \
    -v mem="$(jq -r .memory "$sj")" -v memd="$(jq -r .memory_decoy "$sj")" '
    BEGIN {
      tok["/v1/channels/{channel}/messages"] = "SESSION"
      tok["/v1/tasks/{id}"] = "DECOY_TASK"
      tok["/v1/tasks/{id}/claim"] = "TASK"
      tok["/v1/tasks/{id}/release"] = "TASK"
      tok["/v1/memories/{id}"] = "DECOY_MEMORY"
      tok["/v1/memories/{id}/revisions"] = "MEMORY"
      tok["/v1/sessions/{session}"] = "DECOY_SESSION"
      tok["/v1/sessions/{session}/peek"] = "SESSION"
      tok["/v1/sessions/{session}/receive"] = "SESSION"
      tok["/v1/sessions/{session}/watch"] = "SESSION"
      tok["/v1/sessions/{session}/status"] = "SESSION"
      val["SESSION"] = ses; val["DECOY_SESSION"] = sesd; val["TASK"] = task
      val["DECOY_TASK"] = taskd; val["PARENT_TASK"] = taskp; val["MEMORY"] = mem; val["DECOY_MEMORY"] = memd
    }
    /^\// { sec = $0; sub(/:$/, "", sec); print; next }
    /^  parent: / {
      v = $0; sub(/^  parent: /, "", v)
      if (val["PARENT_TASK"] == v) { sub(/: .*$/, ": <PARENT_TASK>"); }
      print; next
    }
    /^  (id|session): / {
      v = $0; sub(/^  (id|session): /, "", v)
      t = tok[sec]
      if (t != "" && val[t] == v) { sub(/: .*$/, ": <" t ">"); }
      print; next
    }
    { print }' "$2"
}

case_refdata_recorded() {
  local s=$TMP/seed
  h up1 up --dir "$D"
  expect_rc 0 "up" up1
  h seed1 seed --dir "$D" --out "$s"
  expect_rc 0 "seed" seed1
  [ "$CASE_FAIL" -eq 0 ] || return 0
  tokenize_refdata "$s/seed.json" "$s/refdata.yml" >"$TMP/refdata-tokenized.yml"
  compare "$TMP/refdata-tokenized.yml" expected-refdata.yml
  jq -r '.fixtures[].key' "$s/fixtures.json" >"$TMP/fixtures-keys.txt"
  compare "$TMP/fixtures-keys.txt" expected-fixtures-keys.txt
  local t
  for t in SESSION DECOY_SESSION TASK DECOY_TASK PARENT_TASK MEMORY DECOY_MEMORY; do
    grep -q -F "<$t>" "$TMP/refdata-tokenized.yml" || fail "refdata has no <$t> after tokenizing (an id changed shape?)"
  done
  # Task 8.4: the agent's PUT of an ACL keeps its own admin, and createTask drops
  # the members that name other objects (a random parent or blocked_by is a 400).
  grep -q -x -F '  permissions[*]: admin' "$s/refdata.yml" || fail "refdata lacks permissions[*]: admin for the ACL PUT"
  for t in blocked_by before after; do
    grep -q -x -F "  $t: cats_remove_field" "$s/refdata.yml" || fail "refdata does not remove $t from createTask"
  done
  # Task 8.1 g: the throwaway identity is registered and mapped in the refData.
  grep -q -x -F '/v1/admin/identities/{identity}/reset-credential:' "$s/refdata.yml" || fail "refdata lacks the reset-credential section"
  grep -q -x -F '  identity: cats-victim' "$s/refdata.yml" || fail "refdata does not map reset-credential's identity to cats-victim"
  [ -f "$D/config/credentials/cats/cats-victim" ] || fail "cats-victim has no credential in the harness directory"
  # Task 8.1 a: every verify_url is a path (the plugin joins it onto the server).
  if jq -e '.fixtures[] | select(.verify_url | startswith("/") | not)' "$s/fixtures.json" >/dev/null; then
    fail "a fixtures.json verify_url is not a path"
  fi
  # A second seed re-reads the same fixtures (state, Definition of Done D).
  h seed2 seed --dir "$D" --out "$TMP/seed2"
  expect_rc 0 "second seed" seed2
  local k
  for k in task task_decoy task_parent memory memory_decoy; do
    [ "$(jq -r ".$k" "$s/seed.json")" = "$(jq -r ".$k" "$TMP/seed2/seed.json")" ] || fail "second seed returned another $k id"
  done
}

# admin_curl METHOD PATH [JSON-BODY]: an API call as cats-admin; the bearer goes
# to curl on stdin (-K -), never on argv or into a capture. Prints the HTTP code
# and, for a GET, the body after it.
admin_curl() {
  local t url body=()
  url=$(cat "$D/server.url")
  t=$(bash "$HARNESS" token --dir "$D" admin)
  [ -z "${3:-}" ] || body=(-H 'Content-Type: application/json' -d "$3")
  printf 'header = "Authorization: Bearer %s"\n' "$t" |
    curl -s -m 10 -K - -X "$1" -w '\n%{http_code}' "${body[@]}" "$url$2"
}

# Task 8.1 e and f: every channel names the administrator; a decoy that is gone
# is re-created with a new id, one that is alive keeps its id.
case_seed_recreates_decoys() {
  local before=$TMP/seed3 after=$TMP/seed4 c body code
  h sd1 seed --dir "$D" --out "$before"
  expect_rc 0 "seed before the delete" sd1
  [ "$CASE_FAIL" -eq 0 ] || return 0
  for c in cats-ordinary cats-ordinary-decoy cats-sub cats-tasks cats-memory; do
    body=$(admin_curl GET "/v1/channels/$c/acl")
    case "$body" in *cats-admin*) ;; *) fail "the ACL of $c does not name cats-admin" ;; esac
  done
  # cats-acl names the agent alone (the agent's PUT could not succeed otherwise).
  body=$(admin_curl GET "/v1/channels/cats-acl/acl")
  case "$body" in *cats-agent*) ;; *) fail "the ACL of cats-acl does not name cats-agent" ;; esac
  case "$body" in *cats-admin*) fail "the ACL of cats-acl names cats-admin" ;; esac
  local memd taskd
  memd=$(jq -r .memory_decoy "$before/seed.json")
  taskd=$(jq -r .task_decoy "$before/seed.json")
  code=$(admin_curl DELETE "/v1/memories/$memd" | tail -n 1)
  [ "$code" = 204 ] || { fail "DELETE memory $memd: HTTP $code"; return 0; }
  h sd2 seed --dir "$D" --out "$after"
  expect_rc 0 "seed after the delete" sd2
  [ "$CASE_FAIL" -eq 0 ] || return 0
  [ "$(jq -r .memory_decoy "$after/seed.json")" != "$memd" ] || fail "the deleted memory decoy $memd was not re-created"
  contains sd2 err 're-created memory'
  [ "$(jq -r .memory "$before/seed.json")" = "$(jq -r .memory "$after/seed.json")" ] || fail "the live memory fixture changed id"
  [ "$(jq -r .task_decoy "$after/seed.json")" = "$taskd" ] || fail "the live task decoy changed id"
  # The new id is the one in the refData and it is live.
  grep -q -x -F "  id: $(jq -r .memory_decoy "$after/seed.json")" "$after/refdata.yml" || fail "refdata lacks the new memory decoy id"
  code=$(admin_curl GET "/v1/memories/$(jq -r .memory_decoy "$after/seed.json")" | tail -n 1)
  [ "$code" = 200 ] || fail "the re-created memory decoy answers HTTP $code"
  # Task 8.4: a seed puts an emptied ACL back (a fuzzed PUT of []), on a channel
  # that names both identities and on cats-acl.
  for c in cats-ordinary cats-acl; do
    code=$(admin_curl PUT "/v1/channels/$c/acl" '[]' | tail -n 1)
    [ "$code" = 204 ] || fail "PUT [] on the ACL of $c: HTTP $code"
  done
  h sd4 seed --dir "$D" --out "$TMP/seed6"
  expect_rc 0 "seed after the ACLs were emptied" sd4
  body=$(admin_curl GET "/v1/channels/cats-ordinary/acl")
  case "$body" in *cats-agent*cats-admin* | *cats-admin*cats-agent*) ;; *) fail "seed did not restore both entries on cats-ordinary" ;; esac
  body=$(admin_curl GET "/v1/channels/cats-acl/acl")
  case "$body" in *cats-agent*) ;; *) fail "seed did not restore cats-agent on cats-acl" ;; esac
  # A removed channel is re-created too (the delete is the API's, as a fuzzer's).
  code=$(admin_curl DELETE "/v1/channels/cats-ordinary-decoy" | tail -n 1)
  case "$code" in 2??) ;; *) fail "DELETE channel: HTTP $code"; return 0 ;; esac
  h sd3 seed --dir "$D" --out "$TMP/seed5"
  expect_rc 0 "seed after the channel delete" sd3
  code=$(admin_curl GET "/v1/channels/cats-ordinary-decoy/acl" | tail -n 1)
  [ "$code" = 200 ] || fail "the removed channel was not re-created (HTTP $code)"
}

JWT_RE='^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
case_token_prints_one_line() {
  h tok1 token --dir "$D" agent
  expect_rc 0 "token agent" tok1
  [ "$(wc -l <"$TMP/cap/tok1.out" | tr -d ' ')" = 1 ] || fail "token agent printed other than one line"
  grep -q -E "$JWT_RE" "$TMP/cap/tok1.out" || fail "token agent output is not JWT-shaped"
  [ -s "$TMP/cap/tok1.err" ] && fail "token agent wrote to stderr"
  h tok2 token --dir "$D" nobody
  expect_rc 2 "token nobody" tok2
  h tok3 token --dir "$D"
  expect_rc 2 "token with no argument" tok3
}

case_no_bearer_leaks() {
  local f
  for f in "$OUT1/cats.log" "$D/harness.log" "$D/server.log"; do
    [ -f "$f" ] || { fail "$f is missing"; continue; }
    if grep -q -E 'Bearer ey|eyJ[A-Za-z0-9_-]{10,}\.|abe_[A-Za-z0-9_-]{20,}' "$f"; then
      fail "a bearer pattern is in $f"
    fi
  done
  if grep -r -q -E 'Bearer ey|eyJ[A-Za-z0-9_-]{10,}\.|abe_[A-Za-z0-9_-]{20,}' "$OUT1/report"; then
    fail "a bearer pattern is in the report"
  fi
  # The harness's own output, apart from the token line, carries no eyJ.
  for f in "$TMP"/cap/*.out "$TMP"/cap/*.err; do
    case "$f" in */tok1.out) continue ;; esac
    if grep -q 'eyJ' "$f"; then fail "eyJ in $(basename "$f")"; fi
  done
}

case_headers_file_removed() {
  # The fake's watcher saw the file vanish while the harness directory still
  # existed: only run's own removal explains that (a directory removal would read "gone").
  wait_for 10 test -s "$TMP/watch1.txt" || { fail "the headers file was never seen to vanish"; return 0; }
  [ "$(cat "$TMP/watch1.txt")" = present ] || fail "the headers file vanished only with its directory, not by run's own removal"
  [ ! -e "$D/headers.yml" ] || fail "$D/headers.yml exists after run"
  local found
  found=$(find "$TMP" -name headers.yml -not -path "$D/*" 2>/dev/null || true)
  [ -z "$found" ] || fail "a headers file is left: $found"
}

case_second_up_refused() {
  h up2 up --dir "$D"
  expect_rc 3 "second up" up2
  contains up2 err 'down'
  if [ ! -f "$D/server.pid" ] || ! alive "$(cat "$D/server.pid")"; then fail "the first server died"; fi
}

case_server_argv() {
  local cmd pair
  cmd=$(ps -o command= -p "$(cat "$D/server.pid")")
  for pair in 'send_messages_per_second=10000' 'send_kib_per_second=65536' \
    'token_lifetime_seconds=86400' 'session_lease_seconds=86400' \
    'watch_max_seconds=1' 'maintenance_interval_seconds=3600' \
    'signing_key_rotation_cooldown_seconds=1'; do
    case "$cmd" in *"-set $pair"*) ;; *) fail "server argv lacks '-set $pair'" ;; esac
  done
  case "$cmd" in *'-listen 127.0.0.1:'*) ;; *) fail "server argv lacks '-listen 127.0.0.1:'" ;; esac
}

case_leftovers_cleaned() {
  # $D is up (case up1). Kill its server hard, then run over the leftovers.
  local old
  old=$(cat "$D/server.pid")
  kill -9 "$old" 2>/dev/null || true
  wait_for 10 sh -c "! kill -0 $old 2>/dev/null" || fail "could not kill $old"
  : >"$CATS_FAKE_LOG"
  h run2 run --dir "$D" --out "$TMP/out2" --paths /v1/discover
  expect_rc 0 "run over leftovers" run2
  contains run2 out "cleaned leftovers (pid $old dead)"
  cp "$CATS_FAKE_LOG" "$TMP/argv-run2.txt"
  [ ! -e "$D" ] || fail "$D exists after run"
}

case_down_removes_dir() {
  local d=$TMP/h9
  h dn_up up --dir "$d"
  expect_rc 0 "up" dn_up
  local pid
  pid=$(cat "$d/server.pid")
  alive "$pid" || fail "the server of $d is not alive before down"
  h dn1 down --dir "$d"
  expect_rc 0 "down" dn1
  wait_for 10 sh -c "! kill -0 $pid 2>/dev/null" || fail "the server (pid $pid) is alive after down"
  [ ! -e "$d" ] || fail "$d exists after down"
  h dn2 down --dir "$d"
  expect_rc 0 "second down" dn2
}

SKIP_ARG='--skipPaths=/v1/admin/reset,/v1/admin/signing-keys/rotate,/v1/admin/identities/{identity}/reset-credential,/v1/admin/bridges,/v1/admin/bridges/{channel}'
case_skip_paths_vs_paths() {
  grep -q -x -F -e "$SKIP_ARG" "$TMP/argv-run1.txt" || fail "default run lacks the five-entry $SKIP_ARG"
  grep -q -x -F -e '--paths=/v1/discover' "$TMP/argv-run2.txt" || fail "--paths run lacks --paths=/v1/discover"
  if grep -q -F -e '--skipPaths=' "$TMP/argv-run2.txt"; then fail "--paths run passes --skipPaths="; fi

  : >"$CATS_FAKE_LOG"
  h sk3 run --dir "$D" --out "$TMP/out-sk3" --paths /v1/discover,/v1/admin/reset
  expect_rc 0 "paths with a skipped entry" sk3
  contains sk3 out 'skipped: /v1/admin/reset (use --no-skip)'
  log_has_line '--paths=/v1/discover' || fail "mixed list did not pass --paths=/v1/discover"

  : >"$CATS_FAKE_LOG"
  h sk4 run --dir "$D" --out "$TMP/out-sk4" --paths /v1/admin/reset --no-skip
  expect_rc 0 "--no-skip" sk4
  log_has_line '--paths=/v1/admin/reset' || fail "--no-skip did not pass --paths=/v1/admin/reset"
  if grep -q -F -e '--skipPaths=' "$CATS_FAKE_LOG"; then fail "--no-skip passes --skipPaths="; fi

  rm -f "$CATS_FAKE_LOG"
  h sk5 run --dir "$D" --out "$TMP/out-sk5" --paths /v1/admin/reset
  expect_rc 0 "only a skipped path" sk5
  contains sk5 out 'nothing to fuzz'
  [ ! -e "$CATS_FAKE_LOG" ] || fail "the fake ran for a skipped-only list"
  [ ! -e "$D" ] || fail "a skipped-only run started a server"
}

case_no_skip_skips_fixture_check() {
  local k=$TMP/out-nsk
  : >"$CATS_FAKE_LOG"
  CATS_FAKE_KILL_FIXTURE=1 h nsk1 run --dir "$D" --out "$k-1" --paths /v1/discover
  expect_rc 1 "a killed fixture without --no-skip" nsk1
  contains nsk1 out 'died'
  CATS_FAKE_KILL_FIXTURE=1 h nsk2 run --dir "$D" --out "$k-2" --paths /v1/admin/reset --no-skip
  expect_rc 0 "a killed fixture under --no-skip" nsk2
  contains nsk2 out 'tests=3'
  if grep -q -F 'died' "$TMP/cap/nsk2.out"; then fail "--no-skip ran the fixture check"; fi
}

case_cats_not_found() {
  local d=$TMP/nf
  CATS_BIN=/nonexistent h nf1 run --dir "$d" --out "$TMP/out-nf"
  expect_rc 2 "CATS_BIN=/nonexistent" nf1
  contains nf1 err 'missing tool: /nonexistent'
  CATS_BIN=cats-not-installed-here h nf2 run --dir "$d" --out "$TMP/out-nf"
  expect_rc 2 "a missing cats" nf2
  contains nf2 err 'missing tool: cats-not-installed-here'
  [ ! -e "$d" ] && [ ! -e "$d/server.pid" ] || fail "a server directory appeared before the tool check"
}

case_shellcheck() {
  if ! command -v shellcheck >/dev/null 2>&1; then
    echo "cats-harness-selftest: (shellcheck absent)"
    return 0
  fi
  shellcheck -x "$ROOT/scripts/cats-harness.sh" "$ROOT/scripts/cats-harness-selftest.sh" "$FAKE" >"$TMP/sc.txt" 2>&1 ||
    fail "shellcheck: $(head -n 8 "$TMP/sc.txt" | tr '\n' '|')"
}

case_admin_paths_match_spec() {
  local want got
  got=$(bash "$HARNESS" admin-paths | LC_ALL=C sort)
  want=$(awk '/^paths:/ { p = 1; next } /^[^ ]/ { p = 0 } p && /^  \/v1\/admin\// { sub(/^  /, ""); sub(/:$/, ""); print }' \
    "$ROOT/api/openapi.yaml" | LC_ALL=C sort)
  [ -n "$want" ] || fail "no /v1/admin paths found in api/openapi.yaml"
  [ "$got" = "$want" ] || fail "ADMIN_PATHS differs from the spec: $(diff <(echo "$got") <(echo "$want") | tr '\n' '|')"
}

case_dir_guard() {
  local nm=$TMP/not-mine
  mkdir "$nm"
  echo keep >"$nm/file"
  h dg1 up --dir "$nm"
  expect_rc 2 "up on a foreign directory" dg1
  contains dg1 err 'not a harness directory'
  h dg2 down --dir "$nm"
  expect_rc 2 "down on a foreign directory" dg2
  contains dg2 err 'not a harness directory'
  [ -f "$nm/file" ] || fail "the foreign directory's file did not survive"
}

case_dir_symlink_dots() {
  local t=$TMP/target link=$TMP/link
  mkdir "$t"
  ln -s "$t" "$link"
  h sl1 down --dir "$link/"
  expect_rc 2 "down on link/" sl1
  [ -d "$t" ] || fail "down --dir link/ removed the target"
  h sl2 down --dir "$link"
  expect_rc 2 "down on link" sl2
  touch "$t/.agentmesh-cats"
  h sl3 down --dir "$link//"
  expect_rc 2 "down on link// with a marked target" sl3
  [ -f "$t/.agentmesh-cats" ] || fail "a marked target was removed through a symlink"
  local m=$TMP/marked
  mkdir "$m"
  touch "$m/.agentmesh-cats"
  h dd1 down --dir "$TMP/./marked"
  expect_rc 2 "down on a . component" dd1
  h dd2 down --dir "$TMP/marked/../marked"
  expect_rc 2 "down on a .. component" dd2
  [ -f "$m/.agentmesh-cats" ] || fail "a . or .. path removed a marked directory"
  h dd3 down --dir relative/path
  expect_rc 2 "down on a relative path" dd3
  rm -rf "$t" "$m" "$link"
}

case_overlap() {
  local d=$TMP/ov pid
  : >"$CATS_FAKE_LOG"
  CATS_FAKE_SLEEP=20 bash "$HARNESS" run --dir "$d" --out "$TMP/out-ov" >"$TMP/cap/ov1.out" 2>"$TMP/cap/ov1.err" &
  BG=$!
  if ! wait_for 240 test -s "$CATS_FAKE_LOG"; then
    fail "the first run never reached cats"
    return 0
  fi
  pid=$(cat "$d/server.pid")
  h ov2 run --dir "$d" --out "$TMP/out-ov2"
  expect_rc 3 "second run while the first lives" ov2
  contains ov2 err 'another harness command is active'
  h ov3 up --dir "$d"
  expect_rc 3 "up while a run lives" ov3
  alive "$pid" || fail "the first run's server died"
  [ -f "$d/.agentmesh-cats" ] || fail "the first run's directory was removed"
  local rc=0
  wait "$BG" || rc=$?
  BG=
  [ "$rc" -eq 0 ] || fail "the first run exited $rc"
  [ ! -e "$d" ] || fail "$d remains after the first run"
  [ ! -e "$d.lock" ] || fail "the lock $d.lock remains"
}

case_repo_checks() {
  local d=$TMP/rp
  : >"$CATS_FAKE_LOG"
  (cd "$(dirname "$ROOT")" && h rp1 run --dir "$d" --out "$TMP/out-rp" --repo "./$(basename "$ROOT")" --paths /v1/discover)
  RC=$(cat "$TMP/cap/rp1.rc")
  expect_rc 0 "a relative --repo" rp1
  grep -q -x -F -e "$ROOT/api/openapi.yaml" "$CATS_FAKE_LOG" || fail "cats did not get the absolute $ROOT/api/openapi.yaml"
  mkdir "$TMP/emptyrepo"
  h rp2 run --dir "$d" --out "$TMP/out-rp" --repo "$TMP/emptyrepo"
  expect_rc 2 "a repo without the spec" rp2
  contains rp2 err 'no api/openapi.yaml'
  h rp3 up --dir "$d" --repo "$TMP/does-not-exist"
  expect_rc 2 "a missing repo" rp3
  [ ! -e "$d" ] || fail "a refused repo left a directory"
}

case_flag_checks() {
  local d=$TMP/fl
  h fl1 status --dir "$d" extra
  expect_rc 2 "status with an extra argument" fl1
  contains fl1 err "unexpected argument for status: extra"
  h fl2 down --dir "$d" --paths /v1/discover
  expect_rc 2 "down --paths" fl2
  contains fl2 err "--paths is not valid for down"
  h fl3 up --dir "$d" --out "$TMP/x"
  expect_rc 2 "up --out" fl3
  contains fl3 err "--out is not valid for up"
  h fl4 run --dir "$d" --paths ""
  expect_rc 2 'run --paths ""' fl4
  contains fl4 err "--paths: empty list"
  h fl5 run --dir "$d" extra
  expect_rc 2 "run with an extra argument" fl5
  contains fl5 err "unexpected argument for run: extra"
  h fl6 admin-paths --dir "$d"
  expect_rc 2 "admin-paths --dir" fl6
  contains fl6 err "--dir is not valid for admin-paths"
  h fl7 bogus
  expect_rc 2 "an unknown subcommand" fl7
  contains fl7 err "unknown subcommand: bogus"
  h fl8 up --bogus
  expect_rc 2 "an unknown option" fl8
  contains fl8 err "unknown option: --bogus"
  h fl9 up --dir "$d" --port abc
  expect_rc 2 "a non-numeric port" fl9
  contains fl9 err "--port: want a number"
  [ ! -e "$d" ] || fail "a refused command created $d"
}

case_leak_scan_detects() {
  local d=$TMP/lk spec mode want smoke
  # MODE:WHERE the leak scan must name:CATS_SMOKE. Every planted value is a real
  # secret of that run (ruling 39), planted by the fake.
  for spec in agent-bearer:cats.log:0 admin-bearer:report:0 server-log-bearer:server.log:0 \
    credential:report:0 enrollment:report:0 smoke-dir:smoke:1 smoke-line:smoke.txt:1; do
    mode=${spec%%:*}
    want=${spec#*:}
    smoke=${want#*:}
    want=${want%%:*}
    CATS_SMOKE=$smoke CATS_FAKE_PLANT=$mode h "lk-$mode" run --dir "$d" --out "$TMP/out-lk-$mode" --paths /v1/discover
    expect_rc 1 "a planted $mode value" "lk-$mode"
    contains "lk-$mode" out 'bearer leaked into'
    contains "lk-$mode" out "$want"
    # Names only: the run never prints a value.
    if grep -q -e 'eyJ' -e 'abe_' "$TMP/cap/lk-$mode.out" "$TMP/cap/lk-$mode.err"; then fail "the $mode run printed a secret-shaped value"; fi
    [ ! -e "$d" ] || fail "the failed run left $d"
  done
}

# Ruling 39: the spec's example tokens (a JWT, an abe_ token) are expected
# content; only this run's own secrets count.
case_leak_scan_ignores_spec_examples() {
  local d=$TMP/lk2
  CATS_FAKE_PLANT=spec-examples h lk-spec run --dir "$d" --out "$TMP/out-lk-spec" --paths /v1/discover
  expect_rc 0 "spec-example tokens in the report" lk-spec
  if grep -q -F 'bearer leaked' "$TMP/cap/lk-spec.out"; then fail "the scan fired on a spec-example token"; fi
  grep -r -q -F 'eyJfake' "$TMP/out-lk-spec" || fail "the fake did not plant the spec-example JWT (the case proves nothing)"
  [ ! -e "$d" ] || fail "$d remains"
}

case_smoke_runs() {
  local d=$TMP/sm
  : >"$CATS_FAKE_LOG"
  CATS_SMOKE=1 h sm1 run --dir "$d" --out "$TMP/out-sm" --paths /v1/discover
  expect_rc 0 "run with CATS_SMOKE=1" sm1
  [ "$(head -n 1 "$CATS_FAKE_LOG")" = smoke ] || fail "the first cats call was not smoke"
  [ "$(cat "$TMP/out-sm/smoke.txt" 2>/dev/null)" = 'Summary: fake' ] || fail "smoke.txt does not hold the smoke summary line"
}

case_fake_rejects_bad_headers() {
  local f=$TMP/badheaders.yml o=$TMP/fake-out rc=0
  printf 'all:\n  Authorization: Bearer fake-secret-value\n' >"$f"
  chmod 644 "$f"
  : >"$CATS_FAKE_LOG"
  "$FAKE" -c x --headers="$f" -o "$o" >"$TMP/cap/fk.out" 2>&1 || rc=$?
  [ "$rc" -eq 9 ] || fail "wrong mode: exit $rc, want 9"
  grep -q 'fake-cats: FAIL' "$TMP/cap/fk.out" || fail "no FAIL line for a wrong mode"
  chmod 600 "$f"
  rc=0
  "$FAKE" -c x --headers="$f" -o "$o" >"$TMP/cap/fk.out" 2>&1 || rc=$?
  [ "$rc" -eq 9 ] || fail "missing admin key: exit $rc, want 9"
  if grep -q 'fake-secret-value' "$TMP/cap/fk.out"; then fail "the fake printed a header value"; fi
  rc=0
  "$FAKE" smoke -c x >"$TMP/cap/fk.out" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] || ! grep -q '^Summary: fake$' "$TMP/cap/fk.out"; then fail "smoke: exit $rc or no summary"; fi
}

case_real_campaign() {
  local d=$TMP/real n
  CATS_BIN=cats h real1 run --dir "$d" --out "$TMP/out-real" --paths /v1/discover,/v1/channels
  expect_rc 0 "real run" real1
  n=$(sed -n 's/.*tests=\([0-9]*\) .*/\1/p' "$TMP/cap/real1.out")
  [ "${n:-0}" -gt 500 ] || fail "tests=${n:-none}, want above 500"
}

# Order matters: the first cases share the run of case 1 and the server of
# refdata-recorded, which later cases use and then run over.
run_case run-completes case_run_completes
run_case argv-recorded case_argv_recorded
run_case headers-file-removed case_headers_file_removed
run_case refdata-recorded case_refdata_recorded
run_case seed-recreates-decoys case_seed_recreates_decoys
run_case token-prints-one-line case_token_prints_one_line
run_case no-bearer-leaks case_no_bearer_leaks
run_case second-up-refused case_second_up_refused
run_case server-argv case_server_argv
run_case leftovers-cleaned case_leftovers_cleaned
run_case down-removes-dir case_down_removes_dir
run_case skip-paths-vs-paths case_skip_paths_vs_paths
run_case no-skip-skips-fixture-check case_no_skip_skips_fixture_check
run_case cats-not-found case_cats_not_found
run_case shellcheck case_shellcheck
run_case admin-paths-match-spec case_admin_paths_match_spec
run_case dir-guard case_dir_guard
run_case dir-symlink-and-dots case_dir_symlink_dots
run_case overlapping-runs case_overlap
run_case repo-checks case_repo_checks
run_case flag-checks case_flag_checks
run_case leak-scan-detects case_leak_scan_detects
run_case leak-scan-ignores-spec-examples case_leak_scan_ignores_spec_examples
run_case smoke-runs case_smoke_runs
run_case fake-rejects-bad-headers case_fake_rejects_bad_headers
if [ "$REAL" -eq 1 ]; then
  run_case real-campaign case_real_campaign
fi

if [ "$RECORDED" -eq 1 ]; then
  echo "cats-harness-selftest: expectations were recorded, not compared; run again without --record"
  [ "${#FAILED[@]}" -gt 0 ] && echo "cats-harness-selftest: failed: ${FAILED[*]}"
  exit 1
fi
if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "cats-harness-selftest: $RUNS cases, ${#FAILED[@]} failed: ${FAILED[*]}"
  exit 1
fi
echo "cats-harness-selftest: $RUNS cases, all passed"
