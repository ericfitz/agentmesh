#!/usr/bin/env bash
# cats-precommit-selftest.sh: tests scripts/cats-precommit.sh against a fake
# `cats` (scripts/testdata/cats-fake/cats) in a throwaway worktree of HEAD
# (issue #30, Definition of Done C). It commits nothing and never touches the
# real index or the working tree. The files under test are copied from this
# checkout's $ROOT into the worktree (ruling 27), so uncommitted edits and the
# mutations of check-gates-selftest block 40 reach it.
#
#   scripts/cats-precommit-selftest.sh
#
# State (Definition of Done D): everything lives under one mktemp directory; the
# EXIT trap removes the worktree (git worktree remove --force, then prune),
# fails on a stray hook directory or server and removes the directory. A second
# run starts from nothing.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

unset CATS_HARNESS_DIR CATS_SMOKE CATS_IDENTITY CATS_FAKE_SLEEP CATS_FAKE_PLANT CATS_FAKE_WATCH \
  AGENTMESH_PROFILE AGENTMESH_IDENTITY AGENTMESH_SERVER AGENTMESH_CREDENTIAL \
  AGENTMESH_CONFIG_DIR AGENTMESH_DATA_DIR

TMP=$(mktemp -d "${TMPDIR:-/tmp}/cats-pc-selftest.XXXXXX")
TMP=$(cd "$TMP" && pwd -P)
WT=$TMP/wt
HOOKTMP=$TMP/hooktmp # the hook's TMPDIR: leftovers show up here
mkdir "$TMP/cap" "$HOOKTMP"
FAKE_LOG=$TMP/fake.log
UNDER_TEST=(scripts/cats-precommit.sh scripts/cats-harness.sh .githooks/pre-commit
  scripts/testdata/cats-fake tools/catscheck)

cleanup() {
  local rc=$? stray=0 d pid
  trap - EXIT INT TERM HUP
  if [ -d "$TMP" ]; then
    for d in "$HOOKTMP"/cats-precommit.*; do
      [ -e "$d" ] || continue
      echo "cats-precommit-selftest: FAIL cleanup: $d was left behind" >&2
      stray=1
    done
    for pid in $(pgrep -f "$TMP/[^ ]*/agentmesh server" 2>/dev/null || true); do
      echo "cats-precommit-selftest: FAIL cleanup: a stray server (pid $pid) had to be killed" >&2
      stray=1
      kill -KILL "$pid" 2>/dev/null || true
    done
    git -C "$ROOT" worktree remove --force "$WT" >/dev/null 2>&1 || true
    git -C "$ROOT" worktree prune >/dev/null 2>&1 || true
    rm -rf "$TMP"
  fi
  if [ "$stray" -eq 1 ] && [ "$rc" -eq 0 ]; then rc=1; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

git -C "$ROOT" worktree add --detach "$WT" HEAD >/dev/null 2>&1

CASE=
CASE_FAIL=0
FAILED=()
RUNS=0
fail() {
  echo "cats-precommit-selftest: FAIL $CASE: $*"
  CASE_FAIL=1
}
run_case() {
  CASE=$1
  CASE_FAIL=0
  RUNS=$((RUNS + 1))
  reset_wt
  "$2" || true
  if [ "$CASE_FAIL" -eq 0 ]; then
    echo "cats-precommit-selftest: ok $CASE"
  else
    FAILED+=("$CASE")
  fi
}

wt() { git -C "$WT" "$@"; }

copy_under_test() {
  local f
  for f in "${UNDER_TEST[@]}"; do
    mkdir -p "$(dirname "$WT/$f")"
    rm -rf "${WT:?}/$f"
    cp -R "$ROOT/$f" "$WT/$f"
  done
  # The hook runs the staged copy of the harness and catscheck (ruling 29), so
  # the files under test are staged too.
  wt add -A -f -- "${UNDER_TEST[@]}"
}
reset_wt() {
  wt reset -q --hard HEAD
  wt clean -fdq
  copy_under_test
  rm -f "$FAKE_LOG"
}

RC=0
# hook NAME [shim]: runs the hook in the worktree; stdout and stderr to cap/NAME.out.
hook() {
  local name=$1 entry=scripts/cats-precommit.sh
  [ "${2:-}" = shim ] && entry=.githooks/pre-commit
  RC=0
  (cd "$WT" && CATS_BIN="${HOOK_CATS_BIN:-$WT/scripts/testdata/cats-fake/cats}" \
    CATS_FAKE_LOG=$FAKE_LOG TMPDIR=$HOOKTMP \
    perl -e 'alarm 1500; exec @ARGV' bash "$entry") >"$TMP/cap/$name.out" 2>&1 || RC=$?
}
contains() { grep -q -F -e "$2" "$TMP/cap/$1.out" || fail "$1 output lacks '$2': $(head -c 400 "$TMP/cap/$1.out" | tr '\n' '|')"; }
expect_rc() { [ "$RC" -eq "$1" ] || fail "exit $RC, want $1: $(head -c 400 "$TMP/cap/$2.out" | tr '\n' '|')"; }
fake_not_run() { [ ! -e "$FAKE_LOG" ] || fail "the fake cats ran"; }

# Spec edits.
edit_description() { # a description: edit of listChannels
  awk '/operationId: listChannels/ {s=1} s && /^        Lists the channels/ {print $0 " Selftest edit."; s=0; next} {print}' \
    "$WT/api/openapi.yaml" >"$TMP/spec.new"
  cmp -s "$TMP/spec.new" "$WT/api/openapi.yaml" && fail "the description edit changed nothing"
  cp "$TMP/spec.new" "$WT/api/openapi.yaml"
}
edit_subject() { # maxLength: 256 under Task.properties.subject (type-neutral, ruling 26)
  awk '/^    Task:$/ {t=1; print; next} t && /^    [A-Za-z]/ {t=0}
       t && /^        subject:$/ {print; s=1; next}
       s && /^          type: string$/ {print; print "          maxLength: 256"; s=0; t=0; next}
       {print}' "$WT/api/openapi.yaml" >"$TMP/spec.new"
  cmp -s "$TMP/spec.new" "$WT/api/openapi.yaml" && fail "the subject edit changed nothing"
  cp "$TMP/spec.new" "$WT/api/openapi.yaml"
}
stage_change() { # the subject edit with the regenerated internal/gen
  edit_subject
  (cd "$WT" && make generate >/dev/null 2>&1) || fail "make generate failed in the worktree"
  wt add api/openapi.yaml internal/gen
}

case_no_spec_change() {
  echo selftest >>"$WT/README.md"
  wt add README.md
  hook nsc shim
  expect_rc 0 nsc
  [ ! -s "$TMP/cap/nsc.out" ] || fail "output is not empty"
  fake_not_run
}

case_doc_only_skips() {
  edit_description
  wt add api/openapi.yaml
  hook doc
  expect_rc 0 doc
  contains doc 'documentation-only'
  fake_not_run
}

case_change_runs_widened_paths() {
  stage_change
  hook chg
  expect_rc 1 chg
  contains chg 'fuzzing 4 changed path(s)'
  contains chg 'finding(s) not covered'
  grep -q -x -F -e '--paths=/v1/channels/{channel}/tasks,/v1/tasks/{id},/v1/tasks/{id}/claim,/v1/tasks/{id}/release' "$FAKE_LOG" 2>/dev/null ||
    fail "the fake's argv lacks the four task paths"
}

case_recorded_fp_passes() {
  local rc=0
  (cd "$WT" && go build -o "$TMP/catscheck" ./tools/catscheck &&
    "$TMP/catscheck" classify --rules api/cats-false-positives.yaml scripts/testdata/cats-fake/report) \
    >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 1 ] || fail "the committed rules already match the fake's records (exit $rc); ruling 30"
  cat >>"$WT/api/cats-false-positives.yaml" <<'YAML'

  - id: FAKE_CATS_SELFTEST
    why: the fake cats's records; selftest only
    when: {fuzzer: FakeCatsFuzzer, response_code: {in: [400, 404]}}
YAML
  stage_change
  wt add api/cats-false-positives.yaml
  hook fp
  expect_rc 0 fp
  contains fp 'no finding'
}

case_stale_gen_blocks() {
  edit_subject
  wt add api/openapi.yaml
  hook stale
  expect_rc 1 stale
  contains stale 'internal/gen is stale'
  fake_not_run
}

case_missing_cats_fails_closed() {
  stage_change
  HOOK_CATS_BIN=/nonexistent hook miss
  HOOK_CATS_BIN=
  expect_rc 1 miss
  contains miss 'is not installed'
  fake_not_run
}

case_shellcheck() {
  if ! command -v shellcheck >/dev/null 2>&1; then
    fail "shellcheck is not installed"
    return 0
  fi
  shellcheck -x "$ROOT/.githooks/pre-commit" "$ROOT/scripts/cats-precommit.sh" \
    "$ROOT/scripts/cats-precommit-selftest.sh" >"$TMP/sc.txt" 2>&1 ||
    fail "shellcheck: $(head -n 8 "$TMP/sc.txt" | tr '\n' '|')"
}

edit_servers() { # a servers[0].url edit: widens to every path
  awk '/^servers:/ {s=1} s && /^  - url: / {print $0 "1"; s=0; next} {print}' "$WT/api/openapi.yaml" >"$TMP/spec.new"
  cmp -s "$TMP/spec.new" "$WT/api/openapi.yaml" && fail "the servers edit changed nothing"
  cp "$TMP/spec.new" "$WT/api/openapi.yaml"
}
edit_bridge() { # maxLength: 64 under Bridge.properties.slack_name: only the bridges paths
  awk '/^    Bridge:$/ {t=1; print; next} t && /^    [A-Za-z]/ {t=0}
       t && /^        slack_name:$/ {print; s=1; next}
       s && /^          type: string$/ {print; print "          maxLength: 64"; s=0; t=0; next}
       {print}' "$WT/api/openapi.yaml" >"$TMP/spec.new"
  cmp -s "$TMP/spec.new" "$WT/api/openapi.yaml" && fail "the bridge edit changed nothing"
  cp "$TMP/spec.new" "$WT/api/openapi.yaml"
}
stage_with() { # stage_with EDIT_FUNCTION: the edit and the regenerated internal/gen
  "$1"
  (cd "$WT" && make generate >/dev/null 2>&1) || fail "make generate failed in the worktree"
  wt add api/openapi.yaml internal/gen
}
# A stand-in catscheck (staged, so the hook builds it): the exit codes and the
# paths come from the environment.
stage_stub() {
  rm -rf "${WT:?}/tools/catscheck"
  mkdir -p "$WT/tools/catscheck"
  cat >"$WT/tools/catscheck/main.go" <<'GO'
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	var env, out string
	switch os.Args[1] {
	case "changed-paths":
		env, out = "CATS_STUB_CP_EXIT", os.Getenv("CATS_STUB_PATHS")
	default:
		env = "CATS_STUB_CL_EXIT"
	}
	code, _ := strconv.Atoi(os.Getenv(env))
	if out != "" {
		fmt.Println(strings.ReplaceAll(out, ",", "\n"))
	}
	os.Exit(code)
}
GO
  wt add -A tools/catscheck
}

count_lines() { grep -c -E -e "$1" "$2" 2>/dev/null || true; }

case_partition_widened() {
  stage_with edit_servers
  CATS_FAKE_KILL_FIXTURE=destructive hook wide
  expect_rc 1 wide
  contains wide 'not fuzzing /v1/admin/bridges (no Slack bridge in the campaign server; ADR 0018)'
  contains wide 'not fuzzing /v1/admin/bridges/{channel} (no Slack bridge in the campaign server; ADR 0018)'
  local p
  for p in /v1/admin/reset /v1/admin/signing-keys/rotate '/v1/admin/identities/{identity}/reset-credential'; do
    grep -q -x -F -e "--paths=$p" "$FAKE_LOG" 2>/dev/null || fail "no single-path run of $p"
  done
  [ "$(count_lines '^--paths=' "$FAKE_LOG")" -eq 4 ] || fail "want 4 runs (3 destructive plus the main one)"
  [ "$(count_lines '^--skipPaths=' "$FAKE_LOG")" -eq 0 ] || fail "--skipPaths= was passed with --paths"
  local main
  main=,$(grep -E '^--paths=.*,' "$FAKE_LOG" | head -n 1 | sed 's/^--paths=//'),
  for p in /v1/admin/reset /v1/admin/signing-keys/rotate '/v1/admin/identities/{identity}/reset-credential' \
    /v1/admin/bridges '/v1/admin/bridges/{channel}'; do
    case "$main" in *",$p,"*) fail "the main run holds $p" ;; esac
  done
  # The destructive runs killed a fixture and were still classified (Finding 1).
  contains wide '8 finding(s) not covered'
  if grep -q -F 'harness failed' "$TMP/cap/wide.out"; then fail "a destructive run was judged by the fixture check"; fi
}

case_partition_bridges_only() {
  stage_with edit_bridge
  hook brg
  expect_rc 0 brg
  contains brg 'not fuzzing /v1/admin/bridges'
  contains brg 'only bridges paths changed; nothing to fuzz'
  fake_not_run
}

case_catscheck_exit_codes() {
  stage_with edit_subject
  stage_stub
  CATS_STUB_CP_EXIT=2 hook cs2
  expect_rc 1 cs2
  contains cs2 'changed-paths failed (exit 2)'
  CATS_STUB_CP_EXIT=7 hook cs7
  expect_rc 1 cs7
  contains cs7 'changed-paths failed (exit 7)'
  CATS_STUB_CP_EXIT=10 hook cs10
  expect_rc 1 cs10
  contains cs10 'catscheck contract violated'
  fake_not_run
}

case_classify_exit_2() {
  stage_with edit_subject
  stage_stub
  CATS_STUB_CP_EXIT=10 CATS_STUB_PATHS=/v1/discover CATS_STUB_CL_EXIT=2 hook cl2
  expect_rc 1 cl2
  contains cl2 'classify failed (exit 2)'
}

case_harness_nonzero() {
  stage_with edit_subject
  stage_stub
  CATS_STUB_CP_EXIT=10 CATS_STUB_PATHS=/v1/discover CATS_FAKE_PLANT=agent-bearer hook hn
  expect_rc 1 hn
  contains hn 'the CATS harness failed'
}

case_spec_deleted() {
  wt rm -q api/openapi.yaml
  hook del
  expect_rc 1 del
  contains del 'staged for deletion'
  fake_not_run
}

case_missing_curl_or_bash_guard() {
  local bin=$TMP/nocurl
  mkdir -p "$bin"
  local t
  for t in git bash go jq perl make awk grep sed cp rm mkdir mktemp cat cmp diff dirname basename date tail head tr pwd; do
    ln -sf "$(command -v "$t")" "$bin/$t" 2>/dev/null || true
  done
  stage_with edit_subject
  RC=0
  (cd "$WT" && PATH=$bin CATS_BIN=$WT/scripts/testdata/cats-fake/cats TMPDIR=$HOOKTMP bash scripts/cats-precommit.sh) >"$TMP/cap/curl.out" 2>&1 || RC=$?
  expect_rc 1 curl
  contains curl 'curl is not installed'
}

case_real_git_commit() {
  local ident=(-c user.name=selftest -c user.email=selftest@example.invalid -c "core.hooksPath=$WT/.githooks")
  local head
  # A commit the hook refuses (findings): the shim runs with GIT_DIR and GIT_INDEX_FILE set.
  stage_with edit_subject
  head=$(wt rev-parse HEAD)
  RC=0
  (cd "$WT" && CATS_BIN=$WT/scripts/testdata/cats-fake/cats CATS_FAKE_LOG=$FAKE_LOG TMPDIR=$HOOKTMP \
    perl -e 'alarm 1500; exec @ARGV' git "${ident[@]}" commit -q -m selftest) >"$TMP/cap/gc1.out" 2>&1 || RC=$?
  [ "$RC" -ne 0 ] || fail "git commit succeeded despite findings"
  contains gc1 'finding(s) not covered'
  [ "$(wt rev-parse HEAD)" = "$head" ] || fail "HEAD moved on a refused commit"
  # A documentation-only commit passes through the hook.
  wt reset -q --hard HEAD
  copy_under_test
  edit_description
  wt add api/openapi.yaml
  RC=0
  (cd "$WT" && CATS_BIN=$WT/scripts/testdata/cats-fake/cats CATS_FAKE_LOG=$FAKE_LOG TMPDIR=$HOOKTMP \
    perl -e 'alarm 1500; exec @ARGV' git "${ident[@]}" commit -q -m selftest) >"$TMP/cap/gc2.out" 2>&1 || RC=$?
  expect_rc 0 gc2
  contains gc2 'documentation-only'
  [ "$(wt rev-parse HEAD)" != "$head" ] || fail "HEAD did not move on an allowed commit"
}

case_sigterm_cleans_up() {
  stage_with edit_subject
  rm -f "$FAKE_LOG"
  local pid i
  (cd "$WT" && CATS_BIN=$WT/scripts/testdata/cats-fake/cats CATS_FAKE_LOG=$FAKE_LOG TMPDIR=$HOOKTMP CATS_FAKE_SLEEP=20 \
    exec perl -e 'alarm 300; exec @ARGV' bash scripts/cats-precommit.sh) >"$TMP/cap/term.out" 2>&1 &
  pid=$!
  for ((i = 0; i < 150; i++)); do
    [ -s "$FAKE_LOG" ] && break
    sleep 0.2
  done
  [ -s "$FAKE_LOG" ] || fail "the fake never started"
  kill -TERM "$pid" 2>/dev/null || true
  RC=0
  wait "$pid" || RC=$?
  [ "$RC" -eq 143 ] || fail "exit $RC after SIGTERM, want 143"
  pkill -f "$WT/scripts/testdata/cats-fake/cats" 2>/dev/null || true
  if pgrep -f "$HOOKTMP/[^ ]*/agentmesh server" >/dev/null 2>&1; then fail "the campaign server survived SIGTERM"; fi
  ls "$HOOKTMP"/cats-precommit.* >/dev/null 2>&1 && fail "the hook's directory survived SIGTERM"
  return 0
}

HOOK_CATS_BIN=
run_case no-spec-change case_no_spec_change
run_case doc-only-skips case_doc_only_skips
run_case change-runs-widened-paths case_change_runs_widened_paths
run_case recorded-fp-passes case_recorded_fp_passes
run_case stale-gen-blocks case_stale_gen_blocks
run_case missing-cats-fails-closed case_missing_cats_fails_closed
run_case partition-widened case_partition_widened
run_case partition-bridges-only case_partition_bridges_only
run_case catscheck-exit-codes case_catscheck_exit_codes
run_case classify-exit-2 case_classify_exit_2
run_case harness-nonzero case_harness_nonzero
run_case spec-deleted case_spec_deleted
run_case missing-curl case_missing_curl_or_bash_guard
run_case real-git-commit case_real_git_commit
run_case sigterm-cleans-up case_sigterm_cleans_up
run_case shellcheck case_shellcheck

if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "cats-precommit-selftest: $RUNS cases, ${#FAILED[@]} failed: ${FAILED[*]}"
  exit 1
fi
echo "cats-precommit-selftest: $RUNS cases, all passed"
