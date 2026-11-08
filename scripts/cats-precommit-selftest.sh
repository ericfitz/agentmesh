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
    echo "cats-precommit-selftest: (shellcheck absent)"
    return 0
  fi
  shellcheck -x "$ROOT/.githooks/pre-commit" "$ROOT/scripts/cats-precommit.sh" \
    "$ROOT/scripts/cats-precommit-selftest.sh" >"$TMP/sc.txt" 2>&1 ||
    fail "shellcheck: $(head -n 8 "$TMP/sc.txt" | tr '\n' '|')"
}

HOOK_CATS_BIN=
run_case no-spec-change case_no_spec_change
run_case doc-only-skips case_doc_only_skips
run_case change-runs-widened-paths case_change_runs_widened_paths
run_case recorded-fp-passes case_recorded_fp_passes
run_case stale-gen-blocks case_stale_gen_blocks
run_case missing-cats-fails-closed case_missing_cats_fails_closed
run_case shellcheck case_shellcheck

if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "cats-precommit-selftest: $RUNS cases, ${#FAILED[@]} failed: ${FAILED[*]}"
  exit 1
fi
echo "cats-precommit-selftest: $RUNS cases, all passed"
