#!/usr/bin/env bash
# verify-linux-selftest.sh: tests scripts/verify-linux.sh against a fake docker
# (scripts/testdata/verify-linux/docker, Definition of Done C). No Docker is
# touched. Prints only `cases: N passed: N failed: N` and the failed case names;
# a failed case's files stay in the temporary directory named on failure.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
SCRIPT=$ROOT/scripts/verify-linux.sh
FAKE=$ROOT/scripts/testdata/verify-linux/docker
[ -f "$SCRIPT" ] || { echo "verify-linux-selftest: $SCRIPT does not exist" >&2; exit 2; }
SHA=$(git -C "$ROOT" rev-parse HEAD)

TMP=$(mktemp -d "${TMPDIR:-/tmp}/verify-linux-selftest.XXXXXX")
KEEP=0
trap '[ "$KEEP" = 1 ] || rm -rf "$TMP"' EXIT

PASSED=0 FAILED=0 FAILED_NAMES="" CASE="" CASE_FAILS=""
CDIR="" STATE="" CALLS="" OUT="" ERR="" RC=0

fail() { CASE_FAILS="$CASE_FAILS
  $*"; }
setup_case() {
  CASE=$1 CASE_FAILS=""
  CDIR=$TMP/$1 STATE=$CDIR/state CALLS=$CDIR/calls.log OUT=$CDIR/stdout ERR=$CDIR/stderr
  mkdir -p "$STATE"
  : >"$CALLS"
}
run_script() { # [env VAR=VALUE]...
  RC=0
  env AGENTMESH_DEV_STATE="$STATE" AGENTMESH_DOCKER="$FAKE" VL_CALLS="$CALLS" \
    AGENTMESH_VERIFY_LINUX_PG_TRIES=3 AGENTMESH_VERIFY_LINUX_POLL_SECONDS=0 \
    "$@" bash "$SCRIPT" HEAD >"$OUT" 2>"$ERR" || RC=$?
}
expect_rc() { [ "$RC" = "$1" ] || fail "exit $RC, want $1 (stderr: $(head -c 300 "$ERR" | tr '\n' ' '))"; }
expect_msg() { cat "$OUT" "$ERR" | grep -qF -- "$1" || fail "output lacks: $1"; }
expect_out() { grep -qF -- "$1" "$OUT" || fail "stdout lacks: $1"; }
expect_call() { grep -qE -- "$1" "$CALLS" || fail "no docker call matching: $1"; }
expect_no_call() { ! grep -qE -- "$1" "$CALLS" || fail "unexpected docker call matching: $1"; }
expect_cleanup() {
  expect_call '^rm -f agentmesh-verify-linux-test-[0-9]+ agentmesh-verify-linux-pg-[0-9]+'
  expect_call '^network rm agentmesh-verify-linux-[0-9]+$'
}
expect_pass() { [ -f "$STATE/passes/verify-linux/$SHA" ] || fail "no pass recorded"; }
expect_no_pass() { [ ! -e "$STATE/passes/verify-linux/$SHA" ] || fail "a pass is recorded"; }
finish_case() {
  if [ -z "$CASE_FAILS" ]; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1)) FAILED_NAMES="$FAILED_NAMES $CASE" KEEP=1
    printf '%s\n' "$CASE_FAILS" >"$CDIR/failures"
  fi
}

case_docker_down() {
  setup_case docker-down
  run_script VL_INFO_FAIL=1
  expect_rc 2
  expect_msg "Docker"
  expect_no_call '^network create'
  expect_no_pass
  finish_case
}
case_pg_never_ready() {
  setup_case pg-never-ready
  run_script VL_PG_NEVER_READY=1
  expect_rc 3
  expect_msg "Postgres"
  expect_no_call 'make test'
  expect_cleanup
  expect_no_pass
  finish_case
}
case_test_fails() {
  setup_case test-fails
  run_script VL_TEST_RC=1 'VL_TEST_LOG=--- FAIL: TestBar (0.01s)
FAIL	example.com/pkg	0.1s'
  expect_rc 1
  expect_out "TestBar"
  expect_out "example.com/pkg"
  expect_cleanup
  expect_no_pass
  finish_case
}
case_container_cannot_run() {
  setup_case container-cannot-run
  run_script VL_TEST_RC=125
  expect_rc 3
  expect_cleanup
  expect_no_pass
  finish_case
}
case_happy() {
  setup_case happy
  run_script
  expect_rc 0
  expect_out "result: passed"
  expect_pass
  expect_cleanup
  expect_call '^network create agentmesh-verify-linux-[0-9]+$'
  expect_call 'cgr\.dev/chainguard/postgres:latest@sha256:0926ac72'
  expect_call 'POSTGRES_USER=agentmesh'
  expect_call '--platform linux/arm64'
  expect_call 'golang:1\.27\.3-bookworm@sha256:[0-9a-f]{64} make test test-conformance'
  expect_call ':/src:ro'
  expect_call 'agentmesh-verify-linux-gomod:/go/pkg/mod'
  expect_call 'agentmesh-verify-linux-gocache:/root/.cache/go-build'
  expect_call 'AGENTMESH_TEST_POSTGRES_DSN=postgres://agentmesh:agentmesh@agentmesh-verify-linux-pg-[0-9]+:5432/agentmesh\?sslmode=disable'
  expect_call 'GOFLAGS=-buildvcs=false'
  expect_no_call 'docker\.sock'
  [ -s "$STATE/logs/verify-linux/$SHA/test.log" ] || fail "no test.log"
  finish_case
}
case_second_run_reruns() {
  setup_case second-run-reruns
  run_script
  expect_pass
  : >"$CALLS"
  run_script
  expect_rc 0
  expect_call 'make test test-conformance'
  expect_pass
  # A failing rerun clears the earlier pass.
  run_script VL_TEST_RC=1
  expect_rc 1
  expect_no_pass
  finish_case
}
case_bad_commit() {
  setup_case bad-commit
  RC=0
  env AGENTMESH_DEV_STATE="$STATE" AGENTMESH_DOCKER="$FAKE" VL_CALLS="$CALLS" \
    bash "$SCRIPT" no-such-commit >"$OUT" 2>"$ERR" || RC=$?
  expect_rc 2
  expect_msg "no-such-commit"
  expect_no_call '.'
  finish_case
}

for c in docker_down pg_never_ready test_fails container_cannot_run happy second_run_reruns bad_commit; do
  "case_$c"
done

echo "cases: $((PASSED + FAILED)) passed: $PASSED failed: $FAILED"
if [ "$FAILED" -gt 0 ]; then
  echo "failed:$FAILED_NAMES"
  echo "details: $TMP/<case>/failures"
  exit 1
fi
