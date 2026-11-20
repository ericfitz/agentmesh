#!/usr/bin/env bash
# windows-test-selftest.sh: tests scripts/windows-test.sh against a fake vmrun and
# a fake security (scripts/testdata/windows-test/, Definition of Done C). No VM,
# Fusion or Keychain item is touched: the script reaches both only through the
# seams AGENTMESH_VMRUN and AGENTMESH_SECURITY. Every case runs; the exit code is
# 1 when any failed. Prints only `cases: N passed: N failed: N` and the failed
# case names; each case's stdout, stderr, calls.log and state directory stay in
# the temporary directory named on a failure (kept only then).
#
# State (Definition of Done D): everything lives under one mktemp directory that
# the EXIT trap removes (kept on failure); a second run starts from nothing.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
SCRIPT=$ROOT/scripts/windows-test.sh
DATA=$ROOT/scripts/testdata/windows-test
SOURCE_VMX="$HOME/Virtual Machines.localized/Windows 11 64-bit Arm.vmwarevm/Windows 11 64-bit Arm.vmx"
FAKE_VM_PW=FAKE-VM-PASS-7f3a
FAKE_GUEST_PW=FAKE-GUEST-PASS-91bc

for t in zip unzip iconv perl git; do
  command -v "$t" >/dev/null || { echo "windows-test-selftest: $t is not installed" >&2; exit 2; }
done
[ -x "$SCRIPT" ] || [ -f "$SCRIPT" ] || { echo "windows-test-selftest: $SCRIPT does not exist" >&2; exit 2; }

unset AGENTMESH_WINDOWS_TEST_VMX AGENTMESH_WINDOWS_TEST_TOOLS_TIMEOUT AGENTMESH_WINDOWS_TEST_RUN_TIMEOUT \
  AGENTMESH_WINDOWS_TEST_POLL_SECONDS AGENTMESH_WINDOWS_TEST_CALL_TIMEOUT
SHA=$(git -C "$ROOT" rev-parse HEAD)

TMP=$(mktemp -d "${TMPDIR:-/tmp}/windows-test-selftest.XXXXXX")
KEEP=0
trap '[ "$KEEP" = 1 ] || rm -rf "$TMP"' EXIT

PASSED=0
FAILED=0
FAILED_NAMES=""
CASE=""
CASE_FAILS=""

# Per-case paths, set by setup_case.
FIXTURE="" CDIR="" STATE="" VMX="" CALLS="" OUT="" ERR=""

fail() { CASE_FAILS="$CASE_FAILS
  $*"; }

setup_case() { # NAME [fixture directory name, default NAME]
  CASE=$1
  FIXTURE=${2:-$1}
  CASE_FAILS=""
  CDIR=$TMP/$1
  STATE=$CDIR/state
  VMX=$CDIR/test.vmx
  CALLS=$CDIR/calls.log
  OUT=$CDIR/stdout
  ERR=$CDIR/stderr
  mkdir -p "$CDIR" "$STATE"
  : >"$VMX"
  : >"$CALLS"
  rm -f "$CALLS".once.*
}

# run_script [env VAR=VALUE]...: run windows-test.sh HEAD, set RC, fill OUT and ERR.
run_script() {
  : >"$CALLS"
  rm -f "$CALLS".once.*
  RC=0
  env AGENTMESH_DEV_STATE="$STATE" \
    AGENTMESH_VMRUN="$DATA/vmrun" AGENTMESH_SECURITY="$DATA/security" \
    AGENTMESH_WINDOWS_TEST_VMX="${WT_VMX_OVERRIDE:-$VMX}" \
    AGENTMESH_WINDOWS_TEST_POLL_SECONDS=1 \
    WT_CASE_DIR="$DATA/$FIXTURE" WT_BASE_DIR="$DATA/happy" WT_CALLS="$CALLS" WT_VMX="$VMX" \
    "$@" bash "$SCRIPT" HEAD >"$OUT" 2>"$ERR" || RC=$?
}

expect_rc() { [ "$RC" = "$1" ] || fail "exit $RC, want $1 (stderr: $(head -c 300 "$ERR" | tr '\n' ' '))"; }
expect_msg() { # fixed string in stdout or stderr
  cat "$OUT" "$ERR" | grep -qF -- "$1" || fail "output lacks: $1"
}
expect_out() { grep -qF -- "$1" "$OUT" || fail "stdout lacks: $1"; }
expect_called() { cut -d' ' -f1 "$CALLS" | grep -qx -- "$1" || fail "no $1 call"; }
expect_not_called() { ! cut -d' ' -f1 "$CALLS" | grep -qx -- "$1" || fail "unexpected $1 call"; }
expect_stop_hard() {
  grep -E '^stop \|' "$CALLS" | grep -q " stop .* hard" || fail "no 'stop ... hard' call"
}
expect_no_lock() { [ ! -e "$STATE/windows-test.lock" ] || fail "lock file remains"; [ ! -e "$STATE/windows-test.lock.d" ] || fail "lock mutex remains"; }
expect_pass() { [ -f "$STATE/passes/windows-test/$SHA" ] || fail "no pass recorded"; }
expect_no_pass() { [ ! -e "$STATE/passes/windows-test/$SHA" ] || fail "a pass is recorded"; }
expect_no_secrets() {
  if grep -rqF -e "$FAKE_VM_PW" -e "$FAKE_GUEST_PW" "$OUT" "$ERR" "$STATE" "$CALLS" 2>/dev/null; then
    fail "a fake password appears on stdout, stderr, in a log or in calls.log"
  fi
}
# The sequence of vmrun commands, consecutive duplicates collapsed.
vmrun_seq() { grep -v '^security ' "$CALLS" | cut -d' ' -f1 | uniq | tr '\n' ' ' | sed 's/ $//'; }

finish_case() {
  expect_no_secrets
  if [ -z "$CASE_FAILS" ]; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1))
    FAILED_NAMES="$FAILED_NAMES $CASE"
    KEEP=1
    printf '%s\n' "$CASE_FAILS" >"$CDIR/failures"
  fi
}

dead_pid() { # a PID that is not running
  bash -c 'exit 0' &
  local p=$!
  wait "$p" || true
  echo "$p"
}

HAPPY_SEQ="list revertToSnapshot start checkToolsState runProgramInGuest CopyFileFromHostToGuest runProgramInGuest CopyFileFromGuestToHost stop"

case_happy() {
  setup_case happy
  run_script
  expect_rc 0
  expect_out "steps: 11 passed: 11 failed: 0"
  expect_out "$STATE/logs/windows-test/$SHA"
  [ "$(vmrun_seq)" = "$HAPPY_SEQ" ] || fail "call sequence: $(vmrun_seq)"
  grep -E '^revertToSnapshot ' "$CALLS" | grep -q ' baseline$' || fail "revert is not to baseline"
  grep -E '^start ' "$CALLS" | grep -q ' nogui$' || fail "start is not nogui"
  [ "$(grep -c '^CopyFileFromHostToGuest ' "$CALLS")" = 2 ] || fail "want 2 host-to-guest copies (zip and job.ps1)"
  expect_pass
  expect_no_lock
  [ -f "$STATE/logs/windows-test/$SHA/src.zip" ] || fail "no archive in the log directory"
  [ -f "$STATE/logs/windows-test/$SHA/guest/go-test-arm64.log" ] || fail "guest logs not unpacked"
  grep -q 'github.com/example/pkg' "$STATE/logs/windows-test/$SHA/job.out.txt" || fail "job.out not converted from UTF-16"
  # A second run starts from the snapshot again and passes the same way.
  run_script
  expect_rc 0
  [ "$(vmrun_seq)" = "$HAPPY_SEQ" ] || fail "second run call sequence: $(vmrun_seq)"
  expect_no_lock
  finish_case
}

case_test_fails() {
  setup_case test-fails
  run_script
  expect_rc 1
  expect_out "steps: 11 passed: 10 failed: 1"
  expect_out "go-test-arm64"
  expect_out "TestFoo"
  expect_no_pass
  expect_stop_hard
  expect_no_lock
  finish_case
}

case_stale_pass_cleared() {
  # A failed rerun of a commit must not leave the pass an earlier run recorded.
  setup_case stale-pass-cleared test-fails
  mkdir -p "$STATE/passes/windows-test"
  : >"$STATE/passes/windows-test/$SHA"
  run_script
  expect_rc 1
  expect_no_pass
  finish_case
}

case_tools_timeout() {
  setup_case tools-timeout
  run_script AGENTMESH_WINDOWS_TEST_TOOLS_TIMEOUT=2
  expect_rc 3
  expect_stop_hard
  expect_no_lock
  expect_no_pass
  expect_not_called CopyFileFromHostToGuest
  finish_case
}

case_already_running() {
  setup_case already-running
  plant_files
  run_script
  expect_rc 2
  expect_msg "$VMX"
  expect_msg "vmrun stop"
  expect_not_called revertToSnapshot
  expect_not_called start
  expect_no_lock
  expect_planted
  finish_case
}

case_stale_lock() {
  setup_case stale-lock
  echo "$(dead_pid) 1700000000" >"$STATE/windows-test.lock"
  run_script
  expect_rc 0
  [ "$(vmrun_seq | cut -d' ' -f1-3)" = "list stop revertToSnapshot" ] || fail "stale VM not stopped before the revert: $(vmrun_seq)"
  expect_no_lock
  expect_pass
  finish_case
}

# plant_files: a recorded pass and a log file for the commit, as a live run or an
# earlier pass would hold them; a refused run must leave both intact.
plant_files() {
  mkdir -p "$STATE/passes/windows-test" "$STATE/logs/windows-test/$SHA"
  : >"$STATE/passes/windows-test/$SHA"
  echo live >"$STATE/logs/windows-test/$SHA/src.zip"
}
expect_planted() {
  [ -f "$STATE/passes/windows-test/$SHA" ] || fail "a refused run deleted the recorded pass"
  [ "$(cat "$STATE/logs/windows-test/$SHA/src.zip" 2>/dev/null)" = live ] || fail "a refused run wiped the live run's log files"
}

case_live_lock() {
  setup_case live-lock
  plant_files
  echo "$$ $(date +%s)" >"$STATE/windows-test.lock"
  run_script
  expect_rc 2
  expect_msg "$$"
  expect_not_called revertToSnapshot
  [ -f "$STATE/windows-test.lock" ] || fail "the live run's lock was removed"
  expect_planted
  finish_case
}

case_bad_lock() {
  setup_case bad-lock
  plant_files
  echo "not a lock" >"$STATE/windows-test.lock"
  run_script
  expect_rc 2
  expect_msg "windows-test.lock"
  expect_not_called revertToSnapshot
  expect_planted
  finish_case
}

case_no_keychain() {
  setup_case no-keychain
  run_script
  expect_rc 2
  expect_msg "agentmesh-windows-test"
  expect_msg "vm-encryption"
  expect_msg "security add-generic-password -U -s agentmesh-windows-test -a vm-encryption"
  [ ! -s "$CALLS" ] || ! grep -qv '^security ' "$CALLS" || fail "vmrun was called"
  expect_no_lock
  finish_case
}

case_source_vm() {
  setup_case source-vm
  WT_VMX_OVERRIDE=$SOURCE_VMX run_script
  unset WT_VMX_OVERRIDE
  expect_rc 2
  expect_msg "source VM"
  [ ! -s "$CALLS" ] || fail "a tool was called: $(head -c 200 "$CALLS")"
  finish_case
}

case_copy_back_fails() {
  setup_case copy-back-fails
  run_script
  expect_rc 3
  expect_stop_hard
  expect_no_pass
  expect_no_lock
  finish_case
}

case_sigint() {
  setup_case sigint
  : >"$CALLS"
  # shellcheck disable=SC2016  # perl code, not shell
  env AGENTMESH_DEV_STATE="$STATE" \
    AGENTMESH_VMRUN="$DATA/vmrun" AGENTMESH_SECURITY="$DATA/security" \
    AGENTMESH_WINDOWS_TEST_VMX="$VMX" AGENTMESH_WINDOWS_TEST_POLL_SECONDS=1 \
    WT_CASE_DIR="$DATA/$FIXTURE" WT_BASE_DIR="$DATA/happy" WT_CALLS="$CALLS" WT_VMX="$VMX" \
    perl -e '$SIG{INT} = "DEFAULT"; exec @ARGV' bash "$SCRIPT" HEAD >"$OUT" 2>"$ERR" &
  local pid=$! n=0
  until grep -q '^runProgramInGuest .*job\.ps1' "$CALLS" 2>/dev/null; do
    n=$((n + 1))
    if [ "$n" -gt 150 ]; then fail "the job never started"; kill -KILL "$pid" 2>/dev/null || true; break; fi
    sleep 0.2
  done
  kill -INT "$pid" 2>/dev/null || true
  RC=0
  wait "$pid" || RC=$?
  [ "$RC" -ne 0 ] || fail "exit 0 after SIGINT"
  expect_stop_hard
  expect_no_lock
  expect_no_pass
  finish_case
}

case_run_timeout() {
  setup_case run-timeout
  run_script AGENTMESH_WINDOWS_TEST_RUN_TIMEOUT=2
  expect_rc 3
  expect_msg "timed out"
  expect_stop_hard
  expect_no_lock
  finish_case
}

case_stale_baseline() {
  setup_case stale-baseline
  run_script
  expect_rc 0
  expect_out "baseline stale: refresh it (docs/windows-test.md)"
  expect_pass
  finish_case
}

case_bad_vm_password() {
  setup_case bad-vm-password
  run_script
  expect_rc 2
  expect_msg "agentmesh-windows-test"
  expect_msg "vm-encryption"
  expect_msg "security add-generic-password -U -s agentmesh-windows-test -a vm-encryption"
  expect_no_lock
  expect_no_pass
  finish_case
}

case_bad_guest_password() {
  setup_case bad-guest-password
  run_script
  expect_rc 2
  expect_msg "guest-test"
  expect_stop_hard
  expect_no_lock
  finish_case
}

case_revert_retry() {
  setup_case revert-retry
  run_script
  expect_rc 0
  [ "$(grep -c '^revertToSnapshot ' "$CALLS")" = 2 ] || fail "revert was not retried exactly once"
  finish_case
}

for c in happy test_fails stale_pass_cleared tools_timeout already_running stale_lock live_lock bad_lock \
  no_keychain source_vm copy_back_fails sigint run_timeout stale_baseline bad_vm_password \
  bad_guest_password revert_retry; do
  "case_$c"
done

echo "cases: $((PASSED + FAILED)) passed: $PASSED failed: $FAILED"
if [ "$FAILED" -gt 0 ]; then
  echo "failed:$FAILED_NAMES"
  echo "details: $TMP/<case>/failures"
  exit 1
fi
