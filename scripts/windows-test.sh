#!/usr/bin/env bash
# windows-test.sh [COMMIT]: run the Windows checks of COMMIT (default HEAD) in the
# dedicated Windows 11 test VM, driven by VMware Fusion's vmrun (local CI spec
# section 3; guide: docs/windows-test.md). Fully unattended: revert to the
# `baseline` snapshot, start headless, wait for VMware Tools, copy a `git archive`
# of COMMIT in, run scripts/windows-test/job.ps1, copy the results back, power off.
#
# Runner contract (docs/superpowers/plans/2026-11-15-local-ci.md):
#   exit 0  every step passed
#   exit 1  a step failed (names of failed steps and tests are in the summary)
#   exit 2  usage or a precondition failed (tool, Keychain item, VM already running)
#   exit 3  infrastructure failure (Tools timeout, guest copy failed, run timed out)
# stdout carries only the summary; messages go to stderr; full logs are under
# <state dir>/logs/windows-test/<sha>/.
#
# Seams: AGENTMESH_VMRUN (default: Fusion's vmrun), AGENTMESH_SECURITY (security),
# AGENTMESH_WINDOWS_TEST_VMX (the test VM's .vmx), AGENTMESH_DEV_STATE (state dir),
# AGENTMESH_WINDOWS_TEST_TOOLS_TIMEOUT (600 s), AGENTMESH_WINDOWS_TEST_RUN_TIMEOUT
# (2700 s), AGENTMESH_WINDOWS_TEST_CALL_TIMEOUT (120 s, any other vmrun call),
# AGENTMESH_WINDOWS_TEST_POLL_SECONDS (5, the checkToolsState interval).
#
# State (Definition of Done D): a second run reverts to the snapshot, so it starts
# clean. Two runs overlap only as far as the lock: the second is refused, naming the
# first's PID. A killed run leaves the VM running and a stale lock; the next run sees
# the dead PID, powers the VM off and clears the lock. The lock is written under a
# short mutex directory (windows-test.lock.d) made with mkdir; a run killed with
# SIGKILL inside that window leaves it, and the error message names it.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=/dev/null
. "$ROOT/scripts/lib/devstate.sh"

CHECK=windows-test
SNAPSHOT=baseline
KEYCHAIN_SERVICE=agentmesh-windows-test
GUEST_USER='test'
GUEST_DIR='C:\amt'
GUEST_PS='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
SOURCE_VM_DIR="$HOME/Virtual Machines.localized/Windows 11 64-bit Arm.vmwarevm"
VMRUN=${AGENTMESH_VMRUN:-/Applications/VMware Fusion.app/Contents/Library/vmrun}
SECURITY=${AGENTMESH_SECURITY:-security}
VMX=${AGENTMESH_WINDOWS_TEST_VMX:-$HOME/Virtual Machines.localized/Windows 11 Test VM.vmwarevm/Windows 11 Test VM.vmx}
TOOLS_TIMEOUT=${AGENTMESH_WINDOWS_TEST_TOOLS_TIMEOUT:-600}
RUN_TIMEOUT=${AGENTMESH_WINDOWS_TEST_RUN_TIMEOUT:-2700}
CALL_TIMEOUT=${AGENTMESH_WINDOWS_TEST_CALL_TIMEOUT:-120}
POLL_SECONDS=${AGENTMESH_WINDOWS_TEST_POLL_SECONDS:-5}
EXPECTED_STEPS="vet-arm64 vet-tags-arm64 go-test-arm64 vet-amd64 vet-tags-amd64 go-test-amd64 ps1-parse-5 ps1-parse-7 install-selftest-5 install-5 install-7"

VMPW="" GUESTPW="" STARTED=0 LOCKED=0 CHILD="" LOGDIR="" LOCKFILE="" MUTEX="" START_EPOCH=$(date +%s)
MUTEX_PATH=""
# WORK holds only vmrun output (never a secret); cleanup removes it.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/windows-test.XXXXXX")

say() { printf '%s\n' "windows-test: $*" >&2; }
die() { # die CODE MESSAGE...
  local code=$1
  shift
  say "$*"
  exit "$code"
}

for v in TOOLS_TIMEOUT RUN_TIMEOUT CALL_TIMEOUT POLL_SECONDS; do
  case "${!v}" in '' | *[!0-9]*) die 2 "$v must be a whole number of seconds, got '${!v}'" ;; esac
done
[ $# -le 1 ] || die 2 "usage: windows-test.sh [COMMIT]"

keychain_help() { # ACCOUNT WHAT
  printf 'Keychain item service %s, account %s (%s) is missing or wrong. Create or update it with:\n  security add-generic-password -U -s %s -a %s -T /usr/bin/security -w\n(it prompts for the value; see docs/windows-test.md)' \
    "$KEYCHAIN_SERVICE" "$1" "$2" "$KEYCHAIN_SERVICE" "$1"
}

# ---- cleanup: power off if this run started the VM, then drop the lock ----
# shellcheck disable=SC2329  # runs from the EXIT trap
cleanup() {
  local rc=$?
  trap '' INT TERM
  trap - EXIT
  if [ -n "$CHILD" ]; then
    kill "$CHILD" 2>/dev/null || true
    wait "$CHILD" 2>/dev/null || true
    CHILD=""
  fi
  if [ "$STARTED" = 1 ]; then
    vm_stop_hard || say "could not power off $VMX; the next run stops it"
  fi
  if [ "$LOCKED" = 1 ] && [ -f "$LOCKFILE" ] && [ "$(cut -d' ' -f1 "$LOCKFILE" 2>/dev/null)" = "$$" ]; then
    rm -f "$LOCKFILE"
  fi
  [ -z "$MUTEX" ] || rmdir "$MUTEX" 2>/dev/null || true
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- vmrun wrapper ----
# vm TIMEOUT OUTFILE MODE ARGS...   MODE none (list), host (-vp) or guest (-vp -gu -gp).
# The call runs in the background and is waited for, so a signal reaches the trap at
# once. Passwords go on vmrun's argv (accepted by the spec) and never into a log.
vm() {
  local to=$1 out=$2 mode=$3
  shift 3
  local rc=0
  case "$mode" in
    none) vm_log "vmrun -T fusion $*" ; perl -e 'alarm shift; exec @ARGV' "$to" "$VMRUN" -T fusion "$@" >"$out" 2>&1 & ;;
    host) vm_log "vmrun -T fusion -vp REDACTED $*" ; perl -e 'alarm shift; exec @ARGV' "$to" "$VMRUN" -T fusion -vp "$VMPW" "$@" >"$out" 2>&1 & ;;
    guest) vm_log "vmrun -T fusion -vp REDACTED -gu $GUEST_USER -gp REDACTED $*" ; perl -e 'alarm shift; exec @ARGV' "$to" "$VMRUN" -T fusion -vp "$VMPW" -gu "$GUEST_USER" -gp "$GUESTPW" "$@" >"$out" 2>&1 & ;;
    *) die 2 "internal: unknown vm mode '$mode'" ;;
  esac
  CHILD=$!
  wait "$CHILD" || rc=$?
  CHILD=""
  [ -z "$LOGDIR" ] || { cat "$out" >>"$LOGDIR/vmrun.log"; }
  return "$rc"
}
vm_log() { [ -z "$LOGDIR" ] || printf '%s\n' "$*" >>"$LOGDIR/vmrun.log"; }

# vm_check OUTFILE: a vmrun answer that names a wrong password is a precondition failure.
vm_check() {
  if grep -qF 'Incorrect password' "$1"; then
    die 2 "vmrun refused the VM encryption password. $(keychain_help vm-encryption 'the VM encryption password')"
  fi
  if grep -qF 'Invalid user name or password for the guest OS' "$1"; then
    die 2 "the guest refused the account '$GUEST_USER' password. $(keychain_help guest-test "the guest account $GUEST_USER password")"
  fi
}

# vm_step WHAT TIMEOUT MODE ARGS...: run, die 3 on a failure or timeout, 2 on a wrong password.
vm_step() {
  local what=$1 to=$2 mode=$3 rc=0 out
  shift 3
  out=$WORK/step.out
  vm "$to" "$out" "$mode" "$@" || rc=$?
  vm_check "$out"
  if [ "$rc" = 142 ]; then die 3 "$what timed out after ${to}s"; fi
  if [ "$rc" -ne 0 ]; then die 3 "$what failed (exit $rc): $(head -c 300 "$out" | tr '\n' ' ')"; fi
}

# shellcheck disable=SC2329  # called from cleanup
vm_stop_hard() {
  local out=$WORK/stop.out rc=0
  vm "$CALL_TIMEOUT" "$out" host stop "$VMX" hard || rc=$?
  return "$rc"
}

# ---- 1. resolve the commit and check preconditions ----
COMMIT_ARG=${1:-HEAD}
SHA=$(git -C "$ROOT" rev-parse --verify --quiet "$COMMIT_ARG^{commit}") || die 2 "'$COMMIT_ARG' is not a commit of $ROOT"

norm() { # lowercase absolute path, symlinks resolved when the parent exists
  local d b
  d=$(dirname "$1")
  b=$(basename "$1")
  if [ -d "$d" ]; then d=$(cd "$d" && pwd -P); fi
  printf '%s/%s' "$d" "$b" | tr '[:upper:]' '[:lower:]'
}
src_norm=$(norm "$SOURCE_VM_DIR/x")
src_norm=${src_norm%/x}
vmx_norm=$(norm "$VMX")
case "$vmx_norm/" in
  "$src_norm"/*) die 2 "AGENTMESH_WINDOWS_TEST_VMX is Eric's general-use source VM ($SOURCE_VM_DIR); refusing. Point it at the test VM." ;;
esac

[ -x "$VMRUN" ] || die 2 "vmrun not found or not executable: $VMRUN (install VMware Fusion or set AGENTMESH_VMRUN)"
[ -f "$VMX" ] || die 2 "the test VM does not exist: $VMX (set it up per docs/windows-test.md or set AGENTMESH_WINDOWS_TEST_VMX)"
for t in git perl iconv unzip; do command -v "$t" >/dev/null || die 2 "$t is not installed"; done

fetch_secret() { # ACCOUNT WHAT -> stdout
  local v
  v=$("$SECURITY" find-generic-password -s "$KEYCHAIN_SERVICE" -a "$1" -w 2>/dev/null) || die 2 "$(keychain_help "$1" "$2")"
  [ -n "$v" ] || die 2 "$(keychain_help "$1" "$2")"
  printf '%s' "$v"
}
VMPW=$(fetch_secret vm-encryption 'the VM encryption password')
GUESTPW=$(fetch_secret guest-test "the guest account $GUEST_USER password")

STATE=$(devstate_dir)
LOCKFILE=$STATE/windows-test.lock
MUTEX_PATH=$STATE/windows-test.lock.d

# ---- 2. lock and the already-running check, serialized by the mutex ----
n=0
until mkdir "$MUTEX_PATH" 2>/dev/null; do
  n=$((n + 1))
  if [ "$n" -gt 50 ]; then
    die 2 "cannot take $MUTEX_PATH (another run is starting, or a killed run left it: remove the directory if no run is active)"
  fi
  sleep 0.1
done
MUTEX=$MUTEX_PATH

vm 60 "$WORK/list.out" none list || die 2 "vmrun list failed: $(head -c 300 "$WORK/list.out" | tr '\n' ' ')"
RUNNING=0
grep -qxF "$VMX" "$WORK/list.out" && RUNNING=1

STALE=0
if [ -e "$LOCKFILE" ]; then
  read -r lock_pid lock_start extra <"$LOCKFILE" || true
  case "${lock_pid:-}${lock_start:-}" in '' | *[!0-9]*) lock_bad=1 ;; *) lock_bad=0 ;; esac
  if [ "$lock_bad" = 1 ] || [ -z "${lock_pid:-}" ] || [ -z "${lock_start:-}" ] || [ -n "${extra:-}" ]; then
    die 2 "$LOCKFILE is not a lock this script wrote (want 'pid start_epoch'); remove it if no run is active"
  fi
  if kill -0 "$lock_pid" 2>/dev/null; then
    die 2 "another windows-test run is active: PID $lock_pid (started $(date -r "$lock_start" '+%F %T' 2>/dev/null || echo "$lock_start")); wait for it"
  fi
  STALE=1
fi
if [ "$RUNNING" = 1 ] && [ "$STALE" = 0 ]; then
  die 2 "the test VM is already running and no windows-test run owns it: $VMX. Stop it first (vmrun stop \"$VMX\" hard, with -vp for this encrypted VM)."
fi
if [ "$STALE" = 1 ]; then
  say "clearing the stale lock of dead PID $lock_pid"
  if [ "$RUNNING" = 1 ]; then
    say "powering off the VM the dead run left running"
    vm_step "stop of the leftover VM" "$CALL_TIMEOUT" host stop "$VMX" hard
  fi
  rm -f "$LOCKFILE"
fi
printf '%s %s\n' "$$" "$START_EPOCH" >"$LOCKFILE.tmp.$$"
mv "$LOCKFILE.tmp.$$" "$LOCKFILE"
LOCKED=1
rmdir "$MUTEX_PATH"
MUTEX=""

# Only now, owning the lock, may this run touch the commit's logs and pass record:
# a refused run (exit 2 above) must leave a live run's files and a recorded pass alone.
LOGDIR=$(devstate_logdir "$CHECK" "$SHA")
find "$LOGDIR" -mindepth 1 -delete
rm -f "$STATE/passes/$CHECK/$SHA"

# ---- 3. archive, revert, start, wait for Tools ----
git -C "$ROOT" archive --format=zip -o "$LOGDIR/src.zip" "$SHA" || die 2 "git archive of $SHA failed"

revert_out=$WORK/revert.out
rc=0
STARTED=1 # a revert that fails after the VM resumed must still be stopped by the trap
vm 120 "$revert_out" host revertToSnapshot "$VMX" "$SNAPSHOT" || rc=$?
vm_check "$revert_out"
if [ "$rc" -ne 0 ] && grep -qF 'Cannot read the virtual machine configuration file' "$revert_out"; then
  say "revertToSnapshot hit the configuration-file error once; retrying"
  rc=0
  vm 120 "$revert_out" host revertToSnapshot "$VMX" "$SNAPSHOT" || rc=$?
  vm_check "$revert_out"
fi
if [ "$rc" -ne 0 ]; then die 3 "revertToSnapshot $SNAPSHOT failed (exit $rc): $(head -c 300 "$revert_out" | tr '\n' ' ')"; fi

vm_step "start" 180 host start "$VMX" nogui

deadline=$((SECONDS + TOOLS_TIMEOUT))
while :; do
  rc=0
  vm "$CALL_TIMEOUT" "$WORK/tools.out" host checkToolsState "$VMX" || rc=$?
  vm_check "$WORK/tools.out"
  if [ "$rc" = 0 ] && [ "$(tr -d '[:space:]' <"$WORK/tools.out")" = running ]; then break; fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    die 3 "VMware Tools did not reach 'running' within ${TOOLS_TIMEOUT}s (last: $(head -c 100 "$WORK/tools.out" | tr '\n' ' '))"
  fi
  sleep "$POLL_SECONDS"
done

# ---- 4. copy in ----
vm_step "clearing $GUEST_DIR" "$CALL_TIMEOUT" guest runProgramInGuest "$VMX" "$GUEST_PS" -NoProfile -Command \
  "Remove-Item -Recurse -Force $GUEST_DIR -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force $GUEST_DIR | Out-Null"
vm_step "copying the archive in" 300 guest CopyFileFromHostToGuest "$VMX" "$LOGDIR/src.zip" "$GUEST_DIR\\src.zip"
vm_step "copying job.ps1 in" "$CALL_TIMEOUT" guest CopyFileFromHostToGuest "$VMX" "$ROOT/scripts/windows-test/job.ps1" "$GUEST_DIR\\job.ps1"

# ---- 5. run the job; its exit status is not trusted, results.txt is ----
rc=0
vm "$RUN_TIMEOUT" "$WORK/job.run" guest runProgramInGuest "$VMX" "$GUEST_PS" -NoProfile -ExecutionPolicy Bypass -Command \
  "& '$GUEST_DIR\\job.ps1' *> '$GUEST_DIR\\job.out'" || rc=$?
vm_check "$WORK/job.run"
if [ "$rc" = 142 ]; then die 3 "the job timed out after ${RUN_TIMEOUT}s"; fi
[ "$rc" = 0 ] || say "the job's runProgramInGuest exited $rc; reading the results anyway"

# ---- 6. copy back; a result that cannot be copied counts as failed (exit 3) ----
vm_step "copying results.txt back" "$CALL_TIMEOUT" guest CopyFileFromGuestToHost "$VMX" "$GUEST_DIR\\out\\results.txt" "$LOGDIR/results.txt"
vm_step "copying job.out back" "$CALL_TIMEOUT" guest CopyFileFromGuestToHost "$VMX" "$GUEST_DIR\\job.out" "$LOGDIR/job.out"
vm_step "copying the step logs back" "$CALL_TIMEOUT" guest CopyFileFromGuestToHost "$VMX" "$GUEST_DIR\\logs.zip" "$LOGDIR/logs.zip"
iconv -f UTF-16 -t UTF-8 <"$LOGDIR/job.out" >"$LOGDIR/job.out.txt" 2>/dev/null || cp "$LOGDIR/job.out" "$LOGDIR/job.out.txt"
mkdir -p "$LOGDIR/guest"
unzip -q -o "$LOGDIR/logs.zip" -d "$LOGDIR/guest" || die 3 "logs.zip from the guest is not a valid archive"

# ---- summary ----
tr -d '\r' <"$LOGDIR/results.txt" >"$WORK/results.clean"
steps=0 passed=0 failed_steps=""
seen=" "
while read -r kind name status extra; do
  [ "$kind" = STEP ] || continue
  [ -z "${extra:-}" ] || die 3 "malformed result line in $LOGDIR/results.txt: STEP $name $status $extra"
  case " $EXPECTED_STEPS " in *" $name "*) ;; *) die 3 "unknown step '$name' in $LOGDIR/results.txt" ;; esac
  case "$seen" in *" $name "*) die 3 "step '$name' appears twice in $LOGDIR/results.txt" ;; esac
  seen="$seen$name "
  steps=$((steps + 1))
  if [ "$status" = PASS ]; then passed=$((passed + 1)); else failed_steps="$failed_steps $name"; fi
done <"$WORK/results.clean"
missing=""
for s in $EXPECTED_STEPS; do case "$seen" in *" $s "*) ;; *) missing="$missing $s" ;; esac; done
[ -z "$missing" ] || die 3 "the job did not report these steps:$missing (see $LOGDIR/job.out.txt)"
failed=$((steps - passed))

summary() {
  echo "windows-test: commit $SHA"
  echo "steps: $steps passed: $passed failed: $failed"
  if [ -n "$failed_steps" ]; then
    echo "failed steps:$failed_steps"
    tests=$(sed -n 's/^FAILED //p' "$WORK/results.clean" | sort -u | tr '\n' ' ')
    [ -z "$tests" ] || echo "failed tests: $tests"
  fi
  if grep -qx 'GOMODCACHE-MISS' "$WORK/results.clean"; then
    echo "baseline stale: refresh it (docs/windows-test.md)"
  fi
  echo "elapsed: $(($(date +%s) - START_EPOCH))s"
  echo "logs: $LOGDIR"
}
summary | tee "$LOGDIR/summary.txt"

if [ "$failed" -ne 0 ]; then exit 1; fi
devstate_record_pass "$CHECK" "$SHA"
exit 0
