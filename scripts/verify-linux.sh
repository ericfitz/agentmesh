#!/usr/bin/env bash
# verify-linux.sh [COMMIT]: run `make test test-conformance` of COMMIT (default HEAD)
# in a linux/arm64 container with a sibling Postgres (local CI spec section 4).
# `git archive` of COMMIT is extracted to a temp directory and mounted read-only at
# /src, so a package that writes into the tree fails (that is a finding, not a
# reason for a writable mount). No Docker socket goes into the test container.
#
# Runner contract (docs/superpowers/plans/2026-11-15-local-ci.md):
#   exit 0  make test and test-conformance passed
#   exit 1  they failed (failed test names are in the summary)
#   exit 2  usage or a precondition failed (Docker, tool, commit)
#   exit 3  infrastructure failure (Postgres never ready, container could not run, timeout)
# stdout carries only the summary; messages go to stderr; the full log is
# <state dir>/logs/verify-linux/<sha>/test.log.
#
# Seams: AGENTMESH_DOCKER (default docker), AGENTMESH_DEV_STATE (state dir),
# AGENTMESH_VERIFY_LINUX_PG_TRIES (60 readiness polls), AGENTMESH_VERIFY_LINUX_POLL_SECONDS (1),
# AGENTMESH_VERIFY_LINUX_RUN_TIMEOUT (3000 s for the test container).
#
# State (Definition of Done D): a second run clears the commit's logs and recorded
# pass first and reruns (the record is for the hook, not for this script). Runs
# overlap safely (same commit: the second is refused, exit 2, naming the first's PID; a dead holder's lock is cleared): names carry the PID, and the Go module and build caches are the
# named volumes agentmesh-verify-linux-gomod and -gocache (kept between runs; Go's
# caches tolerate concurrent use). A killed run (SIGKILL) leaves its two containers
# and network; they are named agentmesh-verify-linux-*-<pid> and are removed by hand.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=/dev/null
. "$ROOT/scripts/lib/devstate.sh"

CHECK=verify-linux
DOCKER=${AGENTMESH_DOCKER:-docker}
PG_TRIES=${AGENTMESH_VERIFY_LINUX_PG_TRIES:-60}
POLL=${AGENTMESH_VERIFY_LINUX_POLL_SECONDS:-1}
RUN_TIMEOUT=${AGENTMESH_VERIFY_LINUX_RUN_TIMEOUT:-3000}
# Same Chainguard Postgres as scripts/ci-sim.sh.
PG_IMAGE=cgr.dev/chainguard/postgres:latest@sha256:0926ac7262a2c1963179eb939cd5d610e1be3ecca90b4b5cad8db8df16fab87e
# golang:1.27.3-bookworm, the multi-arch index digest (docker buildx imagetools inspect, 2026-11-19).
GO_IMAGE=golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0
NET=agentmesh-verify-linux-$$
PG=agentmesh-verify-linux-pg-$$
TESTC=agentmesh-verify-linux-test-$$
START_EPOCH=$(date +%s)
WORK="" NET_MADE=0 LOCKED=0 LOCKFILE="" MUTEX=""

say() { printf '%s\n' "verify-linux: $*" >&2; }
die() { # die CODE MESSAGE...
  local code=$1
  shift
  say "$*"
  exit "$code"
}

for v in PG_TRIES POLL RUN_TIMEOUT; do
  case "${!v}" in '' | *[!0-9]*) die 2 "$v must be a whole number, got '${!v}'" ;; esac
done
[ $# -le 1 ] || die 2 "usage: verify-linux.sh [COMMIT]"

# shellcheck disable=SC2329  # runs from the EXIT trap
cleanup() {
  local rc=$?
  trap '' INT TERM
  trap - EXIT
  if [ "$NET_MADE" = 1 ]; then
    "$DOCKER" rm -f "$TESTC" "$PG" >/dev/null 2>&1 || true
    "$DOCKER" network rm "$NET" >/dev/null 2>&1 || true
  fi
  if [ "$LOCKED" = 1 ] && [ "$(cut -d' ' -f1 "$LOCKFILE" 2>/dev/null)" = "$$" ]; then rm -f "$LOCKFILE"; fi
  [ -z "$MUTEX" ] || rmdir "$MUTEX" 2>/dev/null || true
  [ -z "$WORK" ] || rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

COMMIT_ARG=${1:-HEAD}
SHA=$(git -C "$ROOT" rev-parse --verify --quiet "$COMMIT_ARG^{commit}") || die 2 "'$COMMIT_ARG' is not a commit of $ROOT"
for t in git tar perl; do command -v "$t" >/dev/null || die 2 "$t is not installed"; done
command -v "$DOCKER" >/dev/null || die 2 "docker not found: $DOCKER (install Docker Desktop or set AGENTMESH_DOCKER)"
"$DOCKER" info >/dev/null 2>&1 || die 2 "Docker is not running or not reachable ('$DOCKER info' failed); start Docker Desktop"

STATE=$(devstate_dir)
# A per-commit lock, taken before the log wipe and the pass removal, so an overlapping
# run of the same commit cannot delete the first's log. Short mutex directory (mkdir is
# atomic) guards the lock file's check-and-write; a dead holder's lock is cleared.
LOCKFILE=$STATE/verify-linux-$SHA.lock
MUTEX_PATH=$STATE/verify-linux-$SHA.lock.d
n=0
until mkdir "$MUTEX_PATH" 2>/dev/null; do
  n=$((n + 1))
  [ "$n" -le 50 ] || die 2 "cannot take $MUTEX_PATH (another run is starting, or a killed run left it: remove the directory if no run is active)"
  sleep 0.1
done
MUTEX=$MUTEX_PATH
if [ -e "$LOCKFILE" ]; then
  read -r lock_pid lock_start extra <"$LOCKFILE" || true
  case "${lock_pid:-}${lock_start:-}" in '' | *[!0-9]*) lock_bad=1 ;; *) lock_bad=0 ;; esac
  if [ "$lock_bad" = 1 ] || [ -z "${lock_pid:-}" ] || [ -z "${lock_start:-}" ] || [ -n "${extra:-}" ]; then
    die 2 "$LOCKFILE is not a lock this script wrote (want 'pid start_epoch'); remove it if no run is active"
  fi
  if kill -0 "$lock_pid" 2>/dev/null; then
    die 2 "another verify-linux run of $SHA is active: PID $lock_pid; wait for it"
  fi
  say "clearing the stale lock of dead PID $lock_pid"
  rm -f "$LOCKFILE"
fi
printf '%s %s\n' "$$" "$START_EPOCH" >"$LOCKFILE.tmp.$$"
mv "$LOCKFILE.tmp.$$" "$LOCKFILE"
LOCKED=1
rmdir "$MUTEX_PATH"
MUTEX=""

LOGDIR=$(devstate_logdir "$CHECK" "$SHA")
find "$LOGDIR" -mindepth 1 -delete
rm -f "$STATE/passes/$CHECK/$SHA"
LOG=$LOGDIR/test.log

WORK=$(mktemp -d "${TMPDIR:-/tmp}/verify-linux.XXXXXX")
mkdir "$WORK/src"
git -C "$ROOT" archive --format=tar "$SHA" | tar -x -C "$WORK/src" || die 2 "git archive of $SHA failed"

NET_MADE=1
"$DOCKER" network create "$NET" >/dev/null || die 3 "cannot create network $NET"
"$DOCKER" run -d --name "$PG" --network "$NET" \
  -e POSTGRES_USER=agentmesh -e POSTGRES_PASSWORD=agentmesh -e POSTGRES_DB=agentmesh \
  "$PG_IMAGE" >/dev/null || die 3 "cannot start the Postgres container"

# The image restarts postgres once during first-boot init, so pg_isready can answer
# before the final start: require two consecutive answers (as scripts/ci-sim.sh).
ready=0 i=0
while [ "$i" -lt "$PG_TRIES" ]; do
  i=$((i + 1))
  if "$DOCKER" exec "$PG" pg_isready -U agentmesh >/dev/null 2>&1; then ready=$((ready + 1)); else ready=0; fi
  [ "$ready" -lt 2 ] || break
  sleep "$POLL"
done
[ "$ready" -ge 2 ] || die 3 "Postgres was not ready after $PG_TRIES polls"

DSN="postgres://agentmesh:agentmesh@$PG:5432/agentmesh?sslmode=disable"
rc=0
perl -e 'alarm shift; exec @ARGV' "$RUN_TIMEOUT" \
  "$DOCKER" run --name "$TESTC" --network "$NET" --platform linux/arm64 \
  -v "$WORK/src:/src:ro" -w /src \
  -v agentmesh-verify-linux-gomod:/go/pkg/mod -v agentmesh-verify-linux-gocache:/root/.cache/go-build \
  -e AGENTMESH_TEST_POSTGRES_DSN="$DSN" -e GOFLAGS=-buildvcs=false \
  "$GO_IMAGE" make test test-conformance >"$LOG" 2>&1 || rc=$?

case "$rc" in
  0 | 1 | 2) ;;
  142) die 3 "the test container timed out after ${RUN_TIMEOUT}s (log: $LOG)" ;;
  *) die 3 "the test container could not run (exit $rc; log: $LOG)" ;;
esac

failed_tests=$(sed -n 's/^[[:space:]]*--- FAIL: \([^ ]*\).*/\1/p' "$LOG" | sort -u | tr '\n' ' ')
failed_pkgs=$(sed -n 's/^FAIL[[:space:]]\{1,\}\([^ ]*\).*/\1/p' "$LOG" | sort -u | tr '\n' ' ')
{
  echo "verify-linux: commit $SHA"
  if [ "$rc" = 0 ]; then
    echo "result: passed"
  else
    echo "result: failed (container exit $rc)"
    [ -z "$failed_tests" ] || echo "failed tests: $failed_tests"
    [ -z "$failed_pkgs" ] || echo "failed packages: $failed_pkgs"
  fi
  echo "elapsed: $(($(date +%s) - START_EPOCH))s"
  echo "logs: $LOGDIR"
} | tee "$LOGDIR/summary.txt"

[ "$rc" = 0 ] || exit 1
devstate_record_pass "$CHECK" "$SHA"
exit 0
