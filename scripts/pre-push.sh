#!/usr/bin/env bash
# pre-push.sh: the pre-push hook (.githooks/pre-push): picks the slow local checks
# a push needs from the changed paths and runs each once per tip commit (local CI
# spec section 5).
#
#   pre-push.sh [REMOTE URL]          git's hook call; reads
#                                     "<local ref> <local sha> <remote ref> <remote sha>" lines on stdin
#   pre-push.sh --select BASE TIP     print the checks BASE..TIP selects, one per line: "<check> <reason>"
#   pre-push.sh --hooks-check         exit 1 unless core.hooksPath is .githooks (exit 0 when GITHUB_ACTIONS=true)
#
# Base per ref: a deletion is skipped; a tag is skipped (the release preflight covers
# tags); a new remote ref, or a remote sha missing locally (a note is printed), uses
# the merge-base of the tip and origin/main; otherwise the base is the remote sha.
#
# Path rules (pinned, ratified by Eric 2026-11-19; scripts/pre-push-selftest.sh encodes them):
#   gates-selftest  scripts/check-gates*.sh, scripts/m*-exit-checks.sh, scripts/ci-gate-negative.sh,
#                   scripts/ci-sim.sh, scripts/pen-gate*.sh, internal/dbtest/**, or a change inside the
#                   rule block of a Makefile gate target (verify, check-gates, check-gates-selftest, test,
#                   test-race, test-conformance, every *-check). A header's ## help text, a variable and
#                   .PHONY do not count. The comparison is of each gate block at BASE and at TIP.
#   windows-test    *.ps1, release/**, go.mod, go.sum, *_windows.go, a .go file whose //go:build line
#                   contains windows, internal/{procs,credential,sessionstate,fileacl,filelock}/**,
#                   scripts/windows-test*, scripts/windows-test/**
#   verify-linux    Dockerfile, go.mod, go.sum, *_linux.go, *_unix.go, a .go file whose //go:build line
#                   contains linux or unix, scripts/verify-linux*
# A deleted .go file is read at BASE for its build line.
#
# The hook runs, per distinct tip and check (windows-test, verify-linux, gates-selftest in that
# order), `bash scripts/<runner> TIP` unless <state>/passes/<check>/<tip> exists. gates-selftest is
# scripts/check-gates-selftest.sh TIP bounded at 5400 s (log <state>/logs/gates-selftest/<tip>/run.log);
# the hook records its pass, the two other runners record their own. The first failure ends the
# hook: exit 1 naming the check and its log directory.
#
# Exit codes: 0 nothing to run or all passed; 1 a check failed, a hook precondition failed or the
# input is not understood; 2 usage.
# Seams: AGENTMESH_PREPUSH_RUNNERS (a directory holding an executable <check> per check, replacing
# the runners), AGENTMESH_DEV_STATE (state directory).
#
# State (Definition of Done D): a second push of a passed tip skips what passed; a failed check
# leaves no pass, so the next push reruns it; overlapping pushes are serialized by the runners
# themselves (windows-test and verify-linux refuse a second run of one commit).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=/dev/null
. "$ROOT/scripts/lib/devstate.sh"

CHECKS="windows-test verify-linux gates-selftest"
GATES_TIMEOUT=5400
ZERO='^0+$'

say() { printf '%s\n' "pre-push: $*"; }
err() { printf '%s\n' "pre-push: $*" >&2; }
die() { # die CODE MESSAGE...
  local code=$1
  shift
  err "$*"
  exit "$code"
}

hooks_check() {
  [ "${GITHUB_ACTIONS:-}" = true ] && return 0
  local v
  v=$(git config core.hooksPath 2>/dev/null || true)
  if [ "$v" != .githooks ]; then
    err "core.hooksPath is '${v:-unset}', not .githooks"
    echo "run: git config core.hooksPath .githooks" >&2
    return 1
  fi
}

# gate_blocks REV: print "<targets>\t<line>" for the header and recipe lines of every Makefile
# gate target at REV, headers without their ## help text, blank and comment lines dropped.
gate_blocks() {
  git show "$1:Makefile" 2>/dev/null | awk '
    function isgate(n) {
      return n == "verify" || n == "check-gates" || n == "check-gates-selftest" || n == "test" ||
        n == "test-race" || n == "test-conformance" || n ~ /-check$/
    }
    /^[A-Za-z0-9_.-]+([ \t]+[A-Za-z0-9_.-]+)*[ \t]*:([^=]|$)/ {
      line = $0
      sub(/[ \t]*##.*$/, "", line)
      names = line
      sub(/[ \t]*:.*$/, "", names)
      n = split(names, a, /[ \t]+/)
      gate = 0
      for (i = 1; i <= n; i++) if (isgate(a[i])) gate = 1
      cur = gate ? names : ""
      if (gate) print names "\t" line
      next
    }
    /^\t/ { if (cur != "") print cur "\t" $0; next }
    /^[ \t]*$/ || /^#/ { next }
    { cur = "" }
  ' || true
}

# build_line BASE TIP FILE: the first //go:build line of FILE at TIP (else at BASE).
build_line() {
  { git show "$2:$3" 2>/dev/null || git show "$1:$3" 2>/dev/null || true; } |
    awk '/^\/\/go:build / { print; exit } /^package / { exit }'
}

# select_checks BASE TIP: print "<check> <reason>" lines.
select_checks() {
  local base=$1 tip=$2 files f bl hit_g="" hit_w="" hit_l="" mk=""
  files=$(git diff --no-renames --name-only "$base" "$tip")
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
      scripts/check-gates*.sh | scripts/m*-exit-checks.sh | scripts/ci-gate-negative.sh | scripts/ci-sim.sh | scripts/pen-gate*.sh | internal/dbtest/*)
        [ -n "$hit_g" ] || hit_g="$f matches the gate script paths"
        ;;
      Makefile) mk=1 ;;
    esac
    case "$f" in
      *.ps1 | release/* | go.mod | go.sum | *_windows.go | internal/procs/* | internal/credential/* | internal/sessionstate/* | internal/fileacl/* | internal/filelock/* | scripts/windows-test*)
        [ -n "$hit_w" ] || hit_w="$f matches the Windows paths"
        ;;
    esac
    case "$f" in
      Dockerfile | go.mod | go.sum | *_linux.go | *_unix.go | scripts/verify-linux*)
        [ -n "$hit_l" ] || hit_l="$f matches the Linux paths"
        ;;
    esac
    case "$f" in
      *.go)
        bl=$(build_line "$base" "$tip" "$f")
        case "$bl" in *windows*) [ -n "$hit_w" ] || hit_w="$f has build line '$bl'" ;; esac
        case "$bl" in *linux* | *unix*) [ -n "$hit_l" ] || hit_l="$f has build line '$bl'" ;; esac
        ;;
    esac
  done <<<"$files"
  if [ -z "$hit_g" ] && [ -n "$mk" ]; then
    local d
    d=$(diff <(gate_blocks "$base") <(gate_blocks "$tip") | sed -n 's/^[<>] //p' | head -n 1 | cut -f1) || true
    [ -z "$d" ] || hit_g="Makefile changed inside the recipe of: $d"
  fi
  [ -z "$hit_w" ] || echo "windows-test $hit_w"
  [ -z "$hit_l" ] || echo "verify-linux $hit_l"
  [ -z "$hit_g" ] || echo "gates-selftest $hit_g"
  return 0
}

runner_for() { # runner_for CHECK: print the runner path (a bash script)
  if [ -n "${AGENTMESH_PREPUSH_RUNNERS:-}" ]; then
    printf '%s\n' "$AGENTMESH_PREPUSH_RUNNERS/$1"
    return
  fi
  case "$1" in
    windows-test) printf '%s\n' "$ROOT/scripts/windows-test.sh" ;;
    verify-linux) printf '%s\n' "$ROOT/scripts/verify-linux.sh" ;;
    gates-selftest) printf '%s\n' "$ROOT/scripts/check-gates-selftest.sh" ;;
    *) die 1 "no runner for check '$1'" ;;
  esac
}

# run_check CHECK TIP: run one runner; exit 1 from the hook on a failure.
run_check() {
  local check=$1 tip=$2 runner rc=0 logdir
  runner=$(runner_for "$check")
  logdir=$(devstate_logdir "$check" "$tip")
  if [ "$check" = gates-selftest ]; then
    if [ -n "${AGENTMESH_PREPUSH_RUNNERS:-}" ]; then
      bash "$runner" "$tip" </dev/null >"$logdir/run.log" 2>&1 || rc=$?
    else
      perl -e 'alarm shift; exec @ARGV' "$GATES_TIMEOUT" bash "$runner" "$tip" </dev/null >"$logdir/run.log" 2>&1 || rc=$?
    fi
    tail -n 5 "$logdir/run.log"
  else
    bash "$runner" "$tip" </dev/null || rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    err "FAILED: $check at $tip (exit $rc); logs: $logdir"
    exit 1
  fi
  [ "$check" != gates-selftest ] || devstate_record_pass "$check" "$tip"
  say "$check passed at $tip"
}

main_hook() {
  local lref lsha rref rsha base tip tmp
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/pre-push.XXXXXX")
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  : >"$tmp/plan"
  while read -r lref lsha rref rsha extra; do
    [ -n "$lref$lsha$rref$rsha" ] || continue
    [[ -n $lref && -n $lsha && -n $rref && -n $rsha && -z ${extra:-} ]] || die 1 "malformed ref line: '$lref $lsha $rref $rsha ${extra:-}'"
    [[ $lsha =~ ^[0-9a-f]{40,64}$ && $rsha =~ ^[0-9a-f]{40,64}$ ]] || die 1 "malformed sha in ref line for $lref"
    if [[ $lsha =~ $ZERO ]]; then
      say "$rref: deletion, nothing to check"
      continue
    fi
    case "$lref $rref" in
      refs/tags/* | *' refs/tags/'*)
        say "$rref: tag push, skipped (the release preflight covers tags)"
        continue
        ;;
    esac
    tip=$(git rev-parse --verify "$lsha^{commit}" 2>/dev/null) || die 1 "$lref: $lsha is not a commit in this repository"
    if [[ $rsha =~ $ZERO ]]; then
      base=$(git merge-base "$tip" origin/main 2>/dev/null) || die 1 "$rref is new and there is no merge-base of $tip with origin/main"
      say "$rref: new ref, base is the merge-base with origin/main ($base)"
    elif ! git cat-file -e "$rsha^{commit}" 2>/dev/null; then
      base=$(git merge-base "$tip" origin/main 2>/dev/null) || die 1 "$rref: remote sha $rsha is not present locally and there is no merge-base of $tip with origin/main"
      say "note: $rref: remote sha $rsha is not present locally; base is the merge-base with origin/main ($base)"
    else
      base=$rsha
    fi
    select_checks "$base" "$tip" | while IFS= read -r line; do
      printf '%s %s %s\n' "$tip" "${line%% *}" "${line#* }"
    done >>"$tmp/plan"
  done
  [ -s "$tmp/plan" ] || { say "no check selected"; return 0; }
  local c reason
  # distinct tips in order of appearance
  awk '!seen[$1]++ { print $1 }' "$tmp/plan" >"$tmp/uniq"
  while IFS= read -r tip; do
    for c in $CHECKS; do
      reason=$(awk -v t="$tip" -v c="$c" '$1 == t && $2 == c { $1 = ""; $2 = ""; sub(/^ +/, ""); print; exit }' "$tmp/plan")
      [ -n "$reason" ] || continue
      say "$c selected for $tip: $reason"
      if devstate_passed "$c" "$tip"; then
        say "$c at $tip: already passed"
        continue
      fi
      run_check "$c" "$tip"
    done
  done <"$tmp/uniq"
}

case "${1:-}" in
  --hooks-check)
    [ $# -eq 1 ] || die 2 "usage: pre-push.sh --hooks-check"
    hooks_check
    ;;
  --select)
    [ $# -eq 3 ] || die 2 "usage: pre-push.sh --select BASE TIP"
    git rev-parse --verify "$2^{commit}" >/dev/null 2>&1 || die 2 "BASE '$2' is not a commit"
    git rev-parse --verify "$3^{commit}" >/dev/null 2>&1 || die 2 "TIP '$3' is not a commit"
    select_checks "$2" "$3"
    ;;
  -*) die 2 "unknown option '$1'" ;;
  *)
    [ $# -le 2 ] || die 2 "usage: pre-push.sh [REMOTE URL] < ref lines"
    main_hook
    ;;
esac
