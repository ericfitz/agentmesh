#!/usr/bin/env bash
# pre-push-selftest.sh: tests scripts/pre-push.sh (Definition of Done C). Part 1 is the table
# test: each row of testdata/pre-push/rows.txt builds a throwaway repository (a base commit with
# the fixture Makefile, then a commit touching the row's files) and compares `--select` with the
# expected checks. Part 2 feeds git's stdin format to the hook with fake runners (the seam
# AGENTMESH_PREPUSH_RUNNERS) and asserts on their calls. Nothing outside one mktemp directory is
# touched, no real runner runs, nothing is pushed; the EXIT trap removes the directory (kept on
# failure). Prints `cases: N passed: N failed: N` and the failed case names; exit 1 on a failure.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
SCRIPT=$ROOT/scripts/pre-push.sh
DATA=$ROOT/scripts/testdata/pre-push
ZERO=0000000000000000000000000000000000000000
[ -f "$SCRIPT" ] || { echo "pre-push-selftest: $SCRIPT does not exist" >&2; exit 2; }
command -v git >/dev/null || { echo "pre-push-selftest: git is not installed" >&2; exit 2; }

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
unset AGENTMESH_PREPUSH_RUNNERS GITHUB_ACTIONS

TMP=$(mktemp -d "${TMPDIR:-/tmp}/pre-push-selftest.XXXXXX")
KEEP=0
trap '[ "$KEEP" = 1 ] || rm -rf "$TMP"' EXIT

PASSED=0 FAILED=0 FAILED_NAMES="" CASE="" CASE_FAILS=""
fail() { CASE_FAILS="$CASE_FAILS
  $*"; }
begin() { CASE=$1 CASE_FAILS=""; }
finish() {
  if [ -z "$CASE_FAILS" ]; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1))
    FAILED_NAMES="$FAILED_NAMES
  $CASE$CASE_FAILS"
    KEEP=1
  fi
}

new_repo() { # new_repo DIR: a repository with the base commit (the fixture Makefile)
  mkdir -p "$1"
  git -C "$1" init -q -b main
  cp "$DATA/fixtures/Makefile.base" "$1/Makefile"
  git -C "$1" add Makefile
  git -C "$1" commit -q -m base
}

commit_files() { # commit_files DIR SPEC... (path or path=fixture)
  local dir=$1 spec p fx
  shift
  for spec in "$@"; do
    p=${spec%%=*}
    mkdir -p "$dir/$(dirname "$p")"
    if [ "$p" != "$spec" ]; then
      fx=${spec#*=}
      cp "$DATA/fixtures/$fx" "$dir/$p"
    else
      echo "x" >"$dir/$p"
    fi
    git -C "$dir" add "$p"
  done
  git -C "$dir" commit -q -m change
}

# ---- part 1: the table test
n=0
while IFS='|' read -r name files want; do
  case "$name" in '#'* | '') continue ;; esac
  name=$(echo "$name" | xargs)
  files=$(echo "$files" | xargs)
  want=$(echo "$want" | xargs)
  n=$((n + 1))
  begin "row $name"
  repo=$TMP/row-$n
  new_repo "$repo"
  base=$(git -C "$repo" rev-parse HEAD)
  IFS=',' read -r -a specs <<<"$files"
  commit_files "$repo" "${specs[@]}"
  got=$(cd "$repo" && bash "$SCRIPT" --select "$base" HEAD 2>"$TMP/row-err") || fail "select failed: $(cat "$TMP/row-err")"
  got_names=$(printf '%s\n' "$got" | awk 'NF { print $1 }' | sort | paste -sd, -)
  want_sorted=$(echo "$want" | tr ',' '\n' | sort | paste -sd, -)
  [ "$want" = none ] && want_sorted=""
  [ "$got_names" = "$want_sorted" ] || fail "selected '${got_names:-none}', want '${want_sorted:-none}'"
  if [ -n "$want_sorted" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      reason=${line#* }
      [ "$reason" != "$line" ] && [ -n "$reason" ] || fail "no reason in '$line'"
    done <<<"$got"
  fi
  finish
done <"$DATA/rows.txt"

# A deleted tagged file is read at BASE.
begin "row deleted-tagged-go-file"
repo=$TMP/row-deleted
new_repo "$repo"
commit_files "$repo" internal/x/tagged.go=go-build-windows
base=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" rm -q internal/x/tagged.go
git -C "$repo" commit -q -m rm
got=$(cd "$repo" && bash "$SCRIPT" --select "$base" HEAD | awk '{print $1}' | paste -sd, -)
[ "$got" = windows-test ] || fail "selected '$got', want windows-test"
finish

# ---- part 2: the hook on stdin
RUNNERS=$TMP/runners
mkdir -p "$RUNNERS"
for c in windows-test verify-linux gates-selftest; do
  cat >"$RUNNERS/$c" <<'FAKE'
#!/usr/bin/env bash
c=$(basename "$0")
echo "$c $1" >>"$PP_CALLS"
rcvar=PP_RC_${c//-/_}
exit "${!rcvar:-0}"
FAKE
  chmod +x "$RUNNERS/$c"
done

# Base commit C0; origin/main is C0 plus a go.sum commit (C1, on main only). feat branches from C0.
HREPO=$TMP/hook-repo
new_repo "$HREPO"
C0=$(git -C "$HREPO" rev-parse HEAD)
commit_files "$HREPO" go.sum
C1=$(git -C "$HREPO" rev-parse HEAD)
git -C "$HREPO" update-ref refs/remotes/origin/main "$C1"
git -C "$HREPO" checkout -q -b feat "$C0"
commit_files "$HREPO" internal/procs/x.go
TIPW=$(git -C "$HREPO" rev-parse HEAD)
commit_files "$HREPO" go.mod
TIPB=$(git -C "$HREPO" rev-parse HEAD) # windows-test and verify-linux
commit_files "$HREPO" scripts/ci-sim.sh
TIPG=$(git -C "$HREPO" rev-parse HEAD) # gates-selftest against TIPB

STATE="" CALLS="" OUT="" RC=0
setup_hook() { # setup_hook NAME: fresh state, calls and output files
  begin "hook $1"
  STATE=$TMP/state-$1
  CALLS=$TMP/calls-$1
  OUT=$TMP/out-$1
  mkdir -p "$STATE"
  : >"$CALLS"
}
run_hook() { # run_hook [VAR=VALUE]... : the ref lines on stdin
  RC=0
  (cd "$HREPO" && env AGENTMESH_DEV_STATE="$STATE" AGENTMESH_PREPUSH_RUNNERS="$RUNNERS" PP_CALLS="$CALLS" "$@" \
    bash "$SCRIPT" origin git@example.com:x/y.git) >"$OUT" 2>&1 || RC=$?
}
expect_rc() { [ "$RC" = "$1" ] || fail "exit $RC, want $1 (output: $(tr '\n' ' ' <"$OUT" | head -c 400))"; }
expect_out() { grep -qF -- "$1" "$OUT" || fail "output lacks: $1"; }
expect_calls() { # expect_calls LINE... : the calls file holds exactly these lines (sorted)
  local want got
  want=$(printf '%s\n' "$@" | sort)
  got=$(sort "$CALLS")
  [ "$want" = "$got" ] || fail "calls: '$(echo "$got" | tr '\n' ';')' want '$(echo "$want" | tr '\n' ';')'"
}
expect_no_calls() { [ ! -s "$CALLS" ] || fail "runners were called: $(tr '\n' ';' <"$CALLS")"; }

setup_hook deletion
run_hook <<<"(delete) $ZERO refs/heads/gone $C1"
expect_rc 0
expect_no_calls
expect_out "deletion"
finish

setup_hook tag-push
run_hook <<<"refs/tags/v1 $TIPB refs/tags/v1 $ZERO"
expect_rc 0
expect_no_calls
expect_out "release preflight covers tags"
finish

setup_hook new-branch
run_hook <<<"refs/heads/feat $TIPW refs/heads/feat $ZERO"
expect_rc 0
expect_calls "windows-test $TIPW"
expect_out "merge-base with origin/main ($C0)"
finish

setup_hook unknown-remote-sha
run_hook <<<"refs/heads/feat $TIPW refs/heads/feat 1234567890123456789012345678901234567890"
expect_rc 0
expect_calls "windows-test $TIPW"
expect_out "not present locally"
finish

setup_hook existing-branch-uses-remote-sha
run_hook <<<"refs/heads/feat $TIPB refs/heads/feat $TIPW"
expect_rc 0
expect_calls "windows-test $TIPB" "verify-linux $TIPB"
finish

setup_hook two-refs-same-tip
run_hook <<<"refs/heads/feat $TIPW refs/heads/a $C0
refs/heads/feat $TIPW refs/heads/b $C0"
expect_rc 0
expect_calls "windows-test $TIPW"
finish

setup_hook two-tips
run_hook <<<"refs/heads/feat $TIPW refs/heads/a $C0
refs/heads/feat $TIPB refs/heads/b $C0"
expect_rc 0
expect_calls "windows-test $TIPW" "windows-test $TIPB" "verify-linux $TIPB"
finish

setup_hook recorded-pass
mkdir -p "$STATE/passes/windows-test"
: >"$STATE/passes/windows-test/$TIPW"
run_hook <<<"refs/heads/feat $TIPW refs/heads/feat $C0"
expect_rc 0
expect_no_calls
expect_out "already passed"
finish

setup_hook gates-selftest-records-pass
run_hook <<<"refs/heads/feat $TIPG refs/heads/feat $TIPB"
expect_rc 0
expect_calls "gates-selftest $TIPG"
[ -f "$STATE/passes/gates-selftest/$TIPG" ] || fail "no pass recorded"
: >"$CALLS"
run_hook <<<"refs/heads/feat $TIPG refs/heads/feat $TIPB"
expect_rc 0
expect_no_calls
expect_out "already passed"
finish

setup_hook failing-runner
run_hook PP_RC_windows_test=1 <<<"refs/heads/feat $TIPB refs/heads/feat $C0"
expect_rc 1
expect_calls "windows-test $TIPB"
expect_out "windows-test"
expect_out "$STATE/logs/windows-test/$TIPB"
finish

setup_hook failing-gates-selftest-leaves-no-pass
run_hook PP_RC_gates_selftest=1 <<<"refs/heads/feat $TIPG refs/heads/feat $TIPB"
expect_rc 1
expect_out "$STATE/logs/gates-selftest/$TIPG"
[ ! -f "$STATE/passes/gates-selftest/$TIPG" ] || fail "a pass was recorded for a failure"
finish

setup_hook nothing-selected
run_hook <<<"refs/heads/feat $C0 refs/heads/feat $C0"
expect_rc 0
expect_no_calls
finish

setup_hook malformed-line
run_hook <<<"refs/heads/feat not-a-sha refs/heads/feat $C0"
expect_rc 1
expect_out "malformed"
expect_no_calls
finish

setup_hook unknown-local-sha
run_hook <<<"refs/heads/feat 1234567890123456789012345678901234567890 refs/heads/feat $C0"
expect_rc 1
expect_out "not a commit"
finish

setup_hook new-branch-without-origin-main
git -C "$HREPO" update-ref -d refs/remotes/origin/main
run_hook <<<"refs/heads/feat $TIPW refs/heads/feat $ZERO"
expect_rc 1
expect_out "origin/main"
expect_no_calls
git -C "$HREPO" update-ref refs/remotes/origin/main "$C1"
finish

# ---- --hooks-check and option handling
hc() { # hc [VAR=VALUE]... : run --hooks-check in a fresh repository, set RC, fill OUT
  RC=0
  (cd "$TMP/hc-repo" && env "$@" bash "$SCRIPT" --hooks-check) >"$OUT" 2>&1 || RC=$?
}
new_repo "$TMP/hc-repo"
begin "hooks-check unset"
OUT=$TMP/out-hc1
hc
expect_rc 1
expect_out "run: git config core.hooksPath .githooks"
finish
begin "hooks-check wrong value"
OUT=$TMP/out-hc2
git -C "$TMP/hc-repo" config core.hooksPath other
hc
expect_rc 1
expect_out "run: git config core.hooksPath .githooks"
finish
begin "hooks-check set"
OUT=$TMP/out-hc3
git -C "$TMP/hc-repo" config core.hooksPath .githooks
hc
expect_rc 0
finish
begin "hooks-check in GitHub Actions"
OUT=$TMP/out-hc4
git -C "$TMP/hc-repo" config --unset core.hooksPath
hc GITHUB_ACTIONS=true
expect_rc 0
finish
begin "hooks-check outside a repository"
OUT=$TMP/out-hc5
RC=0
mkdir -p "$TMP/norepo"
(cd "$TMP/norepo" && GIT_CEILING_DIRECTORIES=$TMP bash "$SCRIPT" --hooks-check) >"$OUT" 2>&1 || RC=$?
expect_rc 1
finish

begin "unknown option"
OUT=$TMP/out-opt
RC=0
(cd "$HREPO" && bash "$SCRIPT" --bogus) >"$OUT" 2>&1 || RC=$?
expect_rc 2
finish
begin "select with a bad commit"
RC=0
(cd "$HREPO" && bash "$SCRIPT" --select nope HEAD) >"$OUT" 2>&1 || RC=$?
expect_rc 2
finish
begin "select with missing arguments"
RC=0
(cd "$HREPO" && bash "$SCRIPT" --select HEAD) >"$OUT" 2>&1 || RC=$?
expect_rc 2
finish

echo "cases: $((PASSED + FAILED)) passed: $PASSED failed: $FAILED"
if [ "$FAILED" -ne 0 ]; then
  echo "failed:$FAILED_NAMES"
  echo "kept: $TMP"
  exit 1
fi
