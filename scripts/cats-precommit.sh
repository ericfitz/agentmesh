#!/usr/bin/env bash
# cats-precommit.sh: the pre-commit hook body (issue #30, Eric's decision 3).
#
# When the staged api/openapi.yaml differs from HEAD beyond documentation, it
# fuzzes only the changed paths (widened through $ref by tools/catscheck) and
# blocks on any finding that api/cats-false-positives.yaml does not record. A
# documentation-only diff passes at once. `git commit --no-verify` bypasses it.
#
# The staged tree is the only source (ruling 15): the index is exported with
# git checkout-index into a temporary directory and everything runs from there
# (rulings 15 and 29), never from the working tree. No git stash.
#
# Requires bash 4.4 or newer (empty-array expansions under set -u); it checks.
#
# Definition of Done D (state):
#   second run             the hook owns a fresh `mktemp -d` and a harness
#                          --dir "$tmp/harness" inside it, so a second commit
#                          after a failed hook starts clean.
#   overlapping runs       each run has its own temporary directory, harness
#                          --dir and lock, so two commits (two worktrees) never
#                          collide with each other or with a campaign in
#                          progress.
#   leftovers              on EXIT, INT, TERM and HUP the trap stops the running
#                          harness child, runs `cats-harness.sh down --dir
#                          "$tmp/harness"` (which stops the campaign server) and
#                          removes $tmp. SIGKILL of the hook leaves the
#                          temporary directory and, if a campaign was running,
#                          its server: the next run uses a fresh --dir and its
#                          `up` does not reap that server. Stop it with
#                          `cats-harness.sh down --dir <that dir>` (while the
#                          directory still exists) or kill the stray
#                          `agentmesh server` by hand.
set -euo pipefail

if [ "${BASH_VERSINFO[0]}" -lt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
  echo "cats-precommit: bash 4.4 or newer is required (this is $BASH_VERSION); put a newer bash first on PATH, or commit with --no-verify to bypass" >&2
  exit 1
fi

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

if [ -z "$(git diff --cached --name-only -- api/openapi.yaml)" ]; then
  exit 0
fi

if git diff --cached --name-status -- api/openapi.yaml | grep -q -E '^D'; then
  echo "cats-precommit: api/openapi.yaml is staged for deletion; the API spec cannot be deleted by a commit (git commit --no-verify bypasses this hook)" >&2
  exit 1
fi

CATS_BIN=${CATS_BIN:-cats}
export CATS_BIN
for tool in "$CATS_BIN" jq go curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "cats-precommit: ${tool##*/} is not installed (brew install endava/tap/cats); commit with --no-verify to bypass" >&2
    exit 1
  fi
done

tmp=$(mktemp -d "${TMPDIR:-/tmp}/cats-precommit.XXXXXX")
tmp=$(cd "$tmp" && pwd -P)
HPID=
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  local rc=$?
  trap - EXIT INT TERM HUP
  if [ -n "$HPID" ] && kill -0 "$HPID" 2>/dev/null; then
    kill -TERM "$HPID" 2>/dev/null || true
    wait "$HPID" 2>/dev/null || true
  fi
  if [ -f "$tmp/tree/scripts/cats-harness.sh" ]; then
    bash "$tmp/tree/scripts/cats-harness.sh" down --dir "$tmp/harness" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# The staged tree, and the spec before the change.
git checkout-index -a -f --prefix="$tmp/tree/"
git -C "$ROOT" show HEAD:api/openapi.yaml >"$tmp/old.yaml" 2>/dev/null || : >"$tmp/old.yaml"
cp "$tmp/tree/api/openapi.yaml" "$tmp/new.yaml"
cd "$tmp/tree"

# Built once from the staged tree: `go run` maps every non-zero exit of the
# program to 1, and the exit codes 10 and 2 matter here.
go build -o "$tmp/catscheck" ./tools/catscheck
rc=0
"$tmp/catscheck" changed-paths "$tmp/old.yaml" "$tmp/new.yaml" >"$tmp/paths.txt" 2>"$tmp/paths.err" || rc=$?
case "$rc" in
  0)
    if grep -q -F 'no path is affected' "$tmp/paths.err"; then
      echo "cats-precommit: no path is affected by the api/openapi.yaml change; skipping CATS"
    else
      echo "cats-precommit: documentation-only change to api/openapi.yaml; skipping CATS"
    fi
    exit 0 # documentation-only
    ;;
  10) ;;
  *)
    cat "$tmp/paths.err" >&2
    echo "cats-precommit: catscheck changed-paths failed (exit $rc)" >&2
    exit 1
    ;;
esac

# Generated-code freshness against the staged copy.
cp -R "$tmp/tree/internal/gen" "$tmp/gen-staged"
make generate >/dev/null
if ! diff -rq "$tmp/gen-staged" "$tmp/tree/internal/gen" >/dev/null 2>&1; then
  echo "cats-precommit: internal/gen is stale for the staged api/openapi.yaml; run make generate and stage internal/gen" >&2
  exit 1
fi

# Partition the changed paths (ruling 24).
SKIP=()
while IFS= read -r line; do SKIP+=("$line"); done < <(bash scripts/cats-harness.sh skip-paths)
is_skip() {
  local s
  for s in "${SKIP[@]}"; do [ "$s" = "$1" ] && return 0; done
  return 1
}
RUN_PATHS=()
DESTRUCTIVE=()
while IFS= read -r p; do
  [ -n "$p" ] || continue
  case "$p" in
    /v1/admin/bridges | /v1/admin/bridges/*)
      echo "cats-precommit: not fuzzing $p (no Slack bridge in the campaign server; ADR 0018)"
      ;;
    *)
      if is_skip "$p"; then DESTRUCTIVE+=("$p"); else RUN_PATHS+=("$p"); fi
      ;;
  esac
done <"$tmp/paths.txt"

if [ "${#RUN_PATHS[@]}" -eq 0 ] && [ "${#DESTRUCTIVE[@]}" -eq 0 ]; then
  if ! grep -q -E '^/v1/admin/bridges' "$tmp/paths.txt"; then
    echo "cats-precommit: catscheck contract violated: changed-paths exited 10 with no path" >&2
    exit 1
  fi
  echo "cats-precommit: only bridges paths changed; nothing to fuzz"
  exit 0
fi

join_comma() { local IFS=,; echo "$*"; }

OUTS=()
run_harness() { # run_harness OUT PATHS [extra flags...]
  local out=$1 paths=$2 hrc=0
  shift 2
  # In the background and waited for, so a signal reaches the trap at once.
  bash scripts/cats-harness.sh run --dir "$tmp/harness" --repo "$tmp/tree" --out "$out" \
    --paths "$paths" "$@" >"$tmp/harness.out" 2>&1 &
  HPID=$!
  wait "$HPID" || hrc=$?
  HPID=
  # The report directory is removed on exit: do not print its path.
  grep -v -E '^report=' "$tmp/harness.out" || true
  if [ "$hrc" -ne 0 ]; then
    echo "cats-precommit: the CATS harness failed (exit $hrc) for $paths" >&2
    exit 1
  fi
  OUTS+=("$out")
}

n=0
for p in "${DESTRUCTIVE[@]}"; do
  n=$((n + 1))
  echo "cats-precommit: fuzzing 1 changed path(s): $p"
  run_harness "$tmp/out-$n" "$p" --no-skip
done
if [ "${#RUN_PATHS[@]}" -gt 0 ]; then
  echo "cats-precommit: fuzzing ${#RUN_PATHS[@]} changed path(s): $(join_comma "${RUN_PATHS[@]}")"
  run_harness "$tmp/out" "$(join_comma "${RUN_PATHS[@]}")"
fi

# Classify every report against the staged rules.
summaries=()
findings=0
for out in "${OUTS[@]}"; do
  crc=0
  "$tmp/catscheck" classify --rules api/cats-false-positives.yaml "$out/report" >"$tmp/classify.txt" 2>"$tmp/classify.err" || crc=$?
  case "$crc" in
    0) summaries+=("$(tail -n 1 "$tmp/classify.txt")") ;;
    1)
      cat "$tmp/classify.txt"
      k=$(tail -n 1 "$tmp/classify.txt" | sed -n 's/.*, \([0-9][0-9]*\) finding(s)$/\1/p')
      findings=$((findings + ${k:-1}))
      ;;
    *)
      cat "$tmp/classify.err" >&2
      echo "cats-precommit: catscheck classify failed (exit $crc)" >&2
      exit 1
      ;;
  esac
done
if [ "$findings" -gt 0 ]; then
  keep=$ROOT/.local/cats/precommit/$(date -u +%Y%m%dT%H%M%SZ)
  mkdir -p "$keep"
  for out in "${OUTS[@]}"; do cp -R "$out" "$keep/$(basename "$out")"; done
  echo "cats-precommit: reports kept in $keep" >&2
  echo "cats-precommit: $findings finding(s) not covered by api/cats-false-positives.yaml; fix them or record false positives with /cats:fp (git commit --no-verify bypasses this hook)" >&2
  exit 1 # findings
fi
echo "cats-precommit: no finding; $(join_comma "${summaries[@]}")"
exit 0
