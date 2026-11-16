#!/usr/bin/env bash
# Selftest for pen-gate.sh: six files under a temporary directory, each run
# through the gate, each exit code and reason checked (ADR 0019, Decision 47).
#   usage: pen-gate-selftest.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/scripts/pen-gate.sh"

dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT

ran=0
failed=()

# check NAME EXPECTED_EXIT EXPECTED_TEXT: run the gate on $dir/NAME.go.
check() {
  local name="$1" want_code="$2" want_text="$3" out code=0
  ran=$((ran + 1))
  out="$(bash "$GATE" --file "$dir/$name.go" 2>&1)" || code=$?
  if [ "$code" -ne "$want_code" ] || [[ "$out" != *"$want_text"* ]]; then
    failed+=("$name")
    echo "pen-gate-selftest: $name: exit $code, output: $out" >&2
  fi
}

mk() { printf '%s\n' "$2" >"$dir/$1.go"; }

mk zero 'const PrivateEnterpriseNumber = 0'
mk standin 'const PrivateEnterpriseNumber = 32473'
mk toolarge 'const PrivateEnterpriseNumber = 2147483648'
mk noconst 'package pki'
printf 'const PrivateEnterpriseNumber = 99999\nconst PrivateEnterpriseNumber = 99999\n' >"$dir/twice.go"
mk assigned 'const PrivateEnterpriseNumber = 99999'

check zero 1 'pen-gate: FAIL '
check standin 1 'pen-gate: FAIL 32473 is the documentation number (RFC 5612), not the assigned number (ADR 0019, Decision 50)'
check toolarge 1 'pen-gate: FAIL '
check noconst 1 'pen-gate: FAIL '
check twice 1 'pen-gate: FAIL '
check assigned 0 'pen-gate: ok 99999'

passed=$((ran - ${#failed[@]}))
if [ "${#failed[@]}" -gt 0 ]; then
  echo "pen-gate-selftest: $ran run, $passed passed; failed: ${failed[*]}"
  exit 1
fi
echo "pen-gate-selftest: $ran run, $passed passed"
