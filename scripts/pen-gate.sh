#!/usr/bin/env bash
# Refuses the stand-in enterprise number (ADR 0019, Decisions 36 and 47): the
# branch builds with 32473, this gate keeps it from merging. Reads the one line
# `const PrivateEnterpriseNumber = <digits>` of internal/pki/eku.go.
#   usage: pen-gate.sh [--file F]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
file="$ROOT/internal/pki/eku.go"

fail() {
  echo "pen-gate: FAIL $*" >&2
  exit 1
}

case "${1:-}" in
  "") ;;
  --file)
    [ "$#" -eq 2 ] || { echo "usage: pen-gate.sh [--file F]" >&2; exit 2; }
    file="$2"
    ;;
  *) echo "usage: pen-gate.sh [--file F]" >&2; exit 2 ;;
esac

[ -f "$file" ] || fail "$file does not exist"

lines="$(grep -E '^const PrivateEnterpriseNumber = [0-9]+[[:space:]]*$' "$file" || true)"
count=0
[ -z "$lines" ] || count="$(printf '%s\n' "$lines" | wc -l | tr -d ' ')"
[ "$count" -ne 0 ] || fail "$file has no line 'const PrivateEnterpriseNumber = <digits>'"
[ "$count" -eq 1 ] || fail "$file has the line 'const PrivateEnterpriseNumber' $count times, want once"

digits="$(printf '%s' "$lines" | sed -E 's/^const PrivateEnterpriseNumber = ([0-9]+)[[:space:]]*$/\1/; s/^0+([0-9])/\1/')"

# Ten digits fit a 64-bit integer; anything longer is too large without a compare.
if [ "${#digits}" -gt 10 ] || [ "$digits" -ge 2147483648 ]; then
  fail "$digits is not below 2147483648"
fi
n="$digits"
[ "$n" -ne 0 ] || fail "0 is reserved"
[ "$n" -ne 32473 ] || fail "32473 is the documentation number (RFC 5612); the assigned number is not in yet (ADR 0019, Decision 36)"

echo "pen-gate: ok $n"
