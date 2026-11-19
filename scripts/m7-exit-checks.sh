#!/usr/bin/env bash
# Milestone 7 exit evidence and the Slack bridge import rules.
#   usage: m7-exit-checks.sh <replicas.log>   counts, then import rule
#          m7-exit-checks.sh --deps-only      import rule alone (Docker-free)
# <replicas.log> is a `go test -v -run '^TestReplicas'
# ./internal/conformance/bus/` log. It must exist and be non-empty (exit 2
# naming the path). The script prints fail=<n> (every `--- FAIL` line),
# wake_sqlite=<n> and wake_postgres=<n> (the leaf `--- PASS:
# TestReplicasWake/<engine>/<leaf>` lines) and maint_sqlite=<n> and
# maint_postgres=<n> (likewise for TestReplicasMaintenanceExclusive) and
# trust_sqlite=<n> and trust_postgres=<n> (likewise for TestReplicasTrust), and
# exits 1 unless fail=0, wake_postgres=6, wake_sqlite=4 (the two cross-server
# leaves exist on postgres only: two servers over one SQLite file share no
# hints), both maint counts are 2, trust_sqlite=3 and trust_postgres=4 (the
# watch leaf exists on postgres only, for the same reason).
#
# The import rule is checked on production imports (`go list -deps` without
# -test), for every package a pattern matches:
#   ./internal/store/...             must not import internal/core
#   ./internal/core/notify           must not import internal/store or
#                                    github.com/jackc/pgx
#   ./internal/core/notify/pgnotify  must not import internal/server or
#                                    internal/gen
# A forbidden entry also forbids every package below it (internal/core covers
# internal/core/notify; github.com/jackc/pgx covers github.com/jackc/pgx/v5).
# Prints deps_ok=1 when nothing matched; otherwise one
# deps_violation=<package> imports <forbidden> [rule <name>] line per hit and
# exits 1. A go list failure exits 2. <name> is the rule in the lists here
# (store-no-core, notify-leaf, pgnotify-no-server, slackapi-allowlist,
# slack-go-importers, awskms-importers, hashivault-importers, gcpkms-importers,
# azurekms-importers,
# slackbridge-isolation, slack-consumers, keyprovider-leaf,
# keyprovider-consumers, pki-leaf); the self-test
# (scripts/check-gates-selftest.sh) requires each probe to trip exactly one.
#
# The Slack bridge rules (same output):
#   ./internal/slackapi              imports only the standard library and
#                                    itself (allowlist)
#   ./internal/slackapi/slackfake    imports only the standard library and
#                                    internal/slackapi (allowlist)
#   github.com/slack-go/slack        is imported (directly) only by
#                                    internal/slackapi/slackgo, in any file:
#                                    production, _test.go (internal and
#                                    external) and every GOOS (linux, darwin,
#                                    windows). The allowlists above already
#                                    bar slackapi and slackfake from core,
#                                    store, server, bus and slack-go, so no
#                                    separate rule repeats that.
#   ./internal/slackbridge           never imports internal/server,
#                                    internal/gen, internal/slackapi/slackgo
#                                    or slack-go
#   ./internal/core/..., ./internal/bus/..., ./internal/cli,
#   ./internal/mcpserver, ./internal/client, ./internal/server
#                                    never import internal/slackapi,
#                                    internal/slackbridge or slackapi/slackgo
#                                    (slack-go itself: the importer rule)
#
# The signing key provider rules (same output; Eric 2026-10-27, issue #8):
#   ./internal/keyprovider           imports only itself, internal/auth/keys and
#                                    go-jose (keys imports it; the allowlist
#                                    is transitive)
#   ./internal/keyprovider/kmsfake   likewise, plus internal/keyprovider
#   ./internal/core/..., ./internal/bus/..., ./internal/cli,
#   ./internal/mcpserver, ./internal/client, ./internal/server
#                                    never import internal/keyprovider/awskms,
#                                    gcpkms, azurekms or hashivault, in the
#                                    default build or with all four tags
# The importer scans (check_importers) also run with M7_TAGS, default
# awskms,gcpkms,azurekms,hashivault, so a tagged file cannot hide an import.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOD=github.com/ericfitz/agentmesh
# TAGS is the build-tag set the rules below read ("" is the default build).
# The external key provider backends sit behind tags, so the importer scan and
# the keyprovider-consumers rule also run once with M7_TAGS (every backend tag,
# as `make vet-tags` builds them together).
#
# Speed: the rules read dump files, never `go list` itself. build_dumps runs,
# in parallel and once per run,
#   deps.<n>:        go list -deps -f '<path> <imports>' ./...  for the default
#                    build (n=0) and the M7_TAGS build (n=1), host GOOS: every
#                    package of the module and everything below it, so a rule
#                    takes its transitive closure from the file (awk, a DFS in
#                    go list's own post-order, so a violation list keeps the
#                    order `go list -deps <pkg>` gave);
#   imp.<n>.<goos>:  go list -f '<path> <imports> <test imports> <xtest
#                    imports>' ./... for each tag set and GOOS (CGO off), for
#                    the importer scan.
# Eight go list runs in all, whatever the number of rules.
M7_TAGS="${M7_TAGS:-awskms,gcpkms,azurekms,hashivault}"
TAGS=""
GOOSES="linux darwin windows"
DUMPDIR=""
# tagflags prints the GOFLAGS value for a tag set, keeping the caller's own flags.
tagflags() { printf '%s%s' "${GOFLAGS:+$GOFLAGS }" "${1:+-tags=$1}"; }

build_dumps() {
	DUMPDIR="$(mktemp -d)"
	trap 'rm -rf "$DUMPDIR"' EXIT
	local tags goos n=0 pids=() descs=() files=()
	for tags in "" "$M7_TAGS"; do
		(cd "$ROOT" && GOFLAGS="$(tagflags "$tags")" go list -deps -f '{{.ImportPath}} {{join .Imports " "}}' ./... >"$DUMPDIR/deps.$n" 2>"$DUMPDIR/deps.$n.err") &
		pids+=($!)
		descs+=("tags=$tags go list -deps ./...")
		files+=("$DUMPDIR/deps.$n.err")
		for goos in $GOOSES; do
			(cd "$ROOT" && GOFLAGS="$(tagflags "$tags")" GOOS="$goos" CGO_ENABLED=0 go list -f '{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... >"$DUMPDIR/imp.$n.$goos" 2>"$DUMPDIR/imp.$n.$goos.err") &
			pids+=($!)
			descs+=("GOOS=$goos tags=$tags go list ./...")
			files+=("$DUMPDIR/imp.$n.$goos.err")
		done
		n=$((n + 1))
	done
	local i failed=0
	for i in "${!pids[@]}"; do
		# Explicit exits: a go list failure must never read as a package with
		# no imports.
		if ! wait "${pids[$i]}"; then
			echo "m7-exit-checks: ${descs[$i]} failed" >&2
			head -n 5 "${files[$i]}" >&2 || true
			failed=1
		fi
	done
	[ "$failed" -eq 0 ] || exit 2
}

# deps_dump prints the path of the deps dump for the current TAGS.
deps_dump() {
	if [ -z "$TAGS" ]; then printf '%s' "$DUMPDIR/deps.0"; else printf '%s' "$DUMPDIR/deps.1"; fi
}

# AWK_CLOSURE reads a deps dump ("<path> <imports...>" per line). Variables:
# mode (deps or allow), mod, base (the pattern's import path without a
# trailing /...), wild (1 when the pattern ended in /...), rule, list (the
# forbidden or allowed import paths, space separated). The matched packages
# are walked in import-path order; the closure of each is its DFS post-order
# (self last), as `go list -deps` prints it. Standard library packages (no dot
# in the first path element) are never walked. An exact pattern that matches
# no package is an error (exit 2), as it is for go list.
# shellcheck disable=SC2016  # awk program: no shell expansion wanted
AWK_CLOSURE='
function isstd(p,   a) { split(p, a, "/"); return index(a[1], ".") == 0 }
function dfs(p,   i, n, parts) {
	if (p in seen) return
	seen[p] = 1
	if (isstd(p) || !(p in imps)) return
	n = split(imps[p], parts, " ")
	for (i = 1; i <= n; i++) dfs(parts[i])
	order[++cnt] = p
}
function under(d, e) { return d == e || index(d, e "/") == 1 }
{
	imps[$1] = substr($0, length($1) + 2)
	if (!isstd($1) && ($1 == mod || index($1, mod "/") == 1)) mods[++nm] = $1
}
END {
	for (i = 1; i <= nm; i++) {
		p = mods[i]
		if (wild ? under(p, base) : p == base) sel[++ns] = p
	}
	if (ns == 0 && !wild) { print "no package matches " base > "/dev/stderr"; exit 2 }
	for (i = 2; i <= ns; i++) {
		v = sel[i]
		for (j = i - 1; j >= 1 && sel[j] > v; j--) sel[j + 1] = sel[j]
		sel[j + 1] = v
	}
	nl = split(list, items, " ")
	for (s = 1; s <= ns; s++) {
		p = sel[s]
		delete seen; delete order; cnt = 0
		dfs(p)
		if (mode == "deps") {
			for (k = 1; k <= nl; k++) {
				f = items[k]
				for (i = 1; i <= cnt; i++) {
					if (under(order[i], f)) { print "deps_violation=" p " imports " f " [rule " rule "]"; break }
				}
			}
		} else {
			for (i = 1; i <= cnt; i++) {
				ok = 0
				for (k = 1; k <= nl; k++) if (under(order[i], items[k])) ok = 1
				if (!ok) print "deps_violation=" p " imports " order[i] " [rule " rule "]"
			}
		}
	}
}'

# closure_rule MODE RULE PATTERN ENTRY...: runs AWK_CLOSURE over the dump for
# TAGS, prints its violation lines and adds them to the global violations.
closure_rule() {
	local mode="$1" rule="$2" pattern="$3" base wild=0 out entry list=""
	shift 3
	base="$pattern"
	case "$pattern" in
	./*) base="$MOD/${pattern#./}" ;;
	esac
	case "$base" in
	*/...) wild=1; base="${base%/...}" ;;
	esac
	for entry in "$@"; do list="$list $entry"; done
	out="$(awk -v mode="$mode" -v mod="$MOD" -v base="$base" -v wild="$wild" -v rule="$rule" -v list="$list" "$AWK_CLOSURE" "$(deps_dump)")" || {
		echo "m7-exit-checks: go list $pattern failed" >&2
		exit 2
	}
	if [ -n "$out" ]; then
		printf '%s\n' "$out"
		violations=$((violations + $(printf '%s\n' "$out" | wc -l)))
	fi
}

# check_deps RULE PATTERN FORBIDDEN...: an entry is an in-module path (relative to
# the module) or, when it starts with "github.com/", a third-party path; each
# is matched as a whole line of `go list -deps` or as the prefix "<entry>/" of
# one. Sets the global violations.
violations=0
check_deps() {
	local rule="$1" pattern="$2" f
	local entries=()
	shift 2
	for f in "$@"; do
		if [[ "$f" == github.com/* ]]; then entries+=("$f"); else entries+=("$MOD/$f"); fi
	done
	closure_rule deps "$rule" "$pattern" "${entries[@]}"
}

# check_allowlist RULE PATTERN ALLOWED...: every non-standard production dependency
# of each package PATTERN matches must equal an allowed entry or lie below it
# ("<entry>/..."). Entries are full import paths. Sets the global violations.
check_allowlist() {
	local rule="$1" pattern="$2"
	shift 2
	closure_rule allow "$rule" "$pattern" "$@"
}

# check_importers RULE IMPORT ALLOWED_PKG: only ALLOWED_PKG (a full import
# path) may import IMPORT (or a package below it) directly; every package of
# ./... is scanned for each of GOOS linux, darwin and windows (CGO off), for
# the default build and again with the build tags M7_TAGS, and for its
# production, test and external-test files alike. A package is reported once
# however many GOOS values or tag sets show it. Sets the global violations.
check_importers() {
	local rule="$1" target="$2" allowed="$3" n goos out
	local files=()
	for n in 0 1; do
		for goos in $GOOSES; do files+=("$DUMPDIR/imp.$n.$goos"); done
	done
	# shellcheck disable=SC2016  # awk program: no shell expansion wanted
	out="$(awk -v rule="$rule" -v target="$target" -v allowed="$allowed" '
		$1 == allowed || ($1 in done) { next }
		{
			for (i = 2; i <= NF; i++) {
				if ($i == target || index($i, target "/") == 1) {
					print "deps_violation=" $1 " imports " target " [rule " rule "]"
					done[$1] = 1
					break
				}
			}
		}' "${files[@]}")"
	if [ -n "$out" ]; then
		printf '%s\n' "$out"
		violations=$((violations + $(printf '%s\n' "$out" | wc -l)))
	fi
}

import_check() {
	build_dumps
	check_deps store-no-core './internal/store/...' internal/core
	check_deps notify-leaf ./internal/core/notify internal/store github.com/jackc/pgx
	check_deps pgnotify-no-server ./internal/core/notify/pgnotify internal/server internal/gen
	check_allowlist slackapi-allowlist ./internal/slackapi "$MOD/internal/slackapi"
	check_allowlist slackapi-allowlist ./internal/slackapi/slackfake "$MOD/internal/slackapi"
	check_importers slack-go-importers github.com/slack-go/slack "$MOD/internal/slackapi/slackgo"
	# An external key backend and the SDKs it links are imported by its adapter
	# package alone (the tagged file in internal/server/cmd imports the adapter,
	# not the SDK).
	check_importers awskms-importers github.com/sigstore/sigstore/pkg/signature/kms/aws "$MOD/internal/keyprovider/awskms"
	check_importers awskms-importers github.com/aws/aws-sdk-go-v2 "$MOD/internal/keyprovider/awskms"
	check_importers awskms-importers github.com/aws/smithy-go "$MOD/internal/keyprovider/awskms"
	# The hashivault backend: sigstore's module signs, and the Vault API client
	# reads the transit key (sigstore does not expose the latest key version).
	check_importers hashivault-importers github.com/sigstore/sigstore/pkg/signature/kms/hashivault "$MOD/internal/keyprovider/hashivault"
	check_importers hashivault-importers github.com/hashicorp/vault/api "$MOD/internal/keyprovider/hashivault"
	# The gcpkms backend: sigstore's module signs; the Cloud KMS client reads the
	# key (sigstore does not expose the version it resolves to), the auth
	# library and the metadata client type the credential failures (gRPC
	# flattens them), and gRPC and the API option/iterator packages are the
	# client's own types. Each is imported by the adapter alone.
	check_importers gcpkms-importers github.com/sigstore/sigstore/pkg/signature/kms/gcp "$MOD/internal/keyprovider/gcpkms"
	check_importers gcpkms-importers cloud.google.com/go/kms "$MOD/internal/keyprovider/gcpkms"
	check_importers gcpkms-importers cloud.google.com/go/auth "$MOD/internal/keyprovider/gcpkms"
	check_importers gcpkms-importers cloud.google.com/go/compute/metadata "$MOD/internal/keyprovider/gcpkms"
	check_importers gcpkms-importers google.golang.org/api "$MOD/internal/keyprovider/gcpkms"
	check_importers gcpkms-importers google.golang.org/grpc "$MOD/internal/keyprovider/gcpkms"
	check_importers gcpkms-importers google.golang.org/protobuf "$MOD/internal/keyprovider/gcpkms"
	# The azurekms backend: sigstore's module signs; the azkeys client reads the
	# key (sigstore does not expose the version it resolves to, and builds its
	# own credential and client, so it cannot be pointed at a fake), azidentity
	# types the credential failures and azcore the client's options and errors.
	# Each is imported by the adapter alone.
	check_importers azurekms-importers github.com/sigstore/sigstore/pkg/signature/kms/azure "$MOD/internal/keyprovider/azurekms"
	check_importers azurekms-importers github.com/Azure/azure-sdk-for-go/sdk/azcore "$MOD/internal/keyprovider/azurekms"
	check_importers azurekms-importers github.com/Azure/azure-sdk-for-go/sdk/azidentity "$MOD/internal/keyprovider/azurekms"
	check_importers azurekms-importers github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys "$MOD/internal/keyprovider/azurekms"
	check_deps slackbridge-isolation ./internal/slackbridge internal/server internal/gen internal/slackapi/slackgo github.com/slack-go/slack
	local p
	for p in './internal/core/...' './internal/bus/...' ./internal/cli ./internal/mcpserver ./internal/client ./internal/server; do
		check_deps slack-consumers "$p" internal/slackapi internal/slackbridge internal/slackapi/slackgo
	done
	# The keyprovider port, the file provider included, is a leaf over
	# internal/auth/keys (go-jose comes
	# with it: the allowlist is transitive); the fake adds nothing; the
	# backends and their SDKs are reached from internal/server/cmd's tagged
	# files alone.
	check_allowlist keyprovider-leaf ./internal/keyprovider "$MOD/internal/keyprovider" "$MOD/internal/auth/keys" github.com/go-jose/go-jose/v4
	check_allowlist keyprovider-leaf ./internal/keyprovider/kmsfake "$MOD/internal/keyprovider" "$MOD/internal/auth/keys" github.com/go-jose/go-jose/v4
	# The certificate profiles are a leaf over the standard library alone.
	check_allowlist pki-leaf ./internal/pki "$MOD/internal/pki"
	check_allowlist pki-leaf ./internal/pki/rootca "$MOD/internal/pki"
	# The client's trust store imports the standard library, internal/filelock
	# and internal/pki. The rule lists the dependencies of the platform it runs
	# on: internal/filelock imports no golang.org/x/sys on Unix, while its
	# Windows build imports golang.org/x/sys/windows, so this rule is for Unix.
	check_allowlist trust-leaf ./internal/trust "$MOD/internal/trust" "$MOD/internal/filelock" "$MOD/internal/pki"
	local tags
	for tags in "" "$M7_TAGS"; do
		TAGS="$tags"
		for p in './internal/core/...' './internal/bus/...' ./internal/cli ./internal/mcpserver ./internal/client ./internal/server; do
			check_deps keyprovider-consumers "$p" internal/keyprovider/awskms internal/keyprovider/gcpkms internal/keyprovider/azurekms internal/keyprovider/hashivault
		done
	done
	TAGS=""
	if [ "$violations" -ne 0 ]; then
		return 1
	fi
	echo "deps_ok=1"
}

if [ "$#" -eq 1 ] && [ "$1" = "--deps-only" ]; then
	import_check
	exit $?
fi
if [ "$#" -ne 1 ]; then
	echo "usage: $0 <replicas.log> | --deps-only" >&2
	exit 2
fi
log="$1"
if [ ! -s "$log" ]; then
	echo "m7-exit-checks: log '$log' is missing or empty" >&2
	exit 2
fi
count() { grep -c -E "^[[:space:]]+--- PASS: $1/$2/" "$log" || true; }
fail="$(grep -c -E '^[[:space:]]+--- FAIL' "$log" || true)"
wake_sqlite="$(count TestReplicasWake sqlite)"
wake_postgres="$(count TestReplicasWake postgres)"
maint_sqlite="$(count TestReplicasMaintenanceExclusive sqlite)"
maint_postgres="$(count TestReplicasMaintenanceExclusive postgres)"
trust_sqlite="$(count TestReplicasTrust sqlite)"
trust_postgres="$(count TestReplicasTrust postgres)"
echo "fail=$fail"
echo "wake_sqlite=$wake_sqlite"
echo "wake_postgres=$wake_postgres"
echo "maint_sqlite=$maint_sqlite"
echo "maint_postgres=$maint_postgres"
echo "trust_sqlite=$trust_sqlite"
echo "trust_postgres=$trust_postgres"
rc=0
if [ "$fail" -ne 0 ] || [ "$wake_sqlite" -ne 4 ] || [ "$wake_postgres" -ne 6 ] || [ "$maint_sqlite" -ne 2 ] || [ "$maint_postgres" -ne 2 ] || [ "$trust_sqlite" -ne 3 ] || [ "$trust_postgres" -ne 4 ]; then
	echo "m7-exit-checks: want fail=0, wake_sqlite=4, wake_postgres=6, maint_sqlite=2, maint_postgres=2, trust_sqlite=3 and trust_postgres=4" >&2
	rc=1
fi
import_check || rc=1
exit "$rc"
