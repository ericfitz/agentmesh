#!/usr/bin/env bash
# cats-harness.sh: the CATS fuzzing campaign harness (issue #30).
#
# Builds the agentmesh binary, starts a throwaway native server on loopback over
# a temporary SQLite file, seeds identities and fixtures, mints bearers and runs
# the `cats` CLI against api/openapi.yaml. Everything lives in one harness
# directory (mode 0700, marker file .agentmesh-cats): the binary, the SQLite
# file, the server log, the pid and url files, the config and data dirs (so the
# bearer caches) and the headers file. `down` removes it whole. Eric's own
# config and server are never touched: AGENTMESH_CONFIG_DIR and
# AGENTMESH_DATA_DIR point into the harness directory.
#
# Rulings: 7 (one directory), 8 (up refuses a live pid; run always downs first),
# 10 and 13 (tuned server settings, the two identities, the skip list and the
# decoys), 12 (per-path headers), 14 (exit codes), 24 (--paths minus the skip
# list), 25 (session lease), 31 (check_dir before every rm -rf).
#
# Leak scan (ruling 39): `run` looks for the campaign's own secrets, not for
# token-shaped patterns: the exact minted bearers, the enrollment token and the
# credential key lines, collected into "$DIR/leak.secrets" (mode 0600, removed
# with the directory) and matched with `grep -F -f`. No value is ever printed;
# only the names of the files that hold one. The spec's example tokens and the
# documented `enrollment_token` answers of createAgentIdentity are expected
# content and do not match.
#
# Bearers: a bearer never reaches stdout, a log or a file outside the harness
# directory. The one exception is `token`, which prints the bearer alone. There
# is no `set -x` anywhere. The single-use enrollment token for cats-admin passes
# on `register`'s argv (the CLI has no file form) and is visible in `ps` to the
# same user for under a second: accepted (ruling 31) because it is single-use,
# bound to cats-admin, consumed at once and useless against any other server.
#
# Definition of Done D (state):
#   second `up`            exit 3 while the recorded server is alive.
#   `up` over a dead pid
#     or a stale directory cleaned and restarted.
#   `run` twice            each run tears down what the previous left.
#   two overlapping `run`s (or `up`s) on one directory: the second refuses,
#                          exit 3, while the first holds the lock "$DIR.lock"
#                          (an atomic mkdir holding the owner pid; a lock whose
#                          owner is dead is taken over). Use --dir for a second
#                          campaign.
#   `seed` twice           the same fixtures, re-read (fixed idempotency keys,
#                          conflicts accepted); sessions are reopened. A task or
#                          memory that is gone (a fuzzed DELETE) is re-created
#                          under a fresh key with a new id, and a removed channel
#                          is re-created; the live ids go into the refData.
#   `down` twice           the second is a no-op.
#
# Exit codes: 0 ok; 1 a check failed (a bearer in a log, a dead fixture);
# 2 usage or a missing tool (cats, jq, go) or a refused directory; 3 the server
# did not start, a live server is recorded (up), or the seed failed; 4 CATS
# exited with a code other than 0 or 1 or wrote no cats-summary-report.json.
set -euo pipefail
umask 077

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

# Constants (rulings 10 and 13).
PROFILE=cats
ADMIN=cats-admin
AGENT=cats-agent
VICTIM=cats-victim
SERVER_SETS=(-set send_messages_per_second=10000 -set send_kib_per_second=65536
  -set token_lifetime_seconds=86400 -set session_lease_seconds=86400
  -set watch_max_seconds=1 -set maintenance_interval_seconds=3600
  -set signing_key_rotation_cooldown_seconds=1)
SKIP_PATHS=(/v1/admin/reset /v1/admin/signing-keys/rotate
  '/v1/admin/identities/{identity}/reset-credential'
  /v1/admin/bridges '/v1/admin/bridges/{channel}')
ADMIN_PATHS=(/v1/admin/bridges '/v1/admin/bridges/{channel}' /v1/admin/identities
  /v1/admin/identities/by-email '/v1/admin/identities/{identity}/reset-credential'
  /v1/admin/reset /v1/admin/scopes '/v1/admin/scopes/{scope}'
  '/v1/admin/scopes/{scope}/done' /v1/admin/signing-keys
  /v1/admin/signing-keys/rotate /v1/admin/status /v1/admin/usage)
LISTEN_RE='agentmesh server listening on ([^ ]+) \('
TOKEN_RE='^token: (abe_[^ ]+)$'
MARKER=.agentmesh-cats
CATS_BIN=${CATS_BIN:-cats}

DIR=${CATS_HARNESS_DIR:-${TMPDIR:-/tmp}/agentmesh-cats-$(id -u)}
PORT=0
REPO=$ROOT
OUT=
WHO=${CATS_IDENTITY:-agent}
HEADERS_OUT=
PATHS=
NO_SKIP=0

usage() {
  cat <<'EOF'
scripts/cats-harness.sh up     [--dir DIR] [--port N] [--repo DIR]
scripts/cats-harness.sh seed   [--dir DIR] [--out DIR] [--identity admin|agent]
scripts/cats-harness.sh token  [--dir DIR] <admin|agent>
scripts/cats-harness.sh headers [--dir DIR] [--out FILE]
scripts/cats-harness.sh run    [--dir DIR] [--port N] [--repo DIR] [--out DIR] [--paths LIST] [--no-skip]
scripts/cats-harness.sh down   [--dir DIR]
scripts/cats-harness.sh status [--dir DIR]
scripts/cats-harness.sh admin-paths
scripts/cats-harness.sh skip-paths

Environment: CATS_BIN (the cats executable, default cats), CATS_HARNESS_DIR
(default --dir), CATS_IDENTITY (default seed --identity), CATS_SMOKE=1 (run
`cats smoke` before the campaign in run; off by default).

Exit codes: 0 ok; 1 a check failed (a bearer in a log, a dead fixture);
2 usage, a missing tool (cats, jq, go) or a refused directory; 3 the server did
not start, a live server is recorded (up), or the seed failed; 4 CATS exited
with a code other than 0 or 1 or wrote no cats-summary-report.json.
EOF
}

die() { # die CODE MESSAGE...
  local code=$1
  shift
  echo "cats-harness: $*" >&2
  exit "$code"
}

need_tool() {
  command -v "$1" >/dev/null 2>&1 || die 2 "missing tool: $1"
}

# Lock (finding 3): "$DIR.lock" is an atomic mkdir holding the owner pid, so two
# overlapping `up`s or `run`s cannot both proceed. A lock whose owner is dead is
# taken over, one taker at a time: "$DIR.lock.takeover" is a second atomic mkdir
# (the gate) that the taker holds while it re-reads the owner and replaces the
# lock, so a second taker that also saw the dead pid finds the first one's live
# pid under the gate and backs off (final review, Finding 5). Both are siblings
# of $DIR, so `down` never removes them. A taker killed inside the gate leaves
# it behind; the refusal names the path to remove.
LOCK_HELD=0
GATE_HELD=0
lock_owner() { # lock_owner LOCK: the live pid recorded in LOCK, empty when none or dead
  local o
  o=$(cat "$1/pid" 2>/dev/null || true)
  case "$o" in '' | *[!0-9]*) return 0 ;; esac
  if kill -0 "$o" 2>/dev/null; then echo "$o"; fi
}
release_gate() {
  [ "$GATE_HELD" -eq 1 ] || return 0
  GATE_HELD=0
  rmdir "$DIR.lock.takeover" 2>/dev/null || true
}
acquire_lock() {
  local lock=$DIR.lock gate=$DIR.lock.takeover owner
  mkdir -p "$(dirname "$DIR")"
  if ! mkdir -m 700 "$lock" 2>/dev/null; then
    owner=$(lock_owner "$lock")
    [ -z "$owner" ] || die 3 "another harness command is active (pid $owner, lock $lock)"
    mkdir -m 700 "$gate" 2>/dev/null ||
      die 3 "another harness command is taking over the stale lock $lock (a killed one leaves $gate behind; remove it)"
    GATE_HELD=1
    owner=$(lock_owner "$lock")
    if [ -n "$owner" ]; then
      release_gate
      die 3 "another harness command is active (pid $owner, lock $lock)"
    fi
    rm -f "$lock/pid"
    rmdir "$lock" 2>/dev/null || { release_gate; die 3 "cannot take over the lock $lock"; }
    mkdir -m 700 "$lock" 2>/dev/null || { release_gate; die 3 "another harness command holds the lock $lock"; }
    echo "$$" >"$lock/pid"
    LOCK_HELD=1
    release_gate
    return 0
  fi
  echo "$$" >"$lock/pid"
  LOCK_HELD=1
}
release_lock() {
  [ "$LOCK_HELD" -eq 1 ] || return 0
  LOCK_HELD=0
  rm -f "$DIR.lock/pid"
  rmdir "$DIR.lock" 2>/dev/null || true
}

# check_dir validates $DIR before anything is removed (ruling 31).
check_dir() {
  case "$DIR" in
    /) die 2 "refusing $DIR: not a harness directory" ;;
    /*) ;;
    *) die 2 "refusing $DIR: not a harness directory (want an absolute path)" ;;
  esac
  if [ -L "$DIR" ]; then
    die 2 "refusing $DIR: not a harness directory"
  fi
  [ -e "$DIR" ] || return 0
  if [ ! -d "$DIR" ] || [ ! -O "$DIR" ]; then
    die 2 "refusing $DIR: not a harness directory"
  fi
  if [ -n "$(ls -A "$DIR")" ] && [ ! -f "$DIR/$MARKER" ]; then
    die 2 "refusing $DIR: not a harness directory"
  fi
}

# server_alive prints nothing; returns 0 when server.pid names a live process
# whose command line contains "$DIR/agentmesh server".
server_alive() {
  local pid cmd
  [ -f "$DIR/server.pid" ] || return 1
  pid=$(cat "$DIR/server.pid" 2>/dev/null || true)
  case "$pid" in '' | *[!0-9]*) return 1 ;; esac
  kill -0 "$pid" 2>/dev/null || return 1
  cmd=$(ps -o command= -p "$pid" 2>/dev/null || true)
  case "$cmd" in *"$DIR/agentmesh server"*) return 0 ;; esac
  return 1
}

kill_server() {
  local pid i
  server_alive || return 0
  pid=$(cat "$DIR/server.pid")
  kill -TERM "$pid" 2>/dev/null || true
  for ((i = 0; i < 25; i++)); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

do_down() {
  check_dir
  [ -d "$DIR" ] || return 0
  if [ -f "$DIR/server.pid" ]; then
    if server_alive; then
      kill_server
    else
      echo "cleaned leftovers (pid $(cat "$DIR/server.pid" 2>/dev/null || echo '?') dead)"
    fi
  fi
  rm -rf "$DIR"
}

set_env() {
  export AGENTMESH_CONFIG_DIR="$DIR/config" AGENTMESH_DATA_DIR="$DIR/data"
  # Nothing from the caller's environment may select another profile or identity.
  unset AGENTMESH_PROFILE AGENTMESH_IDENTITY AGENTMESH_SERVER AGENTMESH_CREDENTIAL
}

# am runs the harness binary with the harness environment.
am() { "$DIR/agentmesh" "$@"; }

# collect_secrets appends the campaign's secret values to "$DIR/leak.secrets"
# (0600; one value per line, nothing shorter than 16 characters, so no empty or
# trivial line can match everything): the cached bearers, the credential key
# body lines and any value passed as an argument. Nothing is printed.
collect_secrets() {
  local f v file=$DIR/leak.secrets
  [ -f "$file" ] || { : >"$file"; chmod 600 "$file"; }
  {
    for v in "$@"; do printf '%s\n' "$v"; done
    for f in "$DIR"/data/tokens/*/*.json; do
      [ -f "$f" ] && jq -r '.access_token // empty' "$f"
    done
    for f in "$DIR"/config/credentials/*/*; do
      [ -f "$f" ] && grep -v -e '^-----' "$f"
    done
  } 2>/dev/null | awk 'length($0) >= 16' >>"$file" || true
}

require_live() {
  server_alive || die 3 "no live harness server in $DIR (run: up)"
  set_env
  URL=$(cat "$DIR/server.url")
}

# ---------------------------------------------------------------- up

do_up() {
  need_tool go
  need_tool jq
  check_dir
  [ "$LOCK_HELD" -eq 1 ] || acquire_lock
  if server_alive; then
    die 3 "a harness server is alive (pid $(cat "$DIR/server.pid")); run: scripts/cats-harness.sh down"
  fi
  rm -rf "$DIR"
  mkdir -m 700 "$DIR"
  touch "$DIR/$MARKER"
  set_env
  : >"$DIR/harness.log"

  (cd "$REPO" && CGO_ENABLED=0 go build -trimpath -o "$DIR/agentmesh" .) >>"$DIR/harness.log" 2>&1 ||
    { tail -n 20 "$DIR/harness.log" >&2; die 3 "go build failed"; }

  local db=$DIR/server.sqlite tok
  am server admin -sqlite "$db" create-identity "$ADMIN" >>"$DIR/harness.log" 2>&1 ||
    die 3 "create-identity $ADMIN failed (see $DIR/harness.log)"
  am server admin -sqlite "$db" admins add -identity "$ADMIN" >>"$DIR/harness.log" 2>&1 ||
    die 3 "admins add failed (see $DIR/harness.log)"
  tok=$(am server admin -sqlite "$db" enrollment create -identity "$ADMIN" -expires 24h -uses 1 2>>"$DIR/harness.log" |
    sed -nE "s/$TOKEN_RE/\\1/p") || true
  [ -n "$tok" ] || die 3 "enrollment create returned no token (see $DIR/harness.log)"
  collect_secrets "$tok"

  "$DIR/agentmesh" server -listen "127.0.0.1:$PORT" -sqlite "$db" "${SERVER_SETS[@]}" \
    >"$DIR/server.log" 2>&1 </dev/null &
  local pid=$!
  echo "$pid" >"$DIR/server.pid"
  disown "$pid" 2>/dev/null || true

  local i addr=
  for ((i = 0; i < 150; i++)); do
    if [[ $(cat "$DIR/server.log") =~ $LISTEN_RE ]]; then
      addr=${BASH_REMATCH[1]}
      break
    fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  if [ -z "$addr" ]; then
    tail -n 20 "$DIR/server.log" >&2
    kill_server
    die 3 "the server did not start"
  fi
  URL=http://$addr
  echo "$URL" >"$DIR/server.url"

  local step_fail=0
  am register -profile "$PROFILE" -identity "$ADMIN" -server "$URL" -enrollment-token "$tok" \
    >>"$DIR/harness.log" 2>&1 || step_fail=1
  tok=
  am register -profile "$PROFILE" -identity "$AGENT" -server "$URL" \
    >>"$DIR/harness.log" 2>&1 || step_fail=1
  am login -profile "$PROFILE" -identity "$ADMIN" >>"$DIR/harness.log" 2>&1 || step_fail=1
  am login -profile "$PROFILE" -identity "$AGENT" >>"$DIR/harness.log" 2>&1 || step_fail=1
  if [ "$step_fail" -ne 0 ]; then
    tail -n 20 "$DIR/harness.log" >&2
    kill_server
    die 3 "registration or login failed (see $DIR/harness.log)"
  fi
  collect_secrets
  echo "dir=$DIR"
  echo "server=$URL"
}

# ---------------------------------------------------------------- seed

# cli_seed runs a CLI command as cats-admin, accepting a conflict (an existing
# object); stdout goes to the variable SEED_OUT. Any other failure exits 3.
cli_seed() {
  local err rc=0
  err=$(mktemp "$DIR/err.XXXXXX")
  SEED_OUT=$(am "$1" "${@:2}" 2>"$err") || rc=$?
  if [ "$rc" -ne 0 ]; then
    if [ "$rc" -eq 1 ] && grep -q -E '^agentmesh: conflict:' "$err"; then
      SEED_OUT=
      rm -f "$err"
      return 0
    fi
    tail -n 5 "$err" >&2
    rm -f "$err"
    die 3 "seed: agentmesh $* failed (exit $rc)"
  fi
  rm -f "$err"
}

# ensure_item KIND IDENTITY KEY CHANNEL CONTENT: sets ITEM_ID to the id of a
# live task or memory. The fixed key makes a second seed return the same id; when
# that item is gone (a fuzzed DELETE removed it) the key still replays the dead
# id, so the item is created again under a fresh key and gets a new id.
ensure_item() {
  local kind=$1 who=$2 key=$3 channel=$4 content=$5
  local c=(-profile "$PROFILE" -identity "$who") field=memory_id
  [ "$kind" = task ] && field=id
  item_create() { # item_create KEY
    if [ "$kind" = task ]; then
      cli_seed tasks create "${c[@]}" -key "$1" "$channel" "$content"
    else
      cli_seed send "${c[@]}" -key "$1" "$channel" "$content"
    fi
    ITEM_ID=$(jq -r ".$field // empty" <<<"$SEED_OUT")
  }
  item_create "$key"
  [ -n "$ITEM_ID" ] || die 3 "seed: no $kind id in the CLI output for key $key"
  if ! item_live "$kind" "${c[@]}"; then
    item_create "$key-r$(date +%s)-$$"
    [ -n "$ITEM_ID" ] || die 3 "seed: no $kind id in the CLI output for the re-created $key"
    item_live "$kind" "${c[@]}" || die 3 "seed: the re-created $kind $ITEM_ID is not live"
    echo "seed: re-created $kind $key as $ITEM_ID" >&2
  fi
}

# item_live KIND CLI-FLAGS...: 0 when ITEM_ID names a live task or memory, 1 on
# not_found; any other failure exits 3.
item_live() {
  local kind=$1 err rc=0
  shift
  err=$(mktemp "$DIR/err.XXXXXX")
  if [ "$kind" = task ]; then
    am tasks get "$@" "$ITEM_ID" >/dev/null 2>"$err" || rc=$?
  else
    am memories get "$@" "$ITEM_ID" >/dev/null 2>"$err" || rc=$?
  fi
  if [ "$rc" -ne 0 ] && ! grep -q -E '^agentmesh: not_found:' "$err"; then
    tail -n 5 "$err" >&2
    rm -f "$err"
    die 3 "seed: checking $kind $ITEM_ID failed (exit $rc)"
  fi
  rm -f "$err"
  return "$rc"
}

do_seed() {
  need_tool jq
  case "$WHO" in admin | agent) ;; *) die 2 "--identity: want admin or agent, got $WHO" ;; esac
  require_live
  [ -n "$OUT" ] || OUT=$DIR
  mkdir -p "$OUT"
  # An ACL replaces the default one. Every channel but cats-acl names both identities, so the
  # administrator pass reaches messages and subscription too (a channel with the
  # agent alone answered 403 to the administrator). The fuzzed PUT of an ACL in the agent pass may still
  # drop the agent's own admin entry on cats-acl: that leftover is a recorded
  # rule, not a harness change.
  local acl_both='[{"identity":"cats-agent","permissions":["read","write","admin"]},{"identity":"cats-admin","permissions":["read","write","admin"]}]'
  # cats-acl alone names the agent only. CATS cannot send two different entries
  # in the root-array body of PUT /v1/channels/{channel}/acl (a refData key such
  # as identity sets every entry alike), and an agent that is not an
  # administrator may not take a permission from cats-admin's entry (ADR 0011),
  # so with both seeded the agent's PUT could never succeed. The administrator
  # keeps admin on it through the flag (Task 8.4).
  local acl_agent='[{"identity":"cats-agent","permissions":["read","write","admin"]}]'
  local a=(-profile "$PROFILE" -identity "$ADMIN")

  cli_seed channels create "${a[@]}" -acl "$acl_both" cats-ordinary
  cli_seed channels create "${a[@]}" -acl "$acl_both" cats-ordinary-decoy
  # The fuzzed PUT of an ACL rewrites it (and may drop the agent's own admin), so
  # it gets a channel of its own: cats-ordinary stays usable for the nested paths.
  cli_seed channels create "${a[@]}" -acl "$acl_agent" cats-acl
  # CATS mangles a path parameter with "?" and "#", so a request for
  # DELETE /v1/channels/cats-sub?/subscription reaches DELETE /v1/channels/cats-sub:
  # the one nested operation with a DELETE prefix gets a channel of its own too.
  cli_seed channels create "${a[@]}" -acl "$acl_both" cats-sub
  cli_seed channels create "${a[@]}" -acl "$acl_both" -kind tasks cats-tasks
  cli_seed channels create "${a[@]}" -acl "$acl_both" -kind memory cats-memory
  # An earlier pass may have emptied or rewritten an existing channel's ACL (a
  # fuzzed PUT); every seed puts acl_both back (Task 8.4).
  local ch
  for ch in cats-ordinary cats-ordinary-decoy cats-sub cats-tasks cats-memory; do
    cli_seed channels acl "${a[@]}" -set "$acl_both" "$ch"
  done
  cli_seed channels acl "${a[@]}" -set "$acl_agent" cats-acl
  cli_seed scopes create "${a[@]}" cats-scope
  cli_seed scopes create "${a[@]}" cats-scope-decoy

  local task_id task_decoy_id task_parent_id memory_id memory_decoy_id
  ensure_item task "$ADMIN" cats-seed-task-fixture cats-tasks 'Fixture task'
  task_id=$ITEM_ID
  ensure_item task "$ADMIN" cats-seed-task-decoy cats-tasks 'Decoy task'
  task_decoy_id=$ITEM_ID
  # createTask's parent: a task no other path touches, so the happy path's
  # parent still resolves after the fuzzers have patched the others.
  ensure_item task "$ADMIN" cats-seed-task-parent cats-tasks 'Parent task'
  task_parent_id=$ITEM_ID
  ensure_item memory "$ADMIN" cats-seed-memory-fixture cats-memory 'Fixture memory'
  memory_id=$ITEM_ID
  ensure_item memory "$ADMIN" cats-seed-memory-decoy cats-memory 'Decoy memory'
  memory_decoy_id=$ITEM_ID

  # The throwaway identity for reset-credential: registered (its key lives in
  # the harness directory), and never used to authenticate. A second register
  # answers "existing key".
  am register -profile "$PROFILE" -identity "$VICTIM" -server "$URL" >>"$DIR/harness.log" 2>&1 ||
    die 3 "seed: register $VICTIM failed (see $DIR/harness.log)"

  local who_name=$AGENT
  [ "$WHO" = admin ] && who_name=$ADMIN
  local s=(-profile "$PROFILE" -identity "$who_name")
  cli_seed session open "${s[@]}" -hint cats-primary
  local session_id
  session_id=$(jq -r '.session // empty' <<<"$SEED_OUT")
  cli_seed session open "${s[@]}" -hint cats-decoy
  local session_decoy_id
  session_decoy_id=$(jq -r '.session // empty' <<<"$SEED_OUT")
  [ -n "$session_id" ] && [ -n "$session_decoy_id" ] || die 3 "seed: a session id is missing"

  local scope_line='  scope: cats_remove_field'
  [ "$WHO" = admin ] && scope_line='  scope: cats-scope'

  jq -n --arg task "$task_id" --arg taskd "$task_decoy_id" --arg taskp "$task_parent_id" --arg mem "$memory_id" \
    --arg memd "$memory_decoy_id" --arg ses "$session_id" --arg sesd "$session_decoy_id" \
    --arg who "$WHO" '{identity: $who, channels: ["cats-ordinary", "cats-ordinary-decoy", "cats-acl", "cats-sub", "cats-tasks", "cats-memory"],
      scopes: ["cats-scope", "cats-scope-decoy"], task: $task, task_decoy: $taskd, task_parent: $taskp, memory: $mem,
      memory_decoy: $memd, session: $ses, session_decoy: $sesd}' >"$OUT/seed.json"

  cat >"$OUT/refdata.yml" <<EOF
/v1/channels:
  acl[*]#identity: cats-agent
  acl[*]#permissions: [read, write, admin]
$scope_line
/v1/channels/{channel}:
  channel: cats-ordinary-decoy
/v1/channels/{channel}/acl:
  channel: cats-acl
  identity: cats-agent
  permissions[*]: admin
/v1/channels/{channel}/subscription:
  channel: cats-sub
/v1/channels/{channel}/messages:
  channel: cats-ordinary
  reply_to: cats_remove_field
  session: $session_id
/v1/channels/{channel}/tasks:
  channel: cats-tasks
  parent: $task_parent_id
  blocked_by: cats_remove_field
  before: cats_remove_field
  after: cats_remove_field
/v1/tasks/{id}:
  id: $task_decoy_id
  owner: cats-agent
  parent: $task_parent_id
/v1/tasks/{id}/claim:
  id: $task_id
/v1/tasks/{id}/release:
  id: $task_id
/v1/memories/{id}:
  id: $memory_decoy_id
/v1/memories/{id}/revisions:
  id: $memory_id
/v1/sessions/{session}:
  session: $session_decoy_id
/v1/sessions/{session}/peek:
  session: $session_id
/v1/sessions/{session}/receive:
  session: $session_id
  channels[*]: cats-ordinary
/v1/search:
  channel: cats-ordinary
/v1/sessions/{session}/watch:
  session: $session_id
/v1/sessions/{session}/status:
  session: $session_id
/v1/identities/{identity}/statuses:
  identity: cats-agent
/v1/admin/scopes/{scope}:
  scope: cats-scope
/v1/admin/scopes/{scope}/done:
  scope: cats-scope-decoy
  retire: normal
/v1/admin/identities:
  scope: cats-scope
/v1/admin/identities/{identity}/reset-credential:
  identity: $VICTIM
EOF

  jq -n --arg task "$task_id" --arg mem "$memory_id" --arg ses "$session_id" --arg who "$WHO" '
    {fixtures: ([
      {key: "channel", id: "cats-ordinary", verify_url: "/v1/channels/cats-ordinary/acl", anchor_path: "/v1/channels/{channel}", decoyed: true},
      {key: "tasks-channel", id: "cats-tasks", verify_url: "/v1/channels/cats-tasks/tasks", anchor_path: "/v1/channels/{channel}", decoyed: true},
      {key: "task", id: $task, verify_url: ("/v1/tasks/" + $task), anchor_path: "/v1/tasks/{id}", decoyed: true},
      {key: "memory", id: $mem, verify_url: ("/v1/memories/" + $mem), anchor_path: "/v1/memories/{id}", decoyed: true},
      {key: "session", id: $ses, verify_url: ("/v1/sessions/" + $ses + "/peek"), anchor_path: "/v1/sessions/{session}", decoyed: true}
    ] + (if $who == "admin" then [
      {key: "scope", id: "cats-scope", verify_url: "/v1/admin/scopes/cats-scope", anchor_path: "/v1/admin/scopes/{scope}/done", decoyed: true}
    ] else [] end))}' >"$OUT/fixtures.json"
  echo "seeded: $OUT"
}

# ---------------------------------------------------------------- token, headers

# mint_token NAME: refreshes the bearer through login and prints it.
mint_token() {
  local name=$1
  am login -profile "$PROFILE" -identity "$name" >>"$DIR/harness.log" 2>&1 ||
    die 3 "login $name failed (see $DIR/harness.log)"
  collect_secrets
  jq -r .access_token "$DIR/data/tokens/$PROFILE/$name.json"
}

do_token() {
  need_tool jq
  local name
  case "${1:-}" in
    admin) name=$ADMIN ;;
    agent) name=$AGENT ;;
    *) usage >&2; exit 2 ;;
  esac
  require_live
  mint_token "$name"
}

do_headers() {
  need_tool jq
  require_live
  local file=${HEADERS_OUT:-$DIR/headers.yml} agent_b admin_b p
  agent_b=$(mint_token "$AGENT")
  admin_b=$(mint_token "$ADMIN")
  rm -f "$file" # never write a bearer into a file that already exists under a wider mode
  {
    echo 'all:'
    echo "  Authorization: Bearer $agent_b"
    for p in "${ADMIN_PATHS[@]}"; do
      echo "$p:"
      echo "  Authorization: Bearer $admin_b"
    done
  } >"$file"
  chmod 600 "$file"
  echo "$file"
}

# ---------------------------------------------------------------- status

do_status() {
  echo "dir=$DIR"
  if [ -d "$DIR" ] && [ ! -L "$DIR" ] && [ -f "$DIR/server.url" ]; then
    echo "server=$(cat "$DIR/server.url")"
  else
    echo "server=none"
  fi
  if [ -d "$DIR" ] && [ ! -L "$DIR" ] && [ -f "$DIR/server.pid" ]; then
    local pid
    pid=$(cat "$DIR/server.pid")
    if server_alive; then echo "pid=$pid alive"; else echo "pid=$pid dead"; fi
  else
    echo "pid=none"
  fi
}

# ---------------------------------------------------------------- run

in_skip() { # in_skip PATH
  local s
  for s in "${SKIP_PATHS[@]}"; do [ "$s" = "$1" ] && return 0; done
  return 1
}

join_comma() { local IFS=,; echo "$*"; }

RUN_STARTED=0
run_cleanup() {
  if [ "$RUN_STARTED" -eq 1 ]; then
    RUN_STARTED=0
    rm -f "$DIR/headers.yml" 2>/dev/null || true
    do_down >/dev/null 2>&1 || true
  fi
}

on_exit() {
  run_cleanup
  release_gate
  release_lock
}

do_run() {
  need_tool "$CATS_BIN"
  need_tool jq
  need_tool go
  need_tool curl
  check_dir
  if [ -z "$OUT" ]; then
    OUT=$ROOT/.local/cats/results/run-$(date -u +%Y%m%dT%H%M%SZ)
  fi
  case "$OUT" in /*) ;; *) OUT=$PWD/$OUT ;; esac
  case "$OUT/" in "$DIR"/*) die 2 "--out must not be inside the harness directory" ;; esac

  # Ruling 24: subtract the skip list from an explicit --paths.
  local paths_list=() skip_args=() p
  if [ -n "$PATHS" ]; then
    local given=()
    IFS=, read -r -a given <<<"$PATHS"
    for p in "${given[@]}"; do
      [ -n "$p" ] || continue
      if [ "$NO_SKIP" -eq 0 ] && in_skip "$p"; then
        echo "skipped: $p (use --no-skip)"
      else
        paths_list+=("$p")
      fi
    done
    if [ "${#paths_list[@]}" -eq 0 ]; then
      echo "nothing to fuzz"
      return 0
    fi
  elif [ "$NO_SKIP" -eq 0 ]; then
    skip_args=("--skipPaths=$(join_comma "${SKIP_PATHS[@]}")")
  fi

  acquire_lock
  RUN_STARTED=1 # before up: an interrupt during up still runs down
  do_down
  do_up >/dev/null
  require_live
  mkdir -p "$OUT"
  local run_out=$OUT
  OUT=$DIR
  do_seed >/dev/null
  OUT=$run_out
  HEADERS_OUT=
  do_headers >/dev/null
  mkdir -p "$DIR/cwd"
  local path_args=()
  [ "${#paths_list[@]}" -gt 0 ] && path_args=("--paths=$(join_comma "${paths_list[@]}")")

  local common=(-c "$REPO/api/openapi.yaml" -s "$URL" --headers="$DIR/headers.yml"
    --no-checkUpdate --noEnvFile)

  if [ "${CATS_SMOKE:-0}" = 1 ]; then
    (cd "$DIR/cwd" && "$CATS_BIN" smoke "${common[@]}" "${skip_args[@]}" "${path_args[@]}" \
      -o "$OUT/smoke" >"$DIR/smoke.log" 2>&1) || true
    tail -n 1 "$DIR/smoke.log" >"$OUT/smoke.txt" 2>/dev/null || true
  fi

  local cats_rc=0
  (cd "$DIR/cwd" && "$CATS_BIN" "${common[@]}" --refData="$DIR/refdata.yml" -o "$OUT/report" \
    --maxRequestsPerMinute=10000 --printExecutionStatistics "${skip_args[@]}" "${path_args[@]}" \
    >"$OUT/cats.log" 2>&1) || cats_rc=$?
  rm -f "$DIR/headers.yml"
  echo "$cats_rc" >"$OUT/cats.exit"

  local rc=0 summary=$OUT/report/cats-summary-report.json
  if [ "$cats_rc" -gt 1 ] || [ ! -f "$summary" ]; then
    tail -n 20 "$OUT/cats.log" >&2
    echo "cats-harness: CATS exited $cats_rc or wrote no cats-summary-report.json" >&2
    return 4
  fi

  # Post-run fixture check, with the agent bearer. Not under --no-skip: a
  # destructive run (reset, rotate, reset-credential) is expected to destroy the
  # fixtures or the credential, so the check would fail and minting a bearer
  # could die; the run is judged by its report alone.
  if [ "$NO_SKIP" -eq 0 ]; then
    local agent_b key url code
    agent_b=$(mint_token "$AGENT")
    while IFS=$'\t' read -r key url; do
      # The bearer goes to curl on stdin (-K -), never on argv.
      code=$(printf 'header = "Authorization: Bearer %s"\n' "$agent_b" |
        curl -s -m 10 -K - -o /dev/null -w '%{http_code}' "${URL%/}$url" || true)
      case "$code" in
        2??) ;;
        *) echo "fixture $key died (HTTP $code)"; rc=1 ;;
      esac
    done < <(jq -r '.fixtures[] | select(.key != "scope") | [.key, .verify_url] | @tsv' "$DIR/fixtures.json")
    agent_b=
  fi

  # Leak scan (ruling 39): the exact secrets of this run, never a pattern.
  collect_secrets
  local leaks=() hit scan grc
  if [ ! -s "$DIR/leak.secrets" ]; then
    echo "leak scan has no secrets to look for"
    rc=1
  else
    for scan in "$DIR/server.log" "$OUT/cats.log" "$OUT/report" "$OUT/smoke" "$OUT/smoke.txt"; do
      [ -e "$scan" ] || continue
      grc=0
      hit=$(grep -r -l -F -f "$DIR/leak.secrets" "$scan" 2>/dev/null) || grc=$?
      if [ "$grc" -gt 1 ]; then
        echo "leak scan failed on $scan"
        rc=1
      fi
      while IFS= read -r hit; do
        [ -n "$hit" ] && leaks+=("$hit")
      done <<<"$hit"
    done
    if [ "${#leaks[@]}" -gt 0 ]; then
      echo "bearer leaked into: $(join_comma "${leaks[@]}")"
      rc=1
    fi
  fi

  jq -r '"tests=\(.totalTests) success=\(.success) warnings=\(.warnings) errors=\(.errors) status=\(.runStatus)"' "$summary"
  echo "report=$OUT/report"
  return "$rc"
}

# ---------------------------------------------------------------- main

[ $# -ge 1 ] || { usage >&2; exit 2; }
CMD=$1
shift
case "$CMD" in -h | --help) usage; exit 0 ;; esac

POS=()
SEEN=" "
PATHS_GIVEN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dir | --port | --repo | --out | --identity | --paths)
      [ $# -ge 2 ] || die 2 "$1 needs a value"
      SEEN+="$1 "
      case "$1" in
        --dir) DIR=$2 ;;
        --port) PORT=$2 ;;
        --repo) REPO=$2 ;;
        --out) OUT=$2; HEADERS_OUT=$2 ;;
        --identity) WHO=$2 ;;
        --paths) PATHS=$2; PATHS_GIVEN=1 ;;
      esac
      shift 2 ;;
    --no-skip) SEEN+="--no-skip "; NO_SKIP=1; shift ;;
    -h | --help) usage; exit 0 ;;
    -*) usage >&2; die 2 "unknown option: $1" ;;
    *) POS+=("$1"); shift ;;
  esac
done

# Each subcommand takes only its own flags and positionals.
case "$CMD" in
  up) ALLOWED=" --dir --port --repo " ;;
  seed) ALLOWED=" --dir --out --identity " ;;
  token) ALLOWED=" --dir " ;;
  headers) ALLOWED=" --dir --out " ;;
  run) ALLOWED=" --dir --port --repo --out --paths --no-skip " ;;
  down | status) ALLOWED=" --dir " ;;
  admin-paths | skip-paths | help) ALLOWED=" " ;;
  *) usage >&2; die 2 "unknown subcommand: $CMD" ;;
esac
for f in $SEEN; do
  case "$ALLOWED" in *" $f "*) ;; *) usage >&2; die 2 "$f is not valid for $CMD" ;; esac
done
if [ "$CMD" = token ]; then
  [ "${#POS[@]}" -eq 1 ] || { usage >&2; die 2 "token takes one argument: admin or agent"; }
elif [ "${#POS[@]}" -ne 0 ]; then
  usage >&2
  die 2 "unexpected argument for $CMD: ${POS[0]}"
fi
if [ "$PATHS_GIVEN" -eq 1 ] && [ -z "$PATHS" ]; then
  die 2 "--paths: empty list"
fi
case "$PORT" in '' | *[!0-9]*) die 2 "--port: want a number" ;; esac

case "$CMD" in
  admin-paths | skip-paths | help) ;;
  *)
    # Finding 1: normalize before any -L, -d or rm: no trailing slashes (a
    # trailing slash makes `[ -L ]` follow a symlink) and no . or .. component.
    while [ "${#DIR}" -gt 1 ] && [ "${DIR%/}" != "$DIR" ]; do DIR=${DIR%/}; done
    case "/$DIR/" in
      */./* | */../*) die 2 "refusing $DIR: not a harness directory (no . or .. components)" ;;
    esac
    ;;
esac
case "$CMD" in
  up | run)
    # Finding 4: an existing repository with the spec, as an absolute path.
    [ -d "$REPO" ] || die 2 "--repo $REPO: not a directory"
    REPO=$(cd "$REPO" && pwd -P)
    [ -f "$REPO/api/openapi.yaml" ] || die 2 "--repo $REPO: no api/openapi.yaml"
    ;;
esac
case "$CMD" in
  up | run)
    trap on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    ;;
esac

case "$CMD" in
  admin-paths) printf '%s\n' "${ADMIN_PATHS[@]}" ;;
  skip-paths) printf '%s\n' "${SKIP_PATHS[@]}" ;;
  up) do_up ;;
  seed) do_seed ;;
  token) do_token "${POS[0]}" ;;
  headers) do_headers ;;
  run) do_run ;;
  down) do_down ;;
  status) do_status ;;
  help) usage ;;
esac
