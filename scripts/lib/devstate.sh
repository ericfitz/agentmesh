#!/usr/bin/env bash
# devstate.sh: the local CI state directory (local CI spec, runner contract).
# Sourced by windows-test.sh and the other runners; defines functions only.
#
#   $AGENTMESH_DEV_STATE, else ${XDG_STATE_HOME:-$HOME/.local/state}/agentmesh-dev
#     logs/<check>/<commit>/   full logs of one run
#     passes/<check>/<commit>  empty file recorded on a pass
#     windows-test.lock        "pid start_epoch" of a running windows-test.sh
#
# Check names: windows-test, verify-linux, gates-selftest, release-preflight.
# A check or commit argument that is empty or has a character outside
# [A-Za-z0-9._-] is refused (return 2), so no argument escapes the directory.

# devstate_dir: print the state directory, creating it.
devstate_dir() {
  local d=${AGENTMESH_DEV_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/agentmesh-dev}
  mkdir -p "$d" || return 2
  printf '%s\n' "$d"
}

# _devstate_name_ok NAME...: return 0 when every argument is a safe name.
_devstate_name_ok() {
  local n
  for n in "$@"; do
    case "$n" in
      '' | . | .. | *[!A-Za-z0-9._-]*)
        echo "devstate: invalid name '$n'" >&2
        return 2
        ;;
    esac
  done
}

# devstate_logdir CHECK COMMIT: print <state>/logs/<check>/<commit>, creating it.
devstate_logdir() {
  [ $# -eq 2 ] || { echo "usage: devstate_logdir CHECK COMMIT" >&2; return 2; }
  _devstate_name_ok "$1" "$2" || return 2
  local d
  d=$(devstate_dir) || return 2
  mkdir -p "$d/logs/$1/$2" || return 2
  printf '%s\n' "$d/logs/$1/$2"
}

# devstate_passed CHECK COMMIT: return 0 when a pass is recorded.
devstate_passed() {
  [ $# -eq 2 ] || { echo "usage: devstate_passed CHECK COMMIT" >&2; return 2; }
  _devstate_name_ok "$1" "$2" || return 2
  local d
  d=$(devstate_dir) || return 2
  [ -f "$d/passes/$1/$2" ]
}

# devstate_record_pass CHECK COMMIT: record a pass.
devstate_record_pass() {
  [ $# -eq 2 ] || { echo "usage: devstate_record_pass CHECK COMMIT" >&2; return 2; }
  _devstate_name_ok "$1" "$2" || return 2
  local d
  d=$(devstate_dir) || return 2
  mkdir -p "$d/passes/$1" || return 2
  : >"$d/passes/$1/$2"
}
