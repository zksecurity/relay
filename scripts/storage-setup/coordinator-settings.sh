#!/usr/bin/env bash
# Sourced helpers. No cloud calls and no secret-bearing environment serialization.
prepare_coordinator_settings_export() {
  local target=$1 parent
  [[ -n "$target" ]] || return 0
  [[ "$target" == /* && "$target" != *$'\n'* && "$target" != *$'\r'* ]] || die 'Use an absolute coordinator-settings output path.'
  case "$target/" in *'/../'*|*'/./'*|*'//'*) die 'Use a clean coordinator-settings output path.';; esac
  [[ ! -e "$target" && ! -L "$target" ]] || die 'Coordinator settings output already exists; it will not be overwritten.'
  parent=$(dirname "$target")
  [[ -d "$parent" && -w "$parent" ]] || die 'Create the coordinator-settings parent folder first.'
  while [[ "$parent" != / ]]; do
    [[ ! -L "$parent" ]] || die 'Coordinator-settings parent folders must not be symlinks.'
    parent=$(dirname "$parent")
  done
}

save_coordinator_settings_export() {
  local target=$1
  prepare_coordinator_settings_export "$target"
  # Input is constructed from an explicit non-secret whitelist by the caller.
  (set -o noclobber; umask 077; jq -S . > "$target") || die 'Could not create coordinator settings; preserve any partial output for review.'
  printf '\nSend this non-secret settings file to the coordinator through your agreed channel:\n  %s\nDeliver credentials separately; never put them in this JSON file.\n' "$target"
}
