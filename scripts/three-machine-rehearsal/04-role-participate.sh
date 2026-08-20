#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -eq 4 ]] || die "usage: $0 ROLE_CONFIG phase1|phase2 PARTICIPANT GRANT_FILE"
load_rehearsal_config "$1"
phase=$2
participant_id=$3
grant=$4
require_common
verify_binary_hashes
ensure_run_directories
phase_number "$phase" >/dev/null
participant_is_valid "$participant_id"
[[ -f "$grant" && ! -L "$grant" ]] || die "grant is absent or unsafe: $grant"
[[ -f "$KEYS_ROOT/${participant_id}.ed25519.private.hex" ]] || die "participant key is absent"
[[ -f "$CONFIG_ROOT/environment.json" ]] || die "environment.json is absent"

participant_root="$RUN_ROOT/participants/$phase/$participant_id/transcript"
candidate_parent="$RUN_ROOT/candidates/$phase/$participant_id"
participant_config="$RUN_ROOT/configs/$phase-$participant_id.relay.json"
participate_log="$RUN_ROOT/logs/$phase-$participant_id.participate.log"
manifest_key_file="$RUN_ROOT/outbox/$phase-$participant_id.manifest-key.txt"

require_fresh_path "$participant_config"
require_fresh_path "$participate_log"
require_fresh_path "$manifest_key_file"
mkdir -p "$participant_root" "$candidate_parent"
chmod 0700 "$participant_root" "$candidate_parent"

# A failed turn must stay recoverable without knowledge of the run-root
# layout: archive this attempt's outputs so the fresh-path checks above pass
# on retry, and nothing is deleted. The archive keeps the local candidate;
# nothing in it has been published.
archive_failed_attempt() {
  local status=$?
  [[ $status -eq 0 ]] && return 0
  local archive
  archive="$RUN_ROOT/failed/$phase-$participant_id-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$archive"
  chmod 0700 "$RUN_ROOT/failed" "$archive"
  local path
  for path in "$participant_config" "$participate_log" "$manifest_key_file" \
    "$candidate_parent" "$participant_root"; do
    [[ -e "$path" ]] && mv "$path" "$archive/" 2>/dev/null
  done
  printf '\nAttempt failed (exit %d); its outputs were archived to:\n%s\n' \
    "$status" "$archive" >&2
  printf 'Rerun this script to retry. Nothing was deleted.\n' >&2
  return "$status"
}
trap archive_failed_attempt EXIT

"$RELAY_BIN" enroll \
  --storage "$STORAGE_CONFIG" \
  --grant "$grant" \
  --phase "$phase" \
  --root "$participant_root" \
  --ceremony "$CEREMONY_ROOT/ceremony.json" \
  --ceremony-signature "$CEREMONY_ROOT/ceremony.sig" \
  --coordinator-key "$TRUSTED_COORDINATOR_KEY" \
  --ceremony-binary "$MPC_BIN" \
  --signing-key "$KEYS_ROOT/${participant_id}.ed25519.private.hex" \
  --environment "$CONFIG_ROOT/environment.json" \
  --candidate-parent "$candidate_parent" \
  --out "$participant_config"

printf '\nAfter contribution, destroy the rehearsal environment as planned.\n'
printf 'Wait at least one second before typing DESTROYED.\n\n'

"$RELAY_BIN" participate --config "$participant_config" | tee "$participate_log"

mapfile -t manifest_keys < <(sed -n 's/^manifest: //p' "$participate_log")
[[ ${#manifest_keys[@]} -eq 1 && -n "${manifest_keys[0]}" ]] || die "participate did not print exactly one manifest key"
printf '%s\n' "${manifest_keys[0]}" >"$manifest_key_file"
chmod 0600 "$manifest_key_file"

printf '\nSend this non-secret manifest-key file to Machine 1:\n%s\n' "$manifest_key_file"
