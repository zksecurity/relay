#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -eq 4 ]] || die "usage: $0 COORDINATOR_CONFIG phase1|phase2 PARTICIPANT OUT_FILE"
load_rehearsal_config "$1"
phase=$2
participant_id=$3
out=$4
require_coordinator
verify_binary_hashes
phase_number "$phase" >/dev/null
participant_is_valid "$participant_id"
require_fresh_path "$out"
mkdir -p "$(dirname "$out")"
chmod 0700 "$(dirname "$out")"

read_r2_parent_token_if_needed
trap clear_r2_parent_token EXIT

"$RELAY_BIN" coordinator grant \
  --storage "$STORAGE_CONFIG" \
  --role participant \
  --identity "$participant_id" \
  --credential-ttl 1h \
  --minimum-upload-window 15m \
  --out "$out"

chmod 0600 "$out"
printf '\nPrivately transfer this bearer grant to the assigned participant machine:\n%s\n' "$out"
