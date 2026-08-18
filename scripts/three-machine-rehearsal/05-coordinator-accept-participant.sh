#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -eq 4 ]] || die "usage: $0 COORDINATOR_CONFIG phase1|phase2 PARTICIPANT MANIFEST_KEY_FILE"
load_rehearsal_config "$1"
phase=$2
participant_id=$3
manifest_key_file=$4
require_coordinator
verify_binary_hashes
ensure_run_directories
phase_number "$phase" >/dev/null
participant_is_valid "$participant_id"
[[ -f "$manifest_key_file" && ! -L "$manifest_key_file" ]] || die "manifest-key file is absent or unsafe"

mapfile -t manifest_keys <"$manifest_key_file"
[[ ${#manifest_keys[@]} -eq 1 && -n "${manifest_keys[0]}" ]] || die "manifest-key file must contain exactly one key"
candidate_key=${manifest_keys[0]}
review_dir="$RUN_ROOT/review/$phase-$participant_id"
require_fresh_path "$review_dir"

"$RELAY_BIN" coordinator candidates \
  --storage "$STORAGE_CONFIG" \
  --phase "$phase"

phase_flags=()
if [[ "$phase" == phase2 ]]; then
  phase_flags=(
    --phase1-seal "$CEREMONY_ROOT/phase1/sealed/seal.json"
    --phase1-seal-signature "$CEREMONY_ROOT/phase1/sealed/seal.sig"
  )
fi

"$RELAY_BIN" coordinator accept \
  --storage "$STORAGE_CONFIG" \
  --candidate-key "$candidate_key" \
  --root "$CEREMONY_ROOT" \
  --candidate-dir "$review_dir" \
  --coordinator-signing-key "$KEYS_ROOT/coordinator.ed25519.private.hex" \
  --verify-publish \
  "${phase_flags[@]}"

sleep 2
