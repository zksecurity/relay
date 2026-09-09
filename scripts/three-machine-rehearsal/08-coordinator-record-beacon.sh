#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -eq 2 ]] || die "usage: $0 COORDINATOR_CONFIG phase1|phase2"
load_rehearsal_config "$1"
phase=$2
require_coordinator
verify_binary_hashes
ensure_run_directories
phase_number "$phase" >/dev/null

closure="$CEREMONY_ROOT/$phase/closure/record.json"
closure_signature="$CEREMONY_ROOT/$phase/closure/record.sig"
[[ -f "$closure" && -f "$closure_signature" ]] || die "$phase closure is absent"

relay_dir="$RUN_ROOT/$phase-relays"

readarray -t beacon_fields < <(python3 - "$closure" <<'PY'
import json
import sys

with open(sys.argv[1], "rb") as handle:
    closure = json.load(handle)
print(closure["beacon_round"])
print(closure["beacon_not_before"])
PY
)
[[ ${#beacon_fields[@]} -eq 2 ]] || die "cannot read beacon schedule"
round=${beacon_fields[0]}
not_before=${beacon_fields[1]}
not_before_epoch=$(date -u -d "$not_before" +%s)

while true; do
  now=$(date -u +%s)
  if (( now >= not_before_epoch )); then
    break
  fi
  remaining=$((not_before_epoch - now))
  printf 'waiting for %s Quicknet round %s: %s seconds remain\n' "$phase" "$round" "$remaining"
  sleep 15
done

# Resume successful retrievals without changing their original timestamps.
# These are two actual operators, not three Protocol Labs hostnames.
retrieved1=$(python3 "$SCRIPT_ROOT/beacon-download.py" "$relay_dir" "$round")

"$MPC_BIN" "$phase" beacon \
  --ceremony "$CEREMONY_ROOT/ceremony.json" \
  --ceremony-signature "$CEREMONY_ROOT/ceremony.sig" \
  --coordinator-public-key-file "$TRUSTED_COORDINATOR_KEY" \
  --closure "$closure" \
  --closure-signature "$closure_signature" \
  --raw-response "$relay_dir/protocol-labs.json" \
  --published-at "$retrieved1" \
  --coordinator-signing-key "$KEYS_ROOT/coordinator.ed25519.private.hex" \
  --transcript-dir "$CEREMONY_ROOT"

sequence=$(phase_final_sequence "$phase")

if [[ "$phase" == phase1 ]]; then
  "$MPC_BIN" phase1 seal \
    --ceremony "$CEREMONY_ROOT/ceremony.json" \
    --ceremony-signature "$CEREMONY_ROOT/ceremony.sig" \
    --coordinator-public-key-file "$TRUSTED_COORDINATOR_KEY" \
    --transcript-dir "$CEREMONY_ROOT" \
    --closure "$CEREMONY_ROOT/phase1/closure/record.json" \
    --closure-signature "$CEREMONY_ROOT/phase1/closure/record.sig" \
    --beacon "$CEREMONY_ROOT/phase1/beacon/record.json" \
    --beacon-signature "$CEREMONY_ROOT/phase1/beacon/record.sig" \
    --coordinator-signing-key "$KEYS_ROOT/coordinator.ed25519.private.hex" \
    --out-dir "$CEREMONY_ROOT/phase1/sealed"

  publish_phase_head phase1 "$sequence" yes

  "$MPC_BIN" phase2 init \
    --ceremony "$CEREMONY_ROOT/ceremony.json" \
    --ceremony-signature "$CEREMONY_ROOT/ceremony.sig" \
    --coordinator-public-key-file "$TRUSTED_COORDINATOR_KEY" \
    --phase1-transcript-dir "$CEREMONY_ROOT" \
    --phase1-seal "$CEREMONY_ROOT/phase1/sealed/seal.json" \
    --phase1-seal-signature "$CEREMONY_ROOT/phase1/sealed/seal.sig" \
    --coordinator-signing-key "$KEYS_ROOT/coordinator.ed25519.private.hex" \
    --out-dir "$CEREMONY_ROOT/phase2"

  publish_phase_head phase2 0000 no
  printf '\nPhase 2 is initialized and published. Begin its participant turns.\n'
else
  publish_phase_head phase2 "$sequence" yes
  printf '\nBoth contribution phases and beacons are complete.\n'
fi
