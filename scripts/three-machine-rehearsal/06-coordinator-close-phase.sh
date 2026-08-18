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
phase_number "$phase" >/dev/null

sequence=$(phase_final_sequence "$phase")
chain=$(phase_chain "$phase" "$sequence")
signature=$(phase_chain_signature "$phase" "$sequence")
[[ -f "$chain" && -f "$signature" ]] || die "final $phase chain is absent"

signed_lead=$(python3 - "$CEREMONY_ROOT/ceremony.json" <<'PY'
import json
import sys

with open(sys.argv[1], "rb") as handle:
    definition = json.load(handle)
if definition.get("mode") != "rehearsal":
    raise SystemExit("this script accepts rehearsal definitions only")
print(definition["beacon_policy"]["minimum_witness_lead_seconds"])
PY
)
observation_buffer=${REHEARSAL_WITNESS_BUFFER_SECONDS:-120}
[[ "$observation_buffer" =~ ^[1-9][0-9]*$ ]] || die "REHEARSAL_WITNESS_BUFFER_SECONDS must be positive"
lead=$((signed_lead + observation_buffer))

phase_flags=()
if [[ "$phase" == phase2 ]]; then
  phase_flags=(
    --phase1-seal "$CEREMONY_ROOT/phase1/sealed/seal.json"
    --phase1-seal-signature "$CEREMONY_ROOT/phase1/sealed/seal.sig"
  )
fi

"$MPC_BIN" "$phase" close \
  --ceremony "$CEREMONY_ROOT/ceremony.json" \
  --ceremony-signature "$CEREMONY_ROOT/ceremony.sig" \
  --coordinator-public-key-file "$TRUSTED_COORDINATOR_KEY" \
  --transcript-dir "$CEREMONY_ROOT" \
  --chain "$chain" \
  --chain-signature "$signature" \
  --coordinator-signing-key "$KEYS_ROOT/coordinator.ed25519.private.hex" \
  --beacon-round-lead "$lead" \
  "${phase_flags[@]}"

publish_phase_head "$phase" "$sequence" yes

printf '\nSigned witness lead: %s seconds\n' "$signed_lead"
printf 'Rehearsal observation buffer: %s seconds\n' "$observation_buffer"
printf 'The phase is published closed. Run 07-role-witness-watch.sh on Machines 2 and 3 now.\n'
