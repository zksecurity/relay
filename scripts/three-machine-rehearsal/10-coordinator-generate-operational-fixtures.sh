#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -eq 1 ]] || die "usage: $0 COORDINATOR_CONFIG"
load_rehearsal_config "$1"
require_coordinator
verify_binary_hashes
require_var PROOF_TOOL_ROOT
[[ -d "$PROOF_TOOL_ROOT" && ! -L "$PROOF_TOOL_ROOT" ]] || die "proof-tool checkout is absent or unsafe"
[[ -d "$RUN_ROOT/phase1-relays" ]] || die "Phase 1 relay responses are absent"
[[ -d "$RUN_ROOT/phase2-relays" ]] || die "Phase 2 relay responses are absent"
require_fresh_path "$CEREMONY_ROOT/operational"

helper="$RUN_ROOT/mpc-rehearsal-operational-evidence"
require_fresh_path "$helper"
(
  cd "$PROOF_TOOL_ROOT"
  CGO_ENABLED=0 go build \
    -trimpath \
    -buildvcs=false \
    -o "$helper" \
    ./scripts/mpc-rehearsal-operational-evidence
)
chmod 0500 "$helper"

"$helper" \
  --transcript-root "$CEREMONY_ROOT" \
  --keys-dir "$KEYS_ROOT" \
  --coordinator-public-key-file "$TRUSTED_COORDINATOR_KEY" \
  --phase1-relays "$RUN_ROOT/phase1-relays" \
  --phase2-relays "$RUN_ROOT/phase2-relays" \
  --assembled-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --out-dir "$CEREMONY_ROOT/operational"

"$MPC_BIN" ops verify \
  --record-type evidence-bundle \
  --record "$CEREMONY_ROOT/operational/evidence-bundle.json" \
  --signature "$CEREMONY_ROOT/operational/evidence-bundle.sig" \
  --ceremony "$CEREMONY_ROOT/ceremony.json" \
  --ceremony-signature "$CEREMONY_ROOT/ceremony.sig" \
  --coordinator-public-key-file "$TRUSTED_COORDINATOR_KEY" \
  --signer-public-key-file "$KEYS_ROOT/coordinator.ed25519.public.hex" \
  --evidence-root "$CEREMONY_ROOT"

printf '\nThese are centrally generated same-host fixtures, not independent role evidence.\n'
