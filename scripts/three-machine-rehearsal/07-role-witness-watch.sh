#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -eq 3 ]] || die "usage: $0 ROLE_CONFIG phase1|phase2 WITNESS_ID"
load_rehearsal_config "$1"
phase=$2
witness_id=$3
require_reader
verify_binary_hashes
ensure_run_directories
phase_number "$phase" >/dev/null
[[ "$witness_id" =~ ^witness-[0-9][0-9]$ ]] || die "invalid witness identity"

view_root="$RUN_ROOT/role-views/$witness_id/$phase"
mkdir -p "$view_root"
chmod 0700 "$view_root"

"$RELAY_BIN" witness watch \
  --once \
  --root "$view_root" \
  --ceremony "$CEREMONY_ROOT/ceremony.json" \
  --ceremony-signature "$CEREMONY_ROOT/ceremony.sig" \
  --coordinator-key "$TRUSTED_COORDINATOR_KEY" \
  --ceremony-binary "$MPC_BIN" \
  --phase "$phase" \
  --bucket "$PUBLISHED_BUCKET" \
  --public-base-url "$PUBLISHED_BASE_URL"

printf '\n%s saw the Relay closure notification for %s.\n' "$witness_id" "$phase"
printf 'This command does not create or sign a public-witness receipt.\n'
