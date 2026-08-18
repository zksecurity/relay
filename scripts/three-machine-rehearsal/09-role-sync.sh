#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -eq 4 ]] || die "usage: $0 ROLE_CONFIG mirror|auditor phase1|phase2 ID"
load_rehearsal_config "$1"
role=$2
phase=$3
identity=$4
require_reader
verify_binary_hashes
ensure_run_directories
phase_number "$phase" >/dev/null
[[ "$role" == mirror || "$role" == auditor ]] || die "role must be mirror or auditor"
[[ "$identity" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || die "invalid role identity"

view_root="$RUN_ROOT/role-views/$identity"
mkdir -p "$view_root"
chmod 0700 "$view_root"

"$RELAY_BIN" "$role" sync \
  --root "$view_root" \
  --ceremony "$CEREMONY_ROOT/ceremony.json" \
  --ceremony-signature "$CEREMONY_ROOT/ceremony.sig" \
  --coordinator-key "$TRUSTED_COORDINATOR_KEY" \
  --ceremony-binary "$MPC_BIN" \
  --phase "$phase" \
  --bucket "$PUBLISHED_BUCKET" \
  --endpoint "$STORAGE_ENDPOINT" \
  --profile "$PUBLISHED_READER_PROFILE"
