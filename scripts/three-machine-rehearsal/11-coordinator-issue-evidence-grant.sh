#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -eq 4 ]] || die "usage: $0 COORDINATOR_CONFIG witness|mirror|auditor|release|decision ID OUT_FILE"
load_rehearsal_config "$1"
role=$2
identity=$3
out=$4
require_coordinator
verify_binary_hashes
[[ "$role" == witness || "$role" == mirror || "$role" == auditor || "$role" == release || "$role" == decision ]] || die "unsupported evidence role"
[[ "$identity" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || die "invalid identity"
require_fresh_path "$out"
mkdir -p "$(dirname "$out")"
chmod 0700 "$(dirname "$out")"

enrollment="$CEREMONY_ROOT/operational/enrollments/$identity.json"
enrollment_signature="$CEREMONY_ROOT/operational/enrollments/$identity.sig"
[[ -f "$enrollment" && -f "$enrollment_signature" ]] || die "signed enrollment is absent"

read_r2_parent_token_if_needed
trap clear_r2_parent_token EXIT

"$RELAY_BIN" coordinator grant \
  --storage "$STORAGE_CONFIG" \
  --role "$role" \
  --identity "$identity" \
  --credential-ttl 1h \
  --minimum-upload-window 15m \
  --enrollment "$enrollment" \
  --enrollment-signature "$enrollment_signature" \
  --out "$out"

chmod 0600 "$out"
printf '\nPrivately transfer this bearer grant to the assigned role machine:\n%s\n' "$out"
