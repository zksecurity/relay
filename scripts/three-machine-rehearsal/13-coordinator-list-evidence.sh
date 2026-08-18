#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -eq 1 ]] || die "usage: $0 COORDINATOR_CONFIG"
load_rehearsal_config "$1"
require_coordinator
verify_binary_hashes

"$RELAY_BIN" coordinator evidence --storage "$STORAGE_CONFIG"
