#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -eq 1 ]] || die "usage: $0 CONFIG"
load_rehearsal_config "$1"
require_common
verify_binary_hashes
ensure_run_directories

"$RELAY_BIN" --help >/dev/null
"$MPC_BIN" help >/dev/null

printf 'machine check passed\n'
printf 'relay:        %s\n' "$RELAY_BIN"
printf 'mpc-ceremony: %s\n' "$MPC_BIN"
printf 'ceremony:     %s\n' "$CEREMONY_ROOT/ceremony.json"
printf 'run root:     %s\n' "$RUN_ROOT"
