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

chain=$(phase_chain "$phase" 0000)
signature=$(phase_chain_signature "$phase" 0000)
[[ -f "$chain" && -f "$signature" ]] || die "$phase initial chain is absent"

publish_phase_head "$phase" 0000 no
