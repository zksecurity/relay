#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -ge 3 ]] || die "usage: $0 ROLE_CONFIG GRANT_FILE EVIDENCE_FILE [EVIDENCE_FILE...]"
load_rehearsal_config "$1"
grant=$2
shift 2
require_common
verify_binary_hashes
[[ -f "$grant" && ! -L "$grant" ]] || die "grant is absent or unsafe"

file_flags=()
for evidence in "$@"; do
  [[ -f "$evidence" && ! -L "$evidence" ]] || die "evidence file is absent or unsafe: $evidence"
  file_flags+=(--file "$evidence")
done

"$RELAY_BIN" submit-evidence \
  --grant "$grant" \
  "${file_flags[@]}"
