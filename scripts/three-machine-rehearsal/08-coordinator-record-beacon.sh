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
require_fresh_path "$relay_dir"
mkdir -m 0700 "$relay_dir"

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

chain_hash=52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971
url1="https://api.drand.sh/$chain_hash/public/$round"
url2="https://api2.drand.sh/$chain_hash/public/$round"
url3="https://api3.drand.sh/$chain_hash/public/$round"

curl --fail --silent --show-error "$url1" --output "$relay_dir/api-1.json"
retrieved1=$(date -u +%Y-%m-%dT%H:%M:%SZ)
curl --fail --silent --show-error "$url2" --output "$relay_dir/api-2.json"
retrieved2=$(date -u +%Y-%m-%dT%H:%M:%SZ)
curl --fail --silent --show-error "$url3" --output "$relay_dir/api-3.json"
retrieved3=$(date -u +%Y-%m-%dT%H:%M:%SZ)

python3 - "$round" "$relay_dir/api-1.json" "$relay_dir/api-2.json" "$relay_dir/api-3.json" <<'PY'
import json
import sys

expected_round = int(sys.argv[1])
responses = []
for path in sys.argv[2:]:
    with open(path, "rb") as handle:
        value = json.load(handle)
    if value.get("round") != expected_round:
        raise SystemExit(f"{path}: wrong round")
    responses.append((value.get("signature"), value.get("randomness")))
if len(set(responses)) != 1:
    raise SystemExit("drand endpoints disagree")
PY

hash1=$(printf '%s' "$url1" | sha256sum | cut -d ' ' -f 1)
hash2=$(printf '%s' "$url2" | sha256sum | cut -d ' ' -f 1)
hash3=$(printf '%s' "$url3" | sha256sum | cut -d ' ' -f 1)

{
  printf 'relay_id\toperator_id\tendpoint_sha256\tretrieved_at\tfilename\n'
  printf 'api-1\trehearsal-operator-1\tsha256:%s\t%s\tapi-1.json\n' "$hash1" "$retrieved1"
  printf 'api-2\trehearsal-operator-2\tsha256:%s\t%s\tapi-2.json\n' "$hash2" "$retrieved2"
  printf 'api-3\trehearsal-operator-3\tsha256:%s\t%s\tapi-3.json\n' "$hash3" "$retrieved3"
} >"$relay_dir/relays.tsv"

"$MPC_BIN" "$phase" beacon \
  --ceremony "$CEREMONY_ROOT/ceremony.json" \
  --ceremony-signature "$CEREMONY_ROOT/ceremony.sig" \
  --coordinator-public-key-file "$TRUSTED_COORDINATOR_KEY" \
  --closure "$closure" \
  --closure-signature "$closure_signature" \
  --raw-response "$relay_dir/api-1.json" \
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
