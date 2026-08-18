#!/usr/bin/env bash

set -euo pipefail
umask 077

SCRIPT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

load_rehearsal_config() {
  [[ $# -eq 1 ]] || die "usage: $0 CONFIG [arguments...]"
  local config=$1
  [[ -f "$config" && ! -L "$config" ]] || die "config must be a regular non-symlink file: $config"
  # The operator owns this file. It contains shell assignments so paths can
  # refer to one another without duplicating machine-specific roots.
  # shellcheck disable=SC1090
  source "$config"
  REHEARSAL_CONFIG=$config
}

require_var() {
  local name=$1
  [[ -n "${!name:-}" ]] || die "$name is required in $REHEARSAL_CONFIG"
}

require_common() {
  local name
  for name in RELAY_BIN MPC_BIN CEREMONY_ROOT CONFIG_ROOT KEYS_ROOT RUN_ROOT \
    TRUSTED_COORDINATOR_KEY STORAGE_CONFIG PUBLISHED_BUCKET STORAGE_ENDPOINT; do
    require_var "$name"
  done
  [[ -x "$RELAY_BIN" ]] || die "Relay binary is not executable: $RELAY_BIN"
  [[ -x "$MPC_BIN" ]] || die "mpc-ceremony binary is not executable: $MPC_BIN"
  [[ -f "$CEREMONY_ROOT/ceremony.json" ]] || die "ceremony.json is absent"
  [[ -f "$CEREMONY_ROOT/ceremony.sig" ]] || die "ceremony.sig is absent"
  [[ -f "$TRUSTED_COORDINATOR_KEY" ]] || die "trusted coordinator key is absent"
}

require_coordinator() {
  require_common
  require_var COORDINATOR_PROFILE
  [[ -f "$KEYS_ROOT/coordinator.ed25519.private.hex" ]] || die "coordinator private key is absent"
}

require_reader() {
  require_common
  require_var PUBLISHED_READER_PROFILE
}

verify_binary_hashes() {
  require_var RELAY_SHA256
  require_var MPC_SHA256
  [[ "$RELAY_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "RELAY_SHA256 is malformed"
  [[ "$MPC_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "MPC_SHA256 is malformed"
  printf '%s  %s\n' "$RELAY_SHA256" "$RELAY_BIN" | sha256sum --check
  printf '%s  %s\n' "$MPC_SHA256" "$MPC_BIN" | sha256sum --check
}

phase_number() {
  case "$1" in
    phase1) printf '1\n' ;;
    phase2) printf '2\n' ;;
    *) die "phase must be phase1 or phase2" ;;
  esac
}

participant_is_valid() {
  [[ "$1" =~ ^participant-[0-9][0-9]$ ]] || die "invalid participant identity: $1"
}

phase_participant_count() {
  local phase=$1
  local field
  phase_number "$phase" >/dev/null
  field="${phase}_policy"
  python3 - "$CEREMONY_ROOT/ceremony.json" "$field" <<'PY'
import json
import sys

with open(sys.argv[1], "rb") as handle:
    definition = json.load(handle)
participants = definition[sys.argv[2]]["participants"]
if not isinstance(participants, list) or not participants:
    raise SystemExit("authenticated definition has no participants")
print(len(participants))
PY
}

phase_final_sequence() {
  printf '%04d\n' "$(phase_participant_count "$1")"
}

phase_chain() {
  local phase=$1
  local sequence=$2
  printf '%s/%s/chain-%s.json\n' "$CEREMONY_ROOT" "$phase" "$sequence"
}

phase_chain_signature() {
  local phase=$1
  local sequence=$2
  printf '%s/%s/chain-%s.sig\n' "$CEREMONY_ROOT" "$phase" "$sequence"
}

publish_phase_head() {
  local phase=$1
  local sequence=$2
  local closed=$3
  local -a closed_flag=()
  [[ "$closed" == yes || "$closed" == no ]] || die "closed must be yes or no"
  if [[ "$closed" == yes ]]; then
    closed_flag=(--closed)
  fi
  "$RELAY_BIN" coordinator publish \
    --root "$CEREMONY_ROOT" \
    --ceremony "$CEREMONY_ROOT/ceremony.json" \
    --ceremony-signature "$CEREMONY_ROOT/ceremony.sig" \
    --coordinator-key "$TRUSTED_COORDINATOR_KEY" \
    --ceremony-binary "$MPC_BIN" \
    --phase "$phase" \
    --chain "$(phase_chain "$phase" "$sequence")" \
    --chain-signature "$(phase_chain_signature "$phase" "$sequence")" \
    --bucket "$PUBLISHED_BUCKET" \
    --endpoint "$STORAGE_ENDPOINT" \
    --profile "$COORDINATOR_PROFILE" \
    --verify \
    "${closed_flag[@]}"
}

ensure_run_directories() {
  mkdir -p "$RUN_ROOT"
  chmod 0700 "$RUN_ROOT"
  local directory
  for directory in grants configs candidates review logs outbox role-views; do
    mkdir -p "$RUN_ROOT/$directory"
    chmod 0700 "$RUN_ROOT/$directory"
  done
}

require_fresh_path() {
  [[ ! -e "$1" && ! -L "$1" ]] || die "output already exists: $1"
}

read_r2_parent_token_if_needed() {
  if [[ "${STORAGE_PROVIDER:-}" != r2 ]]; then
    return
  fi
  if [[ -z "${RELAY_R2_PARENT_TOKEN:-}" ]]; then
    read -rsp 'R2 parent API token: ' RELAY_R2_PARENT_TOKEN
    printf '\n'
    export RELAY_R2_PARENT_TOKEN
  fi
}

clear_r2_parent_token() {
  unset RELAY_R2_PARENT_TOKEN || true
}
