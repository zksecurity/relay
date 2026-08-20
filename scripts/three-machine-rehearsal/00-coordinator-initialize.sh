#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -eq 1 ]] || die "usage: $0 MACHINE_1_CONFIG"
load_rehearsal_config "$1"

for name in RELAY_BIN MPC_BIN WORK_ROOT CEREMONY_ROOT CONFIG_ROOT KEYS_ROOT \
  TRUSTED_COORDINATOR_KEY; do
  require_var "$name"
done
[[ "$WORK_ROOT" == /* && "$WORK_ROOT" != / ]] ||
  die "WORK_ROOT must be a specific absolute directory"
[[ "$CEREMONY_ROOT" == "$WORK_ROOT/public" ]] ||
  die "CEREMONY_ROOT must be WORK_ROOT/public for the rehearsal initializer"
[[ "$CONFIG_ROOT" == "$WORK_ROOT/config" ]] ||
  die "CONFIG_ROOT must be WORK_ROOT/config for the rehearsal initializer"
[[ "$KEYS_ROOT" == "$WORK_ROOT/keys" ]] ||
  die "KEYS_ROOT must be WORK_ROOT/keys for the rehearsal initializer"
[[ "$TRUSTED_COORDINATOR_KEY" == "$WORK_ROOT/trust/coordinator-public-key.hex" ]] ||
  die "TRUSTED_COORDINATOR_KEY must use the standard rehearsal trust path"
[[ ! -e "$WORK_ROOT" && ! -L "$WORK_ROOT" ]] ||
  die "rehearsal work root must be fresh: $WORK_ROOT"

work_parent=$(dirname "$WORK_ROOT")
if [[ -e "$work_parent" || -L "$work_parent" ]]; then
  [[ -d "$work_parent" && ! -L "$work_parent" && -w "$work_parent" ]] ||
    die "WORK_ROOT parent must be a writable real directory: $work_parent"
else
  mkdir -m 0700 -p "$work_parent"
fi
chmod 0700 "$work_parent"

verify_binary_hashes
rehearsal_help=$("$MPC_BIN" help rehearsal init)
[[ "$rehearsal_help" == *"mpc-ceremony rehearsal init --created-at"* ]] ||
  die "mpc-ceremony does not support the downloadable rehearsal initializer; install the proof-tool release pinned by the current ceremony kit"

created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
"$MPC_BIN" rehearsal init \
  --created-at "$created_at" \
  --out-dir "$WORK_ROOT"

for path in \
  "$CEREMONY_ROOT/ceremony.json" \
  "$CEREMONY_ROOT/ceremony.sig" \
  "$CEREMONY_ROOT/coordinator-public-key.hex" \
  "$CEREMONY_ROOT/phase1/chain-0000.json" \
  "$CEREMONY_ROOT/phase1/chain-0000.sig" \
  "$CONFIG_ROOT/environment.json" \
  "$KEYS_ROOT/coordinator.ed25519.private.hex"; do
  [[ -f "$path" && ! -L "$path" ]] || die "initializer output is absent or unsafe: $path"
done

mkdir -m 0700 "$WORK_ROOT/trust"
install -m 0600 \
  "$CEREMONY_ROOT/coordinator-public-key.hex" \
  "$TRUSTED_COORDINATOR_KEY"

printf '\nMachine 1 tiny rehearsal initialized.\n'
printf 'This same-host trust copy is a functional rehearsal fixture, not independent evidence.\n'
printf 'Next run:\n  %s/00-check-machine.sh %s\n' "$SCRIPT_ROOT" "$REHEARSAL_CONFIG"
