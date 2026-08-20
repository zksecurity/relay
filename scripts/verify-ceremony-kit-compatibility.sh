#!/usr/bin/env bash
# Exercise the released Relay and mpc-ceremony binaries together without a
# source checkout, network storage, or a repository-to-repository pin.
set -euo pipefail
umask 077

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

usage() {
  die "usage: $0 --relay-binary FILE --relay-sha256 HEX --mpc-binary FILE --mpc-sha256 HEX --evidence-out FILE"
}

RELAY_BINARY=
RELAY_SHA256=
MPC_BINARY=
MPC_SHA256=
EVIDENCE_OUT=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --relay-binary) [[ $# -ge 2 ]] || usage; RELAY_BINARY=$2; shift 2 ;;
    --relay-sha256) [[ $# -ge 2 ]] || usage; RELAY_SHA256=$2; shift 2 ;;
    --mpc-binary) [[ $# -ge 2 ]] || usage; MPC_BINARY=$2; shift 2 ;;
    --mpc-sha256) [[ $# -ge 2 ]] || usage; MPC_SHA256=$2; shift 2 ;;
    --evidence-out) [[ $# -ge 2 ]] || usage; EVIDENCE_OUT=$2; shift 2 ;;
    *) usage ;;
  esac
done

[[ -n "$RELAY_BINARY" && -n "$RELAY_SHA256" && -n "$MPC_BINARY" &&
  -n "$MPC_SHA256" && -n "$EVIDENCE_OUT" ]] || usage
[[ "$RELAY_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "Relay SHA-256 must be 64 lowercase hexadecimal characters"
[[ "$MPC_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "mpc-ceremony SHA-256 must be 64 lowercase hexadecimal characters"

for command_name in basename chmod dirname grep install mkdir mktemp realpath rm sed sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command is missing: $command_name"
done
for binary in "$RELAY_BINARY" "$MPC_BINARY"; do
  [[ -f "$binary" && ! -L "$binary" && -x "$binary" ]] ||
    die "compatibility input must be an executable non-symlink regular file: $binary"
done
printf '%s  %s\n' "$RELAY_SHA256" "$RELAY_BINARY" | sha256sum --check --strict
printf '%s  %s\n' "$MPC_SHA256" "$MPC_BINARY" | sha256sum --check --strict

evidence_parent_input=$(dirname -- "$EVIDENCE_OUT")
[[ -d "$evidence_parent_input" && ! -L "$evidence_parent_input" ]] ||
  die "evidence parent must be an existing non-symlink directory"
evidence_parent=$(realpath -e -- "$evidence_parent_input")
EVIDENCE_OUT="$evidence_parent/$(basename -- "$EVIDENCE_OUT")"
[[ ! -e "$EVIDENCE_OUT" && ! -L "$EVIDENCE_OUT" ]] ||
  die "evidence output already exists: $EVIDENCE_OUT"

temp_parent_input=${TMPDIR:-/tmp}
[[ -d "$temp_parent_input" && ! -L "$temp_parent_input" ]] ||
  die "TMPDIR must be an existing non-symlink directory"
temp_parent=$(realpath -e -- "$temp_parent_input")
work_root=$(mktemp -d "$temp_parent/ceremony-kit-compatibility.XXXXXXXX")
cleanup() {
  if [[ -n "${work_root:-}" && "$work_root" == "$temp_parent"/ceremony-kit-compatibility.* ]]; then
    rm -rf -- "$work_root"
  fi
}
trap cleanup EXIT

mkdir "$work_root/bin"
install -m 0755 "$RELAY_BINARY" "$work_root/bin/relay"
install -m 0755 "$MPC_BINARY" "$work_root/bin/mpc-ceremony"
relay="$work_root/bin/relay"
mpc="$work_root/bin/mpc-ceremony"
rehearsal="$work_root/rehearsal"

"$mpc" rehearsal init \
  --created-at 2026-08-20T06:00:00Z \
  --out-dir "$rehearsal" >/dev/null

for path in \
  "$rehearsal/public/ceremony.json" \
  "$rehearsal/public/ceremony.sig" \
  "$rehearsal/public/coordinator-public-key.hex" \
  "$rehearsal/config/environment.json" \
  "$rehearsal/keys/participant-01.ed25519.private.hex"; do
  [[ -f "$path" && ! -L "$path" ]] || die "rehearsal initializer output is absent or unsafe: $path"
done

definition_json=$("$mpc" --format json inspect definition \
  --ceremony "$rehearsal/public/ceremony.json" \
  --ceremony-signature "$rehearsal/public/ceremony.sig" \
  --coordinator-public-key-file "$rehearsal/public/coordinator-public-key.hex")
[[ "$definition_json" == *'"schema":"proof-tool-mpc-command-result-v1"'* &&
  "$definition_json" == *'"ok":true'* &&
  "$definition_json" == *'"schema":"proof-tool-mpc-definition-inspection-v1"'* &&
  "$definition_json" == *'"phase1_participants":["participant-01"'* ]] ||
  die "mpc-ceremony did not emit the expected authenticated definition projection"
ceremony_id=$(printf '%s\n' "$definition_json" |
  sed -n 's/.*"ceremony_id":"\(sha256:[0-9a-f]\{64\}\)".*/\1/p')
[[ "$ceremony_id" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  die "mpc-ceremony definition projection did not contain one valid ceremony ID"

storage="$rehearsal/config/relay-storage.json"
printf '{\n  "schema": "relay-storage-config-v1",\n  "provider": "r2",\n  "ceremony_id": "%s",\n  "endpoint": "https://compatibility.r2.cloudflarestorage.com",\n  "region": "auto",\n  "account_id": "compatibility",\n  "parent_access_key_id": "compatibility",\n  "published_bucket": "compatibility-published",\n  "published_base_url": "https://compatibility.invalid",\n  "inbox_bucket": "compatibility-inbox",\n  "coordinator_profile": "compatibility",\n  "ceremony": "%s",\n  "ceremony_signature": "%s",\n  "coordinator_public_key": "%s",\n  "ceremony_binary": "%s"\n}\n' \
  "$ceremony_id" \
  "$rehearsal/public/ceremony.json" \
  "$rehearsal/public/ceremony.sig" \
  "$rehearsal/public/coordinator-public-key.hex" \
  "$mpc" >"$storage"
chmod 0600 "$storage"

for phase in phase1 phase2; do
  profile="$rehearsal/config/participant-$phase.relay.json"
  HOME="$work_root/home" "$relay" ceremony init-config \
    --home "$rehearsal" \
    --role participant \
    --identity participant-01 \
    --phase "$phase" \
    --storage "$storage" \
    --coordinator-key "$rehearsal/public/coordinator-public-key.hex" \
    --ceremony-binary "$mpc" \
    --signing-key "$rehearsal/keys/participant-01.ed25519.private.hex" \
    --environment "$rehearsal/config/environment.json" \
    --out "$profile" >/dev/null
  [[ -f "$profile" && ! -L "$profile" ]] || die "Relay did not create the $phase participant profile"
  grep -Eq '"schema"[[:space:]]*:[[:space:]]*"relay-role-config-v1"' "$profile" ||
    die "Relay emitted an unexpected role profile schema"
  grep -Eq '"identity_id"[[:space:]]*:[[:space:]]*"participant-01"' "$profile" ||
    die "Relay emitted an unexpected participant identity"
  grep -Eq "\"phase\"[[:space:]]*:[[:space:]]*\"$phase\"" "$profile" ||
    die "Relay emitted an unexpected participant phase"
done

(
  set -o noclobber
  printf '{\n  "schema": "ceremony-kit-compatibility-v1",\n  "test": "tiny-rehearsal-participant-config-v1",\n  "relay_sha256": "%s",\n  "mpc_ceremony_sha256": "%s"\n}\n' \
    "$RELAY_SHA256" "$MPC_SHA256" >"$EVIDENCE_OUT"
)
chmod 0444 "$EVIDENCE_OUT"
printf 'Verified ceremony-kit binary compatibility.\nEvidence: %s\n' "$EVIDENCE_OUT"
