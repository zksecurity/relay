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
  case "$config" in
    machine-N/.env | */machine-N/.env)
      die "N is a placeholder; replace machine-N with machine-1, machine-2, or machine-3"
      ;;
  esac
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
  for name in RELAY_BIN MPC_BIN WORK_ROOT CEREMONY_ROOT CONFIG_ROOT KEYS_ROOT RUN_ROOT \
    TRUSTED_COORDINATOR_KEY STORAGE_CONFIG; do
    require_var "$name"
  done
  [[ "$WORK_ROOT" == /* && "$WORK_ROOT" != / ]] || die "WORK_ROOT must be a specific absolute directory"
  [[ -x "$RELAY_BIN" ]] || die "Relay binary is not executable: $RELAY_BIN"
  [[ -x "$MPC_BIN" ]] || die "mpc-ceremony binary is not executable: $MPC_BIN"
  if [[ ! -f "$CEREMONY_ROOT/ceremony.json" ]]; then
    case "$REHEARSAL_CONFIG" in
      */machine-1/.env)
        die "ceremony.json is absent; run $SCRIPT_ROOT/00-coordinator-initialize.sh $REHEARSAL_CONFIG first"
        ;;
      *)
        die "ceremony.json is absent; wait for the coordinator's authenticated ceremony handoff before checking this machine"
        ;;
    esac
  fi
  [[ -f "$CEREMONY_ROOT/ceremony.sig" ]] || die "ceremony.sig is absent"
  [[ -f "$TRUSTED_COORDINATOR_KEY" ]] || die "trusted coordinator key is absent"
}

require_coordinator() {
  require_common
  hydrate_coordinator_storage_settings
  local name
  for name in COORDINATOR_PROFILE PUBLISHED_BUCKET STORAGE_ENDPOINT; do
    require_var "$name"
  done
  [[ -f "$KEYS_ROOT/coordinator.ed25519.private.hex" ]] || die "coordinator private key is absent"
}

hydrate_coordinator_storage_settings() {
  if [[ -n "${STORAGE_CONFIG:-}" && -f "$STORAGE_CONFIG" && ! -L "$STORAGE_CONFIG" ]]; then
    local -a configured
    mapfile -t configured < <(python3 - "$STORAGE_CONFIG" <<'PY'
import json
import sys

with open(sys.argv[1], "rb") as handle:
    config = json.load(handle)
for name in (
    "provider", "published_bucket", "published_base_url", "inbox_bucket",
    "endpoint", "region", "coordinator_profile", "issuer_profile",
    "grant_role_arn", "grant_role_max_ttl",
):
    print(config.get(name, ""))
PY
    )
    [[ ${#configured[@]} -eq 10 ]] || die "could not read coordinator storage settings"
    STORAGE_PROVIDER=${configured[0]}
    PUBLISHED_BUCKET=${configured[1]}
    PUBLISHED_BASE_URL=${configured[2]}
    INBOX_BUCKET=${configured[3]}
    STORAGE_ENDPOINT=${configured[4]}
    AWS_REGION=${configured[5]}
    COORDINATOR_PROFILE=${configured[6]}
    ISSUER_PROFILE=${configured[7]}
    GRANT_ROLE_ARN=${configured[8]}
    GRANT_ROLE_MAX_TTL=${configured[9]}
    if [[ "$STORAGE_PROVIDER" == aws && -z "$STORAGE_ENDPOINT" ]]; then
      if [[ "$AWS_REGION" == cn-* ]]; then
        STORAGE_ENDPOINT="https://s3.$AWS_REGION.amazonaws.com.cn"
      else
        STORAGE_ENDPOINT="https://s3.$AWS_REGION.amazonaws.com"
      fi
    fi
    return
  fi
  require_var STORAGE_PROVIDER
  case "$STORAGE_PROVIDER" in
    aws)
      require_var COORDINATOR_PROFILE
      require_var ISSUER_PROFILE
      command -v aws >/dev/null 2>&1 || die "AWS CLI is required for AWS storage"
      if [[ -z "${AWS_REGION:-}" ]]; then
        AWS_REGION=$(aws --profile "$COORDINATOR_PROFILE" configure get region 2>/dev/null || true)
      fi
      [[ "$AWS_REGION" =~ ^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$ ]] ||
        die "AWS region is absent from profile $COORDINATOR_PROFILE; set AWS_REGION explicitly"
      if [[ -z "${STORAGE_ENDPOINT:-}" ]]; then
        if [[ "$AWS_REGION" == cn-* ]]; then
          STORAGE_ENDPOINT="https://s3.$AWS_REGION.amazonaws.com.cn"
        else
          STORAGE_ENDPOINT="https://s3.$AWS_REGION.amazonaws.com"
        fi
      fi
      if [[ -z "${GRANT_ROLE_ARN:-}" ]]; then
        require_var GRANT_ROLE_NAME
        [[ "$GRANT_ROLE_NAME" =~ ^[A-Za-z0-9+=,.@_-]{1,64}$ ]] || die "GRANT_ROLE_NAME is invalid"
        local account_id
        account_id=$(aws --profile "$ISSUER_PROFILE" --region "$AWS_REGION" \
          sts get-caller-identity --query Account --output text)
        [[ "$account_id" =~ ^[0-9]{12}$ ]] || die "AWS CLI returned an invalid account ID"
        GRANT_ROLE_ARN="arn:aws:iam::$account_id:role/$GRANT_ROLE_NAME"
      fi
      ;;
    r2)
      require_var STORAGE_ENDPOINT
      ;;
    *) die "STORAGE_PROVIDER must be aws or r2" ;;
  esac
}

require_reader() {
  require_common
  [[ -f "$STORAGE_CONFIG" && ! -L "$STORAGE_CONFIG" ]] ||
    die "storage configuration is absent or unsafe: $STORAGE_CONFIG"
  local -a storage_fields
  mapfile -t storage_fields < <(python3 - "$STORAGE_CONFIG" <<'PY'
import json
import sys

with open(sys.argv[1], "rb") as handle:
    config = json.load(handle)
bucket = config.get("published_bucket", "")
base_url = config.get("published_base_url", "")
print(bucket)
print(base_url)
PY
  )
  [[ ${#storage_fields[@]} -eq 2 ]] || die "could not read published storage settings"
  PUBLISHED_BUCKET=${storage_fields[0]}
  PUBLISHED_BASE_URL=${storage_fields[1]}
  [[ -n "$PUBLISHED_BUCKET" && "$PUBLISHED_BASE_URL" == https://* ]] ||
    die "storage configuration has no published bucket or HTTPS origin"
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
  if [[ -n "${RELAY_R2_PARENT_SECRET_ACCESS_KEY:-}" || -n "${R2_PARENT_SECRET_FILE:-}" ]]; then
    if [[ -z "${RELAY_R2_PARENT_SECRET_ACCESS_KEY:-}" ]]; then
      RELAY_R2_PARENT_SECRET_ACCESS_KEY=$(read_rehearsal_secret_file \
        "$R2_PARENT_SECRET_FILE" "R2 parent Secret Access Key file")
    fi
    [[ "$RELAY_R2_PARENT_SECRET_ACCESS_KEY" =~ ^[0-9a-f]{64}$ ]] ||
      die "R2 parent Secret Access Key must be 64 lowercase hexadecimal characters"
    export RELAY_R2_PARENT_SECRET_ACCESS_KEY
    return
  fi
  if [[ -z "${RELAY_R2_PARENT_TOKEN:-}" ]]; then
    if [[ -n "${R2_PARENT_TOKEN_FILE:-}" ]]; then
      RELAY_R2_PARENT_TOKEN=$(read_rehearsal_secret_file \
        "$R2_PARENT_TOKEN_FILE" "R2 parent token file")
    else
      read -rsp 'R2 parent API token: ' RELAY_R2_PARENT_TOKEN
      printf '\n'
    fi
    [[ "$RELAY_R2_PARENT_TOKEN" =~ ^[A-Za-z0-9._-]+$ ]] ||
      die "R2 parent token contains unexpected characters"
    export RELAY_R2_PARENT_TOKEN
  fi
}

clear_r2_parent_token() {
  unset RELAY_R2_PARENT_SECRET_ACCESS_KEY RELAY_R2_PARENT_TOKEN || true
}

read_r2_control_token_if_needed() {
  if [[ "${STORAGE_PROVIDER:-}" != r2 ]]; then
    return
  fi
  if [[ -z "${RELAY_R2_CONTROL_TOKEN:-}" ]]; then
    if [[ -n "${R2_CONTROL_TOKEN_FILE:-}" ]]; then
      RELAY_R2_CONTROL_TOKEN=$(read_rehearsal_secret_file \
        "$R2_CONTROL_TOKEN_FILE" "R2 control token file")
    elif [[ -n "${R2_CONTROL_WRANGLER_BIN:-}" ]]; then
      [[ "$R2_CONTROL_WRANGLER_BIN" == /* ]] ||
        die "R2_CONTROL_WRANGLER_BIN must be an absolute path"
      local wrangler_real
      wrangler_real=$(realpath -e -- "$R2_CONTROL_WRANGLER_BIN") ||
        die "R2_CONTROL_WRANGLER_BIN does not resolve: $R2_CONTROL_WRANGLER_BIN"
      [[ -f "$wrangler_real" && -x "$wrangler_real" && ! -L "$wrangler_real" ]] ||
        die "R2_CONTROL_WRANGLER_BIN must resolve to a non-symlink executable"
      local wrangler_auth
      wrangler_auth=$("$wrangler_real" auth token --json) ||
        die "Wrangler could not refresh the R2 control-plane token; log in again"
      RELAY_R2_CONTROL_TOKEN=$(jq -er \
        'select(.type == "oauth") | .token' <<<"$wrangler_auth") ||
        die "Wrangler is not using OAuth; unset CLOUDFLARE_API_TOKEN and log in again"
      unset wrangler_auth
    else
      read -rsp 'Cloudflare R2 control-plane bearer token (Admin Read only): ' RELAY_R2_CONTROL_TOKEN
      printf '\n'
    fi
    [[ "$RELAY_R2_CONTROL_TOKEN" =~ ^[A-Za-z0-9._-]+$ ]] ||
      die "R2 control-plane token contains unexpected characters"
    export RELAY_R2_CONTROL_TOKEN
  fi
}

clear_r2_control_token() {
  unset RELAY_R2_CONTROL_TOKEN || true
}

read_rehearsal_secret_file() {
  [[ $# -eq 2 ]] || die "internal secret-file usage error"
  local path=$1
  local label=$2
  local value
  local -a lines
  [[ "$path" == /* ]] || die "$label must use an absolute path"
  [[ -f "$path" && ! -L "$path" ]] ||
    die "$label must be a regular non-symlink file: $path"
  [[ "$(stat -c '%a' -- "$path")" == 600 ]] ||
    die "$label must have mode 0600: $path"
  [[ "$(stat -c '%u' -- "$path")" == "$EUID" ]] ||
    die "$label must be owned by the current user: $path"
  [[ "$(stat -c '%h' -- "$path")" == 1 ]] ||
    die "$label must not have hard links: $path"
  mapfile -t lines <"$path"
  [[ ${#lines[@]} -eq 1 && -n "${lines[0]}" ]] ||
    die "$label must contain exactly one non-empty line"
  value=${lines[0]}
  [[ "$value" =~ ^[A-Za-z0-9._-]+$ ]] || die "$label contains unexpected characters"
  printf '%s' "$value"
}
