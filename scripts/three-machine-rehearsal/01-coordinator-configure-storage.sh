#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_ROOT/lib.sh"

[[ $# -eq 1 ]] || die "usage: $0 COORDINATOR_CONFIG"
load_rehearsal_config "$1"
require_coordinator
verify_binary_hashes
ensure_run_directories

require_var STORAGE_PROVIDER
require_var PUBLISHED_BASE_URL
require_var INBOX_BUCKET
require_fresh_path "$STORAGE_CONFIG"

case "$STORAGE_PROVIDER" in
  aws)
    require_var AWS_REGION
    require_var ISSUER_PROFILE
    require_var GRANT_ROLE_ARN
    require_var GRANT_ROLE_MAX_TTL
    printf 'Resolved AWS rehearsal storage:\n'
    printf '  region:          %s\n' "$AWS_REGION"
    printf '  endpoint:        %s\n' "$STORAGE_ENDPOINT"
    printf '  published:       %s\n' "$PUBLISHED_BUCKET"
    printf '  private inbox:   %s\n' "$INBOX_BUCKET"
    printf '  grant role:      %s\n' "$GRANT_ROLE_ARN"
    "$RELAY_BIN" coordinator configure-storage \
      --provider aws \
      --region "$AWS_REGION" \
      --published-bucket "$PUBLISHED_BUCKET" \
      --published-base-url "$PUBLISHED_BASE_URL" \
      --inbox-bucket "$INBOX_BUCKET" \
      --profile "$COORDINATOR_PROFILE" \
      --issuer-profile "$ISSUER_PROFILE" \
      --grant-role-arn "$GRANT_ROLE_ARN" \
      --grant-role-max-ttl "$GRANT_ROLE_MAX_TTL" \
      --ceremony "$CEREMONY_ROOT/ceremony.json" \
      --ceremony-signature "$CEREMONY_ROOT/ceremony.sig" \
      --coordinator-key "$TRUSTED_COORDINATOR_KEY" \
      --ceremony-binary "$MPC_BIN" \
      --out "$STORAGE_CONFIG"
    ;;
  r2)
    require_var R2_ACCOUNT_ID
    require_var R2_PARENT_ACCESS_KEY_ID
    read_r2_control_token_if_needed
    trap clear_r2_control_token EXIT
    "$RELAY_BIN" coordinator configure-storage \
      --provider r2 \
      --account-id "$R2_ACCOUNT_ID" \
      --parent-access-key-id "$R2_PARENT_ACCESS_KEY_ID" \
      --endpoint "$STORAGE_ENDPOINT" \
      --published-bucket "$PUBLISHED_BUCKET" \
      --published-base-url "$PUBLISHED_BASE_URL" \
      --inbox-bucket "$INBOX_BUCKET" \
      --profile "$COORDINATOR_PROFILE" \
      --ceremony "$CEREMONY_ROOT/ceremony.json" \
      --ceremony-signature "$CEREMONY_ROOT/ceremony.sig" \
      --coordinator-key "$TRUSTED_COORDINATOR_KEY" \
      --ceremony-binary "$MPC_BIN" \
      --out "$STORAGE_CONFIG"
    clear_r2_control_token
    trap - EXIT
    ;;
  *)
    die "STORAGE_PROVIDER must be aws or r2"
    ;;
esac

chmod 0600 "$STORAGE_CONFIG"
printf '\nCopy this file to the same trusted path configured on Machines 2 and 3:\n%s\n' "$STORAGE_CONFIG"
