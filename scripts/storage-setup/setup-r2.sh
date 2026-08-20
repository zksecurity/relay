#!/usr/bin/env bash
set -euo pipefail
umask 077

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || die "usage: $0 R2_CONFIG"
config=$1
[[ -f "$config" && ! -L "$config" ]] || die "config must be a regular non-symlink file: $config"
# This operator-owned file contains shell assignments, like the rehearsal .env.
# shellcheck disable=SC1090
source "$config"

require_var() {
  local name=$1
  [[ -n "${!name:-}" ]] || die "$name is required in $config"
}

for name in R2_ACCOUNT_ID R2_ZONE_ID PUBLISHED_BUCKET INBOX_BUCKET \
  PUBLISHED_CUSTOM_DOMAIN COORDINATOR_PROFILE R2_PARENT_ACCESS_KEY_ID \
  CONFIRM_CREATE; do
  require_var "$name"
done

[[ "$CONFIRM_CREATE" == yes ]] || die "set CONFIRM_CREATE=yes after reviewing the guide and account"
[[ "$PUBLISHED_BUCKET" != "$INBOX_BUCKET" ]] || die "published and inbox buckets must differ"
[[ "$R2_ACCOUNT_ID" =~ ^[0-9a-f]{32}$ ]] || die "R2_ACCOUNT_ID must be 32 lowercase hex characters"
[[ "$R2_ZONE_ID" =~ ^[0-9a-f]{32}$ ]] || die "R2_ZONE_ID must be 32 lowercase hex characters"
[[ "$PUBLISHED_BUCKET" =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]] || die "PUBLISHED_BUCKET is malformed"
[[ "$INBOX_BUCKET" =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]] || die "INBOX_BUCKET is malformed"
[[ "$PUBLISHED_CUSTOM_DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])$ ]] ||
  die "PUBLISHED_CUSTOM_DOMAIN is malformed"
[[ "$COORDINATOR_PROFILE" =~ ^[A-Za-z0-9_.-]+$ ]] || die "COORDINATOR_PROFILE is malformed"
[[ "$R2_PARENT_ACCESS_KEY_ID" =~ ^[A-Za-z0-9_-]+$ || "$R2_PARENT_ACCESS_KEY_ID" == REPLACE_* ]] ||
  die "R2_PARENT_ACCESS_KEY_ID is malformed"

command -v aws >/dev/null 2>&1 || die "AWS CLI v2 is required for Relay's R2 transport"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v jq >/dev/null 2>&1 || die "jq is required"

printf 'Cloudflare provisioning token (hidden): '
IFS= read -rs provision_token
printf '\n'
[[ -n "$provision_token" ]] || die "a provisioning token is required"
work_dir=$(mktemp -d /tmp/relay-r2-storage-setup.XXXXXXXX)
trap 'unset provision_token coordinator_secret parent_token control_token; rm -rf -- "$work_dir"' EXIT
printf 'header = "Authorization: Bearer %s"\n' "$provision_token" >"$work_dir/provision.curl"
unset provision_token

api_root="https://api.cloudflare.com/client/v4/accounts/$R2_ACCOUNT_ID/r2"

cf_api() {
  local method=$1
  local path=$2
  local body=${3:-}
  local -a args=(--proto '=https' --tlsv1.2 --fail-with-body --silent --show-error
    --request "$method" "$api_root$path"
    --config "$work_dir/provision.curl"
    --header 'Content-Type: application/json')
  [[ -z "$body" ]] || args+=(--data "$body")
  local response
  response=$(curl "${args[@]}") || die "Cloudflare API request failed: $method $path"
  jq -e '.success == true' >/dev/null <<<"$response" || {
    jq -r '.errors[]?.message' <<<"$response" >&2
    die "Cloudflare API rejected: $method $path"
  }
  printf '%s\n' "$response"
}

create_bucket() {
  local bucket=$1
  local response
  local status
  response=$(curl --proto '=https' --tlsv1.2 --silent --show-error \
    --config "$work_dir/provision.curl" \
    --write-out $'\n%{http_code}' \
    "$api_root/buckets/$bucket")
  status=${response##*$'\n'}
  if [[ "$status" == 200 ]]; then
    printf 'Using existing R2 bucket %s\n' "$bucket"
  elif [[ "$status" == 404 ]]; then
    printf 'Creating R2 bucket %s\n' "$bucket"
    cf_api POST /buckets "$(jq -nc --arg name "$bucket" '{name: $name}')" >/dev/null
  else
    printf '%s\n' "${response%$'\n'*}" >&2
    die "could not inspect R2 bucket $bucket (HTTP $status)"
  fi

  cf_api PUT "/buckets/$bucket/domains/managed" '{"enabled":false}' >/dev/null
}

create_bucket "$PUBLISHED_BUCKET"
create_bucket "$INBOX_BUCKET"

custom_domains=$(cf_api GET "/buckets/$PUBLISHED_BUCKET/domains/custom")
if jq -e --arg domain "$PUBLISHED_CUSTOM_DOMAIN" \
  '.result.domains // [] | any(.domain == $domain)' >/dev/null <<<"$custom_domains"; then
  printf 'Using existing R2 custom domain %s\n' "$PUBLISHED_CUSTOM_DOMAIN"
  jq -e --arg domain "$PUBLISHED_CUSTOM_DOMAIN" --arg zone "$R2_ZONE_ID" '
    .result.domains // []
    | any(.domain == $domain and .zoneId == $zone and .enabled == true)
  ' >/dev/null <<<"$custom_domains" ||
    die "existing R2 custom domain is disabled or belongs to a different zone"
else
  printf 'Attaching R2 custom domain %s\n' "$PUBLISHED_CUSTOM_DOMAIN"
  domain_body=$(jq -nc \
    --arg domain "$PUBLISHED_CUSTOM_DOMAIN" \
    --arg zone "$R2_ZONE_ID" \
    '{domain: $domain, enabled: true, zoneId: $zone, minTLS: "1.2"}')
  cf_api POST "/buckets/$PUBLISHED_BUCKET/domains/custom" "$domain_body" >/dev/null
fi

inbox_domains=$(cf_api GET "/buckets/$INBOX_BUCKET/domains/custom")
jq -e '(.result.domains // []) | length == 0' >/dev/null <<<"$inbox_domains" ||
  die "the inbox already has a custom domain; remove it before using Relay"

if [[ "$R2_PARENT_ACCESS_KEY_ID" == REPLACE_* ]]; then
  printf '\nBuckets and public domain are configured.\n'
  printf 'Create the scoped tokens described in docs/R2_SETUP.md, put the inbox parent Access Key ID in %s, then rerun this script.\n' "$config"
  exit 0
fi

printf '\nCreate the three tokens described in docs/R2_SETUP.md, then enter the values below.\n'
printf 'Coordinator R2 Access Key ID: '
IFS= read -r coordinator_access_key
printf 'Coordinator R2 Secret Access Key (hidden): '
IFS= read -rs coordinator_secret
printf '\n'
[[ -n "$coordinator_access_key" && -n "$coordinator_secret" ]] || die "coordinator S3 credentials are required"
[[ "$coordinator_access_key" =~ ^[A-Za-z0-9_-]+$ ]] || die "coordinator Access Key ID is malformed"
[[ "$coordinator_secret" =~ ^[0-9a-f]{64}$ ]] || die "coordinator Secret Access Key must be a SHA-256 hex value"

printf 'User Name,Access key ID,Secret access key\n%s,%s,%s\n' \
  "$COORDINATOR_PROFILE" "$coordinator_access_key" "$coordinator_secret" >"$work_dir/coordinator.csv"
aws configure import --csv "file://$work_dir/coordinator.csv" >/dev/null
rm -f -- "$work_dir/coordinator.csv"
unset coordinator_access_key coordinator_secret
aws configure set region auto --profile "$COORDINATOR_PROFILE"
aws configure set request_checksum_calculation when_required --profile "$COORDINATOR_PROFILE"
aws configure set response_checksum_validation when_required --profile "$COORDINATOR_PROFILE"
endpoint="https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com"
for bucket in "$PUBLISHED_BUCKET" "$INBOX_BUCKET"; do
  aws --profile "$COORDINATOR_PROFILE" --endpoint-url "$endpoint" --region auto \
    s3api list-objects-v2 --bucket "$bucket" --max-items 1 >/dev/null ||
    die "coordinator profile cannot read $bucket"
done

printf 'Inbox parent R2 API token value (hidden): '
IFS= read -rs parent_token
printf '\n'
[[ -n "$parent_token" ]] || die "the inbox parent API token value is required"
printf 'header = "Authorization: Bearer %s"\n' "$parent_token" >"$work_dir/parent.curl"
unset parent_token
temp_body=$(jq -nc \
  --arg bucket "$INBOX_BUCKET" \
  --arg parent "$R2_PARENT_ACCESS_KEY_ID" \
  '{bucket: $bucket, parentAccessKeyId: $parent, permission: "object-read-write", ttlSeconds: 900, prefixes: ["setup-validation/"]}')
temp_response=$(curl --proto '=https' --tlsv1.2 --fail-with-body --silent --show-error \
  "$api_root/temp-access-credentials" \
  --config "$work_dir/parent.curl" \
  --header 'Content-Type: application/json' \
  --data "$temp_body") || die "the inbox parent token could not issue temporary credentials"
jq -e '.success == true and (.result.sessionToken | length > 0)' >/dev/null <<<"$temp_response" ||
  die "the inbox parent token did not return temporary credentials"
unset temp_response
rm -f -- "$work_dir/parent.curl"

printf 'R2 control-plane read token (hidden): '
IFS= read -rs control_token
printf '\n'
[[ -n "$control_token" ]] || die "the R2 control-plane read token is required"
printf 'header = "Authorization: Bearer %s"\n' "$control_token" >"$work_dir/control.curl"
unset control_token
for suffix in domains/managed domains/custom; do
  response=$(curl --proto '=https' --tlsv1.2 --fail-with-body --silent --show-error \
    "$api_root/buckets/$INBOX_BUCKET/$suffix" \
    --config "$work_dir/control.curl") ||
    die "the R2 control-plane token cannot inspect inbox $suffix"
  jq -e '.success == true' >/dev/null <<<"$response" || die "the R2 control-plane token was rejected"
done
unset response
rm -f -- "$work_dir/control.curl" "$work_dir/provision.curl"

printf '\nR2 storage is configured. The custom-domain certificate may still be provisioning.\n'
printf 'Copy these non-secret values into machine-1/.env:\n\n'
printf 'STORAGE_PROVIDER=r2\n'
printf 'PUBLISHED_BUCKET=%s\n' "$PUBLISHED_BUCKET"
printf 'PUBLISHED_BASE_URL=https://%s\n' "$PUBLISHED_CUSTOM_DOMAIN"
printf 'INBOX_BUCKET=%s\n' "$INBOX_BUCKET"
printf 'STORAGE_ENDPOINT=%s\n' "$endpoint"
printf 'COORDINATOR_PROFILE=%s\n' "$COORDINATOR_PROFILE"
printf 'AWS_REGION=\n'
printf 'ISSUER_PROFILE=\n'
printf 'GRANT_ROLE_NAME=\n'
printf 'GRANT_ROLE_ARN=\n'
printf 'R2_ACCOUNT_ID=%s\n' "$R2_ACCOUNT_ID"
printf 'R2_PARENT_ACCESS_KEY_ID=%s\n' "$R2_PARENT_ACCESS_KEY_ID"
printf '\nKeep the parent and control-plane API token values outside .env; Relay prompts for them.\n'
