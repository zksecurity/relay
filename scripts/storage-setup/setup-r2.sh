#!/usr/bin/env bash
set -euo pipefail
umask 077

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf 'usage: %s [--machine-env FILE] [--provision-token-file FILE] ' "$0" >&2
  printf '[--parent-token-file FILE] [--token-manager-file FILE] ' >&2
  printf '[--credential-root DIR] ' >&2
  printf '[--control-token-file FILE | --control-wrangler-bin FILE] R2_CONFIG\n' >&2
  exit 2
}

config=
machine_env=
provision_token_file=
parent_token_file=
token_manager_file=
credential_root=
control_token_file=
control_wrangler_bin=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --machine-env)
      [[ $# -ge 2 ]] || usage
      machine_env=$2
      shift 2
      ;;
    --provision-token-file)
      [[ $# -ge 2 ]] || usage
      provision_token_file=$2
      shift 2
      ;;
    --parent-token-file)
      [[ $# -ge 2 ]] || usage
      parent_token_file=$2
      shift 2
      ;;
    --token-manager-file)
      [[ $# -ge 2 ]] || usage
      token_manager_file=$2
      shift 2
      ;;
    --credential-root)
      [[ $# -ge 2 ]] || usage
      credential_root=$2
      shift 2
      ;;
    --control-token-file)
      [[ $# -ge 2 ]] || usage
      control_token_file=$2
      shift 2
      ;;
    --control-wrangler-bin)
      [[ $# -ge 2 ]] || usage
      control_wrangler_bin=$2
      shift 2
      ;;
    -h | --help)
      printf 'usage: %s [options] R2_CONFIG\n\n' "$0"
      printf 'Creates or validates R2 resources from an explicit configuration.\n'
      printf 'For the browser-login flow, run setup-r2-wrangler.sh instead.\n'
      printf 'Token-file options read secrets without putting them in argv or the config.\n'
      printf 'A token manager with Account API Tokens Write can create the scoped R2 credentials.\n'
      printf -- '--machine-env atomically writes the non-secret rehearsal values.\n'
      exit 0
      ;;
    -*) usage ;;
    *)
      [[ -z "$config" ]] || usage
      config=$1
      shift
      ;;
  esac
done

[[ -n "$config" ]] || usage
[[ -z "$control_token_file" || -z "$control_wrangler_bin" ]] ||
  die "choose only one control token source"
[[ -f "$config" && ! -L "$config" ]] ||
  die "config must be a regular non-symlink file: $config"
# This operator-owned file contains shell assignments, like the rehearsal .env.
# shellcheck disable=SC1090
source "$config"

require_var() {
  local name=$1
  [[ -n "${!name:-}" ]] || die "$name is required in $config"
}

for name in R2_ACCOUNT_ID PUBLISHED_BUCKET INBOX_BUCKET \
  COORDINATOR_PROFILE CONFIRM_CREATE; do
  require_var "$name"
done
PUBLISHED_ACCESS_MODE=${PUBLISHED_ACCESS_MODE:-custom}
R2_PARENT_ACCESS_KEY_ID=${R2_PARENT_ACCESS_KEY_ID:-REPLACE_WITH_PARENT_ACCESS_KEY_ID}

[[ "$CONFIRM_CREATE" == yes ]] ||
  die "set CONFIRM_CREATE=yes after reviewing the guide and account"
[[ "$PUBLISHED_BUCKET" != "$INBOX_BUCKET" ]] || die "published and inbox buckets must differ"
[[ "$R2_ACCOUNT_ID" =~ ^[0-9a-f]{32}$ ]] ||
  die "R2_ACCOUNT_ID must be 32 lowercase hex characters"
[[ "$PUBLISHED_BUCKET" =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]] ||
  die "PUBLISHED_BUCKET is malformed"
[[ "$INBOX_BUCKET" =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]] ||
  die "INBOX_BUCKET is malformed"
case "$PUBLISHED_ACCESS_MODE" in
  custom)
    [[ "${R2_ZONE_ID:-}" =~ ^[0-9a-f]{32}$ ]] ||
      die "R2_ZONE_ID must be 32 lowercase hex characters for a custom domain"
    [[ "${PUBLISHED_CUSTOM_DOMAIN:-}" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])$ ]] ||
      die "PUBLISHED_CUSTOM_DOMAIN is malformed"
    ;;
  r2dev)
    [[ -z "${R2_ZONE_ID:-}" && -z "${PUBLISHED_CUSTOM_DOMAIN:-}" ]] ||
      die "r2dev mode must not set a zone or custom domain"
    ;;
  *) die "PUBLISHED_ACCESS_MODE must be custom or r2dev" ;;
esac
[[ "$COORDINATOR_PROFILE" =~ ^[A-Za-z0-9_.-]+$ ]] ||
  die "COORDINATOR_PROFILE is malformed"
[[ "$R2_PARENT_ACCESS_KEY_ID" =~ ^[A-Za-z0-9_-]+$ ||
  "$R2_PARENT_ACCESS_KEY_ID" == REPLACE_* ]] ||
  die "R2_PARENT_ACCESS_KEY_ID is malformed"

for command_name in aws curl jq grep mktemp realpath sha256sum sleep stat; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command is missing: $command_name"
done

validate_input_secret_file() {
  local path=$1
  local label=$2
  [[ "$path" == /* ]] || die "$label must use an absolute path"
  [[ -f "$path" && ! -L "$path" ]] || die "$label must be a regular non-symlink file: $path"
  [[ "$(stat -c '%a' -- "$path")" == 600 ]] || die "$label must have mode 0600: $path"
  [[ "$(stat -c '%u' -- "$path")" == "$EUID" ]] || die "$label must be owned by the current user: $path"
  [[ "$(stat -c '%h' -- "$path")" == 1 ]] || die "$label must not have hard links: $path"
}

prepare_output_secret_file() {
  local path=$1
  local label=$2
  [[ "$path" == /* ]] || die "$label must use an absolute path"
  [[ ! -L "$path" ]] || die "$label must not be a symbolic link: $path"
  [[ ! -e "$path" || -f "$path" ]] || die "$label must be a regular file: $path"
  local parent
  parent=$(realpath -e -- "$(dirname -- "$path")")
  [[ -d "$parent" && ! -L "$parent" && -w "$parent" ]] ||
    die "$label parent must be a writable real directory"
}

read_secret_file() {
  local path=$1
  local label=$2
  local value
  local -a lines
  validate_input_secret_file "$path" "$label"
  mapfile -t lines <"$path"
  [[ ${#lines[@]} -eq 1 && -n "${lines[0]}" ]] ||
    die "$label must contain exactly one non-empty line"
  value=${lines[0]}
  [[ "$value" =~ ^[A-Za-z0-9._-]+$ ]] || die "$label contains unexpected characters"
  printf '%s' "$value"
}

write_secret_file() {
  local path=$1
  local value=$2
  local label=$3
  prepare_output_secret_file "$path" "$label"
  local parent partial
  parent=$(dirname -- "$path")
  partial=$(mktemp "$parent/.relay-r2-secret.partial.XXXXXXXX")
  if ! printf '%s\n' "$value" >"$partial" ||
    ! chmod 0600 "$partial" || ! mv -- "$partial" "$path"; then
    rm -f -- "$partial"
    die "could not atomically write $label"
  fi
}

storage_env_fields=(
  STORAGE_PROVIDER
  PUBLISHED_BUCKET
  PUBLISHED_BASE_URL
  INBOX_BUCKET
  STORAGE_ENDPOINT
  COORDINATOR_PROFILE
  AWS_REGION
  ISSUER_PROFILE
  GRANT_ROLE_NAME
  GRANT_ROLE_ARN
  GRANT_ROLE_MAX_TTL
  R2_ACCOUNT_ID
  R2_PARENT_ACCESS_KEY_ID
)
optional_storage_env_fields=(
  R2_PARENT_TOKEN_FILE
  R2_PARENT_SECRET_FILE
  R2_CONTROL_TOKEN_FILE
  R2_CONTROL_WRANGLER_BIN
)

validate_machine_env() {
  [[ -n "$machine_env" ]] || return 0
  [[ "$machine_env" == /* ]] || die "--machine-env must be an absolute path"
  [[ -f "$machine_env" && ! -L "$machine_env" ]] ||
    die "machine env must be a regular non-symlink file: $machine_env"
  [[ "$(stat -c '%a' -- "$machine_env")" == 600 ]] ||
    die "machine env must have mode 0600: $machine_env"
  [[ "$(stat -c '%u' -- "$machine_env")" == "$EUID" ]] ||
    die "machine env must be owned by the current user: $machine_env"
  [[ "$(stat -c '%h' -- "$machine_env")" == 1 ]] ||
    die "machine env must not have hard links: $machine_env"

  local parent field count
  parent=$(realpath -e -- "$(dirname -- "$machine_env")")
  [[ -d "$parent" && ! -L "$parent" && -w "$parent" ]] ||
    die "machine env parent must be a writable real directory"
  machine_env="$parent/$(basename -- "$machine_env")"
  for field in "${storage_env_fields[@]}"; do
    count=$(grep -c "^${field}=" "$machine_env" || true)
    [[ "$count" == 1 ]] ||
      die "machine env must contain exactly one $field assignment: $machine_env"
  done
  for field in "${optional_storage_env_fields[@]}"; do
    count=$(grep -c "^${field}=" "$machine_env" || true)
    [[ "$count" -le 1 ]] ||
      die "machine env must contain at most one $field assignment: $machine_env"
  done
}

validate_machine_env
[[ -z "$provision_token_file" ]] || validate_input_secret_file "$provision_token_file" "provision token file"
[[ -z "$parent_token_file" ]] || prepare_output_secret_file "$parent_token_file" "parent token file"
[[ -z "$token_manager_file" ]] || validate_input_secret_file "$token_manager_file" "token manager file"
[[ -z "$control_token_file" ]] || prepare_output_secret_file "$control_token_file" "control token file"
if [[ -n "$credential_root" ]]; then
  [[ "$credential_root" == /* ]] || die "--credential-root must use an absolute path"
  credential_root=$(realpath -e -- "$credential_root")
  [[ -d "$credential_root" && ! -L "$credential_root" ]] ||
    die "credential root must be a real directory: $credential_root"
  [[ "$(stat -c '%a' -- "$credential_root")" == 700 ]] ||
    die "credential root must have mode 0700: $credential_root"
  [[ "$(stat -c '%u' -- "$credential_root")" == "$EUID" ]] ||
    die "credential root must be owned by the current user: $credential_root"
fi
[[ -z "$token_manager_file" || -n "$credential_root" ]] ||
  die "--token-manager-file requires --credential-root"
if [[ -n "$control_wrangler_bin" ]]; then
  [[ "$control_wrangler_bin" == /* && -x "$control_wrangler_bin" && ! -L "$control_wrangler_bin" ]] ||
    die "--control-wrangler-bin must be an absolute non-symlink executable"
fi

if [[ -n "$provision_token_file" ]]; then
  provision_token=$(read_secret_file "$provision_token_file" "provision token file")
else
  printf 'Cloudflare provisioning token (hidden): '
  IFS= read -rs provision_token
  printf '\n'
fi
[[ -n "$provision_token" ]] || die "a provisioning token is required"
[[ "$provision_token" =~ ^[A-Za-z0-9._-]+$ ]] ||
  die "the provisioning token contains unexpected characters"

work_dir=$(mktemp -d /tmp/relay-r2-storage-setup.XXXXXXXX)
created_token_ids=()
credential_files_written=()
credentials_committed=no
cleanup() {
  local token_id secret_file
  unset provision_token token_manager coordinator_secret parent_token control_token
  if [[ "$credentials_committed" != yes && -f "${work_dir:-}/manager.curl" ]]; then
    for token_id in "${created_token_ids[@]}"; do
      curl --proto '=https' --tlsv1.2 --silent --show-error \
        --request DELETE --config "$work_dir/manager.curl" \
        "https://api.cloudflare.com/client/v4/accounts/$R2_ACCOUNT_ID/tokens/$token_id" \
        >/dev/null || true
    done
    for secret_file in "${credential_files_written[@]}"; do
      [[ "$secret_file" == "$credential_root/"* && -f "$secret_file" && ! -L "$secret_file" ]] &&
        rm -- "$secret_file"
    done
  fi
  if [[ -n "${work_dir:-}" && "$work_dir" == /tmp/relay-r2-storage-setup.* ]]; then
    rm -rf -- "$work_dir"
  fi
}
trap cleanup EXIT
printf 'header = "Authorization: Bearer %s"\n' "$provision_token" >"$work_dir/provision.curl"
unset provision_token

if [[ -n "$token_manager_file" ]]; then
  token_manager=$(read_secret_file "$token_manager_file" "token manager file")
  printf 'header = "Authorization: Bearer %s"\n' "$token_manager" >"$work_dir/manager.curl"
  unset token_manager
fi

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
  local response status
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
}

token_api() {
  local method=$1
  local path=$2
  local body=${3:-}
  local -a args=(--proto '=https' --tlsv1.2 --fail-with-body --silent --show-error
    --request "$method"
    "https://api.cloudflare.com/client/v4/accounts/$R2_ACCOUNT_ID/tokens$path"
    --config "$work_dir/manager.curl"
    --header 'Content-Type: application/json')
  [[ -z "$body" ]] || args+=(--data "$body")
  local response
  response=$(curl "${args[@]}") || return 1
  jq -e '.success == true' >/dev/null <<<"$response" || return 1
  printf '%s\n' "$response"
}

create_scoped_r2_token() {
  local name=$1
  local permission_group_id=$2
  shift 2
  local resources='{}' bucket resource body response
  for bucket in "$@"; do
    resource="com.cloudflare.edge.r2.bucket.${R2_ACCOUNT_ID}_default_${bucket}"
    resources=$(jq -nc --argjson current "$resources" --arg resource "$resource" \
      '$current + {($resource): "*"}')
  done
  body=$(jq -nc --arg name "$name" --arg permission "$permission_group_id" \
    --argjson resources "$resources" \
    '{name: $name, policies: [{effect: "allow", resources: $resources,
      permission_groups: [{id: $permission}]}]}')
  response=$(token_api POST '' "$body") ||
    die "could not create scoped R2 token $name; verify Account API Tokens Write permission"
  jq -e '.result.id | type == "string" and length > 0' >/dev/null <<<"$response" ||
    die "Cloudflare did not return an Access Key ID for $name"
  jq -e '.result.value | type == "string" and length > 0' >/dev/null <<<"$response" ||
    die "Cloudflare did not return a one-time token value for $name"
  printf '%s\n' "$response"
}

printf '\nR2 setup plan:\n'
printf '  account:          %s\n' "$R2_ACCOUNT_ID"
printf '  published bucket: %s\n' "$PUBLISHED_BUCKET"
printf '  public mode:      %s\n' "$PUBLISHED_ACCESS_MODE"
printf '  private inbox:    %s\n' "$INBOX_BUCKET"
printf '  coordinator:      AWS profile %s\n' "$COORDINATOR_PROFILE"
if [[ -n "$machine_env" ]]; then
  printf '  update rehearsal: %s\n' "$machine_env"
else
  printf '  update rehearsal: no (print values only)\n'
fi

create_bucket "$PUBLISHED_BUCKET"
create_bucket "$INBOX_BUCKET"

# The inbox must never have any public endpoint, regardless of how the
# published rehearsal bucket is exposed.
cf_api PUT "/buckets/$INBOX_BUCKET/domains/managed" '{"enabled":false}' >/dev/null

inbox_domains=$(cf_api GET "/buckets/$INBOX_BUCKET/domains/custom")
jq -e '(.result.domains // []) | length == 0' >/dev/null <<<"$inbox_domains" ||
  die "the inbox already has a custom domain; remove it before using Relay"

custom_domains=$(cf_api GET "/buckets/$PUBLISHED_BUCKET/domains/custom")
if [[ "$PUBLISHED_ACCESS_MODE" == custom ]]; then
  cf_api PUT "/buckets/$PUBLISHED_BUCKET/domains/managed" '{"enabled":false}' >/dev/null
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
    domain_body=$(jq -nc --arg domain "$PUBLISHED_CUSTOM_DOMAIN" --arg zone "$R2_ZONE_ID" \
      '{domain: $domain, enabled: true, zoneId: $zone, minTLS: "1.2"}')
    cf_api POST "/buckets/$PUBLISHED_BUCKET/domains/custom" "$domain_body" >/dev/null
  fi
  PUBLISHED_BASE_URL="https://$PUBLISHED_CUSTOM_DOMAIN"
else
  jq -e '(.result.domains // []) | length == 0' >/dev/null <<<"$custom_domains" ||
    die "r2dev rehearsal mode requires no custom domain on the published bucket"
  cf_api PUT "/buckets/$PUBLISHED_BUCKET/domains/managed" '{"enabled":true}' >/dev/null
  managed_domain=$(cf_api GET "/buckets/$PUBLISHED_BUCKET/domains/managed")
  jq -e '.result.enabled == true and (.result.domain | endswith(".r2.dev"))' \
    >/dev/null <<<"$managed_domain" ||
    die "Cloudflare did not return an enabled r2.dev domain for the published bucket"
  PUBLISHED_BASE_URL="https://$(jq -r '.result.domain' <<<"$managed_domain")"
  printf 'Enabled rehearsal-only published origin %s\n' "$PUBLISHED_BASE_URL"
fi

wait_for_custom_domain() {
  local attempt response ownership ssl
  for attempt in {1..40}; do
    response=$(cf_api GET "/buckets/$PUBLISHED_BUCKET/domains/custom/$PUBLISHED_CUSTOM_DOMAIN")
    ownership=$(jq -r '.result.status.ownership // "unknown"' <<<"$response")
    ssl=$(jq -r '.result.status.ssl // "unknown"' <<<"$response")
    if [[ "$ownership" == active && "$ssl" == active ]]; then
      printf 'R2 custom domain %s is active with TLS\n' "$PUBLISHED_CUSTOM_DOMAIN"
      return
    fi
    if [[ "$ownership" =~ ^(blocked|deactivated|error)$ ||
      "$ssl" =~ ^(deactivated|error)$ ]]; then
      die "custom domain failed to activate (ownership=$ownership, ssl=$ssl)"
    fi
    if [[ "$attempt" -lt 40 ]]; then
      printf 'Waiting for R2 custom domain TLS (ownership=%s, ssl=%s; attempt %d/40)\n' \
        "$ownership" "$ssl" "$attempt"
      sleep 15
    fi
  done
  die "custom domain did not become active within 10 minutes; rerun setup after Cloudflare finishes provisioning it"
}

automatic_credentials=no
if [[ -n "$credential_root" ]]; then
  coordinator_access_key_file="$credential_root/coordinator-access-key-id"
  coordinator_secret_file="$credential_root/coordinator-secret-access-key"
  parent_access_key_file="$credential_root/inbox-parent-access-key-id"
  automatic_parent_token_file="$credential_root/inbox-parent-api-token"
  parent_secret_file="$credential_root/inbox-parent-secret-access-key"
  [[ -z "$parent_token_file" || "$parent_token_file" == "$automatic_parent_token_file" ]] ||
    die "--parent-token-file must be $automatic_parent_token_file when --credential-root is used"
  parent_token_file=$automatic_parent_token_file
  credential_files=(
    "$coordinator_access_key_file"
    "$coordinator_secret_file"
    "$parent_access_key_file"
    "$parent_token_file"
    "$parent_secret_file"
  )
  existing_credentials=0
  for secret_file in "${credential_files[@]}"; do
    [[ ! -e "$secret_file" && ! -L "$secret_file" ]] || existing_credentials=$((existing_credentials + 1))
  done
  if [[ -n "$token_manager_file" && "$existing_credentials" -ne 0 &&
    "$existing_credentials" -ne ${#credential_files[@]} ]]; then
    die "credential root contains an incomplete scoped R2 credential set: $credential_root"
  fi
  if [[ "$existing_credentials" -eq ${#credential_files[@]} ]]; then
    coordinator_access_key=$(read_secret_file "$coordinator_access_key_file" "coordinator Access Key ID file")
    coordinator_secret=$(read_secret_file "$coordinator_secret_file" "coordinator Secret Access Key file")
    R2_PARENT_ACCESS_KEY_ID=$(read_secret_file "$parent_access_key_file" "parent Access Key ID file")
    parent_token=$(read_secret_file "$parent_token_file" "parent token file")
    parent_secret=$(read_secret_file "$parent_secret_file" "parent Secret Access Key file")
    automatic_credentials=yes
    credentials_committed=yes
    printf 'Using the existing scoped R2 credentials in %s\n' "$credential_root"
  elif [[ -n "$token_manager_file" ]]; then
    printf 'Creating the coordinator and inbox-parent R2 tokens automatically\n'
    permission_groups=$(token_api GET /permission_groups) ||
      die "the token manager cannot list permission groups; grant Account > Account API Tokens > Edit"
    bucket_write_permission=$(jq -er '
      [.result[] | select(.name == "Workers R2 Storage Bucket Item Write")]
      | if length == 1 then .[0].id else error("permission group not found") end
    ' <<<"$permission_groups") ||
      die "Cloudflare did not return the R2 bucket item write permission group"

    coordinator_response=$(create_scoped_r2_token \
      "relay-$PUBLISHED_BUCKET-coordinator" "$bucket_write_permission" \
      "$PUBLISHED_BUCKET" "$INBOX_BUCKET")
    coordinator_access_key=$(jq -er '.result.id' <<<"$coordinator_response")
    coordinator_token=$(jq -er '.result.value' <<<"$coordinator_response")
    created_token_ids+=("$coordinator_access_key")

    parent_response=$(create_scoped_r2_token \
      "relay-$INBOX_BUCKET-parent" "$bucket_write_permission" "$INBOX_BUCKET")
    R2_PARENT_ACCESS_KEY_ID=$(jq -er '.result.id' <<<"$parent_response")
    parent_token=$(jq -er '.result.value' <<<"$parent_response")
    created_token_ids+=("$R2_PARENT_ACCESS_KEY_ID")

    coordinator_hash=$(printf '%s' "$coordinator_token" | sha256sum)
    coordinator_secret=${coordinator_hash%% *}
    parent_hash=$(printf '%s' "$parent_token" | sha256sum)
    parent_secret=${parent_hash%% *}
    unset coordinator_token coordinator_hash parent_hash permission_groups \
      coordinator_response parent_response

    credential_values=(
      "$coordinator_access_key"
      "$coordinator_secret"
      "$R2_PARENT_ACCESS_KEY_ID"
      "$parent_token"
      "$parent_secret"
    )
    for index in "${!credential_files[@]}"; do
      credential_files_written+=("${credential_files[$index]}")
      write_secret_file "${credential_files[$index]}" "${credential_values[$index]}" \
        "scoped R2 credential file"
    done
    unset credential_values
    automatic_credentials=yes
    credentials_committed=yes
    printf 'Stored the scoped R2 credentials in %s (directory 0700, files 0600)\n' \
      "$credential_root"
  fi
fi

if [[ "$automatic_credentials" == no ]]; then
  if [[ "$R2_PARENT_ACCESS_KEY_ID" == REPLACE_* ]]; then
    printf '\nCreate these two bucket-scoped tokens in Cloudflare R2 > Manage API Tokens:\n'
    printf '  1. Coordinator: Object Read & Write for %s and %s.\n' "$PUBLISHED_BUCKET" "$INBOX_BUCKET"
    printf '  2. Inbox parent: Object Read & Write for %s only.\n' "$INBOX_BUCKET"
    printf 'Keep this terminal open while creating them; values entered below are hidden where appropriate.\n\n'
    read -rp 'Inbox parent R2 Access Key ID: ' R2_PARENT_ACCESS_KEY_ID
  fi
  printf 'Coordinator R2 Access Key ID: '
  IFS= read -r coordinator_access_key
  printf 'Coordinator R2 Secret Access Key (hidden): '
  IFS= read -rs coordinator_secret
  printf '\n'
fi
[[ "$R2_PARENT_ACCESS_KEY_ID" =~ ^[A-Za-z0-9_-]+$ ]] ||
  die "inbox parent Access Key ID is malformed"
[[ "$coordinator_access_key" =~ ^[A-Za-z0-9_-]+$ ]] ||
  die "coordinator Access Key ID is malformed"
[[ "$coordinator_secret" =~ ^[0-9a-f]{64}$ ]] ||
  die "coordinator Secret Access Key must be a SHA-256 hex value"

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

if [[ -n "$parent_token_file" && -f "$parent_token_file" ]]; then
  parent_token=$(read_secret_file "$parent_token_file" "parent token file")
else
  printf 'Inbox parent R2 API token value (hidden): '
  IFS= read -rs parent_token
  printf '\n'
fi
[[ -n "$parent_token" ]] || die "the inbox parent API token value is required"
[[ "$parent_token" =~ ^[A-Za-z0-9._-]+$ ]] ||
  die "the inbox parent API token contains unexpected characters"
if [[ -n "${parent_secret_file:-}" && -f "$parent_secret_file" ]]; then
  parent_secret=$(read_secret_file "$parent_secret_file" "parent Secret Access Key file")
elif [[ -z "${parent_secret:-}" ]]; then
  printf 'Inbox parent R2 Secret Access Key (hidden): '
  IFS= read -rs parent_secret
  printf '\n'
fi
[[ "$parent_secret" =~ ^[0-9a-f]{64}$ ]] ||
  die "the inbox parent Secret Access Key must be a SHA-256 hex value"
parent_hash=$(printf '%s' "$parent_token" | sha256sum)
[[ "$parent_secret" == "${parent_hash%% *}" ]] ||
  die "the inbox parent API token and Secret Access Key do not match"
if ! AWS_ACCESS_KEY_ID="$R2_PARENT_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$parent_secret" \
  AWS_SESSION_TOKEN= aws --endpoint-url "$endpoint" --region auto \
  s3api list-objects-v2 --bucket "$INBOX_BUCKET" --max-items 1 >/dev/null 2>&1; then
  die "the inbox parent credential cannot read the private inbox"
fi
if AWS_ACCESS_KEY_ID="$R2_PARENT_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$parent_secret" \
  AWS_SESSION_TOKEN= aws --endpoint-url "$endpoint" --region auto \
  s3api list-objects-v2 --bucket "$PUBLISHED_BUCKET" --max-items 1 >/dev/null 2>&1; then
  die "the inbox parent credential is not limited to the private inbox"
fi
if [[ -n "$parent_token_file" && ! -f "$parent_token_file" ]]; then
  write_secret_file "$parent_token_file" "$parent_token" "parent token file"
fi
if [[ -n "${parent_secret_file:-}" && ! -f "$parent_secret_file" ]]; then
  write_secret_file "$parent_secret_file" "$parent_secret" "parent Secret Access Key file"
fi
unset parent_token parent_secret parent_hash

if [[ -n "$control_wrangler_bin" ]]; then
  control_response=$("$control_wrangler_bin" auth token --json) ||
    die "Wrangler could not provide its current OAuth token"
  control_token=$(jq -er 'select(.type == "oauth") | .token' <<<"$control_response") ||
    die "Wrangler did not return an OAuth control token"
  unset control_response
elif [[ -n "$control_token_file" && -f "$control_token_file" ]]; then
  control_token=$(read_secret_file "$control_token_file" "control token file")
else
  printf 'R2 control-plane read token (hidden): '
  IFS= read -rs control_token
  printf '\n'
fi
[[ -n "$control_token" ]] || die "the R2 control-plane token is required"
[[ "$control_token" =~ ^[A-Za-z0-9._-]+$ ]] ||
  die "the R2 control-plane token contains unexpected characters"
printf 'header = "Authorization: Bearer %s"\n' "$control_token" >"$work_dir/control.curl"
for suffix in domains/managed domains/custom; do
  response=$(curl --proto '=https' --tlsv1.2 --fail-with-body --silent --show-error \
    "$api_root/buckets/$INBOX_BUCKET/$suffix" --config "$work_dir/control.curl") ||
    die "the R2 control-plane token cannot inspect inbox $suffix"
  jq -e '.success == true' >/dev/null <<<"$response" ||
    die "the R2 control-plane token was rejected"
done
if [[ -n "$control_token_file" && ! -f "$control_token_file" ]]; then
  write_secret_file "$control_token_file" "$control_token" "control token file"
fi
if [[ "$PUBLISHED_ACCESS_MODE" == custom ]]; then
  wait_for_custom_domain
fi

unset response control_token
rm -f -- "$work_dir/control.curl" "$work_dir/provision.curl"

update_machine_env() {
  [[ -n "$machine_env" ]] || return 0
  validate_machine_env
  local parent partial
  parent=$(dirname -- "$machine_env")
  partial=$(mktemp "$parent/.relay-machine-env.partial.XXXXXXXX")
  if ! {
    while IFS= read -r line || [[ -n "$line" ]]; do
      case "$line" in
        STORAGE_PROVIDER=*) printf 'STORAGE_PROVIDER=r2\n' ;;
        PUBLISHED_BUCKET=*) printf 'PUBLISHED_BUCKET=%s\n' "$PUBLISHED_BUCKET" ;;
        PUBLISHED_BASE_URL=*) printf 'PUBLISHED_BASE_URL=%s\n' "$PUBLISHED_BASE_URL" ;;
        INBOX_BUCKET=*) printf 'INBOX_BUCKET=%s\n' "$INBOX_BUCKET" ;;
        STORAGE_ENDPOINT=*) printf 'STORAGE_ENDPOINT=%s\n' "$endpoint" ;;
        COORDINATOR_PROFILE=*) printf 'COORDINATOR_PROFILE=%s\n' "$COORDINATOR_PROFILE" ;;
        AWS_REGION=*) printf 'AWS_REGION=\n' ;;
        ISSUER_PROFILE=*) printf 'ISSUER_PROFILE=\n' ;;
        GRANT_ROLE_NAME=*) printf 'GRANT_ROLE_NAME=\n' ;;
        GRANT_ROLE_ARN=*) printf 'GRANT_ROLE_ARN=\n' ;;
        GRANT_ROLE_MAX_TTL=*) printf 'GRANT_ROLE_MAX_TTL=\n' ;;
        R2_ACCOUNT_ID=*) printf 'R2_ACCOUNT_ID=%s\n' "$R2_ACCOUNT_ID" ;;
        R2_PARENT_ACCESS_KEY_ID=*) printf 'R2_PARENT_ACCESS_KEY_ID=%s\n' "$R2_PARENT_ACCESS_KEY_ID" ;;
        R2_PARENT_TOKEN_FILE=*) printf 'R2_PARENT_TOKEN_FILE=%s\n' "$parent_token_file" ;;
        R2_PARENT_SECRET_FILE=*) printf 'R2_PARENT_SECRET_FILE=%s\n' "${parent_secret_file:-}" ;;
        R2_CONTROL_TOKEN_FILE=*) printf 'R2_CONTROL_TOKEN_FILE=%s\n' "$control_token_file" ;;
        R2_CONTROL_WRANGLER_BIN=*) printf 'R2_CONTROL_WRANGLER_BIN=%s\n' "$control_wrangler_bin" ;;
        *) printf '%s\n' "$line" ;;
      esac
    done <"$machine_env"
    grep -q '^R2_PARENT_TOKEN_FILE=' "$machine_env" ||
      printf 'R2_PARENT_TOKEN_FILE=%s\n' "$parent_token_file"
    grep -q '^R2_PARENT_SECRET_FILE=' "$machine_env" ||
      printf 'R2_PARENT_SECRET_FILE=%s\n' "${parent_secret_file:-}"
    grep -q '^R2_CONTROL_TOKEN_FILE=' "$machine_env" ||
      printf 'R2_CONTROL_TOKEN_FILE=%s\n' "$control_token_file"
    grep -q '^R2_CONTROL_WRANGLER_BIN=' "$machine_env" ||
      printf 'R2_CONTROL_WRANGLER_BIN=%s\n' "$control_wrangler_bin"
  } >"$partial"; then
    rm -f -- "$partial"
    die "could not prepare the machine env update"
  fi
  if ! chmod 0600 "$partial" || ! mv -- "$partial" "$machine_env"; then
    rm -f -- "$partial"
    die "could not atomically update the machine env"
  fi
}

update_machine_env

printf '\nR2 storage is ready.\n'
printf 'STORAGE_PROVIDER=r2\n'
printf 'PUBLISHED_BUCKET=%s\n' "$PUBLISHED_BUCKET"
printf 'PUBLISHED_BASE_URL=%s\n' "$PUBLISHED_BASE_URL"
printf 'INBOX_BUCKET=%s\n' "$INBOX_BUCKET"
printf 'STORAGE_ENDPOINT=%s\n' "$endpoint"
printf 'COORDINATOR_PROFILE=%s\n' "$COORDINATOR_PROFILE"
printf 'AWS_REGION=\nISSUER_PROFILE=\nGRANT_ROLE_NAME=\nGRANT_ROLE_ARN=\nGRANT_ROLE_MAX_TTL=\n'
printf 'R2_ACCOUNT_ID=%s\n' "$R2_ACCOUNT_ID"
printf 'R2_PARENT_ACCESS_KEY_ID=%s\n' "$R2_PARENT_ACCESS_KEY_ID"
if [[ -n "$machine_env" ]]; then
  printf '\nUpdated Machine 1 automatically:\n  %s\n' "$machine_env"
fi
printf 'The coordinator S3 profile and parent/control credential sources were validated without printing secrets.\n'
