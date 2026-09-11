#!/usr/bin/env bash
set -euo pipefail
umask 077

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf 'usage: %s [--machine-env FILE] [--wrangler-bin FILE | --cloudflare-token-file FILE] ' "$0" >&2
  printf '[--token-manager-file FILE]\n' >&2
  exit 2
}

machine_env=
coordinator_settings=
script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=portable.sh
source "$script_root/portable.sh"
# shellcheck source=coordinator-settings.sh
source "$script_root/coordinator-settings.sh"
machine_env_explicit=no
wrangler_bin=${WRANGLER_BIN:-}
cloudflare_token_file=
token_manager_file=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --coordinator-settings)
      [[ $# -ge 2 ]] || usage
      coordinator_settings=$2
      shift 2
      ;;
    --machine-env)
      [[ $# -ge 2 ]] || usage
      machine_env=$2
      machine_env_explicit=yes
      shift 2
      ;;
    --wrangler-bin)
      [[ $# -ge 2 ]] || usage
      wrangler_bin=$2
      shift 2
      ;;
    --cloudflare-token-file)
      [[ $# -ge 2 ]] || usage
      cloudflare_token_file=$2
      shift 2
      ;;
    --token-manager-file)
      [[ $# -ge 2 ]] || usage
      token_manager_file=$2
      shift 2
      ;;
    -h | --help)
      printf 'usage: %s [--machine-env FILE] [--wrangler-bin FILE | --cloudflare-token-file FILE] ' "$0"
      printf '[--token-manager-file FILE]\n\n'
      printf 'Uses an existing Wrangler browser login or protected bearer-token file to\n'
      printf 'discover the Cloudflare account\n'
      printf 'and zone, generate R2 resource names, provision storage, securely retain the\n'
      printf 'inbox-parent credentials, and update Machine 1 automatically.\n'
      printf 'A token manager can mint the two bucket-scoped R2 credentials automatically.\n'
      printf -- '--coordinator-settings FRESH_JSON exports the non-secret coordinator handoff.\n'
      exit 0
      ;;
    *) usage ;;
  esac
done

prepare_coordinator_settings_export "$coordinator_settings"

[[ -z "$cloudflare_token_file" || -z "$wrangler_bin" ]] ||
  die "choose only one of --wrangler-bin and --cloudflare-token-file"

for command_name in curl jq mktemp stat; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command is missing: $command_name"
done

validate_token_file() {
  local path=$1
  [[ "$path" == /* ]] || die "--cloudflare-token-file must use an absolute path"
  [[ -f "$path" && ! -L "$path" ]] ||
    die "Cloudflare token file must be a regular non-symlink file: $path"
  [[ "$(portable_stat_mode "$path")" == 600 ]] ||
    die "Cloudflare token file must have mode 0600: $path"
  [[ "$(portable_stat_uid "$path")" == "$EUID" ]] ||
    die "Cloudflare token file must be owned by the current user: $path"
  [[ "$(portable_stat_links "$path")" == 1 ]] ||
    die "Cloudflare token file must not have hard links: $path"
  local token
  token=$(portable_read_single_line "$path") ||
    die "Cloudflare token file must contain exactly one valid token line"
  [[ "$token" =~ ^[A-Za-z0-9._-]+$ ]] ||
    die "Cloudflare token file must contain exactly one valid token line"
}

if [[ -n "$cloudflare_token_file" ]]; then
  cloudflare_token_file=$(portable_realpath "$cloudflare_token_file")
  validate_token_file "$cloudflare_token_file"
else
  if [[ -z "$wrangler_bin" ]]; then
    wrangler_bin=$(command -v wrangler || true)
  fi
  [[ -n "$wrangler_bin" ]] || die "Wrangler v4 is required; install it, then run wrangler login"
  wrangler_bin=$(portable_realpath "$wrangler_bin")
  [[ -f "$wrangler_bin" && -x "$wrangler_bin" && ! -L "$wrangler_bin" ]] ||
    die "Wrangler must resolve to a non-symlink executable file"
  wrangler_version=$("$wrangler_bin" --version 2>/dev/null || true)
  [[ "$wrangler_version" =~ ^4\.[0-9]+\.[0-9]+$ ]] ||
    die "Wrangler v4 is required, got: ${wrangler_version:-unknown}"
fi
if [[ -n "$token_manager_file" ]]; then
  token_manager_file=$(portable_realpath "$token_manager_file")
  validate_token_file "$token_manager_file"
fi

if [[ "$machine_env_explicit" == no && -n "${HOME:-}" ]]; then
  default_machine_env="$HOME/ceremony-tools/three-machine-rehearsal/machine-1/.env"
  if [[ -e "$default_machine_env" || -L "$default_machine_env" ]]; then
    machine_env=$default_machine_env
  fi
fi

work_dir=$(mktemp -d /tmp/relay-r2-wrangler-setup.XXXXXXXX)
cleanup() {
  unset oauth_token
  if [[ -n "${work_dir:-}" && "$work_dir" == /tmp/relay-r2-wrangler-setup.* ]]; then
    rm -rf -- "$work_dir"
  fi
}
trap cleanup EXIT

if [[ -n "$cloudflare_token_file" ]]; then
  bearer_token=$(<"$cloudflare_token_file")
  printf 'header = "Authorization: Bearer %s"\n' "$bearer_token" >"$work_dir/oauth.curl"
  unset bearer_token
  accounts_response=$(curl --proto '=https' --tlsv1.2 --fail-with-body --silent --show-error \
    --get 'https://api.cloudflare.com/client/v4/accounts' \
    --config "$work_dir/oauth.curl" \
    --data-urlencode 'per_page=50') || die "could not list accounts with the Cloudflare token"
  jq -e '.success == true and .result_info.total_pages <= 1' >/dev/null <<<"$accounts_response" ||
    die "Cloudflare account discovery failed or returned more than 50 accounts"
  account_ids=()
  while IFS= read -r value; do account_ids+=("$value"); done < <(jq -r '.result[].id' <<<"$accounts_response")
  account_names=()
  while IFS= read -r value; do account_names+=("$value"); done < <(jq -r '.result[].name' <<<"$accounts_response")
  unset accounts_response
else
  if ! "$wrangler_bin" whoami --json >"$work_dir/whoami.json" 2>"$work_dir/whoami.err"; then
  printf 'Wrangler is not authenticated.\n\n' >&2
  printf 'For an SSH coordinator, open a tunnel from your laptop:\n' >&2
  printf '  ssh -L 8976:127.0.0.1:8976 USER@COORDINATOR\n\n' >&2
  printf 'Then, inside that SSH session, run:\n' >&2
  printf '  %s login --browser=false --callback-host 127.0.0.1 --callback-port 8976\n\n' "$wrangler_bin" >&2
  printf 'Open the printed URL in your laptop browser. This callback flow also avoids\n' >&2
  printf 'the HTTP 403 that some server IPs receive from wrangler login --device.\n' >&2
    die "complete Wrangler login, then rerun this command"
  fi
  jq -e '.loggedIn == true and .authType == "OAuth Token"' \
    "$work_dir/whoami.json" >/dev/null ||
    die "Wrangler must be logged in with OAuth; unset CLOUDFLARE_API_TOKEN and run wrangler login"
  jq -e '(.accounts | length > 0)' "$work_dir/whoami.json" >/dev/null ||
    die "Wrangler returned no authenticated Cloudflare accounts"
  account_ids=()
  while IFS= read -r value; do account_ids+=("$value"); done < <(jq -r '.accounts[].id' "$work_dir/whoami.json")
  account_names=()
  while IFS= read -r value; do account_names+=("$value"); done < <(jq -r '.accounts[].name' "$work_dir/whoami.json")

  oauth_response=$("$wrangler_bin" auth token --json) ||
    die "Wrangler could not provide its current OAuth token"
  bearer_token=$(jq -er 'select(.type == "oauth") | .token' <<<"$oauth_response") ||
    die "Wrangler did not return an OAuth token"
  unset oauth_response
  printf '%s\n' "$bearer_token" >"$work_dir/oauth-token"
  chmod 0600 "$work_dir/oauth-token"
  printf 'header = "Authorization: Bearer %s"\n' "$bearer_token" >"$work_dir/oauth.curl"
  unset bearer_token
fi
[[ ${#account_ids[@]} -gt 0 ]] || die "Cloudflare returned no accessible accounts"
if [[ ${#account_ids[@]} -eq 1 ]]; then
  account_index=0
  printf 'Using the only authenticated Cloudflare account: %s (%s)\n' \
    "${account_names[0]}" "${account_ids[0]}"
else
  printf 'Authenticated Cloudflare accounts:\n'
  for index in "${!account_ids[@]}"; do
    printf '  %d. %s (%s)\n' "$((index + 1))" "${account_names[$index]}" "${account_ids[$index]}"
  done
  read -rp "Select account [1-${#account_ids[@]}]: " selection
  [[ "$selection" =~ ^[0-9]+$ && "$selection" -ge 1 && "$selection" -le ${#account_ids[@]} ]] ||
    die "account selection is invalid"
  account_index=$((selection - 1))
fi
R2_ACCOUNT_ID=${account_ids[$account_index]}
[[ "$R2_ACCOUNT_ID" =~ ^[0-9a-f]{32}$ ]] || die "Wrangler returned a malformed account ID"

zones_response=$(curl --proto '=https' --tlsv1.2 --fail-with-body --silent --show-error \
  --get 'https://api.cloudflare.com/client/v4/zones' \
  --config "$work_dir/oauth.curl" \
  --data-urlencode "account.id=$R2_ACCOUNT_ID" \
  --data-urlencode 'status=active' \
  --data-urlencode 'per_page=50') || die "could not list active zones for the selected account"
jq -e '.success == true and .result_info.total_pages <= 1' >/dev/null <<<"$zones_response" ||
  die "Cloudflare zone discovery failed or returned more than 50 zones"
zone_ids=()
while IFS= read -r value; do zone_ids+=("$value"); done < <(jq -r '.result[].id' <<<"$zones_response")
zone_names=()
while IFS= read -r value; do zone_names+=("$value"); done < <(jq -r '.result[].name' <<<"$zones_response")
if [[ ${#zone_ids[@]} -eq 0 ]]; then
  PUBLISHED_ACCESS_MODE=r2dev
  R2_ZONE_ID=
  zone_name=
  printf 'No active zone is available; using a Cloudflare-managed r2.dev URL for this rehearsal only.\n'
elif [[ ${#zone_ids[@]} -eq 1 ]]; then
  PUBLISHED_ACCESS_MODE=custom
  zone_index=0
  printf 'Using the only active zone: %s (%s)\n' "${zone_names[0]}" "${zone_ids[0]}"
else
  PUBLISHED_ACCESS_MODE=custom
  printf 'Active zones:\n'
  for index in "${!zone_ids[@]}"; do
    printf '  %d. %s (%s)\n' "$((index + 1))" "${zone_names[$index]}" "${zone_ids[$index]}"
  done
  read -rp "Select zone [1-${#zone_ids[@]}]: " selection
  [[ "$selection" =~ ^[0-9]+$ && "$selection" -ge 1 && "$selection" -le ${#zone_ids[@]} ]] ||
    die "zone selection is invalid"
  zone_index=$((selection - 1))
fi
if [[ "$PUBLISHED_ACCESS_MODE" == custom ]]; then
  R2_ZONE_ID=${zone_ids[$zone_index]}
  zone_name=${zone_names[$zone_index]}
  [[ "$R2_ZONE_ID" =~ ^[0-9a-f]{32}$ ]] || die "Cloudflare returned a malformed zone ID"
  [[ "$zone_name" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])$ ]] || die "Cloudflare returned a malformed zone name"
fi

read -rp 'Resource prefix [relay-ceremony]: ' RESOURCE_PREFIX
RESOURCE_PREFIX=${RESOURCE_PREFIX:-relay-ceremony}
[[ "$RESOURCE_PREFIX" =~ ^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$ ]] ||
  die "resource prefix must be 3-32 lowercase letters, numbers, or hyphens"
PUBLISHED_CUSTOM_DOMAIN=
if [[ "$PUBLISHED_ACCESS_MODE" == custom ]]; then
  default_domain="$RESOURCE_PREFIX.$zone_name"
  read -rp "Published hostname [$default_domain]: " PUBLISHED_CUSTOM_DOMAIN
  PUBLISHED_CUSTOM_DOMAIN=${PUBLISHED_CUSTOM_DOMAIN:-$default_domain}
  [[ "$PUBLISHED_CUSTOM_DOMAIN" == *".$zone_name" ]] ||
    die "published hostname must be below the selected zone $zone_name"
  [[ "$PUBLISHED_CUSTOM_DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])$ ]] ||
    die "published hostname is malformed"
fi
read -rp 'Coordinator AWS CLI profile [relay-r2-coordinator]: ' COORDINATOR_PROFILE
COORDINATOR_PROFILE=${COORDINATOR_PROFILE:-relay-r2-coordinator}
[[ "$COORDINATOR_PROFILE" =~ ^[A-Za-z0-9_.-]+$ ]] || die "coordinator profile is malformed"

account_suffix=${R2_ACCOUNT_ID:0:12}
PUBLISHED_BUCKET="$RESOURCE_PREFIX-$account_suffix-published"
INBOX_BUCKET="$RESOURCE_PREFIX-$account_suffix-inbox"

if [[ -n "${XDG_CONFIG_HOME:-}" ]]; then
  secret_root="$XDG_CONFIG_HOME/relay/$RESOURCE_PREFIX-r2"
else
  [[ -n "${HOME:-}" ]] || die "HOME or XDG_CONFIG_HOME is required for the secure token directory"
  secret_root="$HOME/.config/relay/$RESOURCE_PREFIX-r2"
fi
mkdir -p "$secret_root"
chmod 0700 "$secret_root"
parent_token_file="$secret_root/inbox-parent-api-token"

printf '\nAutomatic R2 plan:\n'
printf '  account:          %s (%s)\n' "${account_names[$account_index]}" "$R2_ACCOUNT_ID"
if [[ "$PUBLISHED_ACCESS_MODE" == custom ]]; then
  printf '  zone:             %s (%s)\n' "$zone_name" "$R2_ZONE_ID"
  printf '  public origin:    https://%s\n' "$PUBLISHED_CUSTOM_DOMAIN"
else
  printf '  zone:             none (rehearsal-only r2.dev fallback)\n'
  printf '  public origin:    generated after bucket creation\n'
fi
printf '  published bucket: %s\n' "$PUBLISHED_BUCKET"
printf '  private inbox:    %s\n' "$INBOX_BUCKET"
printf '  coordinator:      AWS profile %s\n' "$COORDINATOR_PROFILE"
printf '  parent credentials: %s\n' "$secret_root"
if [[ -n "$token_manager_file" ]]; then
  printf '  scoped tokens:    create automatically with token manager\n'
else
  printf '  scoped tokens:    enter existing credentials when prompted\n'
fi
if [[ -n "$machine_env" ]]; then
  printf '  update rehearsal: %s\n' "$machine_env"
else
  printf '  update rehearsal: no Machine 1 .env found\n'
fi
read -rp 'Type yes to create or update these resources: ' CONFIRM_CREATE
[[ "$CONFIRM_CREATE" == yes ]] || die "setup was not confirmed"

printf '%s\n' \
  "PUBLISHED_ACCESS_MODE=$PUBLISHED_ACCESS_MODE" \
  "R2_ACCOUNT_ID=$R2_ACCOUNT_ID" \
  "R2_ZONE_ID=$R2_ZONE_ID" \
  "PUBLISHED_BUCKET=$PUBLISHED_BUCKET" \
  "INBOX_BUCKET=$INBOX_BUCKET" \
  "PUBLISHED_CUSTOM_DOMAIN=$PUBLISHED_CUSTOM_DOMAIN" \
  "COORDINATOR_PROFILE=$COORDINATOR_PROFILE" \
  'R2_PARENT_ACCESS_KEY_ID=REPLACE_WITH_PARENT_ACCESS_KEY_ID' \
  'CONFIRM_CREATE=yes' >"$work_dir/r2.env"
chmod 0600 "$work_dir/r2.env"

script_root=$(cd "$(dirname "$0")" && pwd)
if [[ -n "$cloudflare_token_file" ]]; then
  provision_source=$cloudflare_token_file
  control_args=(--control-token-file "$cloudflare_token_file")
else
  provision_source=$work_dir/oauth-token
  control_args=(--control-wrangler-bin "$wrangler_bin")
fi
args=(
  --provision-token-file "$provision_source"
  --parent-token-file "$parent_token_file"
  --credential-root "$secret_root"
  "${control_args[@]}"
)
[[ -z "$token_manager_file" ]] || args+=(--token-manager-file "$token_manager_file")
[[ -z "$machine_env" ]] || args+=(--machine-env "$machine_env")
[[ -z "$coordinator_settings" ]] || args+=(--coordinator-settings "$coordinator_settings")
"$script_root/setup-r2.sh" "${args[@]}" "$work_dir/r2.env"

printf '\nWrangler-backed R2 setup completed.\n'
if [[ -n "$cloudflare_token_file" ]]; then
  printf 'Run coordinator storage configuration before the transferred OAuth token expires.\n'
else
  printf 'Coordinator storage preflight can refresh the control token from Wrangler automatically.\n'
fi
