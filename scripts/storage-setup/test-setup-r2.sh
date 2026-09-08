#!/usr/bin/env bash
# The single-quoted strings below deliberately generate mock scripts without
# expanding their variables in this parent process. The negated greps are
# assertions whose statuses are consumed directly by set -e.
# shellcheck disable=SC2016,SC2251
set -euo pipefail
umask 077

STORAGE_SETUP_SCRIPT_ROOT=$(cd "$(dirname "$0")" && pwd)
TEST_ROOT=$(mktemp -d /tmp/relay-r2-setup-test.XXXXXXXX)
cleanup() {
  local status=$?
  if [[ $status -ne 0 && -f "${TEST_ROOT:-}/stderr" ]]; then
    printf 'mocked R2 setup stderr:\n' >&2
    sed -n '1,200p' "$TEST_ROOT/stderr" >&2
  fi
  if [[ $status -ne 0 && -f "${TEST_ROOT:-}/token-file.stderr" ]]; then
    printf 'mocked token-file R2 setup stderr:\n' >&2
    sed -n '1,200p' "$TEST_ROOT/token-file.stderr" >&2
  fi
  if [[ -n "${TEST_ROOT:-}" && "$TEST_ROOT" == /tmp/relay-r2-setup-test.* ]]; then
    rm -rf -- "$TEST_ROOT"
  fi
  exit "$status"
}
trap cleanup EXIT

mkdir -m 0700 "$TEST_ROOT/bin" "$TEST_ROOT/config"

# The mock files are runtime fixtures under a freshly allocated /tmp root. They
# let CI exercise the interactive orchestration without contacting Cloudflare.
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'case "${1:-} ${2:-}" in' \
  '  "--version ") printf "4.124.0\n" ;;' \
  '  "whoami --json") printf '\''{"loggedIn":true,"authType":"OAuth Token","accounts":[{"id":"11111111111111111111111111111111","name":"Test Account"}]}\n'\'' ;;' \
  '  "auth token") printf '\''{"type":"oauth","token":"oauth-token"}\n'\'' ;;' \
  '  *) printf "unexpected wrangler call: %s\n" "$*" >&2; exit 1 ;;' \
  'esac' >"$TEST_ROOT/bin/wrangler"
chmod 0755 "$TEST_ROOT/bin/wrangler"

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'args=" $* "' \
  '[[ -z "${MOCK_CURL_LOG:-}" ]] || printf "%s\n" "$args" >>"$MOCK_CURL_LOG"' \
  'if [[ "$args" == *"/client/v4/accounts "* ]]; then' \
  '  printf '\''{"success":true,"result":[{"id":"11111111111111111111111111111111","name":"Test Account"}],"result_info":{"total_pages":1}}\n'\''' \
  'elif [[ "$args" == *"/client/v4/zones "* ]]; then' \
  '  if [[ "${MOCK_NO_ZONES:-}" == 1 ]]; then' \
  '    printf '\''{"success":true,"result":[],"result_info":{"total_pages":1}}\n'\''' \
  '  else' \
  '    printf '\''{"success":true,"result":[{"id":"22222222222222222222222222222222","name":"example.test"}],"result_info":{"total_pages":1}}\n'\''' \
  '  fi' \
  'elif [[ "$args" == *"/tokens/permission_groups"* ]]; then' \
  '  printf '\''{"success":true,"result":[{"id":"55555555555555555555555555555555","name":"Workers R2 Storage Bucket Item Write"}]}\n'\''' \
  'elif [[ "$args" == *"/tokens"* && "$args" == *"coordinator"* ]]; then' \
  '  printf '\''{"success":true,"result":{"id":"33333333333333333333333333333333","value":"coordinator-api-token-value"}}\n'\''' \
  'elif [[ "$args" == *"/tokens"* && "$args" == *"parent"* ]]; then' \
  '  printf '\''{"success":true,"result":{"id":"44444444444444444444444444444444","value":"parent-api-token-value"}}\n'\''' \
  'elif [[ "$args" == *" --write-out "* ]]; then' \
  '  printf '\''{"success":false}\n404'\''' \
  'elif [[ "$args" == *"temp-access-credentials"* ]]; then' \
  '  printf '\''{"success":true,"result":{"sessionToken":"temporary"}}\n'\''' \
  'elif [[ "$args" == *"relay-ceremony-111111111111-published/domains/managed"* && "$args" == *" --request GET "* ]]; then' \
  '  printf '\''{"success":true,"result":{"domain":"relay-ceremony-111111111111.r2.dev","enabled":true}}\n'\''' \
  'elif [[ "$args" == *"domains/custom/relay-ceremony.example.test"* ]]; then' \
  '  printf '\''{"success":true,"result":{"status":{"ownership":"active","ssl":"active"}}}\n'\''' \
  'elif [[ "$args" == *"domains/custom"* && "$args" == *" --request GET "* ]]; then' \
  '  printf '\''{"success":true,"result":{"domains":[]}}\n'\''' \
  'else' \
  '  printf '\''{"success":true,"result":{}}\n'\''' \
  'fi' >"$TEST_ROOT/bin/curl"
chmod 0755 "$TEST_ROOT/bin/curl"

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'if [[ "${AWS_ACCESS_KEY_ID:-}" =~ ^(parent-access|44444444444444444444444444444444)$ && " $* " == *"-published "* ]]; then exit 1; fi' \
  'exit 0' >"$TEST_ROOT/bin/aws"
chmod 0755 "$TEST_ROOT/bin/aws"

install -m 0600 \
  "$STORAGE_SETUP_SCRIPT_ROOT/../three-machine-rehearsal/machine-1/.env.example" \
  "$TEST_ROOT/machine-1.env"
# A kit created before the token-source fields existed should be upgraded
# atomically rather than forcing the rehearsal to be rebuilt from scratch.
sed -i '/^R2_\(PARENT_TOKEN_FILE\|CONTROL_TOKEN_FILE\|CONTROL_WRANGLER_BIN\)=/d' \
  "$TEST_ROOT/machine-1.env"

parent_hash=$(printf '%s' parent-token | sha256sum)
input=$(printf '\n\n\nyes\nparent-access\ncoordinator-access\n%s\nparent-token\n%s\n' \
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "${parent_hash%% *}")
PATH="$TEST_ROOT/bin:$PATH" \
XDG_CONFIG_HOME="$TEST_ROOT/config" \
  "$STORAGE_SETUP_SCRIPT_ROOT/setup-r2-wrangler.sh" \
    --wrangler-bin "$TEST_ROOT/bin/wrangler" \
    --machine-env "$TEST_ROOT/machine-1.env" \
    --coordinator-settings "$TEST_ROOT/coordinator-settings.json" \
    >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr" <<<"$input"

parent_file="$TEST_ROOT/config/relay/relay-ceremony-r2/inbox-parent-api-token"
[[ -f "$parent_file" && ! -L "$parent_file" ]]
[[ "$(stat -c '%a' -- "$parent_file")" == 600 ]]
[[ "$(<"$parent_file")" == parent-token ]]

jq -e '.schema == "relay-coordinator-storage-settings-v1" and
  .settings.provider == "r2" and .settings.region == "auto" and
  .settings["parent-access-key-id"] == "parent-access" and
  (.settings | length) == 9' "$TEST_ROOT/coordinator-settings.json" >/dev/null
! grep -Fq 'parent-token' "$TEST_ROOT/coordinator-settings.json"
[[ "$(stat -c '%a' -- "$TEST_ROOT/coordinator-settings.json")" == 600 ]]

grep -Fx 'STORAGE_PROVIDER=r2' "$TEST_ROOT/machine-1.env"
grep -Fx 'PUBLISHED_BUCKET=relay-ceremony-111111111111-published' "$TEST_ROOT/machine-1.env"
grep -Fx 'PUBLISHED_BASE_URL=https://relay-ceremony.example.test' "$TEST_ROOT/machine-1.env"
grep -Fx 'INBOX_BUCKET=relay-ceremony-111111111111-inbox' "$TEST_ROOT/machine-1.env"
grep -Fx 'STORAGE_ENDPOINT=https://11111111111111111111111111111111.r2.cloudflarestorage.com' \
  "$TEST_ROOT/machine-1.env"
grep -Fx 'R2_ACCOUNT_ID=11111111111111111111111111111111' "$TEST_ROOT/machine-1.env"
grep -Fx 'R2_PARENT_ACCESS_KEY_ID=parent-access' "$TEST_ROOT/machine-1.env"
grep -Fx "R2_PARENT_TOKEN_FILE=$parent_file" "$TEST_ROOT/machine-1.env"
grep -Fx "R2_CONTROL_WRANGLER_BIN=$(realpath -e "$TEST_ROOT/bin/wrangler")" \
  "$TEST_ROOT/machine-1.env"

! grep -Fq 'oauth-token' "$TEST_ROOT/stdout" "$TEST_ROOT/stderr"
! grep -Fq 'parent-token' "$TEST_ROOT/stdout" "$TEST_ROOT/stderr"
! grep -Fq 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  "$TEST_ROOT/stdout" "$TEST_ROOT/stderr"

# shellcheck source=../three-machine-rehearsal/lib.sh
source "$STORAGE_SETUP_SCRIPT_ROOT/../three-machine-rehearsal/lib.sh"
STORAGE_PROVIDER=r2
R2_PARENT_TOKEN_FILE=$parent_file
R2_CONTROL_WRANGLER_BIN=$(realpath -e "$TEST_ROOT/bin/wrangler")
unset RELAY_R2_PARENT_TOKEN RELAY_R2_CONTROL_TOKEN
read_r2_parent_token_if_needed
[[ "$RELAY_R2_PARENT_TOKEN" == parent-token ]]
clear_r2_parent_token
read_r2_control_token_if_needed
[[ "$RELAY_R2_CONTROL_TOKEN" == oauth-token ]]
clear_r2_control_token

# Exercise the headless path used when a VPS receives a bot challenge during
# OAuth exchange. The transferred token remains in a protected file and is
# never copied into the machine environment.
install -m 0600 \
  "$STORAGE_SETUP_SCRIPT_ROOT/../three-machine-rehearsal/machine-1/.env.example" \
  "$TEST_ROOT/machine-1-token-file.env"
printf 'transferred-oauth-token\n' >"$TEST_ROOT/cloudflare-token"
chmod 0600 "$TEST_ROOT/cloudflare-token"
input=$(printf '\n\nyes\nparent-access\ncoordinator-access\n%s\n%s\n' \
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "${parent_hash%% *}")
PATH="$TEST_ROOT/bin:$PATH" \
XDG_CONFIG_HOME="$TEST_ROOT/config" \
MOCK_NO_ZONES=1 \
  "$STORAGE_SETUP_SCRIPT_ROOT/setup-r2-wrangler.sh" \
    --cloudflare-token-file "$TEST_ROOT/cloudflare-token" \
    --machine-env "$TEST_ROOT/machine-1-token-file.env" \
    >"$TEST_ROOT/token-file.stdout" 2>"$TEST_ROOT/token-file.stderr" <<<"$input"
grep -Fx "R2_CONTROL_TOKEN_FILE=$TEST_ROOT/cloudflare-token" \
  "$TEST_ROOT/machine-1-token-file.env"
grep -Fx 'R2_CONTROL_WRANGLER_BIN=' "$TEST_ROOT/machine-1-token-file.env"
grep -Fx 'PUBLISHED_BASE_URL=https://relay-ceremony-111111111111.r2.dev' \
  "$TEST_ROOT/machine-1-token-file.env"
! grep -Fq 'transferred-oauth-token' \
  "$TEST_ROOT/token-file.stdout" "$TEST_ROOT/token-file.stderr"

# A short-lived token manager can create both bucket-scoped R2 credentials.
# The powerful token and one-time token values must never reach stdout/stderr
# or Machine 1's non-secret configuration.
mkdir -m 0700 "$TEST_ROOT/config-auto"
install -m 0600 \
  "$STORAGE_SETUP_SCRIPT_ROOT/../three-machine-rehearsal/machine-1/.env.example" \
  "$TEST_ROOT/machine-1-auto.env"
printf 'transferred-oauth-token\n' >"$TEST_ROOT/cloudflare-token-auto"
printf 'account-token-manager-secret\n' >"$TEST_ROOT/token-manager"
chmod 0600 "$TEST_ROOT/cloudflare-token-auto" "$TEST_ROOT/token-manager"
input=$(printf '\n\nyes\n')
PATH="$TEST_ROOT/bin:$PATH" \
XDG_CONFIG_HOME="$TEST_ROOT/config-auto" \
MOCK_NO_ZONES=1 \
MOCK_CURL_LOG="$TEST_ROOT/auto.curl.log" \
  "$STORAGE_SETUP_SCRIPT_ROOT/setup-r2-wrangler.sh" \
    --cloudflare-token-file "$TEST_ROOT/cloudflare-token-auto" \
    --token-manager-file "$TEST_ROOT/token-manager" \
    --machine-env "$TEST_ROOT/machine-1-auto.env" \
    >"$TEST_ROOT/auto.stdout" 2>"$TEST_ROOT/auto.stderr" <<<"$input"

auto_root="$TEST_ROOT/config-auto/relay/relay-ceremony-r2"
[[ "$(<"$auto_root/coordinator-access-key-id")" == 33333333333333333333333333333333 ]]
[[ "$(<"$auto_root/inbox-parent-access-key-id")" == 44444444444444444444444444444444 ]]
[[ "$(<"$auto_root/inbox-parent-api-token")" == parent-api-token-value ]]
coordinator_hash=$(printf '%s' coordinator-api-token-value | sha256sum)
parent_hash=$(printf '%s' parent-api-token-value | sha256sum)
[[ "$(<"$auto_root/coordinator-secret-access-key")" == "${coordinator_hash%% *}" ]]
[[ "$(<"$auto_root/inbox-parent-secret-access-key")" == "${parent_hash%% *}" ]]
[[ "$(stat -c '%a' -- "$auto_root")" == 700 ]]
for secret_file in "$auto_root"/*; do
  [[ -f "$secret_file" && ! -L "$secret_file" ]]
  [[ "$(stat -c '%a' -- "$secret_file")" == 600 ]]
done
grep -Fx 'R2_PARENT_ACCESS_KEY_ID=44444444444444444444444444444444' \
  "$TEST_ROOT/machine-1-auto.env"
grep -Fx "R2_PARENT_TOKEN_FILE=$auto_root/inbox-parent-api-token" \
  "$TEST_ROOT/machine-1-auto.env"
grep -Fx "R2_PARENT_SECRET_FILE=$auto_root/inbox-parent-secret-access-key" \
  "$TEST_ROOT/machine-1-auto.env"
! grep -Fq 'account-token-manager-secret' \
  "$TEST_ROOT/auto.stdout" "$TEST_ROOT/auto.stderr" "$TEST_ROOT/machine-1-auto.env"
! grep -Fq 'coordinator-api-token-value' \
  "$TEST_ROOT/auto.stdout" "$TEST_ROOT/auto.stderr" "$TEST_ROOT/machine-1-auto.env"
! grep -Fq 'parent-api-token-value' \
  "$TEST_ROOT/auto.stdout" "$TEST_ROOT/auto.stderr" "$TEST_ROOT/machine-1-auto.env"

coordinator_request=$(grep '/tokens .*coordinator' "$TEST_ROOT/auto.curl.log")
parent_request=$(grep '/tokens .*parent' "$TEST_ROOT/auto.curl.log")
[[ "$coordinator_request" == *"r2.bucket.11111111111111111111111111111111_default_relay-ceremony-111111111111-published"* ]]
[[ "$coordinator_request" == *"r2.bucket.11111111111111111111111111111111_default_relay-ceremony-111111111111-inbox"* ]]
[[ "$parent_request" == *"r2.bucket.11111111111111111111111111111111_default_relay-ceremony-111111111111-inbox"* ]]
[[ "$parent_request" != *"r2.bucket.11111111111111111111111111111111_default_relay-ceremony-111111111111-published"* ]]

# Rerunning against a complete local credential set must reuse it rather than
# minting more account tokens.
: >"$TEST_ROOT/auto.curl.log"
PATH="$TEST_ROOT/bin:$PATH" \
XDG_CONFIG_HOME="$TEST_ROOT/config-auto" \
MOCK_NO_ZONES=1 \
MOCK_CURL_LOG="$TEST_ROOT/auto.curl.log" \
  "$STORAGE_SETUP_SCRIPT_ROOT/setup-r2-wrangler.sh" \
    --cloudflare-token-file "$TEST_ROOT/cloudflare-token-auto" \
    --token-manager-file "$TEST_ROOT/token-manager" \
    --machine-env "$TEST_ROOT/machine-1-auto.env" \
    >"$TEST_ROOT/auto-rerun.stdout" 2>"$TEST_ROOT/auto-rerun.stderr" <<<"$input"
! grep -Fq '/tokens ' "$TEST_ROOT/auto.curl.log"
grep -Fq 'Using the existing scoped R2 credentials' "$TEST_ROOT/auto-rerun.stdout"

printf 'Wrangler-backed R2 setup test passed\n'
