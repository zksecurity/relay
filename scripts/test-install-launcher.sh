#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=install-launcher.sh
source "$SCRIPT_DIR/install-launcher.sh"

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    printf 'Unexpected success: %s\n' "$*" >&2
    exit 1
  fi
}

tag='' commit=''
test_commit=0123456789012345678901234567890123456789
parse_release "https://github.com/zksecurity/relay/releases/tag/role-images-$test_commit"
[[ "$tag" == "role-images-$test_commit" && "$commit" == "$test_commit" ]]
parse_release "role-images-$test_commit"
expect_failure parse_release https://example.com/role-images-0123456789012345678901234567890123456789
expect_failure parse_release latest
# Intentional literal shell syntax: it must be rejected, never executed.
# shellcheck disable=SC2016
expect_failure parse_release 'role-images-$(touch injected)'
expect_failure main --guided </dev/null
printf 'PASS: exact release parsing and interactive guard\n'

test_root=$(mktemp -d)
# Use the physical path: /tmp itself is a symlink on macOS.
test_root=$(cd "$test_root" && pwd -P)
trap 'rm -rf -- "$test_root"' EXIT
destination="$test_root/release"
role_folder="$test_root/space ' quote \$ dollar ! bang"
save_guided_settings >/dev/null
(
  # Generated values containing shell metacharacters must round-trip as data.
  # shellcheck disable=SC1091
  source "$role_folder/relay-env.sh"
  [[ "$RELAY_COMMIT" == "$test_commit" && "$RELAY_RELEASE" == "$tag" ]]
  [[ "$RELAY" == "$destination/relay" && "$ROLE_ROOT" == "$role_folder" ]]
  [[ "$ROLE_WORK" == "$role_folder/work" && "$ROLE_TRUST" == "$role_folder/trust" && "$ROLE_KEYS" == "$role_folder/keys" ]]
  [[ -d "$ROLE_KEYS" && -d "$ROLE_WORK" && -d "$ROLE_TRUST" ]]
)
printf 'PASS: saved settings survive a new shell scope and safely quote paths\n'
for test_shell in bash zsh; do
  command -v "$test_shell" >/dev/null || { echo "Missing test shell: $test_shell" >&2; exit 1; }
  # Expressions intentionally expand in the child shell, not the test runner.
  # shellcheck disable=SC2016
  "$test_shell" -f -c '
    source "$1"
    test "$ROLE_ROOT" = "$2" &&
    test "$ROLE_WORK" = "$2/work" &&
    test "$ROLE_TRUST" = "$2/trust" &&
    test "$ROLE_KEYS" = "$2/keys" &&
    test "$RELAY" = "$3/relay" &&
    test "$RELAY_COMMIT" = "$4" &&
    test "$RELAY_RELEASE" = "role-images-$4"
  ' shell-test "$role_folder/relay-env.sh" "$role_folder" "$destination" "$test_commit"
done
printf 'PASS: generated settings load correctly in both Bash and Zsh\n'

# Helper tests feed answers without ever invoking installation commands.
expect_failure prepare_guided_settings <<EOF
demo
coordinator
$role_folder
yes
EOF
expect_failure prepare_guided_settings <<EOF
demo
unknown
EOF
expect_failure prepare_guided_settings <<EOF
demo
coordinator
$test_root/fresh
no
EOF
[[ ! -e "$test_root/fresh" ]]
printf 'PASS: existing folders, unknown roles and declined consent are rejected\n'

# Isolate role-instance selection without changing HOME or running a launcher.
(
  default_role_folder() { printf '%s/roles/%s/%s' "$test_root" "$1" "$2"; }
  prepare_guided_settings >/dev/null <<EOF
shared
5

yes
EOF
  first_name=$guided_local_name
  [[ "$guided_name" == shared && "$role_folder" == "$test_root/roles/shared/auditor" ]]
  save_guided_settings >/dev/null
  original=$(shasum -a 256 "$role_folder/start.sh")
  prepare_guided_settings >/dev/null <<EOF
shared
5
1
EOF
  [[ "$resume_start" == "$test_root/roles/shared/auditor/start.sh" ]]
  [[ "$(shasum -a 256 "$resume_start")" == "$original" ]]
  resume_start=''
  prepare_guided_settings >/dev/null <<EOF
shared
5
2

yes
EOF
  [[ -z "$resume_start" && "$guided_name" == shared && "$guided_local_name" != "$first_name" ]]
  [[ "$role_folder" == "$test_root/roles/shared/auditor-2" && ! -e "$role_folder" ]]
)
printf 'PASS: same-ceremony role instances stay separate and resume preserves settings\n'

printf 'fixture launcher\n' > "$test_root/candidate"
digest=$(shasum -a 256 "$test_root/candidate")
digest=${digest%% *}
install_verified_launcher "$test_root/installed" "$test_root/candidate" "$digest"
install_verified_launcher "$test_root/installed" "$test_root/candidate" "$digest" >/dev/null
expect_failure install_verified_launcher "$test_root/installed" "$test_root/candidate" incorrect
[[ "$(shasum -a 256 "$test_root/installed/relay")" == "$digest  $test_root/installed/relay" ]]
ln -s "$test_root/installed" "$test_root/linked"
expect_failure install_verified_launcher "$test_root/linked" "$test_root/candidate" "$digest"
printf 'PASS: verified launcher reuse, mismatch refusal and symlink rejection\n'

# A fresh Bash process keeps errexit active inside main. All external download
# and Docker calls are mocked; failed provenance must prevent installation.
# shellcheck disable=SC2016
expect_failure bash -c '
  source "$1"
  gh() { if [[ "$1" == release ]]; then return 0; else return 1; fi; }
  docker() { return 0; }
  install_verified_launcher() { exit 0; }
  main "$2"
' installer-test "$SCRIPT_DIR/install-launcher.sh" "role-images-$test_commit"
printf 'PASS: failed provenance stops before installation\n'

# Presets skip identity questions but retain folder choice and explicit consent.
(
  preset_label=ceremony-a1f340d25155420cb7b1272276639b83
  preset_role=participant
  prepare_guided_settings <<ANSWERS >"$test_root/preset-output"
$test_root/preset-role
yes
ANSWERS
  [[ "$guided_name" == "$preset_label" && "$guided_role" == participant ]]
  [[ "$role_folder" == "$test_root/preset-role" ]]
  if grep -q 'Choose a role number\|Ceremony label (use' "$test_root/preset-output"; then exit 1; fi
  grep -q 'Type yes to install' "$test_root/preset-output"
)
expect_failure main --guided --role admin
expect_failure main --guided --ceremony-label '../another-folder'
expect_failure main --guided --role participant --role auditor
expect_failure main --role participant "role-images-$test_commit"
expect_failure main --guided --release latest
expect_failure main --guided --ceremony-label
printf 'PASS: role and label presets preserve confirmation and reject invalid input\n'
