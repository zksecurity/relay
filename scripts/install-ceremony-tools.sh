#!/usr/bin/env bash
set -euo pipefail
umask 077

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

usage() {
  die "usage: $0 MACHINE_ENV"
}

[[ $# -eq 1 ]] || usage
CONFIG=$1
[[ -f "$CONFIG" && ! -L "$CONFIG" ]] ||
  die "configuration must be a regular non-symlink file: $CONFIG"

# Read only the installer fields. Do not source the role configuration: a
# downloaded or mistyped dotenv file must not become executable shell code.
declare -A seen=()
while IFS= read -r line || [[ -n "$line" ]]; do
  line=${line%$'\r'}
  [[ -z "$line" || "$line" == \#* ]] && continue
  if [[ ! "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]]; then
    die "invalid dotenv assignment in $CONFIG"
  fi
  name=${BASH_REMATCH[1]}
  value=${BASH_REMATCH[2]}
  case "$name" in
    RELAY_TAG | MPC_RELEASE_REPOSITORY | MPC_TAG | RELAY_SHA256 | MPC_SHA256 | RELAY_BIN | MPC_BIN)
      [[ ! ${seen[$name]+present} ]] || die "duplicate $name in $CONFIG"
      seen[$name]=1
      printf -v "$name" '%s' "$value"
      ;;
  esac
done <"$CONFIG"

required=(
  RELAY_TAG
  MPC_RELEASE_REPOSITORY
  MPC_TAG
  RELAY_SHA256
  MPC_SHA256
  RELAY_BIN
  MPC_BIN
)
for name in "${required[@]}"; do
  [[ -n "${!name:-}" ]] || die "$name is required in $CONFIG"
  [[ "${!name}" != *REPLACE_WITH* ]] || die "$name still contains a placeholder"
done

tag_pattern='^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
[[ "$RELAY_TAG" =~ $tag_pattern ]] || die "RELAY_TAG is malformed"
[[ "$MPC_TAG" =~ $tag_pattern ]] || die "MPC_TAG is malformed"
[[ "$MPC_RELEASE_REPOSITORY" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
  die "MPC_RELEASE_REPOSITORY must be OWNER/REPOSITORY"
[[ "$RELAY_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "RELAY_SHA256 is malformed"
[[ "$MPC_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "MPC_SHA256 is malformed"

validate_target() {
  local target=$1
  local expected_name=$2
  local parent
  [[ "$target" == /* && "$target" != / ]] ||
    die "$expected_name installation path must be absolute"
  [[ "$(basename -- "$target")" == "$expected_name" ]] ||
    die "$expected_name installation path must end in /$expected_name"
  parent=$(dirname -- "$target")
  [[ -d "$parent" && ! -L "$parent" ]] ||
    die "$expected_name installation directory must be an existing non-symlink directory: $parent"
  [[ ! -L "$target" ]] || die "$expected_name installation target must not be a symbolic link: $target"
}

validate_target "$RELAY_BIN" relay
validate_target "$MPC_BIN" mpc-ceremony
[[ "$RELAY_BIN" != "$MPC_BIN" ]] || die "binary installation paths must differ"

for command_name in basename curl dirname install mktemp sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command is missing: $command_name"
done

INSTALL_ROOT=$(mktemp -d /tmp/ceremony-tools-install.XXXXXXXX)
cleanup() {
  if [[ -n "${INSTALL_ROOT:-}" && "$INSTALL_ROOT" == /tmp/ceremony-tools-install.* ]]; then
    rm -rf -- "$INSTALL_ROOT"
  fi
}
trap cleanup EXIT

download() {
  local url=$1
  local output=$2
  curl --proto '=https' --tlsv1.2 --fail --location --show-error \
    "$url" --output "$output"
  [[ -f "$output" && ! -L "$output" ]] || die "download did not create a regular file: $output"
}

download \
  "https://github.com/zksecurity/relay/releases/download/$RELAY_TAG/relay" \
  "$INSTALL_ROOT/relay"
download \
  "https://github.com/$MPC_RELEASE_REPOSITORY/releases/download/$MPC_TAG/mpc-ceremony" \
  "$INSTALL_ROOT/mpc-ceremony"

printf '%s  %s\n' "$RELAY_SHA256" "$INSTALL_ROOT/relay" | sha256sum --check
printf '%s  %s\n' "$MPC_SHA256" "$INSTALL_ROOT/mpc-ceremony" | sha256sum --check

install_verified() {
  local source=$1
  local target=$2
  local parent
  parent=$(dirname -- "$target")
  if [[ $EUID -eq 0 || ( -w "$parent" && ( ! -e "$target" || -w "$target" ) ) ]]; then
    install -m 0755 "$source" "$target"
    return
  fi
  command -v sudo >/dev/null 2>&1 ||
    die "sudo is required to install $target"
  sudo install -m 0755 "$source" "$target"
}

install_verified "$INSTALL_ROOT/relay" "$RELAY_BIN"
install_verified "$INSTALL_ROOT/mpc-ceremony" "$MPC_BIN"

"$RELAY_BIN" --help >/dev/null 2>&1 || die "installed Relay binary did not start"
"$MPC_BIN" help >/dev/null 2>&1 || die "installed mpc-ceremony binary did not start"

printf 'Installed and verified ceremony tools:\n'
printf '  relay:        %s (%s)\n' "$RELAY_BIN" "$RELAY_SHA256"
printf '  mpc-ceremony: %s (%s)\n' "$MPC_BIN" "$MPC_SHA256"
