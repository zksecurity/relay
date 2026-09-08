#!/usr/bin/env bash
# Download this script from the selected release and verify its attestation
# before execution. Installs into a fresh versioned directory without sudo.
set -euo pipefail
umask 077
parse_release() {
  local selection=$1
  selection=${selection#https://github.com/zksecurity/relay/releases/tag/}
  [[ "$selection" =~ ^role-images-([0-9a-f]{40})$ ]] || {
    echo 'Use an exact Relay role-images release URL or tag, not latest or a branch.' >&2
    return 1
  }
  tag=$selection
  commit=${BASH_REMATCH[1]}
}

prepare_guided_settings() {
  local name role folder answer ancestor
  printf 'Ceremony name (lowercase letters, numbers, hyphens): '
  IFS= read -r name
  [[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || { echo 'Invalid ceremony name.' >&2; return 1; }
  printf 'Role: 1 coordinator, 2 participant, 3 witness, 4 mirror, 5 auditor, 6 release-signer, 7 upload-station\n'
  while :; do
    printf 'Choose a role number: '; IFS= read -r role || return 1
    case "$role" in
      1|coordinator) role=coordinator;; 2|participant) role=participant;;
      3|witness) role=witness;; 4|mirror) role=mirror;; 5|auditor) role=auditor;;
      6|release-signer) role=release-signer;; 7|upload-station) role=upload-station;;
      *) printf 'Choose one of the listed roles.\n'; continue;;
    esac
    break
  done
  printf 'Role folder [press Enter for %s/ceremonies/%s/%s]: ' "$HOME" "$name" "$role"
  IFS= read -r folder
  folder=${folder:-"$HOME/ceremonies/$name/$role"}
  # Require a fresh, unambiguous path; never reuse another role's data.
  case "$folder" in /*) ;; *) echo 'Use an absolute folder path.' >&2; return 1 ;; esac
  case "$folder/" in *'/../'*|*'/./'*|*'//'*) echo 'Use a clean folder path without dot components or repeated slashes.' >&2; return 1 ;; esac
  [[ "$folder" != *$'\n'* && "$folder" != *$'\r'* && ! -e "$folder" && ! -L "$folder" ]] || {
    echo 'Choose a fresh role folder; existing paths will not be overwritten.' >&2; return 1;
  }
  ancestor=$(dirname "$folder")
  while [[ "$ancestor" != / ]]; do
    [[ ! -L "$ancestor" ]] || { echo 'Role folder parents must not be symlinks.' >&2; return 1; }
    ancestor=$(dirname "$ancestor")
  done
  printf '\nRelease: %s\nRole: %s / %s\nFolder: %s\nType yes to install and save these settings: ' "$tag" "$name" "$role" "$folder"
  IFS= read -r answer
  [[ "$answer" == yes ]] || { echo 'Cancelled.' >&2; return 1; }
  role_folder=$folder
  guided_role=$role
  guided_name=$name
}

shell_quote() {
  # POSIX single-quoted literals work in Bash and Zsh, including apostrophes.
  printf "'%s'" "${1//\'/\'\\\'\'}"
}

write_setting() {
  printf '%s=' "$1"
  shell_quote "$2"
  printf '\n'
}

save_guided_settings() {
  mkdir -p -- "$(dirname "$role_folder")"
  mkdir -m 0700 -- "$role_folder"
  mkdir -m 0700 -- "$role_folder/work" "$role_folder/trust" "$role_folder/keys"
  # Quote values as portable literals. Never evaluate user input as shell code.
  (
    set -o noclobber
    {
      printf '# Relay local settings for Bash or Zsh. Do not substitute an unverified release.\n'
      write_setting RELAY_COMMIT "$commit"
      write_setting RELAY_RELEASE "$tag"
      write_setting RELAY "$destination/relay"
      write_setting ROLE_ROOT "$role_folder"
      write_setting ROLE_WORK "$role_folder/work"
      write_setting ROLE_TRUST "$role_folder/trust"
      write_setting ROLE_KEYS "$role_folder/keys"
      write_setting ROLE_NAME "${guided_role:-}"
      write_setting CEREMONY_NAME "${guided_name:-}"
    } > "$role_folder/relay-env.sh"
  )
  # A self-contained entry point avoids asking operators to source settings or
  # assemble flags. Quoted literals cannot turn user input into shell commands.
  (
    set -o noclobber
    {
      printf '#!/usr/bin/env bash\nset -euo pipefail\n'
      write_setting relay_launcher "$destination/relay"
      write_setting ceremony_name "${guided_name:-}"
      write_setting ceremony_role "${guided_role:-}"
      write_setting ceremony_release "$tag"
      write_setting ceremony_work "$role_folder/work"
      write_setting ceremony_trust "$role_folder/trust"
      write_setting ceremony_keys "$role_folder/keys"
      # Expand these variables in the generated script, not in the installer.
      # shellcheck disable=SC2016
      printf '%s\n' 'if [[ "$ceremony_role" == coordinator ]]; then' \
        '  exec "$relay_launcher" coordinator prepare --name "$ceremony_name" --release "$ceremony_release" --work "$ceremony_work" --trust "$ceremony_trust" --keys "$ceremony_keys"' \
        'fi' \
        'exec "$relay_launcher" ceremony prepare --name "$ceremony_name" --role "$ceremony_role" --release "$ceremony_release" --work "$ceremony_work" --trust "$ceremony_trust" --keys "$ceremony_keys"'
    } > "$role_folder/start.sh"
  )
  chmod 0700 "$role_folder/start.sh"
  printf '\nSetup saved. Start or resume your role with:\n  '
  shell_quote "$role_folder/start.sh"
  printf '\nNo ceremony profile, credentials, or keys have been created yet.\n'
}

install_verified_launcher() {
  local target=$1 candidate=$2 digest=$3 existing
  mkdir -p "$(dirname "$target")" || return 1
  if [[ -e "$target" || -L "$target" ]]; then
    [[ -d "$target" && ! -L "$target" && -f "$target/relay" && ! -L "$target/relay" ]] || {
      echo 'Existing launcher path is not a regular installation; not overwriting.' >&2; return 1;
    }
    existing=$(shasum -a 256 "$target/relay") || return 1
    [[ "${existing%% *}" == "$digest" ]] || { echo 'Existing launcher differs from verified release; not overwriting.' >&2; return 1; }
    printf 'Existing launcher matches the verified release.\n'
  else
    mkdir "$target" || return 1
    install -m 0700 "$candidate" "$target/relay" || return 1
  fi
}

main() {
local tag commit guided=false role_folder='' selection
if [[ $# -eq 0 || ( $# -eq 1 && "$1" == --guided ) ]]; then
  [[ -t 0 ]] || { echo 'Guided setup needs an interactive terminal.' >&2; return 1; }
  guided=true
  printf 'Paste the exact Relay release URL or tag supplied through your agreed channel: '
  IFS= read -r selection
  parse_release "$selection"
  prepare_guided_settings
elif [[ $# -eq 1 ]]; then
  parse_release "$1"
else
  echo 'Usage: ./scripts/install-launcher.sh [--guided | role-images-COMMIT]' >&2
  return 1
fi
for tool in gh docker shasum; do command -v "$tool" >/dev/null; done
case "$(uname -s)" in Darwin) os=darwin;; Linux) os=linux;; *) exit 1;; esac
case "$(uname -m)" in arm64|aarch64) arch=arm64;; x86_64) arch=amd64;; *) exit 1;; esac
# A Terminal running under Rosetta still needs the Apple Silicon launcher.
if [[ "$os" == darwin ]] && [[ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" == 1 ]]; then arch=arm64; fi
printf 'Your computer: %s / %s\nChecking Docker and verifying release files…\n' "$os" "$arch"
docker info >/dev/null
asset="relay-$os-$arch"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
gh release download "$tag" --repo zksecurity/relay --pattern "$asset" --pattern launcher-checksums.sha256 --dir "$scratch"
for file in "$asset" launcher-checksums.sha256; do
  gh attestation verify "$scratch/$file" --repo zksecurity/relay \
    --signer-workflow zksecurity/relay/.github/workflows/publish-role-images.yml \
    --source-ref refs/heads/main --source-digest "$commit" --deny-self-hosted-runners
done
expected=$(awk -v asset="$asset" '$2 == asset {print $1}' "$scratch/launcher-checksums.sha256")
[[ "$expected" =~ ^[0-9a-f]{64}$ ]]
actual=$(shasum -a 256 "$scratch/$asset")
[[ "${actual%% *}" == "$expected" ]]
destination="$HOME/.local/share/relay/releases/$commit"
install_verified_launcher "$destination" "$scratch/$asset" "$expected"
"$destination/relay" --help >/dev/null
printf '\nInstalled: %s/relay\nUse this exact path for ceremony setup and open.\n' "$destination"
if "$guided"; then save_guided_settings; fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
