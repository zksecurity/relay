#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

find_brew() {
  if have brew; then command -v brew
  elif [[ -x /opt/homebrew/bin/brew ]]; then printf '/opt/homebrew/bin/brew\n'
  elif [[ -x /usr/local/bin/brew ]]; then printf '/usr/local/bin/brew\n'
  else return 1
  fi
}

main() {
  parse_setup_args "$@"
  [[ "$(uname -s)" == Darwin ]] || { fail 'Use linux.sh on Ubuntu/Debian.'; return 1; }
  [[ $(id -u) -ne 0 ]] || { fail 'Run as your normal user, not sudo/root.'; return 1; }
  case "$(uname -m)" in arm64|x86_64) ;; *) fail 'Unsupported Mac architecture.'; return 1 ;; esac
  printf 'macOS %s (%s)\n' "$(sw_vers -productVersion)" "$(uname -m)"
  printf 'Mac host/VM swap is not assessed or modified. Docker cleanup cannot rule out host remnants.\n'
  if "$SETUP_INSTALL"; then
    local brew_bin
    if ! have gh || { [[ ! -d /Applications/Docker.app ]] && ! have docker; }; then
      brew_bin=$(find_brew) || {
        fail 'Install Homebrew from https://brew.sh using its official instructions, or install gh and Docker Desktop manually. Then rerun. This script does not execute a downloaded Homebrew bootstrap script.'
        return 1
      }
      export HOMEBREW_NO_AUTO_UPDATE=1
      if ! have gh; then
        confirm 'Install GitHub CLI using your existing Homebrew installation?' || return 1
        "$brew_bin" install gh
        PATH="$(dirname "$brew_bin"):$PATH"
        export PATH
      fi
      if [[ ! -d /Applications/Docker.app ]] && ! have docker; then
        confirm 'Install Docker Desktop using Homebrew Cask? Review Docker licensing and system requirements first: https://docs.docker.com/desktop/setup/install/mac-install/ . The installer may request administrator permission.' || return 1
        "$brew_bin" install --cask docker-desktop
      fi
    fi
    if ! have docker && [[ -x /Applications/Docker.app/Contents/Resources/bin/docker ]]; then
      export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
    fi
    if [[ -d /Applications/Docker.app ]] && ! docker info >/dev/null 2>&1; then
      confirm 'Open Docker Desktop? Complete its onboarding and review any requested permissions yourself.' || return 1
      open -a Docker
      fail 'Finish Docker Desktop onboarding, wait until it is running, and rerun. No settings were changed automatically.'
      return 1
    fi
  fi
  if ! have docker && [[ -x /Applications/Docker.app/Contents/Resources/bin/docker ]]; then
    export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
  fi
  if ! have shasum; then
    fail 'shasum is missing; ask your administrator to restore it or install Perl. Bash is already running this script.'
    return 1
  fi
  finish_setup
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
