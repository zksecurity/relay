#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

installed_package() {
  [[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)" == 'install ok installed' ]]
}

linux_platform() {
  [[ "$(uname -s)" == Linux ]] || { fail 'Use macos.sh on a Mac.'; return 1; }
  # Root-owned OS identification; derivatives are deliberately not inferred.
  # shellcheck disable=SC1091
  source /etc/os-release
  case "$ID:$VERSION_ID" in
    ubuntu:22.04) DISTRO=ubuntu; CODENAME=jammy ;;
    ubuntu:24.04) DISTRO=ubuntu; CODENAME=noble ;;
    debian:12) DISTRO=debian; CODENAME=bookworm ;;
    debian:13) DISTRO=debian; CODENAME=trixie ;;
    *) fail 'Automated setup supports Ubuntu 22.04/24.04 and Debian 12/13 only. See docs/setup-host.md for manual instructions.'; return 1 ;;
  esac
  ARCH=$(dpkg --print-architecture)
  case "$ARCH" in amd64|arm64) ;; *) fail "Unsupported architecture: $ARCH"; return 1 ;; esac
  printf 'System: %s %s (%s)\n' "$ID" "$VERSION_ID" "$ARCH"
}

install_prerequisites() {
  local packages=()
  have curl || packages+=(curl)
  installed_package ca-certificates || packages+=(ca-certificates)
  have shasum || packages+=(libdigest-sha-perl)
  if [[ ${#packages[@]} -gt 0 ]]; then
    confirm "Install these distribution packages using sudo apt-get: ${packages[*]}?" || return 1
    sudo apt-get update
    sudo apt-get install --no-remove "${packages[@]}"
  fi
}

# Preserve any pre-existing repository/key rather than silently replace trust.
add_repository() {
  local name=$1 key_url=$2 source_line=$3 key_suffix=$4
  local key="/etc/apt/keyrings/relay-$name.$key_suffix"
  local list="/etc/apt/sources.list.d/relay-$name.list"
  [[ ! -e "$key" && ! -L "$key" && ! -e "$list" && ! -L "$list" ]] || {
    fail "Repository files already exist for $name; review them manually before retrying."; return 1;
  }
  confirm "Add the official $name APT repository and its signing key from $key_url? This changes which package publisher your system trusts." || return 1
  local staging
  staging=$(mktemp -d)
  # Retain public downloaded material for inspection; never remove broad paths.
  printf 'Public repository files staged at: %s\n' "$staging"
  curl --proto '=https' --tlsv1.2 --fail --show-error --location "$key_url" --output "$staging/key"
  [[ -s "$staging/key" ]] || { fail 'Empty signing key download.'; return 1; }
  printf '%s\n' "$source_line" > "$staging/source.list"
  sudo install -d -m 0755 /etc/apt/keyrings
  sudo install -m 0644 "$staging/key" "$key"
  sudo install -m 0644 "$staging/source.list" "$list"
}

install_docker() {
  local package
  have docker && return 0
  [[ -d /run/systemd/system ]] || { fail 'Docker installation requires a systemd host. Containers/WSL need a separately reviewed setup.'; return 1; }
  for package in docker-ce docker-ce-cli docker.io docker-desktop docker-doc docker-compose docker-compose-v2 podman-docker containerd containerd.io runc; do
    if installed_package "$package"; then
      fail "Existing package $package needs manual review. Nothing will be removed or replaced."
      return 1
    fi
  done
  if grep -rsq 'download.docker.com' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
    fail 'An existing Docker APT source needs manual review; not adding another.'; return 1
  fi
  add_repository docker "https://download.docker.com/linux/$DISTRO/gpg" \
    "deb [arch=$ARCH signed-by=/etc/apt/keyrings/relay-docker.asc] https://download.docker.com/linux/$DISTRO $CODENAME stable" asc
  confirm 'Install Docker Engine, CLI, containerd, Buildx and Compose? Installation may start Docker now and at boot and change host networking/firewall rules.' || return 1
  sudo apt-get update
  sudo apt-get install --no-remove docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_gh() {
  have gh && return 0
  if grep -rsq 'cli.github.com/packages' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
    fail 'An existing GitHub CLI APT source needs manual review; not adding another.'; return 1
  fi
  add_repository github-cli https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    "deb [arch=$ARCH signed-by=/etc/apt/keyrings/relay-github-cli.gpg] https://cli.github.com/packages stable main" gpg
  confirm 'Install GitHub CLI using sudo apt-get?' || return 1
  sudo apt-get update
  sudo apt-get install --no-remove gh
}

offer_docker_access() {
  local endpoint username
  endpoint=$(local_docker_endpoint) || return 1
  # Never change access to rootless/custom daemons or a remote context.
  [[ "$endpoint" == unix:///var/run/docker.sock ]] || return 0
  if ! systemctl is-active --quiet docker; then
    confirm 'Start the existing system Docker service? This may activate its networking/firewall rules.' || return 1
    sudo systemctl start docker
  fi
  if ! docker info >/dev/null 2>&1; then
    username=$(id -un)
    getent group docker >/dev/null || { fail 'No docker group exists; ask the administrator to review daemon access.'; return 1; }
    if id -nG | tr ' ' '\n' | grep -qx docker; then
      fail 'Docker is still inaccessible despite group membership; review the daemon manually.'; return 1
    fi
    confirm "Add $username to the docker group? THIS GRANTS ROOT-EQUIVALENT ACCESS TO THE MACHINE. Do this only on a machine you administer." || return 1
    sudo usermod -aG docker "$username"
    fail 'Group membership changed. Log out fully and log back in, then rerun this script; do not run Relay with sudo.'
    return 1
  fi
}

check_linux_swap() {
  local available used reserve
  available=$(awk '$1 == "MemAvailable:" {print $2}' /proc/meminfo)
  used=$(awk 'NR>1 {sum += $4} END {printf "%.0f", sum}' /proc/swaps)
  printf 'Available RAM: %s KiB; swap currently used: %s KiB\n' "$available" "$used"
  printf 'Ask the coordinator for the circuit RAM requirement; this script cannot certify capacity.\n'
  [[ "$SETUP_PARTICIPANT" == true ]] || return 0
  if [[ $(awk 'END {print NR}' /proc/swaps) -gt 1 ]]; then
    [[ "$SETUP_INSTALL" == true ]] || { fail 'Participants must disable host swap. Rerun with --install --participant for an explicit prompt.'; return 1; }
    [[ "$available" =~ ^[0-9]+$ && "$used" =~ ^[0-9]+$ ]] || { fail 'Unable to assess RAM/swap.'; return 1; }
    reserve=1048576
    (( available > used + reserve )) || { fail 'Too little available RAM to safely offer swapoff. Close workloads or ask an administrator.'; return 1; }
    confirm 'Disable ALL host swap for this boot using sudo swapoff --all? This affects every workload and can cause out-of-memory failures. Close other workloads first. No swap files, fstab entries or boot settings will be deleted/edited. Swap may return after reboot or via a service; recheck before contributing.' || return 1
    sudo swapoff --all
    [[ $(awk 'END {print NR}' /proc/swaps) -eq 1 ]] || { fail 'Swap remains enabled; stop and ask an administrator.'; return 1; }
    printf 'Swap disabled for now. After the ceremony, have your administrator restore the previous configuration (a reboot may do so).\n'
  fi
}

main() {
  parse_setup_args "$@"
  linux_platform
  [[ $(id -u) -ne 0 ]] || { fail 'Run as your normal user, not sudo/root. Individual approved steps use sudo.'; return 1; }
  if "$SETUP_INSTALL"; then
    have sudo || { fail 'sudo is missing; ask an administrator to install it.'; return 1; }
    install_prerequisites
    install_docker
    install_gh
    offer_docker_access
  fi
  check_linux_swap
  finish_setup
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
