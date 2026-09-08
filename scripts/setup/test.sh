#!/usr/bin/env bash
# Mocked safety tests: never install packages or alter the test host.
# Mocks are called indirectly by sourced helpers; subshell isolation is intentional.
# shellcheck disable=SC2030,SC2031,SC2317,SC2329
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=linux.sh
source "$SCRIPT_DIR/linux.sh"

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    printf 'Unexpected success: %s\n' "$*" >&2
    exit 1
  fi
}

parse_setup_args
[[ "$SETUP_INSTALL" == false && "$SETUP_PARTICIPANT" == false ]]
parse_setup_args --install --participant
[[ "$SETUP_INSTALL" == true && "$SETUP_PARTICIPANT" == true ]]
expect_failure parse_setup_args --check --install
expect_failure parse_setup_args --unknown
expect_failure confirm 'Must not accept piped consent' </dev/null
printf 'PASS: argument defaults and interactive consent\n'

(
  unset DOCKER_CONTEXT
  export DOCKER_HOST=ssh://remote.example
  expect_failure local_docker_endpoint
  export DOCKER_HOST=tcp://127.0.0.1:2375
  expect_failure local_docker_endpoint
  export DOCKER_HOST=unix:///var/run/docker.sock
  [[ "$(local_docker_endpoint)" == "$DOCKER_HOST" ]]
  export DOCKER_CONTEXT=chosen
  docker() { printf 'unix:///chosen.sock\n'; }
  [[ "$(local_docker_endpoint)" == unix:///chosen.sock ]]
)
printf 'PASS: remote endpoint rejection and context precedence\n'

(
  SETUP_PARTICIPANT=true
  SETUP_INSTALL=false
  awk() {
    case "$1" in
      *MemAvailable*) printf '8388608\n' ;;
      *sum*) printf '0\n' ;;
      *) printf '2\n' ;;
    esac
  }
  # Exit the entire subshell if a guard accidentally reaches a mutation.
  sudo() { printf 'UNEXPECTED MUTATION\n' >&2; exit 99; }
  expect_failure check_linux_swap
  SETUP_INSTALL=true
  confirm() { return 1; }
  expect_failure check_linux_swap
  awk() { printf '2\n'; }
  confirm() { printf 'UNEXPECTED PROMPT\n' >&2; exit 99; }
  expect_failure check_linux_swap
  SETUP_PARTICIPANT=false
  check_linux_swap >/dev/null
)
printf 'PASS: swap read-only, declined consent, low RAM and nonparticipant guards\n'

(
  SETUP_PARTICIPANT=true
  local_docker_endpoint() { printf 'unix:///var/run/docker.sock\n'; }
  uname() { printf 'Linux\n'; }
  docker() { printf 'Docker Desktop\n'; }
  expect_failure check_docker
  docker() { printf 'Ubuntu 24.04\n'; }
  check_docker >/dev/null
)
printf 'PASS: Linux participant rejects Docker Desktop\n'

(
  # shellcheck source=macos.sh
  source "$SCRIPT_DIR/macos.sh"
  uname() { if [[ "$1" == -s ]]; then printf 'Darwin\n'; else printf 'arm64\n'; fi; }
  id() { printf '501\n'; }
  sw_vers() { printf 'test\n'; }
  have() { return 0; }
  finish_setup() { return 0; }
  sudo() { exit 99; }
  open() { exit 99; }
  main --check --participant >/dev/null
)
printf 'PASS: Mac check mode performs no installation or host changes\n'
