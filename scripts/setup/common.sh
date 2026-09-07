#!/usr/bin/env bash
# Shared helpers for the interactive host prerequisite scripts.

fail() { printf 'STOP: %s\n' "$*" >&2; return 1; }
have() { command -v "$1" >/dev/null 2>&1; }

confirm() {
  local answer
  [[ -t 0 ]] || { fail 'Changes require an interactive terminal; no changes authorized.'; return 1; }
  printf '%s\nType yes to continue (anything else stops): ' "$*"
  IFS= read -r answer || return 1
  [[ "$answer" == yes ]]
}

parse_setup_args() {
  local arg check_requested=false
  SETUP_INSTALL=false
  SETUP_PARTICIPANT=false
  for arg in "$@"; do
    case "$arg" in
      --install) SETUP_INSTALL=true ;;
      --participant) SETUP_PARTICIPANT=true ;;
      --check) check_requested=true ;;
      --help) printf 'Usage: %s [--check | --install] [--participant]\nDefault: read-only checks. --install prompts before changes.\n' "$0"; exit 0 ;;
      *) fail "Unknown option: $arg"; return 1 ;;
    esac
  done
  if "$check_requested" && "$SETUP_INSTALL"; then
    fail '--check and --install cannot be combined.'; return 1
  fi
}

check_tools() {
  local tool missing=false
  for tool in bash shasum gh docker; do
    if have "$tool"; then printf 'Found: %s\n' "$tool"; else printf 'Missing: %s\n' "$tool"; missing=true; fi
  done
  "$missing" && return 1
  if ! gh attestation verify --help 2>/dev/null | grep -- '--source-digest' >/dev/null; then
    fail 'GitHub CLI is too old for release provenance verification. Update gh and rerun.'
    return 1
  fi
  if ! gh auth status >/dev/null 2>&1; then
    fail 'Sign in yourself with gh auth login, then rerun. Do not share tokens.'
    return 1
  fi
}

# Do not change the user's context or silently check a different daemon.
local_docker_endpoint() {
  local context endpoint
  if [[ -n "${DOCKER_CONTEXT:-}" ]]; then
    context=$DOCKER_CONTEXT
    endpoint=$(docker context inspect "$context" --format '{{.Endpoints.docker.Host}}') || return 1
  elif [[ -n "${DOCKER_HOST:-}" ]]; then
    endpoint=$DOCKER_HOST
  else
    context=$(docker context show) || return 1
    endpoint=$(docker context inspect "$context" --format '{{.Endpoints.docker.Host}}') || return 1
  fi
  case "$endpoint" in
    unix:///*) printf '%s\n' "$endpoint" ;;
    *) fail 'The selected Docker endpoint is not a local Unix socket. Review your Docker context; this script will not change it.'; return 1 ;;
  esac
}

check_docker() {
  local endpoint server
  endpoint=$(local_docker_endpoint) || return 1
  server=$(docker info --format '{{.OperatingSystem}}') || { fail 'Docker is not reachable as your normal user. Start it or review permissions, then rerun.'; return 1; }
  printf 'Docker endpoint: %s\nDocker server: %s\n' "$endpoint" "$server"
  if [[ "$(uname -s)" == Linux && "$SETUP_PARTICIPANT" == true && "$server" == *"Docker Desktop"* ]]; then
    fail 'Linux participants require native Docker Engine, not Docker Desktop. Existing installations were not removed.'
    return 1
  fi
}

finish_setup() {
  check_tools || return 1
  check_docker || return 1
  printf '\nPrerequisites checked. Continue with docs/install.md to install the verified Relay launcher.\n'
  printf 'This is not ceremony approval or proof of erasure. Relay repeats its own security checks.\n'
}
