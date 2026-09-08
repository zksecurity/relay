#!/usr/bin/env bash
# Run directly from Bash or Zsh. Source only your own installer-created settings.
set -euo pipefail
if [[ ${1:-} == --help ]]; then
  printf 'Usage: ./scripts/coordinator.sh [absolute-path-to-relay-env.sh]\n'
  exit 0
fi
if [[ $# -gt 1 || ! -t 0 ]]; then
  printf 'Run interactively with at most one settings-file path.\n' >&2
  exit 1
fi
settings=${1:-}
if [[ -z "$settings" ]]; then
  shopt -s nullglob
  candidates=("$HOME"/ceremonies/*/coordinator/relay-env.sh)
  suggested=''
  if [[ ${#candidates[@]} -eq 1 ]]; then
    suggested=${candidates[0]}
  elif [[ ${#candidates[@]} -gt 1 ]]; then
    printf 'Found multiple coordinator settings files; choose the one for this ceremony:\n'
    printf '  %s\n' "${candidates[@]}"
  fi
  if [[ -n "$suggested" ]]; then
    printf 'Path to your own installer-created relay-env.sh [%s]: ' "$suggested"
  else
    printf 'Path to your own installer-created relay-env.sh: '
  fi
  IFS= read -r settings
  settings=${settings:-$suggested}
fi
[[ "$settings" == /* && -f "$settings" && ! -L "$settings" ]] || {
  printf 'Use an absolute path to your own regular settings file, not a symlink.\n' >&2
  exit 1
}
printf 'Loading settings executes shell code. Only use the file your installer created, never one sent by someone else.\n'
printf 'Load %s? Type yes: ' "$settings"
IFS= read -r answer
[[ "$answer" == yes ]] || exit 1
# shellcheck disable=SC1090
source "$settings"
: "${RELAY:?Missing RELAY}" "${RELAY_RELEASE:?Missing RELAY_RELEASE}" "${ROLE_WORK:?Missing ROLE_WORK}" "${ROLE_TRUST:?Missing ROLE_TRUST}" "${ROLE_KEYS:?Missing ROLE_KEYS}"
if ! "$RELAY" --help 2>&1 | grep -F 'relay coordinator prepare ' >/dev/null; then
  printf 'This launcher does not support guided coordinator preparation. Install a matching approved release containing coordinator prepare; do not substitute a local binary.\n' >&2
  exit 1
fi
printf 'Local ceremony name (reuse the same name when resuming): '
IFS= read -r ceremony_name
exec "$RELAY" coordinator prepare --name "$ceremony_name" --release "$RELAY_RELEASE" \
  --work "$ROLE_WORK" --trust "$ROLE_TRUST" --keys "$ROLE_KEYS"
