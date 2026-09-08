#!/usr/bin/env bash
# Run directly from Bash or Zsh; only source YOUR installer-created settings.
set -euo pipefail
if [[ ${1:-} == --help ]]; then
  printf 'Usage: ./scripts/role.sh [absolute-path-to-your-relay-env.sh]\n'
  exit 0
fi
[[ $# -le 1 && -t 0 ]] || { printf 'Run interactively, with at most one settings-file path.\n' >&2; exit 1; }
settings=${1:-}
if [[ -z "$settings" ]]; then
  shopt -s nullglob
  candidates=("$HOME"/ceremonies/*/*/relay-env.sh)
  if [[ ${#candidates[@]} -gt 0 ]]; then
    printf 'Your saved role folders:\n'
    for ((i=0; i<${#candidates[@]}; i++)); do printf '%d. %s\n' "$((i+1))" "${candidates[$i]}"; done
    printf 'Choose a number, or enter an absolute settings-file path: '
    IFS= read -r settings
    if [[ "$settings" =~ ^[1-9][0-9]{0,3}$ ]]; then
      index=$((10#$settings-1))
      [[ $index -lt ${#candidates[@]} ]] || { printf 'Unknown selection.\n' >&2; exit 1; }
      settings=${candidates[$index]}
    fi
  else
    printf 'Absolute path to your own installer-created relay-env.sh: '
    IFS= read -r settings
  fi
fi
[[ "$settings" == /* && -f "$settings" && ! -L "$settings" ]] || { printf 'Use your own regular settings file, not a symlink.\n' >&2; exit 1; }
printf 'Loading settings executes shell code. Never load a file supplied by another person.\nLoad %s? Type yes: ' "$settings"
IFS= read -r answer
[[ "$answer" == yes ]] || exit 1
# shellcheck disable=SC1090
source "$settings"
: "${RELAY:?Missing RELAY}" "${RELAY_RELEASE:?Missing RELAY_RELEASE}" "${ROLE_WORK:?Missing ROLE_WORK}" "${ROLE_TRUST:?Missing ROLE_TRUST}" "${ROLE_KEYS:?Missing ROLE_KEYS}"
roles=(coordinator participant witness mirror auditor release-signer upload-station)
role=${ROLE_NAME:-}
if [[ -z "$role" ]]; then
  printf 'Which role are you running?\n'
  for ((i=0; i<${#roles[@]}; i++)); do printf '%d. %s\n' "$((i+1))" "${roles[$i]}"; done
  while :; do
    printf 'Choose 1–7: '; IFS= read -r answer
    if [[ "$answer" =~ ^[1-7]$ ]]; then role=${roles[$((answer-1))]}; break; fi
    printf 'A listed role is required.\n'
  done
fi
name=${ROLE_LOCAL_NAME:-${CEREMONY_NAME:-}}
while [[ ! "$name" =~ ^[a-z0-9][a-z0-9_-]{0,63}$ ]]; do
  printf 'Local ceremony name (reuse the same name to resume): '; IFS= read -r name
done
if [[ "$role" == coordinator ]]; then
  exec "$RELAY" coordinator prepare --name "$name" --release "$RELAY_RELEASE" \
    --work "$ROLE_WORK" --trust "$ROLE_TRUST" --keys "$ROLE_KEYS"
fi
exec "$RELAY" ceremony prepare --name "$name" --role "$role" --release "$RELAY_RELEASE" \
  --work "$ROLE_WORK" --trust "$ROLE_TRUST" --keys "$ROLE_KEYS"
