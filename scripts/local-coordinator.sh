#!/usr/bin/env bash
# Developer-only build/run helper. Never changes the approved installation.
set -euo pipefail
umask 077
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
usage() {
  printf 'Usage: ./scripts/local-coordinator.sh prepare|run|identity|clear-mocks /absolute/test-folder\n'
  printf 'prepare builds only; run opens the rehearsal-only interactive helper.\n'
}
if [[ ${1:-} == --help ]]; then usage; exit 0; fi
[[ $# -eq 2 ]] || { usage >&2; exit 1; }
action=$1
test_root=$2
[[ "$test_root" == /* && "$test_root" != / && "$test_root" != "$HOME" ]] || {
  printf 'Choose a dedicated absolute test-folder path, not your home or filesystem root.\n' >&2; exit 1;
}
case "$test_root/" in *'/../'*|*'/./'*|*'//'*) printf 'Use a clean path.\n' >&2; exit 1 ;; esac
case "$action" in
  prepare)
    [[ ! -e "$test_root" && ! -L "$test_root" ]] || {
      printf 'Test folder already exists. Use run to resume, or choose a fresh folder; nothing is overwritten.\n' >&2; exit 1;
    }
    for tool in go docker curl jq shasum; do command -v "$tool" >/dev/null || { printf 'Missing developer tool: %s\n' "$tool" >&2; exit 1; }; done
    case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; x86_64) arch=amd64 ;; *) exit 1 ;; esac
    if [[ "$(uname -s)" == Darwin && "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" == 1 ]]; then arch=arm64; fi
    config="$REPO_DIR/release/role-images.json"
    url=$(jq -er --arg key "linux_$arch" '.mpc[$key].url' "$config")
    expected=$(jq -er --arg key "linux_$arch" '.mpc[$key].sha256' "$config")
    base=$(jq -er '.aws_cli_image' "$config")
    [[ "$url" == https://github.com/zksecurity/proof-tool/releases/download/* && "$expected" =~ ^[0-9a-f]{64}$ && "$base" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] || {
      printf 'Invalid pinned build inputs.\n' >&2; exit 1;
    }
    docker info >/dev/null
    printf 'LOCAL TEST ONLY. This downloads pinned build inputs, compiles local code, and builds two Docker images.\n'
    printf 'It uses disk space but does not start the coordinator helper or initialize a ceremony.\n'
    printf 'Test folder: %s\nType yes to prepare: ' "$test_root"
    [[ -t 0 ]] || exit 1
    IFS= read -r answer
    [[ "$answer" == yes ]] || exit 1
    mkdir -p -- "$(dirname "$test_root")"
    mkdir -m 0700 -- "$test_root"
    test_root=$(cd -- "$test_root" && pwd -P)
    mkdir -m 0700 "$test_root/build"
    cd "$REPO_DIR"
    GOARCH="$arch" CGO_ENABLED=0 go build -tags relaylocal -trimpath -buildvcs=true -o "$test_root/relay-local" ./cmd/relay
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -tags relaylocal -trimpath -buildvcs=true \
      -o "$test_root/build/relay" ./cmd/relay
    curl --proto '=https' --tlsv1.2 --fail --location --show-error "$url" --output "$test_root/build/mpc-ceremony"
    actual=$(shasum -a 256 "$test_root/build/mpc-ceremony")
    [[ "${actual%% *}" == "$expected" ]] || { printf 'proof-tool checksum mismatch; stopped.\n' >&2; exit 1; }
    cp "$REPO_DIR/docker/roles/Dockerfile" "$test_root/build/Dockerfile"
    cp "$REPO_DIR/release/ceremony-policy.json" "$test_root/ceremony-policy.json"
    docker build --platform "linux/$arch" --target online --build-arg "AWS_CLI_IMAGE=$base" \
      --iidfile "$test_root/online-image.txt" "$test_root/build"
    docker build --platform "linux/$arch" --target offline --build-arg "AWS_CLI_IMAGE=$base" \
      --iidfile "$test_root/offline-image.txt" "$test_root/build"
    printf '\nLocal build ready. Approved Relay installation was not changed.\nRun it yourself with:\n'
    printf '  ./scripts/local-coordinator.sh run %q\n' "$test_root"
    ;;
  run|identity|clear-mocks)
    [[ -d "$test_root" && ! -L "$test_root" && -x "$test_root/relay-local" && ! -L "$test_root/relay-local" ]] || {
      printf 'Prepare this dedicated test folder first.\n' >&2; exit 1;
    }
    [[ -t 0 ]] || { printf 'Run from an interactive terminal.\n' >&2; exit 1; }
    test_root=$(cd -- "$test_root" && pwd -P)
    launch=("$test_root/relay-local" coordinator prepare-local --root "$test_root")
    if [[ "$action" == identity ]]; then launch+=(--new-identity); fi
    if [[ "$action" == clear-mocks ]]; then launch+=(--clear-mocks); fi
    exec "${launch[@]}"
    ;;
  *) usage >&2; exit 1 ;;
esac
