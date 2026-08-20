#!/usr/bin/env bash
set -euo pipefail
umask 077

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

usage() {
  die "usage: $0 --mode production|rehearsal --relay-release-dir DIR --relay-repository OWNER/REPO --relay-tag TAG --relay-sha256 HEX --mpc-binary FILE --mpc-repository OWNER/REPO --mpc-tag TAG --mpc-sha256 HEX [--include-rehearsal] --out-dir DIR"
}

MODE=
RELAY_RELEASE_DIR=
RELAY_REPOSITORY=
RELAY_TAG=
RELAY_SHA256=
MPC_BINARY=
MPC_REPOSITORY=
MPC_TAG=
MPC_SHA256=
INCLUDE_REHEARSAL=no
OUT_DIR=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) [[ $# -ge 2 ]] || usage; MODE=$2; shift 2 ;;
    --relay-release-dir) [[ $# -ge 2 ]] || usage; RELAY_RELEASE_DIR=$2; shift 2 ;;
    --relay-repository) [[ $# -ge 2 ]] || usage; RELAY_REPOSITORY=$2; shift 2 ;;
    --relay-tag) [[ $# -ge 2 ]] || usage; RELAY_TAG=$2; shift 2 ;;
    --relay-sha256) [[ $# -ge 2 ]] || usage; RELAY_SHA256=$2; shift 2 ;;
    --mpc-binary) [[ $# -ge 2 ]] || usage; MPC_BINARY=$2; shift 2 ;;
    --mpc-repository) [[ $# -ge 2 ]] || usage; MPC_REPOSITORY=$2; shift 2 ;;
    --mpc-tag) [[ $# -ge 2 ]] || usage; MPC_TAG=$2; shift 2 ;;
    --mpc-sha256) [[ $# -ge 2 ]] || usage; MPC_SHA256=$2; shift 2 ;;
    --include-rehearsal) INCLUDE_REHEARSAL=yes; shift ;;
    --out-dir) [[ $# -ge 2 ]] || usage; OUT_DIR=$2; shift 2 ;;
    *) usage ;;
  esac
done

[[ "$MODE" == production || "$MODE" == rehearsal ]] || usage
[[ -n "$RELAY_RELEASE_DIR" && -n "$RELAY_REPOSITORY" && -n "$RELAY_TAG" && -n "$RELAY_SHA256" &&
  -n "$MPC_BINARY" && -n "$MPC_REPOSITORY" && -n "$MPC_TAG" && -n "$MPC_SHA256" && -n "$OUT_DIR" ]] || usage
[[ "$MODE" == rehearsal || "$INCLUDE_REHEARSAL" == no ]] || die "production kits cannot include rehearsal scripts"
[[ "$INCLUDE_REHEARSAL" == no || "$MODE" == rehearsal ]] || die "--include-rehearsal requires rehearsal mode"

repository_pattern='^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$'
tag_pattern='^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
[[ "$RELAY_REPOSITORY" =~ $repository_pattern && "$MPC_REPOSITORY" =~ $repository_pattern ]] || die "repositories must be OWNER/REPOSITORY"
[[ "$RELAY_TAG" =~ $tag_pattern && "$MPC_TAG" =~ $tag_pattern ]] || die "release tag is malformed"
[[ "$RELAY_SHA256" =~ ^[0-9a-f]{64}$ && "$MPC_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "binary SHA-256 is malformed"
[[ -d "$RELAY_RELEASE_DIR" && ! -L "$RELAY_RELEASE_DIR" ]] || die "Relay release directory is unsafe"
[[ -f "$RELAY_RELEASE_DIR/relay" && ! -L "$RELAY_RELEASE_DIR/relay" ]] || die "Relay release binary is missing"
[[ -f "$RELAY_RELEASE_DIR/setup-ceremony-kit.sh" && ! -L "$RELAY_RELEASE_DIR/setup-ceremony-kit.sh" ]] || die "Relay release setup script is missing"
[[ -f "$RELAY_RELEASE_DIR/build-mode.txt" && ! -L "$RELAY_RELEASE_DIR/build-mode.txt" ]] || die "Relay release mode record is missing"
[[ "$(<"$RELAY_RELEASE_DIR/build-mode.txt")" == "$MODE" ]] || die "Relay release mode does not match kit mode"
if [[ "$MODE" == production ]]; then
  for name in build-package-manifest.sig build-package-manifest-public-key.hex signed-tag-status.txt signed-tag.txt; do
    [[ -f "$RELAY_RELEASE_DIR/$name" && ! -L "$RELAY_RELEASE_DIR/$name" ]] ||
      die "production Relay release record is missing or unsafe: $name"
  done
  [[ "$(<"$RELAY_RELEASE_DIR/signed-tag-status.txt")" == verified ]] || die "production Relay tag was not verified"
  [[ "$(<"$RELAY_RELEASE_DIR/signed-tag.txt")" == "$RELAY_TAG" ]] || die "production Relay tag does not match the kit"
fi
[[ -f "$MPC_BINARY" && ! -L "$MPC_BINARY" ]] || die "mpc-ceremony binary is unsafe"
if [[ "$INCLUDE_REHEARSAL" == yes ]]; then
  [[ -f "$RELAY_RELEASE_DIR/three-machine-rehearsal.tar.gz" && ! -L "$RELAY_RELEASE_DIR/three-machine-rehearsal.tar.gz" ]] ||
    die "Relay release rehearsal archive is missing"
fi

for command_name in basename dirname install mktemp realpath sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command is missing: $command_name"
done

printf '%s  %s\n' "$RELAY_SHA256" "$RELAY_RELEASE_DIR/relay" | sha256sum --check
printf '%s  %s\n' "$MPC_SHA256" "$MPC_BINARY" | sha256sum --check

out_parent_input=$(dirname -- "$OUT_DIR")
[[ -d "$out_parent_input" && ! -L "$out_parent_input" ]] || die "output parent must be an existing non-symlink directory"
out_parent=$(realpath -e -- "$out_parent_input")
OUT_DIR="$out_parent/$(basename -- "$OUT_DIR")"
[[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]] || die "output directory already exists: $OUT_DIR"
staging=$(mktemp -d "$out_parent/.ceremony-kit.partial.XXXXXXXX")
cleanup() {
  if [[ -n "${staging:-}" && "$staging" == "$out_parent"/.ceremony-kit.partial.* ]]; then
    rm -rf -- "$staging"
  fi
}
trap cleanup EXIT

install -m 0755 "$RELAY_RELEASE_DIR/setup-ceremony-kit.sh" "$staging/setup"
install -m 0755 "$RELAY_RELEASE_DIR/relay" "$staging/relay"
install -m 0755 "$MPC_BINARY" "$staging/mpc-ceremony"

REHEARSAL_SHA=none
if [[ "$INCLUDE_REHEARSAL" == yes ]]; then
  install -m 0644 "$RELAY_RELEASE_DIR/three-machine-rehearsal.tar.gz" "$staging/three-machine-rehearsal.tar.gz"
  REHEARSAL_SHA=$(sha256sum "$staging/three-machine-rehearsal.tar.gz")
  REHEARSAL_SHA=${REHEARSAL_SHA%% *}
fi

printf '%s\n' \
  'KIT_SCHEMA=ceremony-kit-v1' \
  "KIT_MODE=$MODE" \
  "RELAY_REPOSITORY=$RELAY_REPOSITORY" \
  "RELAY_TAG=$RELAY_TAG" \
  "RELAY_SHA256=$RELAY_SHA256" \
  "MPC_RELEASE_REPOSITORY=$MPC_REPOSITORY" \
  "MPC_TAG=$MPC_TAG" \
  "MPC_SHA256=$MPC_SHA256" \
  "REHEARSAL_ARCHIVE_SHA256=$REHEARSAL_SHA" >"$staging/release.env"

printf '{\n  "schema": "ceremony-kit-v1",\n  "mode": "%s",\n  "relay": {\n    "repository": "%s",\n    "tag": "%s",\n    "sha256": "%s"\n  },\n  "mpc_ceremony": {\n    "repository": "%s",\n    "tag": "%s",\n    "sha256": "%s"\n  },\n  "rehearsal_archive_sha256": "%s"\n}\n' \
  "$MODE" "$RELAY_REPOSITORY" "$RELAY_TAG" "$RELAY_SHA256" \
  "$MPC_REPOSITORY" "$MPC_TAG" "$MPC_SHA256" "$REHEARSAL_SHA" >"$staging/release.json"

(
  cd "$staging"
  checksum_files=(mpc-ceremony relay release.env release.json setup)
  [[ "$INCLUDE_REHEARSAL" == yes ]] && checksum_files+=(three-machine-rehearsal.tar.gz)
  LC_ALL=C sha256sum "${checksum_files[@]}" >checksums.sha256
)
chmod 0444 "$staging"/*
chmod 0555 "$staging/setup" "$staging/relay" "$staging/mpc-ceremony"
"$staging/setup" verify >/dev/null
mv -- "$staging" "$OUT_DIR"
staging=
printf 'Created verified %s ceremony kit at %s\n' "$MODE" "$OUT_DIR"
