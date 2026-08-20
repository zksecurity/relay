#!/usr/bin/env -S -u SHELLOPTS -u BASHOPTS BASH_ENV=/dev/null ENV=/dev/null /bin/bash
# Verify a signed production package, rebuild the same commit without access to
# its build-signing key, and compare every build-derived artifact.
set -euo pipefail

unset CDPATH GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY
unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG_COUNT
export BASH_ENV=/dev/null
export ENV=/dev/null
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1

usage() {
  echo "usage: $0 --expected-commit COMMIT --expected-tag TAG --tag-signer-fingerprint HEX --trusted-build-public-key-file FILE --rebuild-dir DIR RELEASE_DIR" >&2
  exit 2
}

EXPECTED_COMMIT=
EXPECTED_TAG=
TAG_SIGNER_FINGERPRINT=
TRUSTED_BUILD_PUBLIC_KEY_FILE=
REBUILD_DIR=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --expected-commit)
      [[ $# -ge 2 ]] || usage
      EXPECTED_COMMIT=$2
      shift 2
      ;;
    --expected-tag)
      [[ $# -ge 2 ]] || usage
      EXPECTED_TAG=$2
      shift 2
      ;;
    --tag-signer-fingerprint)
      [[ $# -ge 2 ]] || usage
      TAG_SIGNER_FINGERPRINT=${2^^}
      shift 2
      ;;
    --trusted-build-public-key-file)
      [[ $# -ge 2 ]] || usage
      TRUSTED_BUILD_PUBLIC_KEY_FILE=$2
      shift 2
      ;;
    --rebuild-dir)
      [[ $# -ge 2 ]] || usage
      REBUILD_DIR=$2
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*)
      usage
      ;;
    *)
      break
      ;;
  esac
done
if [[ $# -ne 1 || ! "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ||
  -z "$EXPECTED_TAG" || ! "$TAG_SIGNER_FINGERPRINT" =~ ^([0-9A-F]{40}|[0-9A-F]{64})$ ||
  -z "$TRUSTED_BUILD_PUBLIC_KEY_FILE" || -z "$REBUILD_DIR" ]]; then
  usage
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RELEASE_DIR=$1

"$SCRIPT_DIR/verify-relay-release.sh" \
  --mode production \
  --expected-commit "$EXPECTED_COMMIT" \
  --expected-tag "$EXPECTED_TAG" \
  --tag-signer-fingerprint "$TAG_SIGNER_FINGERPRINT" \
  --trusted-build-public-key-file "$TRUSTED_BUILD_PUBLIC_KEY_FILE" \
  "$RELEASE_DIR"

REBUILD_PARENT_INPUT=$(dirname -- "$REBUILD_DIR")
if [[ ! -d "$REBUILD_PARENT_INPUT" || -L "$REBUILD_PARENT_INPUT" ]]; then
  echo "FAIL: reproduction output parent must be an existing non-symlink directory" >&2
  exit 1
fi
REBUILD_PARENT=$(realpath -e -- "$REBUILD_PARENT_INPUT")
REBUILD_DIR="$REBUILD_PARENT/$(basename -- "$REBUILD_DIR")"
if [[ -e "$REBUILD_DIR" || -L "$REBUILD_DIR" ]]; then
  echo "FAIL: reproduction output already exists: $REBUILD_DIR" >&2
  exit 1
fi

"$SCRIPT_DIR/build-relay-release.sh" \
  --mode rehearsal \
  --out-dir "$REBUILD_DIR"

"$SCRIPT_DIR/verify-relay-release.sh" \
  --mode rehearsal \
  --expected-commit "$EXPECTED_COMMIT" \
  --expected-tag none \
  --tag-signer-fingerprint none \
  --trusted-build-public-key-file none \
  "$REBUILD_DIR"

RELEASE_DIR=$(realpath -e -- "$RELEASE_DIR")
build_outputs=(
  build-flags.txt
  checksums.sha256
  go-build-info.txt
  relay
  sbom.cdx.json
  setup-ceremony-kit.sh
  source-checksums.sha256
  source-commit.txt
  source-date-epoch.txt
  test-status.txt
  three-machine-rehearsal.tar.gz
  toolchain-checksums.sha256
)
for name in "${build_outputs[@]}"; do
  if ! cmp "$RELEASE_DIR/$name" "$REBUILD_DIR/$name"; then
    echo "FAIL: independently rebuilt artifact differs: $name" >&2
    exit 1
  fi
done

printf 'Relay binary is reproducible; independent package retained at %s\n' "$REBUILD_DIR"
