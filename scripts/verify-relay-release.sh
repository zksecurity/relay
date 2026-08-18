#!/usr/bin/env -S -u SHELLOPTS -u BASHOPTS BASH_ENV=/dev/null ENV=/dev/null /bin/bash
# Verify one Relay release package against independently supplied source, tag,
# and build-signing trust inputs. The Relay binary is inspected, never run.
set -euo pipefail

unset CDPATH GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY
unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG_COUNT
export BASH_ENV=/dev/null
export ENV=/dev/null
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1

usage() {
  echo "usage: $0 --mode production|rehearsal --expected-commit COMMIT --expected-tag TAG|none --tag-signer-fingerprint HEX|none --trusted-build-public-key-file FILE|none RELEASE_DIR" >&2
  exit 2
}

MODE=
EXPECTED_COMMIT=
EXPECTED_TAG=
TAG_SIGNER_FINGERPRINT=
TRUSTED_BUILD_PUBLIC_KEY_FILE=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      [[ $# -ge 2 ]] || usage
      MODE=$2
      shift 2
      ;;
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
if [[ $# -ne 1 || ( "$MODE" != "production" && "$MODE" != "rehearsal" ) ||
  ! "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ || -z "$EXPECTED_TAG" ||
  -z "$TAG_SIGNER_FINGERPRINT" || -z "$TRUSTED_BUILD_PUBLIC_KEY_FILE" ]]; then
  usage
fi

for command_name in git go sha256sum realpath mktemp cmp cut sed xargs; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "FAIL: required command is missing: $command_name" >&2
    exit 1
  fi
done

if [[ "$MODE" == "production" ]]; then
  if [[ "$EXPECTED_TAG" == "none" ||
    ! "$TAG_SIGNER_FINGERPRINT" =~ ^([0-9A-F]{40}|[0-9A-F]{64})$ ||
    "$TRUSTED_BUILD_PUBLIC_KEY_FILE" == "none" ]]; then
    usage
  fi
  if [[ ! -f "$TRUSTED_BUILD_PUBLIC_KEY_FILE" || -L "$TRUSTED_BUILD_PUBLIC_KEY_FILE" ]]; then
    echo "FAIL: trusted build public key must be a non-symlink regular file" >&2
    exit 1
  fi
  TRUSTED_KEY_DIR=$(realpath -e -- "$(dirname -- "$TRUSTED_BUILD_PUBLIC_KEY_FILE")")
  TRUSTED_BUILD_PUBLIC_KEY_FILE="$TRUSTED_KEY_DIR/$(basename -- "$TRUSTED_BUILD_PUBLIC_KEY_FILE")"
  if [[ ! -f "$TRUSTED_BUILD_PUBLIC_KEY_FILE" || -L "$TRUSTED_BUILD_PUBLIC_KEY_FILE" ]]; then
    echo "FAIL: trusted build public key must be a non-symlink regular file" >&2
    exit 1
  fi
elif [[ "$EXPECTED_TAG" != "none" || "$TAG_SIGNER_FINGERPRINT" != "NONE" ||
  "$TRUSTED_BUILD_PUBLIC_KEY_FILE" != "none" ]]; then
  usage
else
  TAG_SIGNER_FINGERPRINT=none
fi

if [[ ! -d "$1" || -L "$1" ]]; then
  echo "FAIL: release path must be a real directory" >&2
  exit 1
fi
RELEASE_DIR=$(realpath -e -- "$1")

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR/.." rev-parse --show-toplevel)
SOURCE_COMMIT=$(git -C "$REPO_ROOT" rev-parse --verify HEAD)
if [[ "$SOURCE_COMMIT" != "$EXPECTED_COMMIT" ]]; then
  echo "FAIL: verifier checkout is $SOURCE_COMMIT, want $EXPECTED_COMMIT" >&2
  exit 1
fi
if ! git -C "$REPO_ROOT" diff --quiet --ignore-submodules -- ||
  ! git -C "$REPO_ROOT" diff --cached --quiet --ignore-submodules -- ||
  [[ -n "$(git -C "$REPO_ROOT" ls-files --others --exclude-standard)" ]]; then
  echo "FAIL: verification requires a clean checkout at the expected commit" >&2
  exit 1
fi

TAG_OBJECT=none
if [[ "$MODE" == "production" ]]; then
  if [[ "$EXPECTED_TAG" == -* ]] ||
    ! git -C "$REPO_ROOT" check-ref-format "refs/tags/$EXPECTED_TAG"; then
    echo "FAIL: invalid expected signed tag" >&2
    exit 1
  fi
  TAG_COMMIT=$(git -C "$REPO_ROOT" rev-parse --verify "$EXPECTED_TAG^{commit}")
  if [[ "$TAG_COMMIT" != "$EXPECTED_COMMIT" ]]; then
    echo "FAIL: expected tag does not resolve to the expected commit" >&2
    exit 1
  fi
  TAG_OBJECT=$(git -C "$REPO_ROOT" rev-parse --verify "$EXPECTED_TAG^{tag}")
  VERIFY_TAG_OUTPUT=
  if ! VERIFY_TAG_OUTPUT=$(git -C "$REPO_ROOT" verify-tag --raw "$EXPECTED_TAG" 2>&1); then
    printf '%s\n' "$VERIFY_TAG_OUTPUT" >&2
    echo "FAIL: independent signed-tag verification failed" >&2
    exit 1
  fi
  mapfile -t VALID_TAG_FINGERPRINTS < <(
    printf '%s\n' "$VERIFY_TAG_OUTPUT" |
      sed -n 's/^\[GNUPG:\] VALIDSIG \([0-9A-Fa-f]*\) .*/\U\1/p'
  )
  if [[ "${#VALID_TAG_FINGERPRINTS[@]}" -ne 1 ||
    "${VALID_TAG_FINGERPRINTS[0]}" != "$TAG_SIGNER_FINGERPRINT" ]]; then
    echo "FAIL: signed tag was not made by the approved fingerprint" >&2
    exit 1
  fi
fi

ACTIVE_GOROOT=$(env -u GOROOT \
  CGO_ENABLED=0 GOARCH=amd64 GOENV=off GOEXPERIMENT= GOFIPS140=off \
  GOOS=linux GOAMD64=v1 GOTOOLCHAIN=auto go env GOROOT)
GO_BIN="$ACTIVE_GOROOT/bin/go"
if [[ ! -x "$GO_BIN" || -L "$GO_BIN" ]]; then
  echo "FAIL: approved Go executable is unavailable" >&2
  exit 1
fi
GO_VERSION=$(env -u GOROOT GOENV=off GOTOOLCHAIN=local "$GO_BIN" env GOVERSION)
GO_HOST_OS=$(env -u GOROOT GOENV=off GOTOOLCHAIN=local "$GO_BIN" env GOHOSTOS)
GO_HOST_ARCH=$(env -u GOROOT GOENV=off GOTOOLCHAIN=local "$GO_BIN" env GOHOSTARCH)
if [[ "$GO_VERSION" != "go1.26.5" || "$GO_HOST_OS" != "linux" || "$GO_HOST_ARCH" != "amd64" ]]; then
  echo "FAIL: verification requires Go 1.26.5 on linux/amd64" >&2
  exit 1
fi

EXPECTED_GO_SHA256=8da5fd321795754b994c64e3eb8a5a14ff47bd285559a7e876f3c79abafc67f9
EXPECTED_COMPILE_SHA256=10c67b9de41c1e546b9bf416ceef410e5e3dd87a76d129b08b74a9570db9c463
EXPECTED_LINK_SHA256=e58a36e6550a32ed7175cd6e2a1824dc66c034d1e3539ebeac8af719a9150d5d
EXPECTED_ASM_SHA256=0c9a07447aba3ed1df7a0a3e85f6e003d9bf312d2936dfc4b79e3d81e8ca7636
GO_TOOL_DIR=$(env -u GOROOT GOENV=off GOTOOLCHAIN=local "$GO_BIN" env GOTOOLDIR)
EXPECTED_TOOLCHAIN=$(printf '%s\n' \
  "$EXPECTED_GO_SHA256  go" \
  "$EXPECTED_COMPILE_SHA256  compile" \
  "$EXPECTED_LINK_SHA256  link" \
  "$EXPECTED_ASM_SHA256  asm")
ACTUAL_TOOLCHAIN=$(printf '%s\n' \
  "$(sha256sum "$GO_BIN" | cut -d ' ' -f 1)  go" \
  "$(sha256sum "$GO_TOOL_DIR/compile" | cut -d ' ' -f 1)  compile" \
  "$(sha256sum "$GO_TOOL_DIR/link" | cut -d ' ' -f 1)  link" \
  "$(sha256sum "$GO_TOOL_DIR/asm" | cut -d ' ' -f 1)  asm")
if [[ "$ACTUAL_TOOLCHAIN" != "$EXPECTED_TOOLCHAIN" ]]; then
  echo "FAIL: verifier Go toolchain does not match the approved checksums" >&2
  exit 1
fi
umask 077
VERIFY_ROOT=$(mktemp -d /tmp/relay-release-verify.XXXXXXXX)
cleanup() {
  if [[ -n "${VERIFY_ROOT:-}" && "$VERIFY_ROOT" == /tmp/relay-release-verify.* ]]; then
    rm -rf -- "$VERIFY_ROOT"
  fi
}
trap cleanup EXIT
mkdir -m 0700 "$VERIFY_ROOT/go-cache" "$VERIFY_ROOT/tmp"

go_env=(
  env -u GOROOT
  CGO_ENABLED=0
  GOCACHE="$VERIFY_ROOT/go-cache"
  GOENV=off
  GOEXPERIMENT=
  GOFIPS140=off
  GOTOOLCHAIN=local
  GOWORK=off
  GOOS=linux
  GOARCH=amd64
  GOAMD64=v1
  GOFLAGS=-mod=readonly
  GOPROXY=off
  GOSUMDB=off
  TMPDIR="$VERIFY_ROOT/tmp"
  TZ=UTC
  LC_ALL=C
)

cd "$REPO_ROOT"
"${go_env[@]}" "$GO_BIN" mod verify
"${go_env[@]}" "$GO_BIN" run ./scripts/relay-release-tool verify \
  --dir "$RELEASE_DIR" \
  --mode "$MODE" \
  --commit "$EXPECTED_COMMIT" \
  --tag "$EXPECTED_TAG" \
  --tag-object "$TAG_OBJECT" \
  --tag-signer-fingerprint "$TAG_SIGNER_FINGERPRINT" \
  --trusted-build-public-key-file "$TRUSTED_BUILD_PUBLIC_KEY_FILE"

if [[ "$(<"$RELEASE_DIR/toolchain-checksums.sha256")" != "$EXPECTED_TOOLCHAIN" ]]; then
  echo "FAIL: release records unexpected toolchain checksums" >&2
  exit 1
fi
EXPECTED_SOURCE_DATE_EPOCH=$(git show -s --format=%ct "$EXPECTED_COMMIT")
if [[ "$(<"$RELEASE_DIR/source-date-epoch.txt")" != "$EXPECTED_SOURCE_DATE_EPOCH" ]]; then
  echo "FAIL: release source timestamp does not match the approved commit" >&2
  exit 1
fi
if [[ -n "$("$GO_BIN" tool buildid "$RELEASE_DIR/relay")" ]]; then
  echo "FAIL: release binary contains a non-empty Go build ID" >&2
  exit 1
fi
(
  cd "$RELEASE_DIR"
  "${go_env[@]}" "$GO_BIN" version -m ./relay >"$VERIFY_ROOT/go-build-info.txt"
)
if ! cmp "$VERIFY_ROOT/go-build-info.txt" "$RELEASE_DIR/go-build-info.txt"; then
  echo "FAIL: recorded Go build information does not describe the release binary" >&2
  exit 1
fi
git ls-files -z |
  LC_ALL=C sort -z |
  xargs -0 sha256sum >"$VERIFY_ROOT/source-checksums.sha256"
if ! cmp "$VERIFY_ROOT/source-checksums.sha256" "$RELEASE_DIR/source-checksums.sha256"; then
  echo "FAIL: release source checksums do not match the approved checkout" >&2
  exit 1
fi

printf 'Verified Relay %s release package at %s\n' "$MODE" "$RELEASE_DIR"
