#!/usr/bin/env -S -u SHELLOPTS -u BASHOPTS BASH_ENV=/dev/null ENV=/dev/null /bin/bash
# Build Relay from an exact clean Git state and emit the evidence required for
# independent verification. Compilation scratch is disposable and private;
# the completed release package is moved atomically into the requested output.
set -euo pipefail

unset CDPATH GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY
unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG_COUNT
export BASH_ENV=/dev/null
export ENV=/dev/null
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1

usage() {
  echo "usage: $0 --mode production|rehearsal --out-dir DIR [--signed-tag TAG --tag-signer-fingerprint HEX --build-signing-key KEY]" >&2
  exit 2
}

MODE=
OUT_DIR=
SIGNED_TAG=
TAG_SIGNER_FINGERPRINT=
BUILD_SIGNING_KEY=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      [[ $# -ge 2 ]] || usage
      MODE=$2
      shift 2
      ;;
    --out-dir)
      [[ $# -ge 2 ]] || usage
      OUT_DIR=$2
      shift 2
      ;;
    --signed-tag)
      [[ $# -ge 2 ]] || usage
      SIGNED_TAG=$2
      shift 2
      ;;
    --tag-signer-fingerprint)
      [[ $# -ge 2 ]] || usage
      TAG_SIGNER_FINGERPRINT=${2^^}
      shift 2
      ;;
    --build-signing-key)
      [[ $# -ge 2 ]] || usage
      BUILD_SIGNING_KEY=$2
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

if [[ "$MODE" != "production" && "$MODE" != "rehearsal" ]] || [[ -z "$OUT_DIR" ]]; then
  usage
fi
if [[ "$MODE" == "production" ]]; then
  if [[ -z "$SIGNED_TAG" || -z "$TAG_SIGNER_FINGERPRINT" || -z "$BUILD_SIGNING_KEY" ]]; then
    echo "FAIL: production builds require --signed-tag, --tag-signer-fingerprint, and --build-signing-key" >&2
    exit 1
  fi
  if [[ ! "$TAG_SIGNER_FINGERPRINT" =~ ^([0-9A-F]{40}|[0-9A-F]{64})$ ]]; then
    echo "FAIL: tag signer fingerprint must be exactly 40 or 64 hexadecimal characters" >&2
    exit 1
  fi
else
  if [[ -n "$SIGNED_TAG" || -n "$TAG_SIGNER_FINGERPRINT" || -n "$BUILD_SIGNING_KEY" ]]; then
    echo "FAIL: rehearsal builds must not supply production signing inputs" >&2
    exit 1
  fi
fi

for command_name in git go gzip install sha256sum realpath mktemp grep sed xargs; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "FAIL: required command is missing: $command_name" >&2
    exit 1
  fi
done

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR/.." rev-parse --show-toplevel)
cd "$REPO_ROOT"

if ! git diff --quiet --ignore-submodules -- ||
  ! git diff --cached --quiet --ignore-submodules -- ||
  [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
  echo "FAIL: release builds require a clean Git checkout with no untracked source files" >&2
  exit 1
fi

SOURCE_COMMIT=$(git rev-parse --verify HEAD)
if [[ ! "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "FAIL: HEAD is not an exact 40-character Git commit" >&2
  exit 1
fi
SOURCE_DATE_EPOCH=$(git show -s --format=%ct "$SOURCE_COMMIT")
if [[ ! "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]]; then
  echo "FAIL: source commit has an invalid timestamp" >&2
  exit 1
fi

TAG_STATUS=not-required-for-rehearsal
TAG_OBJECT=none
if [[ "$MODE" == "production" ]]; then
  if [[ "$SIGNED_TAG" == -* ]] || ! git check-ref-format "refs/tags/$SIGNED_TAG"; then
    echo "FAIL: invalid signed tag name: $SIGNED_TAG" >&2
    exit 1
  fi
  TAG_COMMIT=$(git rev-parse --verify "$SIGNED_TAG^{commit}")
  if [[ "$TAG_COMMIT" != "$SOURCE_COMMIT" ]]; then
    echo "FAIL: signed tag $SIGNED_TAG resolves to $TAG_COMMIT, not HEAD $SOURCE_COMMIT" >&2
    exit 1
  fi
  TAG_OBJECT=$(git rev-parse --verify "$SIGNED_TAG^{tag}")
  VERIFY_TAG_OUTPUT=
  if ! VERIFY_TAG_OUTPUT=$(git verify-tag --raw "$SIGNED_TAG" 2>&1); then
    printf '%s\n' "$VERIFY_TAG_OUTPUT" >&2
    echo "FAIL: signed tag verification failed: $SIGNED_TAG" >&2
    exit 1
  fi
  mapfile -t VALID_TAG_FINGERPRINTS < <(
    printf '%s\n' "$VERIFY_TAG_OUTPUT" |
      sed -n 's/^\[GNUPG:\] VALIDSIG \([0-9A-Fa-f]*\) .*/\U\1/p'
  )
  if [[ "${#VALID_TAG_FINGERPRINTS[@]}" -ne 1 ||
    "${VALID_TAG_FINGERPRINTS[0]}" != "$TAG_SIGNER_FINGERPRINT" ]]; then
    echo "FAIL: signed tag fingerprint does not match the approved fingerprint" >&2
    exit 1
  fi
  if [[ ! -f "$BUILD_SIGNING_KEY" || -L "$BUILD_SIGNING_KEY" ]]; then
    echo "FAIL: build signing key must be a non-symlink regular file" >&2
    exit 1
  fi
  BUILD_SIGNING_KEY_DIR=$(realpath -e -- "$(dirname -- "$BUILD_SIGNING_KEY")")
  BUILD_SIGNING_KEY="$BUILD_SIGNING_KEY_DIR/$(basename -- "$BUILD_SIGNING_KEY")"
  if [[ ! -f "$BUILD_SIGNING_KEY" || -L "$BUILD_SIGNING_KEY" ]]; then
    echo "FAIL: build signing key must be a non-symlink regular file" >&2
    exit 1
  fi
  TAG_STATUS=verified
else
  SIGNED_TAG=none
  TAG_SIGNER_FINGERPRINT=none
fi

OUT_PARENT_INPUT=$(dirname -- "$OUT_DIR")
if [[ ! -d "$OUT_PARENT_INPUT" || -L "$OUT_PARENT_INPUT" ]]; then
  echo "FAIL: output parent must be an existing non-symlink directory" >&2
  exit 1
fi
OUT_PARENT=$(realpath -e -- "$OUT_PARENT_INPUT")
OUT_DIR="$OUT_PARENT/$(basename -- "$OUT_DIR")"
if [[ -e "$OUT_DIR" || -L "$OUT_DIR" ]]; then
  echo "FAIL: output directory already exists: $OUT_DIR" >&2
  exit 1
fi
if [[ ! -d "$OUT_PARENT" || -L "$OUT_PARENT" ]]; then
  echo "FAIL: output parent must be an existing real directory: $OUT_PARENT" >&2
  exit 1
fi

ACTIVE_GOROOT=$(env -u GOROOT \
  CGO_ENABLED=0 GOARCH=amd64 GOENV=off GOEXPERIMENT= GOFIPS140=off \
  GOOS=linux GOAMD64=v1 GOTOOLCHAIN=auto go env GOROOT)
GO_BIN="$ACTIVE_GOROOT/bin/go"
if [[ ! -x "$GO_BIN" || -L "$GO_BIN" ]]; then
  echo "FAIL: resolved Go executable must be a non-symlink executable file: $GO_BIN" >&2
  exit 1
fi
GO_VERSION=$(env -u GOROOT \
  CGO_ENABLED=0 GOARCH=amd64 GOENV=off GOEXPERIMENT= GOFIPS140=off \
  GOOS=linux GOAMD64=v1 GOTOOLCHAIN=local "$GO_BIN" env GOVERSION)
if [[ "$GO_VERSION" != "go1.26.5" ]]; then
  echo "FAIL: release build requires go1.26.5, found $GO_VERSION" >&2
  exit 1
fi
GO_HOST_OS=$(env -u GOROOT GOENV=off GOTOOLCHAIN=local "$GO_BIN" env GOHOSTOS)
GO_HOST_ARCH=$(env -u GOROOT GOENV=off GOTOOLCHAIN=local "$GO_BIN" env GOHOSTARCH)
if [[ "$GO_HOST_OS" != "linux" || "$GO_HOST_ARCH" != "amd64" ]]; then
  echo "FAIL: release build host toolchain must be linux/amd64, found $GO_HOST_OS/$GO_HOST_ARCH" >&2
  exit 1
fi
if [[ -n "$(env -u GOROOT GOENV=off GOTOOLCHAIN=local "$GO_BIN" env GOEXPERIMENT)" ]]; then
  echo "FAIL: release build requires an empty GOEXPERIMENT" >&2
  exit 1
fi

EXPECTED_GO_SHA256=8da5fd321795754b994c64e3eb8a5a14ff47bd285559a7e876f3c79abafc67f9
EXPECTED_COMPILE_SHA256=10c67b9de41c1e546b9bf416ceef410e5e3dd87a76d129b08b74a9570db9c463
EXPECTED_LINK_SHA256=e58a36e6550a32ed7175cd6e2a1824dc66c034d1e3539ebeac8af719a9150d5d
EXPECTED_ASM_SHA256=0c9a07447aba3ed1df7a0a3e85f6e003d9bf312d2936dfc4b79e3d81e8ca7636
GO_TOOL_DIR=$(env -u GOROOT GOENV=off GOTOOLCHAIN=local "$GO_BIN" env GOTOOLDIR)
verify_tool_hash() {
  local path=$1
  local expected=$2
  local actual
  actual=$(sha256sum "$path")
  actual=${actual%% *}
  if [[ "$actual" != "$expected" ]]; then
    echo "FAIL: toolchain digest mismatch for $path: $actual, want $expected" >&2
    exit 1
  fi
}
verify_tool_hash "$GO_BIN" "$EXPECTED_GO_SHA256"
verify_tool_hash "$GO_TOOL_DIR/compile" "$EXPECTED_COMPILE_SHA256"
verify_tool_hash "$GO_TOOL_DIR/link" "$EXPECTED_LINK_SHA256"
verify_tool_hash "$GO_TOOL_DIR/asm" "$EXPECTED_ASM_SHA256"

if grep -En '^[[:space:]]*replace([[:space:]]|$)' go.mod >/dev/null; then
  echo "FAIL: release build forbids Go module replace directives" >&2
  exit 1
fi

umask 077
CANONICAL_ROOT="/tmp/relay-release-build-$SOURCE_COMMIT"
CANONICAL_SOURCE="$CANONICAL_ROOT/source"
if [[ -e "$CANONICAL_ROOT" || -L "$CANONICAL_ROOT" ]]; then
  echo "FAIL: canonical clean-build path already exists: $CANONICAL_ROOT" >&2
  exit 1
fi
mkdir -m 0700 "$CANONICAL_ROOT"
mkdir -m 0700 "$CANONICAL_ROOT/go-cache" "$CANONICAL_ROOT/tmp"
STAGING=$(mktemp -d "$OUT_PARENT/.relay-release.partial.XXXXXXXX")
cleanup() {
  if [[ -n "${STAGING:-}" && "$STAGING" == "$OUT_PARENT"/.relay-release.partial.* ]]; then
    rm -rf -- "$STAGING"
  fi
  if [[ "$CANONICAL_ROOT" == "/tmp/relay-release-build-$SOURCE_COMMIT" ]]; then
    rm -rf -- "$CANONICAL_ROOT"
  fi
}
trap cleanup EXIT

git clone --quiet --no-hardlinks --no-checkout "$REPO_ROOT" "$CANONICAL_SOURCE"
git -C "$CANONICAL_SOURCE" checkout --quiet --detach "$SOURCE_COMMIT"

go_env=(
  env -u GOROOT
  CGO_ENABLED=0
  GOCACHE="$CANONICAL_ROOT/go-cache"
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
  TMPDIR="$CANONICAL_ROOT/tmp"
  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"
  TZ=UTC
  LC_ALL=C
)

cd "$CANONICAL_SOURCE"
"${go_env[@]}" "$GO_BIN" mod verify
"${go_env[@]}" "$GO_BIN" test ./...
printf '%s\n' 'go test ./...: passed' >"$STAGING/test-status.txt"

"${go_env[@]}" "$GO_BIN" build \
  -trimpath \
  -buildvcs=true \
  -ldflags=-buildid= \
  -o "$STAGING/relay" \
  ./cmd/relay

# These operator-facing assets are derived from the same exact source commit as
# the binary and are covered by the release manifest. The rehearsal archive
# contains only the tracked rehearsal subtree; private .env files cannot enter
# it. gzip -n removes the gzip header timestamp and original filename.
install -m 0755 scripts/setup-ceremony-kit.sh \
  "$STAGING/setup-ceremony-kit.sh"
git archive \
  --format=tar \
  --mtime="@$SOURCE_DATE_EPOCH" \
  --prefix=three-machine-rehearsal/ \
  "$SOURCE_COMMIT:scripts/three-machine-rehearsal" |
  gzip -n >"$STAGING/three-machine-rehearsal.tar.gz"

(
  cd "$STAGING"
  "${go_env[@]}" "$GO_BIN" version -m ./relay >go-build-info.txt
)
"${go_env[@]}" "$GO_BIN" run ./scripts/relay-release-tool sbom \
  --binary "$STAGING/relay" \
  --out "$STAGING/sbom.cdx.json"

(
  cd "$CANONICAL_SOURCE"
  git ls-files -z |
    LC_ALL=C sort -z |
    xargs -0 sha256sum >"$STAGING/source-checksums.sha256"
)
(
  cd "$STAGING"
  sha256sum \
    relay \
    three-machine-rehearsal.tar.gz >checksums.sha256
)
printf '%s\n' '-trimpath -buildvcs=true -ldflags=-buildid=' >"$STAGING/build-flags.txt"
printf '%s\n' "$MODE" >"$STAGING/build-mode.txt"
printf '%s\n' "$SOURCE_COMMIT" >"$STAGING/source-commit.txt"
printf '%s\n' "$SOURCE_DATE_EPOCH" >"$STAGING/source-date-epoch.txt"
printf '%s\n' "$SIGNED_TAG" >"$STAGING/signed-tag.txt"
printf '%s\n' "$TAG_STATUS" >"$STAGING/signed-tag-status.txt"
printf '%s\n' "$TAG_OBJECT" >"$STAGING/signed-tag-object.txt"
printf '%s\n' "$TAG_SIGNER_FINGERPRINT" >"$STAGING/signed-tag-signer-fingerprint.txt"
cat >"$STAGING/toolchain-checksums.sha256" <<EOF
$EXPECTED_GO_SHA256  go
$EXPECTED_COMPILE_SHA256  compile
$EXPECTED_LINK_SHA256  link
$EXPECTED_ASM_SHA256  asm
EOF

"${go_env[@]}" "$GO_BIN" run ./scripts/relay-release-tool manifest \
  --dir "$STAGING" \
  --out "$STAGING/build-package-manifest.json"
(
  cd "$STAGING"
  sha256sum build-package-manifest.json >build-package-manifest.sha256
)
if [[ "$MODE" == "production" ]]; then
  "${go_env[@]}" "$GO_BIN" run ./scripts/relay-release-tool sign \
    --input "$STAGING/build-package-manifest.json" \
    --private-key "$BUILD_SIGNING_KEY" \
    --signature-out "$STAGING/build-package-manifest.sig" \
    --public-key-out "$STAGING/build-package-manifest-public-key.hex"
fi

chmod 0444 "$STAGING"/*
chmod 0555 \
  "$STAGING/relay" \
  "$STAGING/setup-ceremony-kit.sh"
touch -d "@$SOURCE_DATE_EPOCH" "$STAGING"/*

verify_args=(
  verify
  --dir "$STAGING"
  --mode "$MODE"
  --commit "$SOURCE_COMMIT"
  --tag "$SIGNED_TAG"
  --tag-object "$TAG_OBJECT"
  --tag-signer-fingerprint "$TAG_SIGNER_FINGERPRINT"
)
if [[ "$MODE" == "production" ]]; then
  verify_args+=(--trusted-build-public-key-file "$STAGING/build-package-manifest-public-key.hex")
else
  verify_args+=(--trusted-build-public-key-file none)
fi
"${go_env[@]}" "$GO_BIN" run ./scripts/relay-release-tool "${verify_args[@]}"

mv -- "$STAGING" "$OUT_DIR"
STAGING=
printf 'Relay %s release package created at %s\n' "$MODE" "$OUT_DIR"
