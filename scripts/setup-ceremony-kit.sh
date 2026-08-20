#!/usr/bin/env bash
set -euo pipefail
umask 077

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

usage() {
  die "usage: $0 [verify] [--prefix DIR] [--storage-setup-root DIR] [--machine 1|2|3 --rehearsal-root DIR]"
}

KIT_ROOT=$(cd "$(dirname "$0")" && pwd)
ACTION=install
PREFIX=/usr/local/bin
MACHINE=
REHEARSAL_ROOT=${HOME:+$HOME/ceremony-tools}
STORAGE_SETUP_ROOT=

if [[ ${1:-} == verify ]]; then
  ACTION=verify
  shift
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      [[ $# -ge 2 ]] || usage
      PREFIX=$2
      shift 2
      ;;
    --machine)
      [[ $# -ge 2 ]] || usage
      MACHINE=$2
      shift 2
      ;;
    --rehearsal-root)
      [[ $# -ge 2 ]] || usage
      REHEARSAL_ROOT=$2
      shift 2
      ;;
    --storage-setup-root)
      [[ $# -ge 2 ]] || usage
      STORAGE_SETUP_ROOT=$2
      shift 2
      ;;
    -h | --help)
      printf 'usage: %s [verify] [--prefix DIR] [--storage-setup-root DIR] [--machine 1|2|3 --rehearsal-root DIR]\n' "$0"
      exit 0
      ;;
    *) usage ;;
  esac
done

[[ "$PREFIX" == /* ]] || die "--prefix must be an absolute directory"
[[ -z "$STORAGE_SETUP_ROOT" || "$STORAGE_SETUP_ROOT" == /* ]] ||
  die "--storage-setup-root must be an absolute directory"
if [[ -n "$MACHINE" ]]; then
  [[ "$MACHINE" == 1 || "$MACHINE" == 2 || "$MACHINE" == 3 ]] ||
    die "--machine must be 1, 2, or 3"
  [[ "$REHEARSAL_ROOT" == /* ]] || die "--rehearsal-root must be an absolute directory"
fi

for command_name in install sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command is missing: $command_name"
done

for name in checksums.sha256 release.env release.json relay mpc-ceremony setup storage-setup.tar.gz; do
  path="$KIT_ROOT/$name"
  [[ -f "$path" && ! -L "$path" ]] || die "kit entry is missing or unsafe: $name"
done

declare -A seen=()
while IFS= read -r line || [[ -n "$line" ]]; do
  line=${line%$'\r'}
  [[ -z "$line" || "$line" == \#* ]] && continue
  [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || die "invalid release.env assignment"
  name=${BASH_REMATCH[1]}
  value=${BASH_REMATCH[2]}
  case "$name" in
    KIT_SCHEMA | KIT_MODE | RELAY_REPOSITORY | RELAY_TAG | RELAY_SHA256 | \
      MPC_RELEASE_REPOSITORY | MPC_TAG | MPC_SHA256 | REHEARSAL_ARCHIVE_SHA256)
      [[ ! ${seen[$name]+present} ]] || die "duplicate $name in release.env"
      seen[$name]=1
      printf -v "$name" '%s' "$value"
      ;;
    *) die "unknown release.env field: $name" ;;
  esac
done <"$KIT_ROOT/release.env"

required=(KIT_SCHEMA KIT_MODE RELAY_REPOSITORY RELAY_TAG RELAY_SHA256 \
  MPC_RELEASE_REPOSITORY MPC_TAG MPC_SHA256 REHEARSAL_ARCHIVE_SHA256)
for name in "${required[@]}"; do
  [[ -n "${!name:-}" ]] || die "$name is missing from release.env"
done
[[ "$KIT_SCHEMA" == ceremony-kit-v1 ]] || die "unsupported kit schema: $KIT_SCHEMA"
[[ "$KIT_MODE" == production || "$KIT_MODE" == rehearsal ]] || die "invalid kit mode"
repository_pattern='^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$'
tag_pattern='^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
[[ "$RELAY_REPOSITORY" =~ $repository_pattern ]] || die "invalid Relay repository"
[[ "$MPC_RELEASE_REPOSITORY" =~ $repository_pattern ]] || die "invalid proof-tool repository"
[[ "$RELAY_TAG" =~ $tag_pattern && "$MPC_TAG" =~ $tag_pattern ]] || die "invalid release tag"
[[ "$RELAY_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "invalid Relay SHA-256"
[[ "$MPC_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "invalid mpc-ceremony SHA-256"
if [[ "$KIT_MODE" == rehearsal ]]; then
  [[ "$REHEARSAL_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "invalid rehearsal archive SHA-256"
  [[ -f "$KIT_ROOT/three-machine-rehearsal.tar.gz" && ! -L "$KIT_ROOT/three-machine-rehearsal.tar.gz" ]] ||
    die "rehearsal kit is missing three-machine-rehearsal.tar.gz"
else
  [[ "$REHEARSAL_ARCHIVE_SHA256" == none ]] || die "production kit must not name a rehearsal archive"
  [[ ! -e "$KIT_ROOT/three-machine-rehearsal.tar.gz" ]] || die "production kit contains a rehearsal archive"
fi

(
  cd "$KIT_ROOT"
  sha256sum --check --strict checksums.sha256
)

expected_json=$(printf '{\n  "schema": "ceremony-kit-v1",\n  "mode": "%s",\n  "relay": {\n    "repository": "%s",\n    "tag": "%s",\n    "sha256": "%s"\n  },\n  "mpc_ceremony": {\n    "repository": "%s",\n    "tag": "%s",\n    "sha256": "%s"\n  },\n  "rehearsal_archive_sha256": "%s"\n}' \
  "$KIT_MODE" "$RELAY_REPOSITORY" "$RELAY_TAG" "$RELAY_SHA256" \
  "$MPC_RELEASE_REPOSITORY" "$MPC_TAG" "$MPC_SHA256" "$REHEARSAL_ARCHIVE_SHA256")
[[ "$(<"$KIT_ROOT/release.json")" == "$expected_json" ]] || die "release.json does not match release.env"

printf 'Verified %s ceremony kit:\n' "$KIT_MODE"
printf '  Relay:        %s@%s (%s)\n' "$RELAY_REPOSITORY" "$RELAY_TAG" "$RELAY_SHA256"
printf '  mpc-ceremony: %s@%s (%s)\n' "$MPC_RELEASE_REPOSITORY" "$MPC_TAG" "$MPC_SHA256"
[[ "$ACTION" == verify ]] && exit 0

[[ -d "$PREFIX" && ! -L "$PREFIX" ]] || die "installation prefix must be an existing non-symlink directory: $PREFIX"
for target in "$PREFIX/relay" "$PREFIX/mpc-ceremony"; do
  [[ ! -L "$target" ]] || die "installation target must not be a symbolic link: $target"
  [[ ! -e "$target" || -f "$target" ]] || die "installation target must be a regular file: $target"
done

install_one() {
  local source=$1
  local target=$2
  if [[ $EUID -eq 0 || ( -w "$PREFIX" && ( ! -e "$target" || -w "$target" ) ) ]]; then
    install -m 0755 "$source" "$target"
    return
  fi
  command -v sudo >/dev/null 2>&1 || die "sudo is required to install $target"
  sudo install -m 0755 "$source" "$target"
}

install_one "$KIT_ROOT/relay" "$PREFIX/relay"
install_one "$KIT_ROOT/mpc-ceremony" "$PREFIX/mpc-ceremony"
"$PREFIX/relay" --help >/dev/null 2>&1 || die "installed Relay binary did not start"
"$PREFIX/mpc-ceremony" help >/dev/null 2>&1 || die "installed mpc-ceremony binary did not start"
printf 'Installed Relay and mpc-ceremony in %s\n' "$PREFIX"

if [[ -n "$STORAGE_SETUP_ROOT" ]]; then
  command -v tar >/dev/null 2>&1 || die "tar is required for storage setup extraction"
  storage_destination="$STORAGE_SETUP_ROOT/storage-setup"
  [[ ! -e "$storage_destination" && ! -L "$storage_destination" ]] ||
    die "storage setup directory already exists: $storage_destination"
  if [[ -e "$STORAGE_SETUP_ROOT" || -L "$STORAGE_SETUP_ROOT" ]]; then
    [[ -d "$STORAGE_SETUP_ROOT" && ! -L "$STORAGE_SETUP_ROOT" ]] ||
      die "storage setup root must be a real directory"
  else
    mkdir -p "$STORAGE_SETUP_ROOT"
  fi
  chmod 0700 "$STORAGE_SETUP_ROOT"
  tar -xzf "$KIT_ROOT/storage-setup.tar.gz" -C "$STORAGE_SETUP_ROOT"
  printf 'Prepared provider storage setup:\n  %s\n' "$storage_destination"
fi

[[ -n "$MACHINE" ]] || exit 0
command -v tar >/dev/null 2>&1 || die "tar is required for rehearsal setup"
destination="$REHEARSAL_ROOT/three-machine-rehearsal"
[[ ! -e "$destination" && ! -L "$destination" ]] || die "rehearsal directory already exists: $destination"
if [[ -e "$REHEARSAL_ROOT" || -L "$REHEARSAL_ROOT" ]]; then
  [[ -d "$REHEARSAL_ROOT" && ! -L "$REHEARSAL_ROOT" ]] || die "rehearsal root must be a real directory"
else
  mkdir -p "$REHEARSAL_ROOT"
fi
chmod 0700 "$REHEARSAL_ROOT"
tar -xzf "$KIT_ROOT/three-machine-rehearsal.tar.gz" -C "$REHEARSAL_ROOT"
example="$destination/machine-$MACHINE/.env.example"
config="$destination/machine-$MACHINE/.env"
[[ -f "$example" && ! -L "$example" && ! -e "$config" ]] || die "machine environment template is missing or unsafe"

while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in
    RELAY_TAG=*) printf 'RELAY_TAG=%s\n' "$RELAY_TAG" ;;
    MPC_RELEASE_REPOSITORY=*) printf 'MPC_RELEASE_REPOSITORY=%s\n' "$MPC_RELEASE_REPOSITORY" ;;
    MPC_TAG=*) printf 'MPC_TAG=%s\n' "$MPC_TAG" ;;
    RELAY_SHA256=*) printf 'RELAY_SHA256=%s\n' "$RELAY_SHA256" ;;
    MPC_SHA256=*) printf 'MPC_SHA256=%s\n' "$MPC_SHA256" ;;
    RELAY_BIN=*) printf 'RELAY_BIN=%s/relay\n' "$PREFIX" ;;
    MPC_BIN=*) printf 'MPC_BIN=%s/mpc-ceremony\n' "$PREFIX" ;;
    *) printf '%s\n' "$line" ;;
  esac
done <"$example" >"$config"
chmod 0600 "$config"
printf 'Prepared Machine %s configuration:\n  %s\n' "$MACHINE" "$config"
printf 'Set WORK_ROOT and the remaining machine-specific fields, then run:\n'
printf '  %s/00-check-machine.sh %s\n' "$destination" "$config"
