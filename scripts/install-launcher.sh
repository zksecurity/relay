#!/usr/bin/env bash
# Download this script from the selected release and verify its attestation
# before execution. Installs into a fresh versioned directory without sudo.
set -euo pipefail
umask 077
tag=${1:?Usage: bash install-launcher.sh role-images-COMMIT}
[[ "$tag" =~ ^role-images-([0-9a-f]{40})$ ]] || { echo 'Invalid release tag' >&2; exit 1; }
commit=${BASH_REMATCH[1]}
for tool in gh docker shasum; do command -v "$tool" >/dev/null; done
case "$(uname -s)" in Darwin) os=darwin;; Linux) os=linux;; *) exit 1;; esac
case "$(uname -m)" in arm64|aarch64) arch=arm64;; x86_64) arch=amd64;; *) exit 1;; esac
# A Terminal running under Rosetta still needs the Apple Silicon launcher.
if [[ "$os" == darwin ]] && [[ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" == 1 ]]; then arch=arm64; fi
docker info >/dev/null
asset="relay-$os-$arch"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
gh release download "$tag" --repo zksecurity/relay --pattern "$asset" --pattern launcher-checksums.sha256 --dir "$scratch"
for file in "$asset" launcher-checksums.sha256; do
  gh attestation verify "$scratch/$file" --repo zksecurity/relay \
    --signer-workflow zksecurity/relay/.github/workflows/publish-role-images.yml \
    --source-ref refs/heads/main --source-digest "$commit" --deny-self-hosted-runners
done
expected=$(awk -v asset="$asset" '$2 == asset {print $1}' "$scratch/launcher-checksums.sha256")
[[ "$expected" =~ ^[0-9a-f]{64}$ ]]
actual=$(shasum -a 256 "$scratch/$asset")
[[ "${actual%% *}" == "$expected" ]]
destination="$HOME/.local/share/relay/releases/$commit"
mkdir -p "$(dirname "$destination")"
mkdir "$destination"
install -m 0700 "$scratch/$asset" "$destination/relay"
"$destination/relay" --help
printf '\nInstalled: %s/relay\nUse this exact path for ceremony setup and open.\n' "$destination"
