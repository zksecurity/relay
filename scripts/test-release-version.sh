#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=install-launcher.sh
source "$SCRIPT_DIR/install-launcher.sh"
# shellcheck source=publish-version.sh
source "$SCRIPT_DIR/publish-version.sh"
version_test_root=$(mktemp -d)
trap 'rm -rf -- "$version_test_root"' EXIT
tag='' commit=''
parse_release https://github.com/zksecurity/relay/releases/tag/v0.2.0
[[ "$tag" == v0.2.0 && -z "$commit" ]]
for invalid in v00.2.0 v0.2 v0.2.0-rc.1 v0.2.0+build v0.2.0/ latest; do
  if parse_release "$invalid" >/dev/null 2>&1; then exit 1; fi
done
test_commit=0123456789012345678901234567890123456789
mapping="v0.2.0"$'\n'"$test_commit"$'\n'
reject_attestation=false
gh() {
  if [[ "$1 $2" == 'release download' ]]; then
    printf '%s' "$mapping" > "${!#}/relay-release-version.txt"
  elif [[ "$1 $2" == 'attestation verify' ]]; then
    [[ "$*" == *"--source-digest $test_commit --deny-self-hosted-runners"* ]]
    [[ "$reject_attestation" == false ]]
  else return 1; fi
}
parse_release v0.2.0
resolve_version
[[ "$tag" == "role-images-$test_commit" && "$commit" == "$test_commit" ]]
reject_attestation=true
parse_release v0.2.0
if resolve_version >/dev/null 2>&1; then exit 1; fi
[[ "$tag" == v0.2.0 && -z "$commit" ]]
reject_attestation=false
mapping="v0.2.1"$'\n'"$test_commit"$'\n'
if resolve_version >/dev/null 2>&1; then exit 1; fi
unset -f gh

# A version changed in an earlier commit of the same push still requests release.
cd "$version_test_root"
git init -q
git config user.email fixture@example.invalid
git config user.name Fixture
mkdir release
printf 'v0.1.0\n' > release/version
git add release/version
git commit -qm initial
before=$(git rev-parse HEAD)
printf 'v0.2.0\n' > release/version
git commit -qam version
git commit --allow-empty -qm followup
head=$(git rev-parse HEAD)
export GITHUB_OUTPUT="$version_test_root/outputs"
prepare_version "$before" "$head"
grep -Fx 'version=v0.2.0' "$GITHUB_OUTPUT"
[[ "$(tail -n 1 relay-release-version.txt)" == "$head" ]]
: > "$GITHUB_OUTPUT"
prepare_version "$head" "$head"
[[ ! -s "$GITHUB_OUTPUT" ]]

# Exercise publication in a separate shell so expected failures retain errexit.
export publish_fixture="$version_test_root/publish"
mkdir -p "$publish_fixture/assets"
printf 'reviewed asset\n' > "$publish_fixture/asset.txt"
printf 'reviewed notes\n' > release/release-notes.md
export test_commit
gh() {
  case "$1 $2" in
    'api repos/zksecurity/relay/git/matching-refs/tags/v0.2.0')
      if [[ -f "$publish_fixture/tag" ]]; then
        printf 'commit\t%s\n' "$(cat "$publish_fixture/tag")"
      fi;;
    'api repos/zksecurity/relay/git/refs')
      printf '%s\n' "$test_commit" > "$publish_fixture/tag";;
    'release view')
      [[ -f "$publish_fixture/draft" ]] || return 1
      if [[ "$*" == *'--json assets'* ]]; then
        [[ ! -f "$publish_fixture/list-failure" ]] || return 1
        if [[ -f "$publish_fixture/assets/asset.txt" ]]; then echo asset.txt; fi
      fi;;
    'release create') touch "$publish_fixture/draft";;
    'release upload')
      [[ ! -f "$publish_fixture/upload-failure" ]] || return 1
      cp "$4" "$publish_fixture/assets/asset.txt";;
    'release download') cp "$publish_fixture/assets/asset.txt" "${!#}/asset.txt";;
    'release edit') touch "$publish_fixture/published";;
    *) return 1;;
  esac
}
export -f gh
publish_fixture_run() {
  bash "$SCRIPT_DIR/publish-version.sh" publish v0.2.0 "$test_commit" "$publish_fixture/asset.txt"
}
touch "$publish_fixture/upload-failure"
if publish_fixture_run >/dev/null 2>&1; then exit 1; fi
[[ -f "$publish_fixture/draft" && ! -f "$publish_fixture/published" ]]
rm "$publish_fixture/upload-failure"
publish_fixture_run
[[ -f "$publish_fixture/published" ]]
publish_fixture_run
rm "$publish_fixture/published"
printf 'different bytes\n' > "$publish_fixture/assets/asset.txt"
if publish_fixture_run >/dev/null 2>&1; then exit 1; fi
[[ ! -f "$publish_fixture/published" ]]
touch "$publish_fixture/list-failure"
if publish_fixture_run >/dev/null 2>&1; then exit 1; fi
[[ ! -f "$publish_fixture/published" ]]
printf '%040d\n' 0 > "$publish_fixture/tag"
if publish_fixture_run >/dev/null 2>&1; then exit 1; fi
[[ ! -f "$publish_fixture/published" ]]
echo 'PASS: verified version mapping, legacy pins, push ranges, publication retries and conflict refusal'
