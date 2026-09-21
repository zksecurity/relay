#!/usr/bin/env bash
# Run only from the protected-main publication workflow, after canonical assets.
set -euo pipefail

prepare_version() {
  local before=$1 commit=$2 version previous=''
  [[ "$commit" =~ ^[0-9a-f]{40}$ && "$before" =~ ^[0-9a-f]{40}$ ]]
  [[ "$(git rev-parse HEAD)" == "$commit" ]]
  version=$(cat release/version)
  [[ "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
  if [[ "$before" != 0000000000000000000000000000000000000000 ]]; then
    git cat-file -e "$before^{commit}"
    if git cat-file -e "$before:release/version" 2>/dev/null; then
      previous=$(git show "$before:release/version")
    fi
  fi
  [[ "$version" != "$previous" ]] || return 0
  printf '%s\n%s\n' "$version" "$commit" > relay-release-version.txt
  printf 'version=%s\n' "$version" >> "$GITHUB_OUTPUT"
}

publish_version() {
  local version=$1 commit=$2 existing tag_type tag_commit file assets
  shift 2
  [[ "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]]
  scratch=$(mktemp -d)
  trap 'rm -rf -- "$scratch"' EXIT
  # Listing succeeds or fails explicitly: authorization/network errors must not
  # be interpreted as a missing version. Tags are lightweight and never moved.
  existing=$(gh api "repos/zksecurity/relay/git/matching-refs/tags/$version" \
    --jq ".[] | select(.ref == \"refs/tags/$version\") | [.object.type,.object.sha] | @tsv")
  if [[ -z "$existing" ]]; then
    gh api repos/zksecurity/relay/git/refs -f "ref=refs/tags/$version" -f "sha=$commit" >/dev/null
  else
    read -r tag_type tag_commit <<< "$existing"
    [[ "$tag_type" == commit && "$tag_commit" == "$commit" ]] || {
      echo 'Version tag already names another commit; refusing to move it.' >&2; return 1;
    }
  fi
  # gh release view distinguishes an existing draft on retry. Failure is not
  # assumed to be absence: create itself must succeed before any upload.
  if ! gh release view "$version" --repo zksecurity/relay >/dev/null 2>&1; then
    gh release create "$version" --repo zksecurity/relay --verify-tag --draft \
      --title "Relay $version" --notes-file release/release-notes.md
  fi
  for file in "$@"; do
    [[ -f "$file" ]]
    assets=$(gh release view "$version" --repo zksecurity/relay --json assets --jq '.assets[].name')
    if grep -Fx -- "$(basename "$file")" <<< "$assets" >/dev/null; then
      gh release download "$version" --repo zksecurity/relay --pattern "$(basename "$file")" --dir "$scratch"
      cmp "$file" "$scratch/$(basename "$file")" || {
        echo 'Existing version asset differs; refusing replacement.' >&2; return 1;
      }
    else
      # Never --clobber: concurrent uploads fail rather than replace bytes.
      gh release upload "$version" "$file" --repo zksecurity/relay
    fi
  done
  gh release edit "$version" --repo zksecurity/relay --draft=false --latest \
    --title "Relay $version" --notes-file release/release-notes.md
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "$1" in
    prepare) shift; prepare_version "$@";;
    publish) shift; publish_version "$@";;
    *) exit 2;;
  esac
fi
