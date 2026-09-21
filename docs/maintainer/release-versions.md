# Numbered releases

`release/version` requests the next public version, starting with `v0.2.0`.
Change it in a reviewed main-branch PR to publish another version. Patch versions
are for fixes; minor versions are for substantive features or compatibility
changes. Only exact `vMAJOR.MINOR.PATCH` tags are accepted, without leading zeros,
prerelease suffixes or build metadata.

The protected-main workflow compares the version file before and after the push.
Ordinary main builds still publish canonical `role-images-<commit>` assets, but
do not republish the numbered version. Canonical builds are not marked latest.

After canonical artifacts and attestations are published, the workflow publishes
the numbered release with the same assets and an attested
`relay-release-version.txt`: exactly the version, newline, full source commit,
newline. It is a verified public name for the canonical release, not a new
ceremony or manifest format. The release is published from a draft only when all
assets have uploaded and is marked latest.

Existing version tags cannot move to a different commit. Same-commit retries
compare existing assets byte-for-byte and refuse conflicts; they never clobber
assets. If publication fails, inspect the draft and retry the same workflow run.
Do not move tags or substitute a new build under an existing version.

Installers and CLI entrypoints resolve version selectors to canonical pins.
Retain old releases and their assets for frozen ceremonies and compatible-update
verification. Tessera contracts continue to use canonical commit-based IDs.
