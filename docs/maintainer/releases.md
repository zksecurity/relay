# Software releases

Protected-main CI publishes Relay software. This is separate from the ceremony
role that signs final parameters.

## Inputs and outputs

A merge to Relay main starts `publish-role-images.yml`.
The reviewed `release/role-images.json` pins proof-tool AMD64/ARM64 download
URLs and SHA-256 hashes plus the AWS CLI base-image digest.
Verify proof-tool's provenance and actual downloaded hashes before changing it.

CI builds:
- native Relay for macOS/Linux on AMD64/ARM64;
- online, offline, and contributor Linux images for AMD64/ARM64;
- an installer, launcher checksums, and the JSON image map.

Each launcher asset, image, and map receives GitHub provenance.
Linux Docker smoke jobs gate publication of the release bundle.
The output is `role-images-FULL_COMMIT`; proof-tool uses `mpc-ci-FULL_COMMIT`.
These tags identify distribution artifacts; they are not GPG approval tags.

The map contains image digests, `source_commit`, and `launcher_commit`.
Proof-tool hashes and the AWS base digest reside in the pinned source
`release/role-images.json`, not directly in the output map.
Retain both when auditing the complete dependency selection.

## Trust controls

GitHub Actions and repository administration are trusted release boundaries.
Required CI checks and branch protections gate normal merges.
Relay permits the explicitly configured account `mellowcroc` to bypass PR
review; independent review is therefore not guaranteed for every merge.
Inspect current repository settings before making stronger claims.
There is no offline software approver or GPG source-tag requirement in this path.

## Operator delivery

Send the exact release identifier through the authenticated coordination channel.
Operators follow [installation](../install.md), verify the installer before
execution, then use `setup --release` to verify the map and select their image.
That option rejects image overrides, incompatible commits, malformed maps,
and participant profiles naming another contributor image/platform.
Saved release-based profiles reject a different launcher on later opening.

The installer is per-user and versioned; it does not replace existing installs.
It needs Docker, GitHub CLI, Bash, and shasum. It provides no Apple notarization.
Offline signers prepare before disconnecting; opening uses cached images.

## Audit and validation

Review the exact source commit and workflow, dependency pins, image digests,
launcher checksums, and GitHub attestations.
Provenance authenticates the build source/workflow, not the absence of bugs.
Four platform CI jobs test native builds; Linux release jobs exercise real
Docker role images. Mac Docker smoke tests require a suitable local machine.

Local `build-relay-release.sh` and ceremony-kit scripts remain available for
rehearsal and source audit. They are legacy package tools, not this automatic
production distribution route. Their retained instructions live beside the
[three-machine rehearsal](../../scripts/three-machine-rehearsal/INSTALL.md).

The coordinator still needs reviewed ceremony inputs and matching tool receipts;
a released image map does not create profiles, identities, or a ceremony.
