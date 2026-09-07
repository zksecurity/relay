# Software delivery and audit

This guide describes how Relay software is delivered for a production ceremony.
It is about the software supply chain. It does **not** change the ceremony's
separate *release signer* role, which signs final ceremony parameters after the
required ceremony evidence has been verified.

## Production delivery model

The supported production path is:

1. A change is reviewed and merged to protected `main`.
2. Required CI checks pass for that exact merge commit.
3. GitHub Actions builds the role images from that commit, records build
   provenance, and publishes immutable image digests.
4. CI creates a GitHub Release named `role-images-<full-commit-sha>` containing
   `relay-role-images.release.json`.
5. The coordinator uses only the digests in that release map.

The map binds every role image to a particular Relay commit, the pinned
proof-tool binary hashes, and the pinned AWS CLI base-image digest. An image
tag such as `latest`, a mutable registry tag, or an image hash copied from a
CI log is not an approved input.

GitHub Actions and the protected-main controls are therefore part of the
software trust boundary. The active delivery process has no GPG source-tag
signer, offline build-signing key, separate software release signer, or manual
approval bundle.

## Required repository controls

Before treating an image map as production-ready, confirm that the Relay
repository's `main` branch requires:

- pull requests with at least one independent approval;
- the required CI checks, up to date with `main`;
- resolved review conversations and linear history; and
- no direct pushes, force pushes, or branch deletion.

The same controls are required for proof-tool, because the role-image build
downloads proof-tool binaries from its protected-main CI release.

## Coordinator procedure

1. Obtain the exact `role-images-<commit>` GitHub Release from
   `zksecurity/relay` through the ceremony's authenticated coordination
   channel.
2. Download `relay-role-images.release.json` from that release.
3. Verify the GitHub build provenance for the release asset and its referenced
   images. Confirm the repository, workflow, and source commit all match the
   expected Relay release.
4. For each role and host architecture, use only the corresponding immutable
   `@sha256:` image reference in the map.
5. Record the map, its GitHub Release URL, source commit, image digests, and
   proof-tool URLs/hashes in the ceremony's operational evidence bundle.

See [published role images](role-images.md) for the image names and platform
mapping, and [guided Docker setup](../setup/GUIDED_SETUP.md) for role-machine
setup.

## Proof-tool input

Relay's protected-main image workflow reads
[`release/role-images.json`](../../release/role-images.json). That file pins
the AMD64 and ARM64 `mpc-ceremony` download URLs and SHA-256 hashes.

Each proof-tool URL must point to a GitHub Release produced from proof-tool's
protected `main`. Its release tag is a distribution pointer named
`mpc-ci-<full-commit-sha>`; it is not a GPG source approval tag. Before merging
a change to `release/role-images.json`, verify that both binaries' SHA-256
values match the proof-tool release assets and that their GitHub provenance
identifies the expected repository, workflow, and source commit.

## Rehearsal and source-audit tools

`scripts/build-relay-release.sh`, `scripts/verify-relay-release.sh`, and the
ceremony-kit scripts remain useful for local rehearsal, compatibility testing,
and source-level investigation. They are not the supported production
publication path and must not be used to create a competing manually approved
software release.

For production ceremonies, use the protected-main role-image release map
instead. The protocol-level final-parameter release remains governed by the
[release-signer checklist](../checklists/RELEASE_SIGNER_CHECKLIST.md), which is
independent of software delivery.
