# Publishing role images

The coordinator does not build Docker images. Before merging a release-input
change to protected `main`, a maintainer copies
[`role-images.example.json`](../../release/role-images.example.json) to
`release/role-images.json` and fills it with the independently approved
proof-tool URLs/hashes and AWS CLI digest. A protected-main merge starts
**Publish role images** automatically.

The workflow builds and pushes these public GHCR images for `linux/amd64` and
`linux/arm64`:

- `relay-role-online` for coordinator, witness, mirror, auditor, and upload
  station work;
- `relay-role-offline` for key generation and signing; and
- `relay-ceremony-tool` for the participant contributor.

It reads the exact HTTPS URLs and SHA-256 hashes for each `mpc-ceremony` binary,
plus the immutable AWS CLI base-image reference, from that protected-main
file. Each pushed image and the released map receive a GitHub build-provenance
attestation. A missing or malformed `release/role-images.json` fails
closed—CI never substitutes “latest.”

The result is an approved, GitHub-attested release asset named
`relay-role-images.release.json`. It maps each target and Linux platform to an
immutable image digest and records the exact protected-main commit. CI creates
a distribution-only `role-images-<commit>` GitHub Release for the coordinator.

## Coordinator use

New releases also contain four native Relay launchers, an attested installer,
and attested launcher checksums. `launcher_commit` in the map binds the native
launcher to the same commit as the role images. Follow
[launcher installation](../setup/LAUNCHER.md) to install and automatically
verify/select the role image without copying digests by hand.

Download the map from the GitHub Release and verify its GitHub provenance
against the expected repository, this workflow, and its recorded source commit.
Use only the matching immutable `@sha256:` image for the role and host Linux
architecture. Do not take an image digest from a mutable registry tag or an
unattested CI log. The [coordinator runbook](../operator/COORDINATOR_RUNBOOK.md#authenticate-and-select-the-coordinator-image)
contains the exact download, attestation-verification, and image-selection
commands.

Protected-main review, required CI checks, CODEOWNERS review of release
workflows and inputs, no direct pushes, and no force pushes are mandatory in
this model. GitHub Actions is part of the trusted release boundary; there is no
GPG source-tag signer, offline release signer, or separate approval key.
