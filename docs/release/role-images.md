# Publishing role images

The coordinator does not build Docker images. A release maintainer starts the
**Publish role images** workflow after a signed Relay tag and approved
`mpc-ceremony` binaries exist for both Linux architectures.

The workflow builds and pushes these public GHCR images for `linux/amd64` and
`linux/arm64`:

- `relay-role-online` for coordinator, witness, mirror, auditor, and upload
  station work;
- `relay-role-offline` for key generation and offline signing; and
- `relay-ceremony-tool` for the participant contributor.

It requires exact HTTPS URLs and SHA-256 hashes for each `mpc-ceremony` binary,
plus an immutable AWS CLI base-image reference. It imports the repository's
release-tag public key and refuses a tag whose signature does not match the
approved fingerprint. Each pushed image receives a GitHub build-provenance
attestation.

The result is deliberately an **unapproved candidate** artifact named
`relay-role-images-candidate`. It maps each target and Linux platform to an
immutable image digest and records the source tag and commit.

## Release approval

CI publishing and provenance do not approve a runtime for a ceremony. The
offline release signer must independently verify the candidate's six image
provenance attestations, the source tag, the proof-tool release hashes, and the
AWS base-image digest. Only then may the signer create and distribute the
signed platform-to-digest approval record used by coordinators.

Until the launcher accepts that signed record directly, the coordinator must
copy its digest values only from this independently authenticated approval
channel. Do not take an image digest from a registry tag, CI log, or candidate
artifact alone.

The workflow is manually dispatched rather than triggered by every tag. This
prevents an ordinary source-tag push from publishing images without the exact
approved proof-tool URLs, hashes, and base-image digest.
