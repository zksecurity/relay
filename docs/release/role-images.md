# Publishing role images

The coordinator does not build Docker images. Before signing a Relay tag, the
release maintainer copies
[`role-images.example.json`](../../release/role-images.example.json) to
`release/role-images.json` and fills it with the independently approved
proof-tool URLs/hashes and AWS CLI digest. That exact file becomes part of the
signed tag. A `v*` tag push then starts **Publish role images** automatically.

The workflow builds and pushes these public GHCR images for `linux/amd64` and
`linux/arm64`:

- `relay-role-online` for coordinator, witness, mirror, auditor, and upload
  station work;
- `relay-role-offline` for key generation and offline signing; and
- `relay-ceremony-tool` for the participant contributor.

It reads the exact HTTPS URLs and SHA-256 hashes for each `mpc-ceremony` binary,
plus the immutable AWS CLI base-image reference, from that signed file. It
imports the repository's release-tag public key and refuses a tag whose
signature does not match the approved fingerprint. Each pushed image receives
a GitHub build-provenance attestation. A missing or malformed
`release/role-images.json` fails closed—CI never substitutes “latest.”

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

For a controlled rebuild, dispatch the workflow with the signed tag name. It
reads the same file from that tag; the dispatch form no longer accepts binary
URLs, hashes, or image references.
