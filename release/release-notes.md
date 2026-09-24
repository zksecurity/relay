## What changed

This minor release adds a Relay-only GO publication path for V5 ceremonies
whose pinned proof-tool can verify a signed decision but cannot add a decision
checkpoint after final release.

- The coordinator verifies the exact GO with the pinned proof-tool, packs the
  closed public archive, and signs a publication record for one destination.
- The keyless upload station independently verifies the release, decision,
  final checkpoint, archive, and signed record. It uses conditional writes for
  large AWS archives and a fixed create-only approved pointer.
- The coordinator can read the official publication back. Public verifiers can
  supply a trusted storage URL to check the pointer and published archive as
  well as the signed ceremony evidence.

## Tessera compatibility

The setup contracts, proof-tool pin, and signed ceremony format are unchanged.
Tessera can continue to use the existing archive verifier for proof and GO
checks; to claim official publication it must provide the trusted public
storage URL to this release's verifier. Frozen ceremonies need a qualified
coordinator update and a newly authenticated upload-station installation.
