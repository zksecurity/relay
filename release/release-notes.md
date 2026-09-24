## What changed

This minor release adds a Relay-only GO publication path for V5 ceremonies
whose pinned proof-tool can verify a signed decision but cannot add a decision
checkpoint after final release.

- The coordinator verifies the exact GO with the pinned proof-tool, packs the
  closed public archive, and signs a publication record for one destination.
- The keyless upload station independently verifies the release, decision,
  final checkpoint, archive, and signed record. It uses conditional writes for
  large AWS archives and a fixed create-only approved pointer.
- The coordinator can read the official publication back, check it against its
  local trust anchor and final checkpoint, and rerun the pinned public verifier.
  Public verifiers supply an independently trusted storage URL, ceremony ID,
  and coordinator key. They authenticate the exact final checkpoint chain as
  well as the pointer, archive, and signed ceremony evidence.
- GO upload requires a separate AWS profile on the upload station. Its cloud
  permissions must be restricted to the exact signed archive and pointer keys;
  this restriction needs independent IAM qualification before production use.

## Tessera compatibility

The setup contracts, proof-tool pin, and signed ceremony format are unchanged.
Tessera can continue to use the existing archive verifier for proof and GO
checks; to claim official publication it must provide the trusted public
storage URL, ceremony ID, and coordinator key to this release's verifier.
Frozen ceremonies need a qualified coordinator update and a newly
authenticated upload-station installation. The full guided GO handoff and
restricted upload profile still require end-to-end qualification.
