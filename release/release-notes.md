## What changed

This release adds a Relay-only GO publication path for V5 ceremonies
whose pinned proof-tool can verify a signed decision but cannot add a decision
checkpoint after final release.

- The coordinator verifies the exact GO with the pinned proof-tool, packs the
  closed public archive, and signs a publication record for one destination.
- The coordinator receives the signer's exact public package directly, checks
  its closed inventory, and records the final release without a new upload
  station. It re-verifies the release, decision, final checkpoint, archive, and
  signed record before conditional AWS publication.
- The coordinator can read the official publication back, check it against its
  local trust anchor and final checkpoint, and rerun the pinned public verifier.
  Public verifiers supply an independently trusted storage URL, ceremony ID,
  and coordinator key. They authenticate the exact final checkpoint chain as
  well as the pointer, archive, and signed ceremony evidence.
- The coordinator's configured AWS profile now performs GO and NO-GO uploads.
  Same-host readback checks exact bytes, but independent public verification
  remains important because there is no separate upload host.
- Coordinator upgrade admission now binds an authenticated V5 definition to a
  V5 upgrade record; other roles do not gain V5 upgrade admission.
- Reusing a retained public archive now checks that decision files, signatures,
  evidence, and the coordinator public key still match the current handoff.

## Tessera compatibility

The setup contracts, proof-tool pin, and signed ceremony format are unchanged.
Tessera can continue to use the existing archive verifier for proof and GO
checks; to claim official publication it must provide the trusted public
storage URL, ceremony ID, and coordinator key to this release's verifier.
An ongoing V5 ceremony can retain its signed definition and pinned proof-tool
while its coordinator selects a qualified update between completed actions.
Participants and the release signer retain their releases. The direct signer
handoff, GO publication, official readback, and exact v0.6.0 upgrade path
still require end-to-end qualification before a real ceremony uses them.
