## What changed

Public ceremony verification now works from the released macOS Relay CLI. It authenticates the same-release online image, uses its pinned Linux proof tool through local Docker, and returns the existing JSON verification report. The archive and optional trusted coordinator key are read-only inputs; no ceremony role or signing key is required. Linux verification and existing ceremony workflows are unchanged.

## Tessera compatibility

This is a Relay-only public-verifier feature. It does not change the signed ceremony format, setup contracts, proof-tool pin, participant or signer workflows, or frozen ceremony releases. Tessera may continue using its existing Relay integration.
