## What changed

This patch release fixes four guided K21 trial failures observed with v0.6.0.

- The upload station verifies a release package with the coordinator key saved by its own onboarding flow.
- V5 decision preparation passes the required public evidence root to proof-tool.
- Trial archive preparation and publication compare decoded coordinator keys, accepting a final newline in a public key file while rejecting changed or malformed keys.
- Public trial archive and notice readback now download into fresh paths, so exact published bytes can be checked after upload.

## Tessera compatibility

The setup contracts, signed ceremony formats, and proof-tool pin are unchanged. Existing frozen ceremonies stay on their selected release. This patch does not implement official GO promotion or authorize a NO-GO trial's keys for production ownership proofs.
