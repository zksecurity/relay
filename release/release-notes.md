## What changed

- Add qualification support for coordinator online-container upgrades between completed operations. Existing native-only approval semantics remain unchanged.
- Require continuation, interrupted-updater, unsafe-update-refusal, online publication-retry and predecessor-reentry evidence before approving an exact release pair.
- Preserve proof-tool, signing and contributor runtime pins and the existing clean-exit checks.
- No release pair is approved by this release. Published candidate artifacts must be qualified and their approval published separately before an upgrade can be activated.

## Tessera compatibility

Tessera setup contracts, signed ceremony artifacts and proof-tool pins are unchanged. Existing upgrade approval formats retain their meaning. This adds a qualification format for a future explicitly approved coordinator upgrade; it does not upgrade frozen ceremonies or enable a pair automatically.
