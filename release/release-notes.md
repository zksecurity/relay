## What changed

- Introduce numbered releases, starting with `v0.2.0`. Maintainers request each
  new version by changing `release/version` in a reviewed PR.
- Installers and CLI release flags verify an attested version-to-commit mapping
  before resolving the selected version to its exact software pin.
- Keep existing commit releases available for frozen ceremonies. Numbered tags
  cannot move, and publication retries refuse to replace differing assets.

## Tessera compatibility

Shared setup contracts, signed ceremony policy, proof-tool pins and canonical
commit-based release identities are unchanged. Tessera can continue using those
identities; this change does not activate a new website release or upgrade
existing ceremonies. Older installers must still use commit-based release tags.
