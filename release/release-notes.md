## What changed

- Permit a coordinator-only Relay CLI update between completed storage operations. Relay now reuses the retained-state verifier: it requires a resolved workflow, an authenticated high-water checkpoint, complete signed checkpoint ancestry, exact local public artifacts, completed publication records, and unchanged proof/signing images. A pending release-signer handoff still blocks the update until it is resolved by the original Relay.

## Tessera compatibility

Tessera setup contracts, signed ceremony formats, proof-tool pins, stored checkpoint formats, and role-image pins are unchanged. This changes only local coordinator CLI update admission.
