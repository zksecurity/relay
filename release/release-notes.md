## What changed

- Added the authenticated storage-first protocol foundation: immutable signed
  checkpoints, rollback/fork detection, exact submission attempts, conditional
  root updates, crash-safe coordinator journals, and deterministic Phase 1
  next-action evaluation.
- Relay now consumes the proof-tool's authenticated Phase 2 and final-state
  checkpoint projection as well as Phase 1; it does not parse signed checkpoint
  JSON to infer those lifecycle facts itself.
- Added setup v3 and signed assurance policy. Coordinators may explicitly set
  witness, mirror, ceremony-audit, and external-audit minima to zero. Disabled
  roles disappear from guidance and cannot submit evidence. Future drand beacon
  verification remains mandatory.
- Made the signed closure-to-beacon lead configurable for rehearsal and
  production. Relay recommends 180 seconds for rehearsals and 24 hours for
  production and warns before signing a shorter production value.
- Retained setup v2, setup v2 revision 2, and their existing ceremony behavior
  for already pinned releases.

This is still a draft protocol release. The ordinary coordinator and role
menus are not yet connected to the storage-first execution path, so it must not
be selected for a production ceremony.

## Tessera compatibility

Tessera needs its matching setup-v3 contract and policy-driven role/evidence
handling before this workflow can be enabled. Existing Tessera ceremonies stay
pinned to their prior setup contract and Relay release.
