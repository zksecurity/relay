## What changed

- Added a separate V4 metadata-sync bridge that discovers signed history,
  verifies its complete ancestry before recording progress, and avoids fetching
  old contribution payloads. Normal role-menu integration is still pending.
  Its head-bound record index retains earlier custody packets across retries;
  committed enrollment signatures are checked in one batch before guidance
  facts are returned. This does not imply full replay or a complete roster.

- Added the V4 coordinator/participant turn model for both phases. It retains
  work across upload retries, distinguishes rejected results, and explicitly
  requires the coordinator's return receipt before candidate acceptance.
  Retained computation and complete signed upload packages have distinct IDs;
  the approved-tool inspection checks both together without repeating computation.
  Normal menu/executor integration remains pending.

- Added a transport-only delivery foundation with bounded inventories,
  manifest-last uploads and exact-byte retries. It is not yet connected to role
  menus and does not replace the released signed-envelope workflow.
- Stream large-artifact hash checks and stage verified private upload copies
  so replacing the original file cannot change the uploaded bytes.
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
The revised trusted-coordinator workflow will require a separately versioned
contract; this transport foundation does not change existing setup contracts.
