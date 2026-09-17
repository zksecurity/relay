## What changed

- Added a narrowly scoped recovery command for the affected 1828 coordinator
  release when its first Phase 1 publication was interrupted by expired AWS
  session credentials. The command accepts only the retained authenticated
  index-0 publication, rotates only credential-file references, verifies any
  existing remote bytes, uses create-only writes for missing objects and the
  initial head, and resumes the original frozen workflow only after complete
  reconciliation. It refuses advanced, closed, conflicting, ambiguous or
  differently pinned workflows.
  Ordinary `coordinator publish` has no recovery switch. The hotfix launcher
  invokes a container-only compatibility command with the locked 1828 profile
  and workflow mounted read-only, then revalidates the complete profile,
  runtime, storage target and retained attempt after credential rotation.
  A retry also recognizes a completion checkpoint that landed despite an
  ambiguous local save result, without publishing again.
  In the original coordinator preparation, choose `6) Storage settings`, then
  AWS and the same existing resources to capture a fresh credential snapshot;
  do not change any storage value. Then run the hotfix launcher's
  `relay ceremony recover-publication CEREMONY_NAME`; on success, resume with
  the original release's start script.
- The storage-first design makes the signed beacon lead configurable before
  initialization in both rehearsal and production. Relay will default to 180
  seconds for rehearsals and 24 hours for production, warn explicitly before a
  shorter production choice is signed, and display the additional fixed
  observation window when witnesses are enabled. Existing setup contracts and
  ceremonies keep their original policy.
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
- Corrected V4 replacement guidance: a grant may be renewed and an immutable
  upload resumed only for its original signed allocation. Retiring an
  allocation requires a separately computed candidate under the replacement;
  Relay preserves the old files rather than rebinding them.
- When a coordinator has transport-checked a complete candidate but
  proof-tool cannot verify it, the guided workflow now offers an explicit
  reviewed rejection. It preserves the received files, publishes a signed
  rejection only after confirmation, and requires a fresh contribution for a
  later allocation. It never rejects or replaces a candidate automatically.
- V4 retained-operation files now record and recheck both SHA-256 and
  BLAKE2b-256, matching the signed protocol reference boundary.

The ordinary coordinator, participant, and required release-signer journeys
now derive their next action from authenticated storage state. The coordinator
must complete the full mathematical replay before final release; the required
release signer verifies the exact reviewed files and signatures but does not
repeat that replay. Existing frozen ceremonies remain on their original
schema-dispatched workflow.

## Tessera compatibility

The recovery command does not change setup contracts, signed definitions,
ceremony data, proof-tool pins, Tessera fields or selected releases. It is an
explicit compatibility bridge for one frozen Relay release and does not make
the hotfix release the ceremony runtime. No Tessera change is required.
Tessera's current grant API does not bind credentials to storage-first
checkpoint attempts. Relay must reject Tessera-backed storage-first ceremonies
until a versioned compatible grant/status contract is deployed. Existing
Tessera ceremonies and setup-v2/setup-v2r2 contracts are unchanged.

Setup contracts, ceremony data, and Tessera request fields are unchanged.
The ceremony-flow documentation does not change Tessera integration behavior.
The compiled workflow recipe adds handoff tasks while preserving existing task
IDs and command-field ordering. Existing selected releases stay pinned.
The additive export menu key does not renumber existing actions. No proof-tool
or website change is needed for local bug-report export. Existing role folders
begin recording diagnostics when opened with a compatible updated launcher.
Tessera needs its matching setup-v3 contract and policy-driven role/evidence
handling before storage-first Tessera ceremonies can be enabled. Existing
Tessera ceremonies stay pinned to their prior setup contract and Relay release.
