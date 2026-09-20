## What changed

- R2 setup now accepts the inbox-only credential as a named profile from a
  protected AWS-format file, including the coordinator credential file. Hidden
  paste and single-value files remain available; the two keys must differ.

- Publication frees each refused upload copy before downloading an existing
  object for verification, and admits artifacts in name order so disk
  contention cannot change which failure is reported. Tessera compatibility
  is unchanged; no schema, signed bytes, or API changes are required.

- Storage-first checkpoint publication no longer re-downloads and re-hashes
  every previously accepted artifact on each commit. Each checkpoint carries
  the full cumulative artifact inventory, so every `coordinator commit-v4`
  re-confirmed all earlier objects byte-for-byte, work that grew quadratically
  over a ceremony. The coordinator now records, in workspace-private
  `verified-objects.json` beside the public artifact root, the exact object
  versions it has digest-verified; an already-present artifact is confirmed
  with one object-metadata request, and only an unknown, changed, or
  metadata-unavailable version falls back to a full download-and-hash. Trust
  stays pinned to digest-verified versions — mere existence is still never
  accepted. Staging also hashes the private copy while it is written, instead
  of reading and hashing every artifact twice. The artifact batch is published
  with bounded parallelism: a byte-weighted in-flight cap (default 2 GiB, so
  temporary copies stay within it unless one oversized artifact runs alone)
  plus a worker cap, deterministic first-artifact error reporting, and
  idempotent retries. The
  signed checkpoint, its signature, and the root pointer are still published
  strictly after the batch, so a partial batch never becomes discoverable.
- Storage-first upload grants now cap remaining lifetime at accept
  (`expires_at` versus now, plus two minutes of provider-clock allowance),
  not `expires_at − issued_at`. AWS STS `Expiration` is one hour from
  AssumeRole completion, so a stamp taken before that call made honest 1h
  sessions fail by a few seconds. `issued_at` stays an independent stamp
  and is not derived from AWS expiry. Guided flow still requests a 1h
  credential TTL. This check lives in the online image, so in-progress
  ceremonies on an older image keep the previous rule.
- Fixed Docker participant profiles for the storage-first workflow. Setup now
  measures the host proof-tool companion against the approved receipt but
  records and executes only the image's fixed proof-tool path in Docker.
  Existing profiles that retained a host measurement path remain usable without
  editing, recreation, or changes to their ceremony files, grants, candidates,
  or recovery state.
- Fixed storage-first final signing to pass Proof-tool the authenticated current
  release-review checkpoint, rather than the separately signed operational
  evidence bundle. Proof-tool correctly rejected the bundle when it was used as
  a checkpoint, so affected ceremonies stopped safely before creating or
  publishing a release package. The retained ceremony can resume from its
  frozen review without repeating either contribution phase.
- Pinned the corrected protected-main Proof-tool release so a new empty client
  receives the signed final bootstrap, derives the complete closed release
  inventory, and can reconstruct the published final ceremony without files
  retained from an earlier role workspace.
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
- When a coordinator has transport-checked a complete candidate and proof-tool
  classifies its authenticated candidate semantics as invalid, the guided
  workflow now offers an explicit reviewed rejection. Relay keeps a private
  receipt and rechecks every retained candidate payload byte before that option
  appears and immediately before accepting or rejecting it. If an interrupted
  download leaves no valid receipt, Relay preserves that local copy and fetches
  the same signed attempt again into a fresh folder; it never overwrites the old
  files.
  Runtime, trust, path and I/O failures remain blocking rather than being
  labelled invalid. Rejection preserves the received files, publishes a signed
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

## Validation status and current limits

- Repository tests, vet, and launcher tests pass. The pinned Proof-tool release
  assets and GitHub provenance were verified against its exact protected-main
  commit.
- A live Cloudflare R2 rehearsal with the minimal required roles completed both
  contribution phases, future-beacon transitions, coordinator mathematical
  replay, release signing, final checkpoint publication, and a second fresh
  empty-workspace reconstruction from stored bytes. The recovery check was run
  again after the Docker artifact-root containment fix.
- Live Amazon S3 initial publication/reconstruction and scoped temporary-grant
  tests pass, including version-pinned reads and rejection outside the granted
  prefix. A complete S3 contribution-to-release rehearsal has not yet been run
  for this version.
- The storage-first guided path in this release supports the minimal required
  roles: coordinator, participant, and release signer. Enabled witness, mirror,
  or auditor journeys are deferred; setup refuses those nonzero assurance
  requirements instead of starting an unfinishable ceremony.
- The live rehearsal uses the tiny rehearsal circuit. It does not establish
  production K=21 performance, independent human operators, or physical
  erasure of host or VM remnants.
- Storage-first Tessera ceremonies remain disabled until Tessera's compatible
  setup-v3 and attempt-bound grant/status contract is deployed. Existing
  Tessera ceremonies keep their pinned releases and behavior.

## Tessera compatibility

The R2 profile-selection change affects only local credential entry. No Tessera
contract, signed ceremony data, saved credential format, or API changes.

The release-signing fix changes no setup contract, ceremony format, storage
object, or Tessera request. This release pins a corrected Proof-tool runtime
for new storage-first ceremonies. Existing frozen storage-first ceremonies
retain their exact runtime and signed state and can resume final signing with
the compatibility path in this launcher. No Tessera change is required for
this fix.

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
