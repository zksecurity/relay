# Trusted coordinator and storage: next implementation

Status: implementation in progress, September 16, 2026. This document is not
release evidence or authorization by itself. It follows the
[storage-first design](storage-first-ceremony-design.md) and
[release verification model](release-verification-trust-model.md).

## What we trust

The coordinator follows ceremony rules and runs mathematical verification.
The configured storage service returns committed state and stored objects
according to its API. Participant inputs still require verification.
Ordinary failures, incorrect local files and concurrent processes remain in scope.

## Implementation progress — September 16

The first compatibility/transport slice is local, not released:

- Proof-tool's released schema inventory is in
  `docs/ceremony-schema-compatibility.md` in that repository. Existing V3
  behavior is pinned to explicit version checks before adding a new default.
- Removed the uncommitted backend-object-key output experiment from proof-tool.
- Relay has bounded unsigned delivery framing, private staging, manifest-last
  upload, exact-byte retry and all-or-nothing fetched staging. This does not
  authenticate participant records or record acceptance.
- Large-artifact hashes are streamed rather than loaded entirely into memory.
- Proof-tool's opt-in Definition V4 now makes the coordinator-replay claim
  explicit. Default construction stays V3 until the complete new path is ready.
- Checkpoint V4 has a separate transport-neutral state model and structural
  transition tests through both phases and release. It removes delivery
  envelopes/acknowledgements without relaxing any released checkpoint schema.
- A complete, normalized per-turn `contribution_result_id` distinguishes
  rejected contribution bytes from a retired upload. Attempt IDs and paths are
  not part of that identifier. Terminal dispositions remain in bounded history.

The next library slice authenticates stored checkpoint ancestry and prepares
initial/turn/retry checkpoints against actual files. Acceptance replays the
chain and requires the normalized inventory and verification record to match
the exact replayed chain artifacts. Large payload hashing remains streamed.
Stored-state inspection verifies signatures and structural ancestry; it does
not claim to rehash every historical payload or establish global freshness.

The semantic review caught a mismatch between a candidate inventory and the
artifacts covered by chain replay. Exact-reference checks and per-file negative
tests close it; the follow-up review found no remaining material issue in the
implemented edges. The Linux ceremony/CLI suites and vet pass for this slice.
A Linux subprocess test now exercises a real tiny Phase 1 contribution through
the new authoring API: initialization, outbound handoff, receipt delivery
retirement/reallocation, signed receipt, contribution, cleanup attestation,
mathematical replay and exact acceptance. Same-size payload corruption is
rejected. Independent review found no material false-positive coverage or
ordinary-helper regression. This is single-process evidence with fixture
environment/cleanup statements, not separate role journeys, cloud transport or
proof of erasure. Unsupported release authoring deliberately fails closed.

Still required: final-release and production-decision authoring,
the new signer verification path, normal role-menu integration, full role
rehearsals, live-provider testing and release/deployment. No existing ceremony
is switched to the new transport by these foundations.

Enrollment and mirror evidence now have typed V4 checkpoint edges. Historical
enrollments are re-authenticated with their disclosures; outbound delivery
requires the participant's committed enrollment. Mirror evidence is counted per
exact accepted head using enrolled keys, and phase closure checks every head.
The real tiny subprocess passes with mirrors disabled and with one mirror
required; missing enrollment and missing mirror evidence are rejected. The
review closed a disclosure-size mismatch by sharing the existing 1 MiB bundle
limit and bounded new observer indices. Audit gates and
the release path remain incomplete; this is not readiness to publish V4.

Witness and multi-relay beacon evidence also have typed edges. Witnesses bind
the exact committed closure and enrolled key; partial collection is allowed,
with the full signed minimum checked at sealing/final-candidate preparation.
Multi-relay evidence verifies every raw drand response and is still required
when witnesses are disabled. Independent review found no material mismatch with
the unchanged bundle. The subprocess tests cover observer-disabled/enabled runs
and refuse sealing when witness or multi-relay evidence is omitted. Historical
responses and fixture relay-operator statements do not establish live retrieval.

Final-candidate preparation now derives replay inputs from the authenticated
predecessor checkpoint, replays both phases through the existing full verifier,
and binds its complete closed file inventory. Its versioned replay claim names
the actual approved executable. The tiny subprocess now reaches Phase 2
contribution, custody, optional observers, the second genuine historical drand
round and finalization with both observer settings. The first run caught a test
witness mismatch between the older helper circuit and the released tiny circuit;
the helper now constructs the correct witness for the selected circuit.
Independent review found no blocker and requested one shared versioned replay
method constant, now used. Tests reject missing/wrong replay claims, an omitted
candidate reference, an extra candidate file and signed Phase 2 closures with
reused/older rounds or invalid cross-phase timing. Both Linux ceremony/CLI
suites and vet pass; the final helper extension passes separately. This is not
final release-signing or menu coverage.

Audit collection now has a typed edge after the frozen candidate. A shared
byte-based verifier authenticates every audit while postponing only the minimum
count check during collection. Final release enforces that count; disabled
audits stay forbidden. Records are read through the confined checkpoint reader
and require committed auditor enrollments. The Linux helper performs two real
auditor replays and rejects a missing enrollment; shared tests reject a partial
release quorum, duplicate auditor, wrong candidate and bad signature. Both
Linux ceremony/CLI suites and vet pass for this slice.
The implementation review found no blocker. Release assembly must sort audit
pairs deterministically rather than use reverse ancestry order, and must verify
the complete required enrollment collection through the existing bundle gate.

Operational-bundle preparation now derives the unchanged v3 bundle exclusively
from the authenticated checkpoint history and runs its existing verifier. The
Linux tiny tests cover both observer settings and enabled audits, require every
roster enrollment (including a participant who did not contribute), ignore valid
but uncommitted files, produce deterministic output, and reject corrupted
custody, chain-prefix and raw beacon bytes. Both ceremony/CLI suites and vet pass.
Independent review found no blocker; final-release verification must still
rederive against its exact predecessor, because source-checkpoint metadata is
not embedded in the legacy signed bundle. This does not verify the final proof,
sign the bundle, or complete the release path.

Governance review found that abort/restart cannot be ordinary evidence edges:
the unchanged bundle verifier authenticates them but does not stop progression.
Implement informational incidents separately. Dedicated abort/restart handling
must terminate the old ceremony; restart must additionally bind and authenticate
the exact new definition. Do not route generic rejection records around the
existing exact contribution-result rejection mechanism.

Those V4 governance library gates are now implemented: incidents preserve state,
abort/restart produce an immutable terminal marker, and active delivery history
is retained without waiting for credential expiry. Only the coordinator may
authorize them; restart verifies an exact new V4 definition. Existing record
schemas remain unchanged. Independent review caught a historical scope recheck
gap: ancestry inspection now verifies each governance edge against its exact
predecessor, including a manually signed wrong-head regression. Full Linux
ceremony/CLI suites and vet pass. Production GO/NO-GO and normal CLI guidance
remain separate required work; these gates alone are not a completed release.

The read-only final-review API is implemented; normal V4 release guidance remains off.
It binds the exact review checkpoint and approved coordinator replay claim,
authenticates/derives both phase summaries, verifies a closed candidate tree,
rederives the signed bundle and enforces checkpoint-derived audits/chronology.
Review caught and fixed dependence on the local trusted-definition filename.
The signer checks native/Cardano export coherence and verifies the public proof
without regenerating setup keys or replaying contributions. Legacy V1–V3 gates
remain unchanged. Full Linux ceremony/CLI suites and vet pass; the added negative
test coherently re-signs metadata/checksums around an invalid public proof and
confirms the V4 proof check rejects it. This read-only API does not sign a release,
establish backend freshness, or replace the remaining role-menu/cloud tests.

The independent structural review found and closed a retry-limit deadlock and
an ambiguous predecessor-signature boundary. The final review reported no
remaining material finding in this slice. Proof-tool's Linux ceremony/CLI
suites and vet pass; focused structural tests also pass with the race detector.
The bounded retry model reproduces the old deadlock and passes after the fix.
These results do not establish the still-unimplemented normal CLI journey.

## Existing verification versus planned changes

### Completion review: remaining protocol gates

The independent lifecycle review identified requirements that must be completed
before V4 can ship:

- Acceptance must retain the existing return handoff and coordinator return
  receipt, delivered through storage automatically. Accept only the seven-file
  candidate form; five-file inventories remain useful for rejected candidates.
  Bind the return receipt into checkpoint evidence and check custody chronology.
  A coordinator-receipt error is not rejection of the participant's candidate:
  preserve its result ID, correct the receipt and retire/reallocate delivery if
  needed. Never permanently reject otherwise-valid candidate bytes because a
  coordinator-created receipt was missing or malformed.
- Add typed evidence-recorded edges for enrollments, mirror/witness receipts,
  multi-relay beacon evidence, audits and applicable governance. They preserve
  protocol progress and deliveries. Derive readiness from authenticated ancestry
  rather than storing duplicate mutable counters. Do not count disabled controls.
- Preserve cross-phase beacon separation at checkpoint preparation, not merely
  at final release. Exact-read the preceding Phase 1 records; reject reused
  rounds/challenges and inconsistent chronology. Test with a signed bad closure.
- The review's enrollment-ceiling concern was withdrawn after checking the
  actual constants: 20 participants and 20 per auditor/observer category yield
  at most 82 required enrollments, below the existing 128 limit. A regression
  assertion guards that bound; no bundle-schema change is needed for capacity.

Gate outbound delivery on participant enrollment, closure on each head's mirror
minimum, sealing/final-candidate preparation on the applicable witness and beacon
evidence, and release signing on enrollment, bundle and exact-candidate audits.
External security audits remain part of the later production decision. Reuse
operational bundle v3 and existing signed records where their meaning is unchanged;
do not add another participant envelope or manual transfer step.

The local lifecycle test reaches Phase 2 genesis with a genuine historical drand
response. It is not proof of these remaining evidence gates or live beacon timing.

Coordinator mathematical replay is not a new requirement. Both
`PrepareFinalization` and `Finalize` already required `replayAll` in proof-tool
commit [`c1f177e`](https://github.com/zksecurity/proof-tool/commit/c1f177ee486fd555fac0dc4d9812b86737fccdfd),
dated July 31, 2026. PR #31 (September 15) added mandatory independent
release-signer replay for the new storage-first flow.

Preserve the existing coordinator replay; remove only the additional mandatory
signer replay in the new format. The signer still checks exact files, signatures,
policy and the coordinator's bound verification statement. The release-signer
role remains required; making the role optional is not part of this plan.

| Area | Target | Current implementation gap |
| --- | --- | --- |
| Coordinator replay | Preserve existing mandatory verification | Preserve replay and its exact-file binding in the revised review/release path |
| Release signer | Check files, signatures, policy and coordinator claim; replay optional | Proof-tool still requires full signer replay |
| Participant upload | Existing signed receipt, contribution and cleanup records | Proof-tool and Relay still require envelopes |
| Acceptance | Checkpoint commits outcome and exact artifact references | Separate acknowledgement still required |
| Storage progress | Current provider root drives normal CLI | Advanced sync exists; normal role journeys incomplete |
| Retry | Redeliver identical valid files; candidate rejection persists by digest | Attempt/candidate rejection semantics need implementation |
| Recovery | Preserve unfinished mutations; reconcile provider result | Reusable foundations exist; normal flow integration incomplete |
| Component boundary | Proof-tool verifies logical artifacts; Relay maps storage | Backend-object-key experiment removed; new normal workflows still need integration |

## 1. Resolve the schema and API together

Inventory released identifiers before choosing a new version. Proof-tool PR #31
already shipped storage-first schemas with envelopes and mandatory signer replay.
Preserve that behavior for existing ceremonies. A new schema/version must express
the simpler rules; missing old fields must never silently enable them.

First implementation gate: check in a compatibility table of every released
definition/ruleset, checkpoint, operational bundle, final transcript, release
manifest, decision and Tessera setup contract. Record each one's envelope,
acknowledgement, optional-role and signer-replay rules. Do not assume all older
schemas require minimum-one roles; some optional-role behavior already shipped.

That inventory is now recorded in proof-tool's
`docs/ceremony-schema-compatibility.md`. The next version set is Definition V4,
Checkpoint V4 and `storage-first-v2`, with final transcript V3 carrying the
explicit changed release claim. Keep application key manifest V1: its signed
transcript hash binds that claim. No additional release signature is needed.
Decision V2 may keep its structure with explicit Definition V4/transcript V3
verification. Normal CLI initialization does not yet emit the new identifiers.
Do not release the partial V4 library support before the complete path is tested.

Downstream setup baseline: setup-v2/two-phase-v1 (two auditors),
setup-v2/two-phase-v2 (one auditor), and setup-v3/two-phase-v3 (explicit optional
assurance). Frozen setups keep their exact ruleset and contract hash. Before
V4 rollout, replace version-3-only capability checks, add V3 to the permanent
compatibility matrix, and preserve positive external-audit policy values rather
than silently forcing them to zero. New defaults activate only after the
compatible release is provisioned.

Rework draft proof-tool PR #32 around these operations:

- receive existing participant-signed records and validate exact ceremony,
  phase, turn, participant, predecessor and closed payload inventory;
- derive logical accepted artifact names inside proof-tool;
- prepare/sign a checkpoint accepting those exact records, without a separate
  participant envelope or coordinator acknowledgement;
- record delivery retirement separately from candidate rejection;
- verify releases without contribution algebra, relying on the coordinator's
  signed final-candidate checkpoint for that algebra.

An acceptance helper may wrap existing chain verification/signing commands.
Specify whether it creates the accepted chain or consumes one before
implementation; never accept a prebuilt chain without verifying its candidate
bytes and predecessor. Return logical names, hashes, sizes and local output
paths. Remove the uncommitted object-key experiment. Provider prefixes, bucket
names, object keys and manifests belong to Relay.

Inventory existing `relay_release_id`, `manifest_key` and slot-prefix fields:
the current schema already couples these to proof-tool. For the new API,
prefer opaque attempt IDs and protocol identities; Relay owns the authenticated
delivery mapping. Define its signature and ceremony/checkpoint binding before
moving those fields, so no scope is lost accidentally.

Prefer deterministic prefix/manifest mapping in Relay's storage contract,
with the approved Relay release in bootstrap/Tessera setup and approved
proof-tool executable identities in the definition. Proof-tool receives no
bucket names or backend paths. Reject inconsistent mappings before transfer.

## 2. Complete one real participant turn

Keep draft Relay PR #52 as the integration branch. Start with:

1. Coordinator publishes a turn and allocates receipt delivery access.
2. Participant syncs, downloads inputs and signs the existing receipt.
3. Relay uploads the receipt/signature and unsigned manifest.
4. Coordinator verifies it and commits the receipt-accepted checkpoint.
5. Participant contributes, confirms cleanup and uploads signed candidate files.
6. Coordinator verifies the mathematics and commits candidate acceptance.
7. Participant sees its exact candidate accepted after restarting its CLI.

Acceptance requires exact signed records and the active slot. Attempt retirement
permits redelivery; candidate rejection records its digest and blocks reuse.
Do not attribute upload-attempt consent to the participant.

Define that candidate ID over the complete scoped artifact set, including
signed attestation, cleanup and required return evidence—not only the large
contribution file. Reuse an existing canonical ID only after checking its
coverage. Changed candidate contents need fresh verification and disposition.

The new inventory uses fixed basenames and exact digests, never an
attempt-dependent path. The public field is `contribution_result_id`, avoiding
confusion with the final ceremony's existing `candidate_id`. Signature, scope,
custody and mathematical validity are still checked separately before acceptance.
Retirement/rejection can finish without a replacement, or allocate one without
advancing the turn. A later replacement names the most recent retired/rejected
attempt. An exhausted retry budget must not prevent terminal retirement.
History permits at most 16 attempts per logical submission and 4,096 total
delivery slots across the ceremony; these are separate per-submission and global
budgets. Exceeding a bound fails explicitly, never discards a rejection.
Only the current active allocation can change, one allocation can be active per
submission, and acceptance is terminal. These are protocol bounds, not a reason
to retry automatically.
After terminal retirement, closure is permitted only when the signed minimum
has already been met. Otherwise work remains incomplete; no success is inferred
from giving up on an upload. The signed-edge verifier compares both predecessor
record and signature digests, beyond the structs-only transition checks.

Use fixed transport inventories for each artifact kind and derive public logical
names from proof-tool results. Transport manifest validation never establishes
acceptance or authorizes extra public files.

## 3. Simplify sync without breaking recovery

Remove requirements for challenge responses, independent freshness services
and hostile-provider history reconciliation from the new flow.

Keep provider root reads, signatures, hashes, local locks, conditional writes,
size limits, safe paths, immutable uploads and durable mutation intents.
These prevent errors and duplicate work even with trusted services.
Do not delete a journal or skip a validation merely because it was originally
introduced during a broader threat-model review.

Split mathematical replay from ordinary progress verification explicitly:
opening a CLI should validate records and state without replaying every large
contribution. Coordinator acceptance/finalization and enabled auditor replay
perform the mathematics. Cache verified records for efficient restart.

## 4. Complete the roles and final release

### Incident and termination records

Use separate V4 transitions for an informational incident, abort and restart.
All three reuse governance records but additionally require the coordinator's
identity and signature (the generic legacy governance verifier also allows
other roles). The record names the exact current phase and head. Its legacy
one-based event index is the accepted count, or 1 at genesis; it is not an
assertion that a genesis contribution was accepted. The checkpoint signature
binds the exact predecessor and record as the current authorization; record time
is the time of the statement, not proof of current backend freshness. A record
already committed cannot be added again.

The transition includes exactly the record's reviewed evidence and hashes those
bytes. Incident/abort evidence is one UTF-8 public statement (at most 1 MiB),
whose hash equals the statement digest. Restart evidence is exactly that
statement plus the new definition and signature. Every selected file becomes
permanent public evidence: never select logs, keys, credentials, environment
dumps or private submission data. All reads are confined to public staging;
no files are discovered automatically.
Informational incidents do not advance the phase or change delivery history;
the automatic operational bundle includes every committed incident.

Abort and restart set a typed terminal progress marker naming the kind, signed
record and (for restart) exact new definition pair. The enclosing checkpoint
binds its exact predecessor. Every later
transition is forbidden. Existing delivery history remains intact, including
unfinished attempts: protocol termination must not wait for a grant to expire.
Relay must separately explain that a previously issued cloud credential may
remain usable until revocation or expiry, but can no longer authorize ceremony
acceptance. Do not silently convert an abort into a restart.

Restart additionally names the exact new signed definition and verifies its
signature, distinct ceremony ID and V4 schema (no silent downgrade). The old coordinator's signed checkpoint
approves that exact pair; the new definition's own coordinator signs it. Creating
the new ceremony is a separate action, not an automatic mutation of old files.
This is an authenticated old-side pointer: the bare new definition does not
prove restart lineage. Roles must retain and verify the old terminal checkpoint
to recognize the new ceremony as its authorized restart.
All three record types are unavailable after final release has been recorded. They
are not substitutes for the separately authenticated production GO/NO-GO path.
Terminal progress cannot prepare an operational release bundle or final release.
Existing formats keep their unchanged governance meaning.

Stop authoring verifies its own bounded evidence, not unrelated contribution
payloads or the full enrollment collection: missing data must not prevent a
coordinator from stopping. Statement time cannot predate the old definition;
the restart definition must already exist at that time. These are consistency
checks, not a trusted clock. Historical inspection rechecks every governance
edge against its exact predecessor while walking the signed history, avoiding
copied growing inventories. A manually signed wrong-head edge is rejected too.

Tests must cover wrong signer/head/phase, mismatched statement/evidence, missing
or changed restart definition/signature, reused ceremony ID, abort with an
active delivery, every attempted transition after termination, and automatic
inclusion of committed incidents. Production NO-GO-before-finalization remains
a separate required release/decision slice; this change does not claim it works.

### Automatic operational-bundle assembly

Derive the existing bundle-v3 record from an exact authenticated V4 checkpoint,
not user-maintained file lists. Require a frozen final candidate and no final
release. Sort every signed-record collection by logical record name. For each
accepted turn, use its exact committed chain prefix, input receipt and original
handoff, accepted return handoff/receipt, and matching mirror records. Use the
committed closures, witness records and multi-relay raw evidence for each phase.
Include the complete committed enrollment collection, including roster members
who did not contribute in a threshold rehearsal. Run the existing unsigned
bundle verifier before returning anything for review/signing. This operation
does not sign, upload, or repeat contribution mathematics.

Audit collection remains separate from this unchanged bundle format; the final
signing gate enforces its full minimum. Missing custody or enrollment records
must produce a specific missing-evidence error, never a generated replacement.
Committed incidents are included; a terminated checkpoint cannot prepare a
release bundle. V4 remains unreleased until the complete release path works.

### Exact final review, without duplicate contribution replay

First add a read-only V4 review verifier, before enabling release signing. Its
inputs are the independently trusted definition, public staging root, exact
review checkpoint pair, exact coordinator-signed operational bundle pair, and
proposed release time. No caller-supplied audit list or alternate phase paths.

It authenticates the complete checkpoint ancestry, rejects terminated/released
state, finds the committed final-candidate checkpoint and its approved-binary
coordinator replay claim, and checks the exact candidate files with the existing
non-replay candidate verifier. Its closed file inventory must equal the one
committed by final-candidate authoring; extra files and substitutions fail.
Share the existing closed-tree verifier (including its second verification after
the walk), rather than duplicate its filename list. Authenticate and validate the
exact checkpoint-referenced phase chains, closes, beacons and Phase 1 seal; apply
the existing cross-phase round/timing rules and derive both phase summaries for
comparison with the candidate. This is signature/record verification, not
contribution algebra. Preserve the running proof-tool executable-identity gate
separately from the coordinator's claimed executable identity.
Retain frozen R1CS parsing and native/Cardano verifying-key export coherence.
V4 also verifies the published example proof and report claims with that key;
this is not contribution replay. Do not silently add that stronger proof gate
to older released formats or require proving-key regeneration.

Require the bundle pair's canonical `operational/evidence-bundle.json` and `.sig`
names and confined reads. Verify its signature, read its signed assembly time,
then rederive the unchanged bundle from this
exact review checkpoint using that same time, and require byte equality plus
the coordinator signature and original bundle verification. Authenticate all
checkpointed audits in deterministic order and enforce the full signed minimum,
then require a nonzero UTC release time strictly after candidate finalization,
bundle assembly and the latest audit (when audits are enabled). Return a
deterministic unsigned local result containing the exact review checkpoint pair,
final-candidate checkpoint pair, candidate inventory, bundle pair, sorted audit
pairs, replay method/executable digest and release time. It is not authorization
by itself: do not sign, publish or claim freshness from this operation.

This trusts the coordinator's signed claim that full contribution replay was
performed. It verifies every final candidate and required operational evidence
file it uses, but does not independently repeat contribution mathematics or
claim to rehash every unrelated historical payload. Optional independent replay
remains a separate action. Existing V3 signing continues to require that replay.

The later release packager must bind this review checkpoint and the exact
final-candidate checkpoint in FinalTranscript V3. Recheck the same inputs before
signing and conditionally append against that predecessor: a newer checkpoint
requires new review, even if an older bundle still has a valid signature.
Packaging layout and closed publication inventory remain a separate reviewed
implementation step; this read-only API does not activate V4 releases.

### Reviewed release packaging (implementation in progress)

Keep the application key-bundle layout and manifest format unchanged: one copy
of each native key at the release root. FinalTranscript V3 binds the exact V4
review result, including its review and final-candidate checkpoints, operational
bundle, audit pairs, coordinator replay claim and proposed release time.
Inline the review in the transcript; no separate review file is necessary.
The release signature authenticates that transcript through the existing
manifest hash. Older transcript formats must reject these new fields.

Preserve original logical paths for checkpoint history and operational/audit
records. Do not copy every historical contribution payload into the key bundle:
this package verifies the coordinator's replay claim and required records, not
an independent contribution replay. A full replay archive is a separate product.
Derive a sorted, unique `RequiredArtifacts` set from verified history and
evidence: all checkpoint ancestry pairs, the definition pair, candidate files,
bundle pair and verified referenced artifacts, audit pairs, and lifecycle
chain/close/beacon/seal pairs with their raw beacon responses. Include governance
statements through the verified bundle. Conflicting digests at one name fail.
These are source-review dependencies, not the subsequently generated manifest,
signature, transcript or checksum file. Never publish by recursively copying
the input workspace. Test review against a copy of only this set.

The candidate is committed under `final/candidate/`, whereas application keys
remain at the release root. Use a fixed, V4-only mapping of the closed
candidate filename set to root files; do not use symlinks, arbitrary aliases or
caller-controlled path rewrites. Reject conflicting physical destinations and
extra files. Every V4 package read, including audit candidate reads and candidate
prehashes, uses the same rule. The ordinary staging-root mode remains unchanged.
Make an independent checked copy into private staging; no hardlinks, destructive
moves, or copy-on-write dependency. One key copy within the release does not mean
removing the source copy. Recheck copied bytes in staging before
signing, then self-verify the exact signed package before atomically publishing
the local directory. Local package creation is not cloud/public publication.

The final-release checkpoint must use the exact reviewed predecessor; a changed
backend head requires another review. Keep production approval/NO-GO and public
publication separate, including NO-GO when finalization fails. This layout is
independently reviewed; it does not yet enable V4 release signing. In V4 the
retained manifest-v1 `published_at` value means package-finalization time, not
proof of upload or public availability.

The local signing/verifying library is implemented with this fixed layout and
inline transcript binding. Its output directory must be disjoint from the
source tree, including after resolving parent-directory symlinks. Review found
that exact retries could otherwise accept byte-identical destinations containing
external hardlinks: reverify the actual destination after local publication,
including its copied definition pair. A failure then is explicitly committed;
retain the destination rather than deleting it or reporting success. Exact
signing retries currently require retained source-review dependencies; standalone
verification can use the package itself. This does not implement backend
checkpoint append, production approval, or public publication.
Linux ceremony/CLI suites and vet passed the package implementation. A final
focused Linux run and vet passed after the output-separation guard, including
the real tiny signing/retry path and maximum-size transcript tests. These are
single-process historical-beacon fixtures, not live storage or independent roles.

The first dependency-only snapshot test found an implementation mismatch:
the shared operational verifier hashed and returned every historical
genesis/contribution payload as a dependency. The reviewed V4-only correction
omits those historical bytes while preserving the exact signed chain, cleanup,
verification, custody, observer and beacon records. This is schema-dispatched,
not a caller-selectable skip flag. Final review separately requires the exact
coordinator replay claim; a standalone bundle check does not prove that replay.
Released V1–V3 payload checks remain unchanged. The dependency-only test uses
the copied definition/signature too, retaining only the independent public-key
trust anchor externally; missing signed records and raw beacon evidence fail.
The Linux ceremony/CLI suites and vet pass this correction, including explicit
V3 missing-payload rejection and all three V4 real tiny fixture configurations.
Before inlining the dependency inventory into FinalTranscript V3, test its
maximum canonical size against the bounded transcript reader; do not silently
raise all JSON limits or permit a late-signing size failure.

Tests: changed final files, omitted/extra candidate refs, wrong replay binary,
missing/bad bundle signature, old bundle after a new committed incident or
enrollment, partial audit quorum, invalid release time, terminated state, and
successful review with no replay/circuit input. Preserve V1–V3 regression tests.

Apply the same mechanism to Phase 2, enrollments and enabled observer/auditor
evidence. Preserve the signed optional-role minima and configurable future
beacon lead for both rehearsal and production.

Reuse FinalCandidateRecorded as the coordinator replay claim. Freeze the exact
candidate and required evidence for the release signer. Add a release verifier
that checks signatures, hashes, legal transitions and policy without running
the contribution replay. Keep the explicit NO-GO path when replay fails.
The release-signer role remains; removing it is a separate decision.

For the Mac rehearsal's archive verifier, run the Linux verifier inside the
pinned Docker image. Do not execute a Linux binary directly on macOS.

## 5. Verify and publish the compatible pairing

- Model ordinary delay, missing files, duplicate actions, crashes and two local
  writers; distinguish retired delivery from rejected candidate.
- Test wrong signatures, changed payloads, wrong turn/head/identity, rejected
  candidate redelivery and exact acceptance after restart.
- Run a complete tiny ceremony through the actual role menus with optional
  roles disabled, plus an enabled-role run exercising evidence requirements.
- Test S3 and R2 partial uploads, renewal, conditional writes and timeout recovery.
- Run one independent adversarial review against this agreed trust model.
- Merge/release proof-tool, verify both architecture assets and provenance,
  pin them in Relay, then retest the released pairing before merging Relay.
- Update the versioned Tessera contract and compatibility fixtures, test its
  integration, then release Relay and provision/deploy the exact pairing.

Passing the existing PR CI demonstrates the earlier implementation only.
The new journey is complete when the tests above pass with the revised schemas
and normal CLI, and users can proceed without manual file-placement knowledge.
