# Trusted coordinator and storage: next implementation

Status: implementation in progress, September 16, 2026. This document is not
release evidence or authorization by itself. It follows the
[storage-first design](storage-first-ceremony-design.md) and
[release verification model](release-verification-trust-model.md).

The trusted coordinator/storage review removed custody receipts from the next
format. The normative replacement is
[Trusted-storage ceremony V4](trusted-storage-v4-design.md). Definitions and
Checkpoints V1–V3 are released compatibility formats and remain unchanged. The
earlier receipt-based V4 draft is unreleased and will be replaced rather than
preserved.

## What we trust

The coordinator follows ceremony rules and runs mathematical verification.
The configured storage service returns committed state and stored objects
according to its API. Participant inputs still require verification.
Ordinary failures, incorrect local files and concurrent processes remain in scope.

## Implementation progress — September 16

Normal V4 guide startup now authenticates and binds saved profiles, opens its
separate journal, and refreshes backend stage/turn metadata. This read-only
view does not execute turns; connecting those actions remains the next task.
Independent review corrected phase-specific participant handling and kept
pending local work visible when storage is unavailable. Legacy guides are unchanged.

The normal participant guide can now fetch receipt inputs for its active turn
from exact committed references. Fresh staging has no operation-completion marker;
after interruption, another read-only fetch is safe and does not overwrite earlier
copies. SHA-256/size checks are transport checks; proof-tool still checks signatures
and both signed digests before receipt signing. This is not a computation-ready
Phase 2 transcript. Receipt signing, its later dependency staging, and production
large-object transfer timeouts remain required integration work.

Current boundary: proof-tool's V4 library and explicit CLI now cover checkpoint
authoring, checkpoint-bound bundle preparation/signing, final review, package
signing/verification and Decision V3. These changes are pushed, not released.
The evidence CLI slice is `5c143c5`; full Linux ceremony/CLI suites and vet pass.
Its real tiny artifact test invokes the approved CLI and rejects a modified
executable before output/key access. This is not a normal-role storage journey
or a production K21 approval test. Those, provider tests and releases remain.

The entries below record implementation stages, not independent release claims.
The initial compatibility/transport slice established:

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

Witness evidence has a typed edge when witnesses are enabled. The ordinary
signed phase-beacon record binds one raw drand response to the committed future
round and is sufficient after proof-tool verifies the drand signature. Relay
tries a second endpoint only when the first is unavailable or invalid; it does
not create a separate two-operator evidence record. Witnesses are optional and
are not part of the initial storage-first role journey.

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
- Add typed evidence-recorded edges for enrollments, optional mirror/witness
  receipts, audits and applicable governance. They preserve
  protocol progress and deliveries. Derive readiness from authenticated ancestry
  rather than storing duplicate mutable counters. Do not count disabled controls.
- Preserve cross-phase beacon separation at checkpoint preparation, not merely
  at final release. Exact-read the preceding Phase 1 records; reject reused
  rounds/challenges and inconsistent chronology. Test with a signed bad closure.
- The review's enrollment-ceiling concern was withdrawn after checking the
  actual constants: 20 participants and 20 per auditor/observer category yield
  at most 82 required enrollments, below the existing 128 limit. A regression
  assertion guards that bound; no bundle-schema change is needed for capacity.

Gate outbound delivery on participant enrollment, closure on each enabled
head-mirror minimum, sealing/final-candidate preparation on any enabled witness
minimum and the ordinary signed beacon, and release signing on enrollment,
bundle and any enabled exact-candidate audits.
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
| Release signer | Check files, signatures, policy and coordinator claim; replay optional | Explicit V4 signing/verifying exists; normal Relay flow pending. Released V3 still requires signer replay |
| Participant upload | Existing signed receipt, contribution and cleanup records | V4 protocol exists; Relay's normal journey still uses the old envelope flow |
| Acceptance | Checkpoint commits outcome and exact artifact references | V4 authoring verifies this; normal Relay integration pending |
| Storage progress | Current provider root drives normal CLI | Advanced sync exists; normal role journeys incomplete |
| Retry | Redeliver identical valid files; candidate rejection persists by digest | V4 library semantics tested; normal role delivery/recovery integration pending |
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
Decision V3 is required for Definition V4/transcript V3; released Decision V2
keeps its original behavior. Explicit proof-tool initialization can opt into V4,
but Relay's normal initialization does not yet select it.
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

Reviewed sync bridge (implementation in progress): authenticate a separate
`inspect definition-protocol` projection before selecting the exact V4 /
`storage-first-v2` / `coordinator-full-replay-v1` tuple. Never interpret an
inspection failure as permission to fall back. Existing pinned tools keep
their old command path; ordinary `inspect definition` output stays unchanged.

For V4, `checkpoint inspect-signed-v4` authenticates one pair and reveals only
its predecessor, bounded governance dependencies needed by stored verification,
and a separately labelled enrollment pair for guidance. This discovery result
is not usable ceremony progress. Stage the complete ancestry and enrollment
pairs, then call `inspect-enrollments-v4` once for both structural verification
and enrollment metadata before recording local high-water state or returning
a usable snapshot. Structural-only callers can still use `verify-stored-v4`.
Do not fetch cumulative
contribution payloads during sync. The sequence limit is 16,384 (16,385 records
including genesis), not the legacy sync cap. Fresh-copy contract tests verify
that the discovered dependencies suffice and each required missing file fails.

The proof-tool discovery slice is pushed in `9841387` with command coverage in
`47ba50e`. Full Linux ceremony/CLI suites and vet pass; the strengthened
dependency-only, format-dispatch and CLI tests also pass in Linux.
The Relay adapter and separate V4 synchronizer pass targeted tests, including
partial high-water persistence and restart; normal menus are not connected yet.
The next role recommender must use progress, delivery
history and committed evidence—not the last transition name, because unrelated
evidence may arrive during an active participant turn. Derive evidence facts
from verified ancestry and label coordinator commitments separately from
independently reverified record contents. Keep the existing mutation journal,
exact-byte uploads and conditional root commit; no automatic reparenting.

The reviewed record-index slice keeps all outbound packets for each exact turn,
newest first, plus its accepted input receipt and accepted chain/result. An
accepted receipt may name an older packet; its signed hash selects that packet,
not the newest publication or current upload attempt. An unrelated enrollment
edge and delivery reallocation do not erase prior commitments.
The batch enrollment inspection verifies exactly the checkpoint's
committed enrollment set and signed disclosure references. Disclosure contents
and roster completeness are not part of this check. One ancestry walk returns
separately labelled structural and enrollment results. If download or metadata
verification fails, high-water is not advanced and no guidance-capable snapshot
is returned. Interrupted persistence after successful verification can resume.
Returned facts are immutable copies.
Normal role actions and a full storage-backed journey still remain to implement.
The index/metadata slice passes the full Relay Go tests and vet, plus focused
race tests. Proof-tool's Linux core and actual CLI suites and vet pass, including
nonempty enrollment inspection and missing/changed signature failures. Tests
cover retained older outbounds, reallocation, exact-set/head comparisons,
metadata failure/retry and single-command combined verification. These are
component/CLI checks, not a completed storage-backed role rehearsal.

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

### Reviewed next slice: normal V4 turn guidance

Use authenticated definition requirements and the verified V4 snapshot, not
the latest transition name. Start with coordinator/participant turns in both
phases; unsupported closure, beacon, final and terminal actions must remain
explicitly unavailable rather than falling back to legacy guidance.

- Opening an outbound turn requires that scheduled participant's committed
  enrollment, matching proof-tool. Other missing enrollments remain visible as
  parallel work; do not invent an all-roster gate before every contribution.
- Protocol artifacts bind the exact ceremony/phase/index/participant/parent
  and their own content hashes. They survive unrelated checkpoint updates and
  transport retirement. Grants and uploads also bind the exact attempt.
- Pending checkpoint writes retain their exact predecessor and root version.
  An unrelated update can preserve the turn while invalidating that proposal;
  never silently reparent a signed write.
- Before a receipt exists, suggest the newest outbound packet. After signing
  or accepting a receipt, follow its signed handoff hash, including an older
  valid packet. Only signed checkpoint receipt acceptance permits computation.
- Retired uploads can reuse exact retained protocol artifacts on a new attempt.
  A rejected candidate result cannot be reused; show its rejected state and
  require explicit investigation/new work. Never recompute automatically.
- Completion compares the accepted chain's contribution-result ID with the
  exact local result. A different result or missing local result is not local
  completion. Earlier participants see their own accepted/rejected turn, not
  the current participant's task.
- Re-sync before mutation and check scope, attempt, closure and terminal state.
  Recommendation is not authorization; command verification and conditional
  root updates still enforce the operation's exact inputs.

Tests must branch through unrelated enrollments, old-packet receipts, receipt
and candidate reallocation, rejection, same/different-result acceptance, grant
expiry, abort/restart, previous participants reopening, missing metadata and a
changed root between recommendation and execution. The independent review
removed an unnecessary all-roster gate and separated artifact, upload-attempt
and checkpoint-write bindings before implementation.

The turn model and pure recommender are implemented for both phases. They are
not yet connected to the normal menu/executor or durable V4 fact reconstruction.
The code review added two recovery checks: every recorded upload must match
the exact retained delivery kind/artifact, and coordinator acceptance explicitly
follows download/check → sign return receipt → verify/accept. A replacement
candidate attempt requires comparing the newly received submission before
reusing an existing result/receipt. Tests cover missing local result facts,
unknown/mislabelled uploads, historical receipt uploads, replacement deliveries,
grant expiry, rejected results and exact-result completion. A pending operation
must be surfaced from the durable journal before selecting ordinary turn work;
never manufacture empty local facts by ignoring a reconstruction failure.

The participant's computed inventory contains five files. The final upload
inventory contains those same five plus the signed return handoff, so the two
IDs differ. Reconstruct both in one proof-tool inspection; verify that the
return handoff names the exact computed files. Five files mean prepare/recover
the return packet, never compute again. A partial pair or final ID without
verified computation facts means inspect retained work. Upload, rejection and
acceptance comparisons use only the final seven-file ID. Coordinator downloads
may have a final ID without a separately retained computation-stage marker.
Inspection must match the expected turn, preserve signature/software/chronology
checks, and make no mathematics, freshness or physical-erasure claim. Rehash
the returned closed inventory at upload; inspection does not freeze file paths.

### Reviewed execution and restart integration

Select `workflow-v4/state.json` only after authenticating the V4 definition;
V1–V3 keep `workflow/state.json` unchanged. Bind the new state to the exact
definition pair, ceremony, workspace and role identity. Reuse atomic saves,
workspace locking, input hashing and coordinator commit durability—not legacy
catalog stages, phase1-only local facts or generic retry dispatch.

Persist a bounded operation record before launching anything: local operation
ID and closed action kind, exact turn/predecessor, original runtime/mounts,
command, inputs and expected output paths. Delivery attempts are separate from
local operation IDs. Scope-only computation and return signing survive delivery
reallocation; grants and uploads do not. Keep immutable predecessor copies and
attempt-specific download directories rather than mutable “current” paths.

Hold the workspace lock across loading, sync, recommendation and execution.
Only a prepared operation is known not to have launched. Running, cancelled or
failed children remain uncertain until exact output inspection. Saved success
is a locator, not proof: reverify artifacts before deriving guidance. A sync
failure may allow local inspection of retained work, never new ceremony work.

Coordinator actions also retain the existing commit-journal link: child success
does not mean publication. Confirm the exact authenticated child and root CAS;
on a conflict, sync and inspect without reparenting the signed child. Participant
upload success means only uploaded files/manifest, not contribution acceptance.
Test crashes at each save/launch/output/upload/CAS boundary, backend advancement,
grant expiry, partial five/seven-file output and isolation from legacy journals.

The journal foundation is implemented in `cmd/relay/workflow_v4_journal.go`;
normal menu execution is not connected yet. Its separate create-only workspace
marker binds the exact state location, definition pair and role. The state is
limited to 16 MiB and 8,192 operations; legacy atomic saves retain their 1 MiB
limit. Strict reading rejects duplicate/unknown fields and non-private files.
Failed saves disable the current handle, because a rename may have succeeded
before fsync reported failure. Reopening reads the durable status. Prepared
operations can be abandoned only with no declared outputs; running work requires
exact-result inspection. Coordinator reconciliation also checks the complete
saved publication plan and committed conditional-write status, in addition to
the caller's live artifact/publication verification. These local records are
not cryptographic proof or permission to skip revalidation.

Review tightened the journal's integration contract: its header also pins the
approved runtime profiles, and opening checks the role against authenticated
roster metadata plus the exact authenticated definition pair. Computation and
record-signing commands must match their kind, retained input/output paths and
reviewed record hash. Receipt downloads are a separate attempt-bound operation.
Publication journals use `workflow-v4/commits/<operation-id>.json`, and their
initial output list must equal the outer operation's output list. Network and
coordinated-publication handlers use fixed internal dispatch tokens, not a shell
command. Those handlers remain to be implemented: they must consume only the
saved plan, and persist each actual checkpoint/signing child command before it
runs. The local journal tests do not establish that handler integration.
Before menu wiring, replace generic reconciliation callbacks with closed
per-kind artifact/publication reconcilers and test every handler's interruption
boundaries. A second independent review found no remaining material defect in
the journal foundation; it did not review those still-unimplemented handlers.

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
committed closures, ordinary signed beacon and its single verified raw drand
response, plus witness records only when witnessing is enabled.
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
trust anchor externally; missing signed records and the signed beacon's exact raw
drand response fail.
The Linux ceremony/CLI suites and vet pass this correction, including explicit
V3 missing-payload rejection and all three V4 real tiny fixture configurations.
Before inlining the dependency inventory into FinalTranscript V3, test its
maximum canonical size against the bounded transcript reader; do not silently
raise all JSON limits or permit a late-signing size failure.

### Record the signed private package

Commit five small references under the fixed `final/release/` location: manifest
and signature as the transition pair, plus transcript, exact release checksums,
and bundled public key as evidence. The transcript itself can be large; only its
reference is small. Do not copy the full packaged checkpoint history into the
outer checkpoint's accepted-artifact inventory again.

Before authoring this edge, verify the complete closed package and require its
embedded review checkpoint to equal the exact predecessor pair, including the
signature. Its final-candidate checkpoint must equal authenticated history.
The release signer binds manifest → transcript → reviewed dependencies, while
the coordinator checkpoint additionally binds the exact checksum file. Those
checks cover the full package, not merely its five bootstrap files.

Keep names in two explicit scopes: package-relative artifact names and the fixed
ceremony-relative package prefix. Return a typed inventory with that prefix and
the complete package-relative references; one locator constructs download paths.
Do not double-prefix names or describe the five initial files as the whole
download. GO/NO-GO and public publication remain separate, later actions.

Review identified two maximum-size constraints. The V4 checksum list also needs
a dedicated derived bound: `(maximum review dependencies + 5) × (64 hash bytes
+ 2 spaces + 512 filename bytes + newline)`, without widening legacy readers.
Test its exact maximum and rejection above the bound. The outer V4 checkpoint
must also reserve capacity for the five final references; do not let a legal
pre-release inventory become impossible to finish. Keep legacy limits unchanged.
Allow the original accepted-artifact limit plus five only for the V4
`final-release-recorded` transition, not merely because a progress field is set.
Test an exactly-full predecessor, pre-release overflow, and an extra sixth
final reference. Package-relative names retain their 512-byte bound; the
transport validates the separately constructed prefix-plus-name object key.

The dedicated checksum bound is implemented in proof-tool `e8a1c95`. The exact
maximum-size parser/reader test and over-limit negative pass; existing readers
retain their original limit. Full Linux ceremony and CLI suites plus vet pass
(106.159 s and 46.561 s for the suites). Those results verify the checksum
change; the later final-release edge is tracked separately below.

The final-release library edge is now implemented. Its full verifier returns
all package files through read-only inventory accessors; the fixed prefix is
separate. Review caught that exported mutable inventory fields could let a
caller replace the verifier's membership, so those fields are private and slice
accessors return copies. Structural stored-state inspection deliberately does
not imply full package verification. The real tiny fixture exercises both
boundaries: a changed final key leaves signed-state inspection valid but makes
the full package check fail. Normal CLI/backend wiring remains pending.

The sequence bound has headroom: every non-delivery edge needs at least a fresh
signed pair (governance also rejects already-committed records), while a delivery
slot can be allocated once and become terminal once. Even counting these
separately and adding the final edge remains below the sequence limit. A unit
test ties that inequality to the protocol constants; it is not a full journey
model-checking result.

Validation: the Linux ceremony/CLI suites and vet passed this edge (109.342 s
and 46.008 s). After the read-only inventory fix, all three real tiny V4 fixture
configurations, boundary units and vet passed again (85.349 s). These use known
test keys and historical beacon responses, not independent operators or live
storage. The package and checkpoint remain private local test outputs.

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

### Reviewed production-decision integration (next)

Use a separate Decision V3 and draft V3 for Definition V4. Preserve released
decision structs, hash domains, limits and V1–V3 definition dispatch. Review
confirmed the old enumerated release list, 16 MiB transcript reader and old
checksum layout cannot represent every valid new package.

- Bind the exact final-release checkpoint pair and ceremony under a new release
  ID domain. Include the candidate ID for readable review and verify it against
  the package. Do not enumerate package files again or accept another manifest.
- V4 preparation and evidence verification call
  `VerifyFinalReleaseCheckpointV4` against authenticated trust and the exact
  artifact root. This checks the complete private package, coordinator replay
  claim, mandatory release signature and enabled assurance evidence without
  repeating contribution mathematics.
- Derive the ceremony-auditor signer list from the package; if the decision
  includes that list for readability, require exact equality. Do not duplicate
  the operational bundle or audit files as a second evidence source.
- GO needs the coordinator, release signer and every package-bound ceremony
  auditor. With audits disabled, only the first two sign; reject extra signers.
  Witnesses and mirrors do not sign this decision.
- Preserve the existing external production gates and their explicit evidence:
  source release, exact K=21 rehearsal, deployment plan, formal checklist,
  external security reviews and operational claims. Package verification
  supplies package-derived gates without redundant hand-entered URL arrays.
  Disabled assurance gates remain exactly `NOT_REQUIRED`.
- Never include private access URLs or credentials. The compact package binding
  uses logical names and digests; trusted delivery maps those to storage.
  Require the decision time to be no earlier than package finalization.
- Before a final package exists, NO-GO uses the authenticated abort path; do not
  manufacture empty release evidence. A post-package NO-GO binds the same exact
  checkpoint but cannot authorize publication. Public publication is separate
  and requires verified GO.

Tests must reject cross-version dispatch, wrong checkpoint/candidate, corrupt
package, missing/extra auditor or other signatures, altered assurance policy,
credential-bearing evidence URLs and a decision predating the release. Preserve
all existing decision tests. New APIs must not accept a contribution-replay
callback or circuit input; independent replay remains a separate optional task.

Further review: released source evidence hard-requires an OpenPGP tag, which
does not fit the already agreed protected-main CI release model. Decision V3
instead uses `source_commit` and a plain `verification_report` artifact, with a
separate V3-only `source-release` gate bound to that same report. The existing
`signed-release` gate means the ceremony package, not its source provenance.
All new external evidence references are logical names/digests, not URLs.
Proof-tool bounds and hashes the report and checks the source commit; it does
not contact GitHub or interpret a delivery-tool-specific report schema. Relay
must validate and display the report's exact commit, repository, workflow and
result before approval, never auto-pass it merely because the file exists.
Keep the reviewed source report at `decision/evidence/source-release.json`;
other decision evidence lives under `decision/evidence/` with collision checks,
separate from `final/release/`. Preserve the old source-evidence format unchanged.

Decision V3 core APIs are implemented. Review tightened production-mode
dispatch, fixed package-derived gates to PASS, bound structured gate entries to
their exact report fields, and rejected mixing a package verified after a
trust-file replacement with the initially authenticated definition. GO requires
the exact coordinator/release-signer/package-auditor signature set. Early NO-GO
still uses abort; post-package NO-GO must identify an external/review failure.
Tests cover canonical/version boundaries, source/policy/candidate/time binding,
real known-key Ed25519 thresholds and external signoffs, and fail-closed missing
packages. A real K21 package through the full public approval APIs, CLI wiring
and public publication are still pending; do not claim production readiness.
The Linux ceremony/CLI regression suites and vet passed (111.090 s and
48.328 s). After the final mixed-definition fix, the focused new/legacy decision
tests and vet passed in Linux (1.638 s); native decision units also pass. These
are record/signature/evidence tests, not a production GO claim.

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
