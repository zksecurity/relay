# Trusted coordinator and storage: next implementation

Status: planning only, September 16, 2026. No implementation is authorized by
this document itself. It follows the
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

Still required: new protocol formats, transport-neutral acceptance and rejection,
the new signer verification path, normal role-menu integration, full role
rehearsals, live-provider testing and release/deployment. No existing ceremony
is switched to the new transport by these foundations.

## Existing verification versus planned changes

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
| Component boundary | Proof-tool verifies logical artifacts; Relay maps storage | Local proof-tool experiment still exposes backend object keys |

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
Checkpoint V4 and `storage-first-v2`, with explicitly versioned changed release
claims. These identifiers are not emitted by the first implementation slice.

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
