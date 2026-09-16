# Trusted-storage ceremony V4

Status: proposed replacement for the unreleased Relay V4 journey, September 16,
2026. This design does not change released Definitions V1–V3 or their
checkpoints.

## Why V4 is being simplified

The earlier storage-first protocol retained manual-custody evidence from a model
where the coordinator or delivery service might lie. Our chosen operating model
is narrower:

- the coordinator follows the protocol and performs the required full
  mathematical replay;
- the configured storage service returns committed state and immutable objects
  correctly;
- role operators follow the ceremony instructions and protect their own keys;
- ordinary mistakes, stale local state, interrupted processes, corrupt files and
  concurrent local invocations remain in scope.

Under that model, a participant signature saying “I received these bytes” adds
no cryptographic protection. The contribution command must authenticate and
verify those bytes immediately before it samples secret randomness anyway.
Input and return custody receipts therefore add four signed exchanges without
changing the mathematical result.

V4 removes those exchanges. It keeps the checks that prevent ordinary mistakes
and keeps coordinator replay mandatory.

## Compatibility boundary

Released formats are immutable.

| Format | Meaning |
| --- | --- |
| Definitions V1–V3 | Existing file/manual-storage ceremonies; unchanged |
| Definition V4 + Checkpoint V4 | New trusted-coordinator/trusted-storage workflow described here; unreleased |

V4 uses explicit identifiers. A tool must never infer V4 from missing legacy
fields or fall back to a legacy verifier after V4 authentication fails. The
earlier receipt-based V4 draft was never released and has no compatibility
promise; replace it rather than carrying its custody records forward.

## The complete participant turn

```text
Coordinator commits whose turn it is and allocates one upload attempt
                              |
                              v
Participant synchronizes the signed state and downloads its exact inputs
                              |
                              v
Proof-tool rechecks state, assignment, chain, head and files inside the
isolated contributor immediately before generating randomness
                              |
                              v
Participant contributes, removes the container, confirms cleanup and uploads
the five fixed public candidate files; the manifest is uploaded last
                              |
                              v
Coordinator checks signatures, scope, cleanup claim and contribution math
                              |
                    +---------+---------+
                    |                   |
                    v                   v
          commit exact acceptance   commit exact rejection
                    |                   |
                    v                   v
              next turn/phase       optional new attempt
```

There is no input handoff, participant input receipt, return handoff or
coordinator return receipt in V4.

## Signed allocation

The coordinator's next signed checkpoint is the participant's authorization to
compute. Its transition binds:

- ceremony ID and Definition V4 reference;
- phase and one-based contribution index;
- assigned participant identity, signing key and schedule position;
- exact current accepted-head ID;
- exact signed chain pair and head-payload reference;
- for Phase 2, the exact authenticated Phase 1 seal and required dependency
  boundary;
- a fresh candidate-attempt ID;
- the exact allocation checkpoint pair, previous checkpoint pair and next
  sequence number;
- coordinator allocation time.

Bucket names, object keys, URLs and cloud credentials are Relay concerns. They
do not appear in proof-tool records. Relay deterministically maps the signed
attempt ID to one private upload prefix supplied by the trusted storage setup.

Only one candidate attempt for a turn may be active. Allocating another first
requires a signed retirement or rejection of the previous attempt.

## Participant computation

Relay downloads content-addressed public inputs into a fresh private local
directory. Download-time hashes detect transfer corruption but do not authorize
computation.

Before the contributor container samples randomness, the approved proof-tool
must verify all of the following in one invocation:

1. the independently trusted coordinator key authenticates Definition V4;
2. the exact Checkpoint V4 pair is signed and has valid ancestry;
3. the checkpoint has one active candidate allocation for this participant;
4. the allocation matches the signed schedule, phase, index and current head;
5. the exact chain, chain signature, head payload and Phase 2 dependencies match
   the checkpoint references, including both signed digests and sizes;
6. the local signing key belongs to the assigned participant;
7. the approved runtime and platform match the authenticated definition.

Verification and randomness generation happen in the same network-disabled
process with no user pause. Relay supplies a private, read-only snapshot whose
files cannot be replaced after verification; proof-tool does not reopen mutable
storage paths. The command reports its exact verification depth. Under this
trust model it authenticates the signed state and complete input inventory but
does not replay every earlier contribution before sampling; the coordinator
still performs the mandatory full replay before release. Phase 2 retains the
existing closed-Phase-1 checks required to authenticate its starting state.

The isolated contribution and cleanup behavior remains unchanged: no network,
read-only root, narrow mounts, disabled core dumps/logging, bounded temporary
memory, explicit container identity, forced removal and verified absence.

The public candidate contains exactly:

- `attestation.json`;
- `attestation.sig`;
- `contribution.bin`;
- `erasure.json`;
- `erasure.sig`.

The cleanup record is an authenticated honest-operator claim, not proof that no
copy survives on the host.

## Upload and acceptance

Relay uploads immutable candidate files first and a bounded manifest last. A
missing manifest means the submission is incomplete. Repeating the same upload
may only confirm identical bytes; it must never replace an existing object with
different bytes.

The coordinator accepts only the active attempt and fixed five-file inventory.
Proof-tool then:

- verifies participant signatures and exact turn scope;
- verifies the cleanup record follows contribution creation;
- replays the contribution mathematics from the exact accepted predecessor;
- constructs the exact next signed chain;
- derives a canonical result ID over all five candidate files;
- binds the verification result, accepted chain and result ID into the next
  checkpoint.

Acceptance advances the ceremony. Upload completion alone does not.

If bytes are mathematically or structurally invalid, the coordinator commits a
semantic rejection bound to their complete result ID. Those exact bytes can
never later be accepted. Producing new candidate bytes requires an explicit
operator-approved fresh computation and is never an automatic retry.

Transport failure is different. Candidate identity excludes the transport
attempt ID, so an identical candidate can be re-uploaded under a replacement
attempt after the old upload attempt is signed as retired. Grant expiry renews
the same attempt and is not a rejection. Attempt history is append-only and
bounded, and one turn has at most one active attempt.

## Recovery rules

- Synchronization and downloads are read-only and may be repeated into fresh
  directories.
- Relay records the exact contribution operation before creating the container.
  An uncertain operation is inspected; it is never automatically repeated.
- Relay records the exact upload attempt and manifest before network mutation.
  Restart compares remote bytes before continuing.
- Coordinator verification durably records the exact result ID and current
  root. Immediately before acceptance, Relay re-reads the current root, confirms
  that the allocation remains active, and conditionally publishes a checkpoint
  descending from that root. On a race it revalidates and rebuilds; it never
  merely re-signs stale bytes. Restart distinguishes verified but not signed,
  signed but not published, and published states.
- A newer valid backend checkpoint wins over a stale local suggestion. Local
  pending work is still shown and reconciled; it is not silently discarded.
- An allocation survives unrelated descendant checkpoints only while its
  participant, parent head and scope remain active and no terminal state or
  accepted result supersedes it.
- A running legacy operation always resumes with its original runtime and rules.

## Optional assurance roles

Witnesses, mirrors, ceremony auditors and external security audits remain
independently configurable in the signed policy. Disabled controls create no
assignments, prompts, evidence requirements or empty placeholders. Enabled
controls retain their existing signed evidence semantics.

Future drand verification remains mandatory even when public witnesses are
disabled. The beacon is part of the mathematical phase transition, while a
witness is an optional independent observation of publication timing.

## Final verification and release

The coordinator must replay the complete accepted transcript and bind that
successful verification to the exact final files. This is not a new requirement
and is not optional.

The release signer remains required. The signer verifies the exact candidate,
definition, checkpoint ancestry, coordinator replay statement, signatures,
policy and required enabled evidence. Repeating the complete contribution
mathematics is optional for the signer only when the signed V4 policy selects
coordinator-replay review. A replay-required policy remains available; this is
never inferred from a CLI flag or missing field.

The V4 operational bundle contains accepted chains, participant contribution and
cleanup records, coordinator replay evidence, each signed phase beacon with its
one verified raw drand response, and any enabled observer/audit evidence. A
second drand endpoint is only an availability fallback. It contains no
input/return custody records.

V4 uses explicit V4 bundle, final-transcript, decision and release schemas.
Removed custody fields are absent, not encoded as empty legacy fields. V1–V3
validators remain schema-dispatched and unchanged. Evidence for a disabled
optional role is rejected; enabled roles must meet the minima signed in the
definition.

Only the exact private review package approved by the release signer may be
copied into public storage.

## Role guidance derived from backend state

On every startup Relay authenticates the newest checkpoint returned by the
configured storage service, then combines it with retained local operation
state. Guidance is deterministic:

| Authenticated state | Participant instruction | Coordinator instruction |
| --- | --- | --- |
| no active allocation | wait | allocate the next scheduled turn |
| active allocation for this participant | verify inputs and contribute | wait for the manifest |
| complete candidate manifest | wait for acceptance | verify and accept or reject |
| accepted result ID matches local candidate | turn complete | proceed to next turn or closure |
| rejected result ID matches local candidate | preserve diagnostics; do not retry those bytes | optionally allocate a fresh attempt |
| local operation outcome uncertain | inspect exact retained operation | inspect exact retained operation |

No notification age changes these rules. Notifications only prompt a refresh;
the signed backend state determines the action.

## Required invariants

1. A contribution cannot start without an active signed allocation for its exact
   participant, phase, index and parent head.
2. Proof-tool rechecks allocation and every input in the contributor invocation,
   before randomness exists.
3. At most one active candidate attempt exists for a turn.
4. Transport retirement may re-upload the same candidate; semantic rejection
   permanently forbids accepting that result ID. New bytes require an explicit
   fresh-computation decision.
5. Upload success never means acceptance.
6. Acceptance always includes full mathematical verification and advances from
   the exact signed predecessor.
7. Rejected result IDs cannot later be accepted.
8. Coordinator full replay remains mandatory before final release.
9. Release-signer replay is optional, but the signer role and exact approval
   signature remain mandatory.
10. V1–V3 verification behavior remains byte-for-byte compatible.
11. Contribution creation follows allocation time; cleanup follows contribution;
    acceptance follows cleanup. Unsigned manifest timestamps do not establish
    ceremony chronology.
12. A manifest is only a discovery marker. The coordinator rehashes and
    authenticates every referenced file before mathematical verification.

## Implementation order

1. Replace the unreleased receipt-based Definition/Checkpoint V4 draft while
   leaving released V1–V3 behavior unchanged.
2. Implement and exhaustively test the short allocation/acceptance state machine
   in proof-tool.
3. Add one proof-tool command that verifies allocation and inputs and then starts
   the existing isolated contribution.
4. Add V4 bundle/review/decision/release schemas without custody fields.
5. Route Relay's normal V4 participant and coordinator guides through the new
   states and crash journal.
6. Run complete tiny rehearsals, live S3 and R2 journeys, adversarial review and
   production-sized benchmarks.
7. Release proof-tool, pin and release Relay, then provision the compatible
   Tessera release without altering existing frozen ceremonies.
