# Storage-first ceremony workflow

Status: proposed design for a clean implementation from current `main`. The
experimental ZIP-first branch remains a reference; it is not the base for this
implementation.

This document defines the normal way Relay roles discover ceremony progress and
exchange public artifacts. S3 or R2 is the shared transport. ZIP packages remain
an explicit fallback for a deliberately offline machine or an unavailable
backend.

## Outcome

After the initial trust setup, a connected role should normally need only:

- its own local signing key and identity;
- the independently confirmed coordinator-key fingerprint, ceremony ID and
  approved Relay release;
- the public storage address; and
- typed temporary private access when that role needs to upload a submission,
  read protected review material, or publish an approved release.

When the role opens Relay, the CLI synchronizes from storage, authenticates what
it finds, and answers:

1. Which ceremony is this?
2. Which phase is active?
3. What authenticated transcript head is storage currently showing?
4. Whose participant turn is next?
5. What has this role completed, and what must it do next?

Users should not move individual files into Relay's internal directories or be
expected to know names such as `chain-0001.json`.

Witness, mirror, ceremony-auditor and external-security-audit requirements are
chosen before initialization and signed into the ceremony definition. Any of
them may be disabled, including for production. Relay must not create, display
or wait for a disabled role's work.

The precise promise is:

> Every connected role derives the authenticated public ceremony position from
> storage. It derives its next instruction from that position plus its local
> identity, independently confirmed trust, private access and locally verified
> facts.

Storage cannot reveal that a host was disconnected, a mirror really retained a
copy, a witness first observed something at a particular time, or a private
grant was received. Relay tracks those facts locally or in explicit signed
records instead of guessing them.

## Security boundary

Storage is a courier, not an authority.

An object existing in S3 or R2 does not prove that it is valid, current,
accepted, or complete. Relay trusts only artifacts whose exact bytes are bound
by the ceremony's signatures and hashes. A mutable storage index may tell Relay
where to look, but it cannot authorize a contribution, close a phase, approve a
release, or complete a role's task.

Relay therefore distinguishes:

| Observation | Meaning |
| --- | --- |
| Object listed | Something is available to inspect |
| Hash matched | The downloaded bytes are the named bytes |
| Signature verified | The stated signer approved those exact bytes |
| Protocol checks passed | The artifact is valid for this ceremony and position |
| Accepted record published | The ceremony advanced to include that exact artifact |

Private signing keys, long-lived storage credentials and contribution
randomness never enter shared storage. Temporary upload grants remain private
and narrowly scoped.

## Signed assurance policy

The definition contains these four mandatory integer minima:

```json
"assurance_policy": {
  "public_witnesses_per_phase": 0,
  "mirrors_per_accepted_head": 0,
  "passing_ceremony_audits": 0,
  "external_security_audit_signoffs": 0
}
```

Zero disables that control. A positive value requires at least that many
distinct, valid records. Missing is never interpreted as zero. The definition
validator bounds every minimum and rejects an audit minimum larger than its
frozen auditor roster. When ceremony audits are disabled, that roster must be
empty. Witness and mirror identities may enroll after initialization: a signed
checkpoint must contain enough distinct witness assignments, enrollments and
readiness records before an enabled phase can close. Mirror assignments reserve
known future phase/index slots before the corresponding candidate is accepted;
their later receipts bind the resulting exact accepted head. When either
minimum is zero, its post-definition assignments are forbidden. Later evidence
must agree with the same signed policy.

Witness and mirror minima have fixed protocol maxima even though their
identities are assigned later. Distinctness is required within each quorum. One
identity may serve both phases or retain multiple heads, but it must have a
separate assignment and signed record for each exact scope. An enabled mirror
must be assigned and enrolled for that phase/index before its receipt can be
accepted. Listed ceremony auditors are eligible; at least the signed minimum
must enroll and submit passing reports, and every accepted report requires its
author's enrollment. `external_security_audit_signoffs` is a production-only
control and must be exactly zero in a rehearsal definition.

When a control is enabled, every supplied record is verified even when it
exceeds the minimum. Evidence from a disabled role is rejected rather than
silently ignored, keeping the final inventory closed and unambiguous. External
security-audit signoffs are a separate production control, not ceremony-role
enrollments.

The signed definition is the sole policy authority. An operational bundle may
not choose, copy with changes, or lower these minima. It either omits a policy
copy and is verified against the definition, or carries the complete canonical
policy plus definition digest and must match both exactly. Every checkpoint
that displays the policy must match the authenticated definition exactly before
Relay derives state. A bootstrap-capsule copy is only a preflight display hint;
Relay blocks if it differs from the subsequently authenticated definition.

New signed schemas represent disabled evidence collections as explicit empty
arrays. Omitted arrays are invalid and never mean disabled. When a control is
enabled, every supplied artifact is verified even above the minimum. When it is
disabled, any assignment, grant, enrollment, receipt, report or signoff for
that control is a policy contradiction and is rejected.

Disabling these controls does not weaken contribution mathematics, signed
transcript verification, cleanup acknowledgements, future-beacon verification,
coordinator approval or final release-signing requirements. It deliberately
removes different independent assurances:

| Disabled control | Assurance no longer provided |
| --- | --- |
| Public witnesses | Independent evidence that closure was publicly visible before the beacon became known |
| Mirrors | Independent retention if the primary backend deletes or withholds data |
| Ceremony audits | Independent replay of this exact ceremony and final parameters |
| External security audits | Independent review of the broader implementation and operating design |

Relay shows this loss when the coordinator chooses the policy, in the final
definition review, and in the final GO/NO-GO review. Other roles see one compact
policy summary. It does not repeat warnings before every command.

## Independent bootstrap

Backend contents alone cannot establish their own trust anchor. Before first
use, each role independently confirms:

- the coordinator public-key fingerprint;
- the ceremony ID;
- the approved Relay release; and
- the public storage origin.

Relay packages the non-secret values into one **bootstrap capsule** containing:

- ceremony ID and public storage origin;
- coordinator public key;
- approved Relay release and workflow schema;
- the signed assurance-policy minima;
- a trusted checkpoint lower-bound sequence and digest; and
- the intended role or invitation reference.

The capsule itself may arrive through storage, email or Tessera, but the role
independently compares the SHA-256 digest of its exact canonical bytes through
the agreed channel. A QR or human-readable authenticated code may be used only
if it preserves at least 128 bits of this digest and displays which fields it
binds; a short user-chosen or checksum-style code is not a trust anchor. An
invitee that already independently confirmed the coordinator key before sending
its identity may instead authenticate its capsule through the signed
setup-complete bridge described below. After that check, the large public files
can travel through storage because Relay verifies them.

A new machine that has never seen the ceremony cannot prove from one storage
server alone that it is seeing the newest signed state. A genuine old state
still has valid signatures. **Trusted ancestry** and **confirmed freshness** are
separate ideas:

- ancestry means the fetched checkpoint equals or descends from the capsule's
  trusted lower bound; and
- freshness means another trusted source confirms that this is the current
  checkpoint, rather than merely a valid old one.

V1 handles this honestly:

- returning machines retain a local high-water mark and reject rollback;
- Relay always rereads and verifies storage when the CLI starts and immediately
  before contribution, signing, grant issuance, acceptance or publication;
- with Tessera, Relay requests the current checkpoint through its authenticated
  HTTPS connection and compares it with storage;
- without Tessera, Relay uses the verified storage checkpoint and local
  high-water history. It clearly says that freshness depends on the configured
  storage provider, but does not require a manual challenge or block normal
  operation; and
- ceremonies wanting stronger protection can optionally require a live signed
  confirmation from the coordinator or an independent mirror. That optional
  confirmation binds the exact checkpoint to a new random challenge generated
  by the CLI, so a saved response cannot be replayed.

There is no user-visible notification expiration or challenge in the normal
workflow. If Relay remains open for a long time, it simply rereads storage—and
Tessera status when configured—before the next important operation.

## Storage layout

The current two-bucket separation remains:

```text
published bucket (publicly readable)
  blob/sha256/<digest>                         immutable bytes
  setup/<provisional-setup-id>/complete.json   signed, create-once bridge
  state/<ceremony-id>/root.json                one mutable discovery hint
  state/<ceremony-id>/phase1/head.json         mutable phase hint
  state/<ceremony-id>/phase2/head.json         mutable phase hint

private inbox bucket
  submissions/<ceremony-id>/<role>/<identity>/<kind>/<attempt>/
    files/<logical path>                       immutable payloads
    manifest.json                              written last

protected review/release staging
  review/<ceremony-id>/<kind>/<attempt>/        final files before GO/NO-GO
```

The three logical planes may use two physical buckets if the private inbox and
review prefixes have separate, tested permissions. Final proving parameters do
not enter the official public release location before an exact GO decision.

| Credential | Minimum access |
| --- | --- |
| Ordinary connected role | Public read; no private access until a typed grant is issued |
| Submission grant | Create plus exact-key HEAD/GET within one preallocated attempt; no list, replace, delete or other prefix |
| Offline-return grant | Create plus exact-key HEAD/GET for one preallocated release-result or decision-signature attempt |
| Coordinator | Authenticated root read/conditional write, published-object create, and exact expected private submissions |
| Enabled auditor/release reviewer | Read only the exact protected review objects named by its grant |
| Upload station | Read only the exact GO-approved review objects; create only in the exact official release prefix; no list, replace, delete or unrelated inbox access |

Provider preflight tests both allowed and denied operations. Storage-provider
administrators remain able to observe or disrupt data; cryptographic checks do
not remove that operational power.

The exact prefix may retain compatible existing names such as `candidates/`,
`operational/`, `audits/`, `releases/` and `decisions/`. The important rules are
semantic, not spelling:

1. Payloads are immutable and content-addressed where public.
2. A submission is discoverable only after its manifest is written last.
3. Mutable state files are hints to immutable content, never proof.
4. Every referenced object is downloaded with a size limit and re-hashed.
5. Existing bytes are never silently replaced.

## Authenticated state graph

Relay should not trust one global `stage` field. A ceremony can have concurrent
work: a mirror may be synchronizing while an auditor waits, and the next
participant may prepare while the coordinator verifies evidence.

Instead, Relay builds an authenticated state graph from protocol artifacts:

```mermaid
flowchart LR
  D[Signed definition and assurance policy] --> E[Core enrollments verified]
  E --> H0[Phase 1 head 0]
  H0 --> O1[Signed outbound handoff]
  O1 --> R1[Signed participant receipt]
  R1 --> C1[Candidate submission]
  C1 --> A1[Accepted Phase 1 head 1]
  A1 --> ON[Next turn or closure]
  ON --> W1[Policy-required witness readiness, or explicit zero]
  W1 --> CL1[Signed Phase 1 closure]
  CL1 --> B1[Verified future beacon]
  B1 --> S1[Signed Phase 1 seal]
  S1 --> H2[Phase 2 head 0]
  H2 --> P2[Phase 2 turns, closure, beacon and seal]
  P2 --> F[Final parameter files]
  F --> AU[Policy-required evidence verified]
  AU --> DEC[Signed production decision]
  DEC --> REL[Published release or private rejection archive]
```

Each node is identified by exact bytes, hashes, signatures and ceremony
position. Edges are protocol prerequisites. The CLI derives a readable global
summary from this graph, then derives a role-specific next action.

### Signed checkpoints and the discovery root

There is one mutable discovery object: `root.json`. It contains only a reference
to an immutable, coordinator-signed checkpoint. The pointer is untrusted; the
checkpoint is authenticated.

Each checkpoint commits to:

- schema and workflow version;
- ceremony ID and approved Relay release;
- all four signed assurance-policy minima;
- a monotonic sequence number;
- the previous checkpoint digest;
- both phase heads and current closure/beacon/seal state;
- the exact accepted public-artifact inventory;
- typed pending submission slots containing kind, assignment/scope, attempt ID,
  expected manifest key, parent checkpoint/head and status;
- accepted or rejected submission acknowledgements; and
- any final decision and release state.

Checkpoint validity includes a deterministic
`ValidateCheckpointTransition(previous, next)` rule. A valid coordinator
signature and previous digest are necessary but not sufficient. The verifier
also requires:

- immutable ceremony, definition, workflow and release identities;
- accepted artifacts and acknowledgements to remain append-only;
- a phase head to extend its authenticated predecessor chain;
- closure only from an allowed head, and the next phase only after a valid seal;
- observer/evidence collections to be recomputed against the signed minima
  from the current indexed authenticated set, not remembered failed checks;
- the checkpoint policy projection to equal the authenticated definition at
  checkpoint zero and every descendant;
- the first outbound turn to follow verified coordinator, release-signer and
  scheduled-participant enrollments;
- each enabled phase closure to follow enough distinct phase-scoped witness
  assignments, enrollments and readiness records;
- each enabled mirror receipt to follow an assignment and enrollment for that
  identity and preallocated phase/index slot, then bind the resulting exact
  accepted head;
- pending submission slots to move only through `allocated`, `accepted`,
  `rejected` or `cancelled`, with replacement attempts explicitly bounded and
  allocated. Temporary credential expiry does not expire an attempt; and
- a terminal GO or NO-GO to be absorbing, except for the narrow post-GO
  publication-confirmation transition.

This versioned transition verifier is shared by state derivation and proof-tool
verification before local high-water state advances.

A checkpoint can name:

- the signed definition and its signature;
- current Phase 1 and Phase 2 head records;
- closure, beacon and seal records;
- published enrollment acknowledgements;
- accepted custody and candidate records;
- witness, mirror and audit evidence accepted for review when enabled;
- the final parameter manifest;
- a production approval or rejection; and
- a published release manifest.

Relay validates the checkpoint's canonical bytes, signature, schema and limits,
then follows only content-addressed references under the bootstrapped storage
origin. It re-hashes each object and asks proof-tool to authenticate the
referenced ceremony records. A signature on the checkpoint does not replace the
artifact's own protocol verification.

Checkpoint publication uploads all immutable objects and the signed checkpoint
first, then moves `root.json` once with a provider-supported conditional write
against the exact ETag/version read earlier. Relay must implement and live-test
real S3 and R2 conditional replacement; a HEAD-then-unconditional-PUT imitation
is not sufficient. Immediately before that write, Relay verifies that the new
checkpoint's `previous_checkpoint` is exactly the checkpoint named by the root
whose durable ETag/version it is using. Recovery repeats the same comparison;
an ETag from a different root read can never commit the checkpoint.

V1 permits one state-changing coordinator workspace. It holds an exclusive
local lock from review through signing and root publication. Cross-machine
coordinator mutation and automatic coordinator failover are unsupported. The
conditional root update detects an unexpected competing writer but cannot undo
two children that were already signed, which is why Relay must not sign from a
second coordinator workspace.

Only the child selected by the committed checkpoint ancestry is accepted. A
signed child that loses the root conditional-write race is a permanent orphan
and is never adopted automatically. Tessera or an optional live confirmation
can detect a backend showing that orphan. A first-time standalone client may
accept a stale or orphaned but valid checkpoint; that is the explicitly
disclosed provider-freshness risk. A returning client rejects it when it
conflicts with its saved high-water history.

The existing per-phase head pointers remain useful for large transcript sync
and compatibility. They are cache hints only: authorization and guide state use
the phase heads committed by one checkpoint. A disagreement is ignored or
repaired; Relay never combines mutable pointers from different snapshots.

Each machine atomically retains `{checkpoint sequence, checkpoint digest}` plus
the phase head and terminal-state digests it has seen. It rejects a lower
sequence, the same sequence with another digest, or a checkpoint that does not
descend from its recorded checkpoint. Numeric contribution counts alone are not
enough to detect forks or a return from Phase 2 to Phase 1.

Only a checkpoint reached through the committed root normally advances this
high-water state. An uploaded-but-orphaned checkpoint, mutable phase hint or
inbox record does not. A trusted external freshness confirmation may explicitly
pin the named checkpoint.

Checkpoint objects, signatures and ancestry are permanent ceremony artifacts in
V1 and are never garbage-collected. The policy bounds checkpoint count and byte
size. A later compaction design would need signed skip links or snapshot
certificates before any ancestor could be removed.

Checkpoint signing runs in the coordinator's network-disabled signing container.
The connected Relay process supplies canonical checkpoint bytes and receives
only the public signature. This is an operational checkpoint signature: every
referenced ceremony artifact still needs its own proof-tool verification.

### Synchronization algorithm

Opening a connected role performs bounded metadata synchronization:

1. Fetch the one root from the bootstrapped origin.
2. Fetch its named immutable checkpoint by digest.
3. Walk every checkpoint missing between the local/bootstrap high-water record
   and the root checkpoint. For each step, verify the checkpoint envelope,
   digest and signature, then fetch and authenticate every small referenced
   artifact required to validate that transition. Missing ancestry, invalid
   inner records, excessive depth or excessive total bytes blocks
   synchronization; verified prefixes are cached.
4. Fetch and authenticate the small records needed to determine this role's
   assignment. A checkpoint signature never substitutes for these protocol
   checks.
5. Only after the complete checkpoint protocol state passes, atomically write
   and sync its digest, sequence and phase-head digests. If this durable write
   fails, Relay permits read-only inspection only.
6. Derive global position, ready/waiting actions and the next instruction.
7. Download large transcript or parameter payloads only when the selected task
   needs them. Mirrors and auditors may request a full synchronization.
8. Immediately before signing, contribution, grant issuance, acceptance or
   publication, reread the root. If it no longer names the expected checkpoint,
   recompute prerequisites instead of continuing from stale input.

Absolute URLs supplied by a checkpoint are rejected. References are safe
relative object keys beneath the independently bootstrapped origin.

The coordinator obtains and conditionally replaces `root.json` through the
authenticated provider API, not a CDN or anonymous public URL. After committing,
it separately verifies that the public origin serves the exact root and
checkpoint.

### Artifact authorship

| Artifact | Signer | What it means |
| --- | --- | --- |
| Definition and initial transcript | Coordinator | Freezes the ceremony, roster, policy and initial state |
| Observer assignment | Coordinator | When enabled, assigns one witness or mirror identity, number and scope |
| Checkpoint | Coordinator | Accepts one coherent graph of already verified artifacts |
| Outbound custody record | Coordinator | Offers exact public input for one participant and parent head |
| Input receipt | Assigned participant | Confirms receipt of those exact input bytes |
| Candidate envelope and optional return handoff | Assigned participant | Submits exact public output and cleanup claim |
| Accepted chain and submission acknowledgement | Coordinator | Accepts that exact output or records a typed rejection |
| Witness or mirror receipt | That assigned observer | When enabled, reports its own observation or retained copy for one exact checkpoint |
| Audit result | Assigned auditor | When enabled, reports verification of the named complete input set |
| Release manifest | Release signer | Signs the exact final file inventory reviewed offline |
| GO or NO-GO decision | Identities required by signed policy | Authorizes only the exact manifest and evidence named |
| Discovery root | Nobody | Locates a checkpoint; it is never authority |

The checkpoint cannot convert an invalid inner artifact into a valid one. Its
signature means the coordinator accepted this coherent set, while the inner
signature identifies who made each underlying claim.

### State used by the guide

For every role, Relay computes four values:

| Value | Contents |
| --- | --- |
| Current state | Verified checkpoint and artifacts, local identity, authenticated assignments, local high-water marks and unresolved local operations |
| Ready actions | Authored actions whose cryptographic and operational prerequisites are satisfied |
| Waiting actions | Authored actions with an exact missing input or another role that must act first |
| Next action | The highest-priority ready required action; if none is ready, the first blocking wait |

File presence alone never satisfies a prerequisite. Verification results are
bound to each file's digest, so replacing a file invalidates the result.

Actions form a dependency graph, not one total list. Authored order is a stable
tie-breaker between ready actions; it is never a heuristic based only on which
files happen to exist. A waiting action does not hide unrelated safe preparation,
but no action may skip an actual predecessor.

The same authenticated facts and role identity must produce the same next
action under the same Relay release.

## Before initialization

A signed ceremony ID and checkpoint do not exist while the coordinator is still
assembling the roster. This is a separate draft lane, and the CLI must call it a
**coordinator draft**, never authenticated ceremony state.

1. The coordinator creates a random provisional setup ID and role invitations.
2. Each invitee independently generates its key and uses a narrow invitation
   grant to upload only `identity.json` to a protected setup inbox.
3. The coordinator reviews the expected identities and roles. The core roster
   and any ceremony auditors are frozen at initialization; enabled witness and
   mirror assignments may be added later under the signed minima.
4. Initialization freezes that roster, assurance policy, storage namespace,
   workflow schema and initial checkpoint.
5. The coordinator publishes a signed, create-once record at
   `setup/<provisional-setup-id>/complete.json` in the publicly readable plane.
   It contains a bounded map from each unguessable invitation ID to that role's
   bootstrap-capsule digest. The random setup and invitation IDs provide
   discovery privacy; the signature and previously confirmed coordinator key
   provide authenticity.
6. Invitees poll that path, verify it with the coordinator key they already
   confirmed, accept only the entry matching their own invitation and identity,
   verify that capsule digest, and continue without a second manual handoff or
   independent digest comparison.
7. Formal proof-of-possession enrollments follow against the signed ceremony.
   Before the first participant turn, a checkpoint verifies the coordinator,
   release-signer and all scheduled-participant enrollments. Witness readiness
   is checked before each enabled phase closure. Mirror assignments reserve
   phase/index slots before candidate acceptance, and their exact-head receipts
   are required before final evidence review.

An invitation grant is tied to one setup ID, role and assignment. Uploading an
identity does not assign or authenticate it; coordinator review and signed
initialization do. If a deployment cannot issue invitation grants, identity JSON
is the one connected-role public handoff allowed through the agreed channel.
An unused provisional invitation is only a draft artifact: it confers no
ceremony role, must expire or be revoked, and never enters a signed checkpoint
or final evidence inventory. The prohibition on disabled-role grants and
assignments applies after the assurance policy is frozen.

## One complete Phase 1 turn

This is the first implementation slice.

### 1. Coordinator publishes the turn

From the authenticated chain head and signed participant schedule, Relay derives
the next participant automatically. The coordinator prepares and signs the
outbound custody record for that exact head and participant. The online Relay
process uploads the record and every named public input, then updates the
signed checkpoint and discovery root.

The coordinator CLI now says that it is waiting for the assigned participant's
signed receipt. It does not offer a grant first.

### 2. Participant discovers and receives it

The participant CLI synchronizes the signed checkpoint and head, confirms that its
identity is next, downloads the exact outbound record and named inputs, and
verifies all hashes and signatures. No manual directory placement is needed.

The participant signs a typed receipt envelope for those exact bytes in the
network-disabled signing container and uploads it to its private inbox prefix.
The signed envelope binds ceremony, definition, role, identity, artifact kind,
phase, turn, parent checkpoint, attempt ID and exact file inventory. The outer
manifest is transport framing, not authentication. The participant retains the
attempt ID locally.

The outbound checkpoint preallocates that receipt attempt and exact expected
manifest key. Tessera or the protected control channel supplies a
receipt-submission grant restricted to it. This is distinct from the later
candidate grant.

### 3. Coordinator verifies the receipt and issues a grant

The coordinator fetches the exact receipt manifest key preallocated in the
outbound checkpoint, downloads it with strict limits, and verifies signer,
ceremony, phase, turn, parent head and file hashes. It publishes a signed
receipt-accepted acknowledgement in the next checkpoint. Only then may Relay
issue the participant's temporary candidate-upload grant through Tessera or the
protected coordination channel.

Before signing the receipt-accepted checkpoint, the coordinator allocates the
candidate attempt ID and commits its exact expected manifest key in that
checkpoint. It then issues the grant for that already committed key.
The grant is never put in the published bucket. It is bound to the exact signed
head, outbound record, receipt-accepted acknowledgement, participant and
candidate attempt ID. Participant credentials
may `HEAD`/`GET`/create objects only within their exact attempt prefix so Relay
can safely resume without giving them bucket-wide `LIST`, overwrite or delete.

### 4. Participant contributes and submits

The participant rechecks the published head immediately before computation.
Relay runs the contribution in its disposable, network-disabled container,
checks container cleanup, creates the signed cleanup acknowledgement and
candidate manifest, and uploads immutable files followed by `manifest.json`.

Upload completion means only **submitted for verification**.

### 5. Coordinator accepts the exact candidate

The coordinator fetches the preallocated candidate manifest, verifies its
identity, assignment, parent head, contribution proof, cleanup acknowledgement
and exact file hashes. The participant's signed candidate envelope is the
return packet. If proof-tool requires a separate return handoff, the participant
creates and signs it and includes it in the same submission; the coordinator
never authors a participant-side custody event.

The coordinator advances the signed chain only for that exact candidate and
publishes a typed signed acceptance acknowledgement. Every acknowledgement
binds the submission kind, identity, assignment/scope, attempt ID and manifest
digest. A rejection uses a non-sensitive reason code and permits a new attempt.

The new accepted chain, acknowledgement and referenced public bytes are uploaded
first; a new signed checkpoint is created and `root.json` moves last.

### 6. Participant confirms acceptance

The participant CLI observes the new signed chain and verifies that the accepted
record contains its exact candidate digest and expected parent head. Only then
does it report **accepted**. A different valid candidate by the same identity
does not complete this task.

```mermaid
sequenceDiagram
  participant C as Coordinator CLI
  participant P as Participant CLI
  participant PUB as Published storage
  participant IN as Private inbox
  C->>PUB: Outbound record + inputs, then checkpoint/root
  P->>PUB: Sync and authenticate current turn
  P->>IN: Signed receipt, manifest last
  C->>IN: Fetch and verify receipt
  C-->>P: Temporary private upload grant
  P->>IN: Candidate + cleanup record, manifest last
  C->>IN: Fetch and verify exact candidate
  C->>PUB: Accepted chain + blobs, then checkpoint/root
  P->>PUB: Verify its exact candidate was accepted
```

## Role-specific inference

The coordinator, at least one participant, and the distinct release signer
remain core roles. Witness, mirror and auditor rows apply only when their signed
minimum is positive. A zero minimum removes the corresponding assignments,
grants, evidence dependencies and guide actions; an empty array alone never
proves that a role is disabled.

If someone directly opens a witness, mirror or auditor launcher that the
authenticated policy disables—or for which that identity has no assignment—
Relay shows read-only ceremony status and **This role is not enabled or assigned
for this ceremony**. It refuses to create assignments, grants, submissions or
completion records from that launcher.

| Role | Reads and authenticates | Writes | Derived next action examples |
| --- | --- | --- | --- |
| Coordinator | Signed public checkpoint graph plus bounded complete private-inbox submissions | Signed operational records, acceptance acknowledgements, accepted transcript state and checkpoints | Publish outbound turn; verify receipt; issue grant; verify candidate; close phase |
| Participant | Definition, assignment, current head, outbound record and later accepted head | Signed receipt, candidate and cleanup record to its private prefix | Wait for turn; acknowledge input; contribute; submit; confirm exact acceptance |
| Witness, if enabled | Definition, signed observer assignment, announced closure and future beacon data | Signed observation to its private prefix | Start watcher; preserve first observation time; observe required interval; submit receipt; wait for acceptance |
| Mirror, if enabled | Definition, signed observer assignment and each authenticated published checkpoint | Signed receipt for its independent destination | Synchronize missing immutable objects; verify exact checkpoint; submit receipt; wait for acceptance |
| Auditor, if enabled | Complete authenticated transcript, expected evidence inventory and protected final files | Signed audit result to its private prefix | Wait for the complete required set; run full verification; submit result; wait for acceptance |
| Release signer | Frozen review checkpoint, exact final files and all policy-required evidence | Signed release ZIP; a separate decision-signature ZIP only if assigned that duty | Independently replay and verify the final files even when audit minima are zero; sign final release; later sign the production decision if assigned |
| Upload station | Offline return ZIP, then terminal GO checkpoint and matching protected release | Preallocated private release-result submission, then approved closed-world public release | Return signer result for coordinator verification; publish only when GO names the exact release bytes |

When enabled, witness and mirror numbers, identities, phases and scopes live in
signed observer assignment records that their CLIs download automatically.
Uploading an identity does not create an assignment. Starting a witness watcher
creates a short-lived signed readiness submission bound to its assignment,
phase, checkpoint and expiry. The coordinator verifies the signed readiness
minimum before closure. This authenticates a readiness claim; it cannot prove
the witness kept watching.

Enabled witnesses, mirrors and auditors infer what work exists from
authenticated public checkpoints. The coordinator does not scan or trust a
role-written submission index. It allocates each attempt in the predecessor
checkpoint before issuing an exact-prefix grant and records the expected
manifest key there. Tessera's submission notification is only a hint to fetch
that already known key.

Replacement attempts are explicitly allocated and bounded; two valid attempts
are never resolved by a timestamp or “latest” heuristic. The coordinator
verifies and selects one exact attempt; a signed acknowledgement records the
outcome. Other roles see their acceptance or rejection in a later checkpoint.
An upload alone never completes their duty. The same pattern applies to
enrollment, witness, mirror, audit, release and decision submissions.

Typed private grants cover three journeys:

- exact-prefix submission writes for participants and observers;
- exact-object protected-review reads for auditors and offline-package staging;
- exact-prefix release promotion after GO.

Tessera supplies them automatically. Standalone mode shows one explicit private
grant import as the missing prerequisite; it never asks the user to move the
public payload files manually.

Every typed grant names the exact checkpoint and attempt it authorizes, so an
already required grant also confirms the operation it belongs to. Standalone V1
does not add a separate manual status exchange before every action.

Mirror destination credentials remain local to an enabled mirror. An enabled
auditor also configures an independent checkpoint source when policy requires
freshness independent of the coordinator backend. These are one-time local
readiness steps, not facts inferred from ceremony storage.

### Future beacon without witnesses

Witnesses and the beacon are independent controls. Even when
`public_witnesses_per_phase` is zero, closure still binds one exact future drand
round. Relay waits for that round, retrieves the required independent relay
responses, verifies the drand signature and applies the randomness. It skips
only witness readiness, observation deadlines and witness receipts.

Without witnesses, nobody independent attests that the closure was publicly
visible before the beacon became known. The coordinator's signed time and
backend history remain evidence, but are not a trusted timestamp. A malicious
coordinator could wait for the round, backdate a closure and publish both
afterward. The future drand mechanism still supplies public randomness when the
honest procedure commits before the round, but Proof-tool cannot establish that
ordering from the coordinator's signature alone. Ceremonies requiring that
assurance must enable witnesses. A future schema could support a separately
trusted commitment-timestamp source only if that source and its rules are
frozen in the signed definition before the relevant closure. An existing no-
witness ceremony can never add this assurance retroactively after the beacon
round is known.

The definition keeps a beacon-round lead rule separate from any witness-
observation window; setting the witness minimum to zero never sets the beacon
lead or `future_round_required` to zero. Verification still checks the exact
committed round, drand signature and required independent relay responses. The
CLI and final decision display that prior public commitment was not
independently established.

### Configurable beacon lead

The coordinator chooses the beacon lead before initialization for both
rehearsal and production. Relay writes it into the policy, Proof-tool signs it
into the ceremony definition, and every later close, checkpoint and release
verifies that exact value. It cannot be changed after initialization.

Relay offers mode-specific defaults rather than hard-coded validity rules:

- rehearsal default: 180 seconds; automated tests may use 12 seconds;
- production default: 24 hours.

A shorter production value is allowed, but the CLI must show the chosen value,
the recommended 24-hour value and the lost review/observation time immediately
before the coordinator signs the definition. It must never silently substitute
a shorter value. If public witnesses are enabled, the existing production
witness-observation window is reserved in addition to the configured beacon
lead, and Relay displays the resulting total minimum close-to-round wait.

This is a new signed-policy behavior. Existing versioned setup contracts and
existing ceremonies keep their original rules. The storage-first Relay setup
contract gets a new version; its guided setup exposes the setting for both
modes and passes it unchanged to Proof-tool.

## Exact approval example

Suppose the final signer reviews release A, whose manifest hash is
`sha256:aaaa...`, and signs **GO** for that hash. A bug or operator later creates
release B with hash `sha256:bbbb...`.

The upload station must reject B even if:

- B belongs to the same ceremony;
- B has a valid release-manifest signature; and
- most files happen to be identical.

Before review, proof-tool validates a closed inventory: required logical names,
counts, sizes, hashes, circuit, curve, backend and key version, with no extra
files. The coordinator then creates a signed **review checkpoint** that freezes
this complete input set. After the freeze, only release, decision, or one
explicit `ReviewCancelled` transition is allowed. Cancellation names the frozen
checkpoint and a non-sensitive reason. Only after it is committed may corrected
evidence be accepted and a new review checkpoint and offline package be created.
Signatures and ZIP returns bound to the cancelled review remain historical
records but can never authorize a decision.

The approval record signs the exact manifest bytes digest—not a parsed
and reserialized copy—and names:

- the ceremony and review checkpoint;
- manifest digest and size;
- final parameter, audit and evidence-bundle digests;
- decision sequence, policy and required signers; and
- destination and release identity.

The production decision retains a fixed, visible gate list. Its status
vocabulary is `PASS`, `FAIL`, `PENDING` and `NOT_REQUIRED`. Gate status is
deterministic:

| Production gate | Signed policy field | Required status when zero | Allowed GO status when positive |
| --- | --- | --- | --- |
| Public witnessing | `public_witnesses_per_phase` | `NOT_REQUIRED` | `PASS` |
| Independent mirrors | `mirrors_per_accepted_head` | `NOT_REQUIRED` | `PASS` |
| Ceremony audits | `passing_ceremony_audits` | `NOT_REQUIRED` | `PASS` |
| External security audit | `external_security_audit_signoffs` | `NOT_REQUIRED` | `PASS` |

Zero requires `NOT_REQUIRED` and an explicit empty evidence inventory; `PASS`
would falsely claim the disabled assurance occurred and is rejected. A positive
minimum forbids `NOT_REQUIRED`, and GO requires `PASS` backed by the exact
policy-required evidence. Every other GO gate must also be `PASS`; a
coordinator cannot weaken this mapping in a later decision.

When `passing_ceremony_audits` is zero, release signing still performs the full
proof-tool replay and exact final-file verification itself. The frozen review
checkpoint binds the candidate, operational bundle and the complete ceremony-
audit and external-audit inventories. Those arrays are explicitly empty when
their minima are zero. When an external minimum is positive, the checkpoint,
release approval and decision all bind the exact closed report/signoff
inventory.

`released_at` must strictly follow the authenticated frozen review checkpoint,
whose creation in turn strictly follows candidate finalization and operational-
bundle assembly. This is the single chronology anchor whether or not audits
exist; verification never compares with a zero timestamp. When enabled, every
supplied audit artifact is signature-, identity- and content-verified even
above the minimum. When disabled, any audit artifact is rejected as a policy
contradiction.

These signed timestamps enforce claimed record ordering and require operators'
clocks to be sane; they are not an external proof of wall-clock time. The exact
checkpoint ancestry and bound artifact digests remain the authorization
boundary.

Decision signatures bind the review checkpoint. The coordinator verifies the
required signatures and creates one **terminal decision checkpoint** descending
from it. The upload station fetches that terminal checkpoint, re-verifies this
dependency set, re-hashes its input and publishes only if every value matches.
Approval of A can never authorize B. An older GO cannot override a later
terminal outcome, and one review checkpoint cannot accept both GO and NO-GO.

In plain language: changing any final file requires a new review and a new
approval.

If the decision is **NO-GO**, Relay may preserve a privacy-checked archive in
protected storage for investigation, but it never publishes the final proving
parameters as an approved release.

The final sequence is explicit:

1. The offline release signer reviews the complete candidate/evidence set and
   returns a signed release manifest.
2. The coordinator verifies it and prepares a decision bound to that manifest.
3. The accountable decision signers sign GO or NO-GO. These are always the
   coordinator and release signer, plus every ceremony auditor whose accepted
   report is bound into the decision. If the release signer is also a decision
   signer, this requires a second offline exchange.
4. The coordinator publishes the one accepted terminal decision checkpoint.
5. A keyless upload station can promote only the exact GO-bound release. It may
   publish only the approved manifest bytes, files enumerated by that manifest,
   required signatures, and a deterministic release pointer derived from the
   decision. Extra sidecars or unreviewed files are rejected.
6. The coordinator independently polls, downloads and verifies the official
   release, then signs the final `ReleasePublished` checkpoint. Until then all
   CLIs say **GO approved; publication not yet verified**. No upload-station
   receipt is treated as authority or added to the approved public inventory.

## Offline signer and ZIP fallback

The final signer is the deliberate exception to live backend inference. Its
machine may be disconnected.

1. An online staging machine synchronizes and authenticates the frozen review
   checkpoint.
2. Relay exports one deterministic `.relay.zip` containing the exact bounded
   input set and a strict manifest.
3. The offline machine verifies the package, approved software and trust
   anchors, then signs the exact result.
4. Relay exports one return ZIP containing only the signed public result.
5. The online upload station imports and re-verifies it, then uploads it through
   a preallocated `release-result` private submission slot. The coordinator
   fetches and verifies that exact manifest before preparing a decision.
6. If the release signer is also a decision signer, its second offline return
   uses a separately preallocated `decision-signature` submission slot.

The ZIP records the source review-checkpoint digest. If that freeze was
explicitly cancelled, the return is rejected and a new package must be reviewed.
ZIP does not become the default for connected roles.

During a storage outage, ZIP may carry already authenticated public inputs for
inspection or preparation, using the same strict manifests. Participant turns,
closure, witness observation, acceptance and publication pause until storage
and any policy-required freshness source return. Only the deliberately offline
final-signer workflow may complete signing while disconnected. There is no
loose-folder mode that asks users to reconstruct Relay paths.

## Failure and recovery

The public backend is the recoverable shared record of accepted public progress.
Most downloaded local files are a verified cache. The coordinator's mutation
journal, every role's unresolved-operation journal, private grants, witness
observation time and local secrets are safety-critical local state and cannot be
reconstructed from public storage.

Coordinator journaling has two durable levels:

1. Before each inner signature, Relay records the operation ID, parent
   checkpoint/root version, signer and scope, digest of the canonical unsigned
   artifact and expected signature path.
2. After signing, Relay verifies and records the resulting signature digest.
   Once every inner reference is fixed, Relay constructs the checkpoint and
   durably records its canonical digest and expected root version before asking
   for the checkpoint signature.

Every journal update uses write, file sync, atomic rename and parent-directory
sync. Startup reconciles the oldest unresolved signature intent before allowing
another signature; it never jumps directly to a replacement checkpoint. Missing
or mismatched coordinator safety state after mutation blocks state-changing
work. The coordinator workspace is not a replaceable cache.

- Downloads go to a staging directory, are size-checked, hashed and
  authenticated, then move atomically into the role workspace.
- Uploads allocate a stable attempt ID before starting. Immutable payloads are
  uploaded first and the manifest last.
- A missing manifest means the submission is incomplete and ignored.
- A retry with the same signed attempt ID verifies any existing remote bytes and
  sends only missing identical objects. Acceptance deduplicates by signed record
  ID, never object path or timestamp.
- A conflicting object is an error; Relay never overwrites it.
- Before a state update, Relay records the expected previous root version,
  attempt/checkpoint ID and exact output digests. After a crash it reads those
  exact objects and the current root. It then adopts the already committed exact
  checkpoint, finishes the same conditional update if the root is unchanged, or
  blocks because another checkpoint won. It never signs a replacement
  acceptance automatically.
- Relay offers one concrete recovery action: continue the safe remaining work,
  inspect an uncertain local result, or wait for another role.
- A read-only verification is re-runnable and its older failure does not block a
  later successful verification of the current bytes.
- Signing, contribution and publication operations retain stricter uncertainty
  handling when the child may have produced output.

### Private grant recovery

Before requesting any temporary credential, Relay durably records:

```text
grant request ID
submission attempt ID and exact prefix
checkpoint digest
requested lifetime
```

Credential generations use separate states:

```text
planned | issued | saved | export shown | delivery reported | expired/revoked
```

Tessera treats the grant request ID idempotently and returns the same unexpired
result. In standalone mode, Relay saves the credential atomically before showing
or exporting it. A saved unexpired credential can be shown again after restart;
Relay never equates that with recipient receipt. If issuance may have succeeded
but cannot be queried, Relay does not create another live credential until the
first is revoked or its maximum lifetime has passed. Delivery to the role
remains a separate private fact or explicit human report.

An expired credential does not force recomputation. Relay renews access only to
the same already committed attempt prefix and resumes the upload. A replacement
contribution requires an explicit new attempt slot and grant.

### What “restart” means

Restart means reopening the same role workspace with its durable journal and
secrets intact. A new empty workspace is a first-use/adoption flow, not a
restart.

| Situation | What Relay can safely do |
| --- | --- |
| Same workspace reopened | Synchronize public progress, reconcile the journal and continue the one safe remaining action |
| New workspace with restored key and bootstrap | Recover accepted public progress only; do not claim unpublished/local work |
| Participant lost local attempt state | Inspect the exact checkpoint-preallocated remote manifest with a replacement grant, or explicitly abandon it and allocate a new attempt |
| Witness lost observation bytes/time | Mark the observation missed or uncertain; never reconstruct a timestamp |
| Mirror lost destination mapping | Reconfigure the destination and prove retention again |
| Offline package lost | Export a new package for the current valid frozen review |
| Coordinator workspace lost after mutation began | Read-only inspection; do not sign from a replacement workspace |

If the local journal is missing or corrupt while an operation may have produced
a signature, contribution or upload, Relay reports that recovery is
indeterminate and never repeats the operation automatically.

Relay must not infer a human-only fact—such as independent key confirmation,
machine cleanup, or delivery of a private grant—unless there is an explicit
record for that fact.

Every submission kind has an executable allowlist for paths, media types, file
counts and byte sizes. Relay snapshots regular files without following links and
rejects devices, links, traversal, unexpected files and private-material names.
Before promoting inbox contents, it runs the type-specific privacy and protocol
checks. Provider administrators can still see private inbox contents and
metadata; V1 does not claim otherwise.

## Concurrency and freshness

The design must handle two processes and a misleading backend safely:

- coordinator root updates use provider-tested conditional replacement;
- acceptance is tied to the exact parent head and scheduled participant;
- only one accepted child can advance a given head;
- stale submissions remain inspectable but cannot advance the ceremony;
- returning roles reject a checkpoint below their local high-water mark;
- an inconsistent checkpoint or root is retried from a fresh read, not merged by
  guessing;
- when Tessera or another policy-required freshness source names a different
  checkpoint than storage, Relay never chooses by sequence or timestamp. It
  shows both digests, retries a bounded number of times and blocks
  state-changing work until they agree or the ceremony follows its explicit
  investigation procedure;
- CDN caching is disabled for mutable `state/*` objects; and
- immutable blobs may be cached indefinitely.

One backend can still hide a newer state from a brand-new client. Signatures
prove authenticity, not freshness. The CLI must expose that limit rather than
claiming otherwise.

When witnesses are enabled, witness timing never comes from an object timestamp.
A witness binds its signed receipt to the signed closure and beacon target, its
locally recorded first observation time and the required observation window.
Late first observation, backend read failure, rollback/fork detection,
inconsistent checkpoint, or failure of a freshness source required by policy is
an incident requiring coordinator attention—not an automatic success or retry.
Where configured, a witness compares the checkpoint through an independent
mirror or Tessera. When witnesses are disabled, these witness-only predicates
are absent; the separate future-beacon timing remains enforced.

Public downloads use deadlines, response and stream size limits, safe relative
paths, same-origin redirect rules and atomic cleanup of partial files.

## Symbolic model

Model the workflow as authenticated facts and transitions, not one enormous UI
tree.

Example facts:

```text
DefinitionVerified(ceremony)
AssuranceMinimum(ceremony, control, count)
Assigned(identity, role, index)
CheckpointVerified(sequence, digest, previousDigest)
HeadVerified(phase, n, digest, checkpointDigest)
OutboundPublished(phase, n+1, identity, parentDigest, attempt)
ReceiptVerified(phase, n+1, identity, outboundDigest, attempt)
GrantPlanned(requestID, attempt, checkpoint, exactPrefix, lifetime)
GrantIssued(requestID, attempt, checkpoint, exactPrefix, credentialGeneration)
CandidateSubmitted(phase, n+1, identity, candidateDigest, parentDigest, attempt)
CandidateAccepted(phase, n+1, identity, candidateDigest, parentDigest, attempt)
SubmissionAcknowledged(kind, identity, scope, attempt, manifestDigest, result)
PhaseClosed(phase, headDigest)
ReviewFrozen(reviewCheckpoint, manifestDigest, evidenceDigest)
ReviewCancelled(reviewCheckpoint, reasonCode)
ReleaseReviewed(reviewCheckpoint, manifestDigest)
DecisionSigned(outcome, reviewCheckpoint, manifestDigest)
TerminalDecisionCommitted(outcome, terminalCheckpoint, reviewCheckpoint, manifestDigest)
ReleaseUploaded(terminalCheckpoint, manifestDigest)
ReleasePublished(publishedCheckpoint, terminalCheckpoint, manifestDigest)
```

Each action declares preconditions and effects. For example:

```text
AcceptCandidate requires
  CheckpointVerified(s, cp, previous)
  HeadVerified(p, n, h, cp)
  Assigned(i, participant, n+1)
  ReceiptVerified(p, n+1, i, outbound, receiptAttempt)
  CandidateSubmitted(p, n+1, i, c, h, candidateAttempt)

AcceptCandidate produces
  CandidateAccepted(p, n+1, i, c, h, candidateAttempt)
  SubmissionAcknowledged(candidate, i, p/n+1, candidateAttempt, manifest, accepted)
  AcceptancePrepared(s+1, cp2, cp, h2)
```

The crash model expands that last abstract effect into observable steps:

```text
InnerSignatureIntentDurable
AcceptanceSigned
ImmutableObjectsUploaded
CheckpointIntentDurable
CheckpointSigned
CheckpointUploaded
RootCASAttempted
RootCASCommitted
RootRead
CheckpointVerified
HighWaterRecorded
ActionStarted
```

Only a checkpoint reached through the committed root, or explicitly pinned by a
trusted freshness source, produces the normal `CheckpointVerified` fact.
Reconciliation may finish the same recorded conditional write or adopt its exact
committed result; it never creates a new signature automatically.

The model must check at least these invariants:

1. No action succeeds because an object merely exists.
2. No participant receives authorization before its exact input receipt passes.
3. No candidate is accepted for the wrong identity, turn or parent head.
4. A participant is complete only when the accepted chain names its exact
   candidate.
5. No mutable hint is used as cryptographic authority.
6. No private grant or signing key reaches public storage.
7. No approval authorizes a different final manifest.
8. A rejection never produces an approved public release.
9. No role silently moves behind its recorded high-water state.
10. For identical authenticated facts, identity and software version, the
    guide chooses the same next required action.
11. Concurrent ready work is visible without allowing required prerequisites to
    be skipped.
12. An offline return is accepted only for the checkpoint and files it reviewed.
13. Every signature requires its exact durable intent, and one parent produces
    only one signed child unless recovery resumes the identical intent.
14. A root commit requires the exact signed checkpoint to exist immutably first,
    its previous digest to equal the checkpoint in the root being replaced, and
    the conditional token to come from that exact durable root read.
15. High-water advances only for a committed, fully verified checkpoint.
16. No state-changing action starts until the corresponding verified high-water
    record is durable.
17. Grant issuance requires the matching durable request, attempt, checkpoint
    and exact prefix.
18. Grant renewal preserves the same attempt and prefix; credential expiry does
    not terminate the attempt.
19. A replacement attempt requires the previous slot to be explicitly rejected
    or cancelled.
20. A role is skipped only when the authenticated definition sets its exact
    minimum to zero; absence of a file, assignment or local fact cannot disable
    it.
21. A disabled role has no assignment, grant, accepted evidence or waiting
    action, while every supplied artifact for an enabled role is verified even
    after its minimum is satisfied.
22. Zero witnesses removes only witness evidence; it never removes the future
    beacon, committed round or multi-relay verification.
23. GO accepts `NOT_REQUIRED` only for a gate whose matching authenticated
    minimum is zero.

Facts for enabled enrollment, witness, mirror and audit duties are indexed by
identity, assignment, checkpoint, attempt and artifact digest. Collection
completion is a predicate over the authenticated minima and current set, never
a sticky result from an old failed check. The model explores zero and positive
minima explicitly; it never treats a missing fact as a policy choice.

TLA+ is suitable for the state, concurrency and crash properties. It does not
reimplement cryptography: signature and hash verification are modeled as
trusted predicates, then Go integration tests confirm the real verifier is
called at every boundary. TLC exhaustively checks bounded configurations; the
result is not a proof for unbounded ceremonies or the Go implementation.

## Test strategy

### Model tests

- Use small compositional models for checkpoint/root/crash behavior, one phase
  turn with duplicate attempts, evidence/quorum/timing, and decision/release.
- Explore reordered, duplicated, missing and conflicting checkpoint updates.
- Pair a valid checkpoint with another root version's ETag and confirm the
  conditional update is rejected before publication and during recovery.
- Explore stale heads, backend rollback, split views and concurrent coordinator
  updates.
- Explore crash points before each payload, manifest, accepted chain, checkpoint
  and root update.
- Mutate identity, phase, turn, parent digest, candidate digest and release
  digest independently.
- Check safety invariants and useful reachability for every role in bounded
  configurations.
- Add deliberately broken configurations to confirm every invariant can fail
  when its guard is removed.
- Explore all eight enabled/disabled combinations for witnesses, mirrors and
  ceremony auditors. Model external security-audit signoffs separately because
  they are not ceremony-role assignments.
- Prove that zero is reachable only through an authenticated explicit minimum,
  and that omitted policy, injected disabled-role evidence, and
  `NOT_REQUIRED` on an enabled gate are rejected.
- Explore the honest no-witness path while recording the explicit limitation:
  the model must not manufacture a trusted before-beacon commitment fact from a
  coordinator timestamp.

### Go tests

- Define one versioned, machine-readable transition/action vocabulary with
  stable predicate IDs. Export bounded model traces as checked-in fixtures that
  map authenticated facts—including time, grant status and unresolved local
  operations—to legal transitions and the next action.
- Run the real Relay evaluator and proof-tool transition verifier against every
  fixture. CI regenerates and diffs the fixtures, or verifies their source hash;
  mutation tests remove each dependency edge to prove the suite detects drift.
- Feed the real state-derivation engine synthetic S3/R2 object graphs.
- Assert the exact role summary, waiting reason and next action for every state.
- Require proof-tool verification results, not fixture file presence.
- Cover scoped role credentials, coordinator exact-key inbox retrieval,
  signed submission envelopes, acknowledgement records, bounded downloads,
  manifest-last uploads and conditional root writes.
- Run existing-session compatibility tests against the old pointer layout.
- Test definition, two-phase operational evidence, final transcript, release
  and decision verification for every witness/mirror/ceremony-auditor
  combination. Include zero and positive external-audit minima in production
  fixtures.
- Assert that legacy definition/evidence/decision schemas retain their
  minimum-one rules, while every new assurance field is mandatory.
- Assert that a no-witness ceremony still verifies the exact future beacon and
  independent relay responses, and that a no-audit release still fully replays
  and binds the final candidate and operational bundle.
- Reject valid-looking witness, mirror, ceremony-audit or external-audit
  evidence injected when its minimum is zero; reject disabled-role assignments,
  grants and enrollments.
- Reject an operational bundle that authors or lowers a quorum, a checkpoint or
  capsule whose policy differs from the definition, zero-minimum gates marked
  `PASS`, and positive-minimum gates marked `NOT_REQUIRED`.
- Reject omitted evidence arrays in every new signed schema; accept only
  explicit empty arrays when the corresponding signed minimum is zero.
- Reject a rehearsal definition with a nonzero external-security-audit minimum.
- Live-test conditional replacement and create-only object semantics on both S3
  and R2; unsupported or ambiguous behavior blocks production.

### Guided role journeys

For coordinator, participant, release signer and upload station, plus every
witness, mirror and auditor enabled by the signed policy:

1. Start with a clean workspace and only that role's legitimate inputs.
2. Let the CLI obtain all ordinary public handoffs from storage.
3. Confirm the recommended instruction follows from authenticated state and
   states exactly what is missing when waiting.
4. Interrupt each consequential operation once and resume.
5. Replace or remove one required backend object and confirm a clear failure.
6. Export a secret-free bug report.

No test may manually place an internal file to make the happy path continue.
Such a fixture can test a verifier, but it cannot validate the user journey.

### End-to-end gates

- One complete tiny ceremony with all connected roles using storage-first
  transport.
- One complete tiny ceremony with all four optional assurance controls set to
  zero; it must contain no hidden observer/audit fixtures or manual completion
  markers.
- The same tiny ceremony on both AWS S3 and Cloudflare R2.
- Two coordinator processes sharing one workspace, proving the exclusive lock
  prevents the second from signing. A simulated unexpected root conflict must
  block rather than publish another child.
- One offline final-signer ZIP round trip.
- One production-shaped run with a signed shortened beacon lead, plus separate
  tests of the recommended 24-hour production setting and final
  approval/rejection behavior.
- One clean released-version run; development images do not establish release
  compatibility.

## Compatibility and rollout

Do not silently reinterpret an unfinished ZIP-first or explicit-file ceremony
as storage-first.

- Existing ceremonies stay pinned to the Relay release and workflow that
  created them.
- The new release creates a versioned storage-first workflow record.
- Existing definition, operational-bundle, final-transcript and production-
  decision schemas retain their current implicit minimum-one policy. They are
  never reinterpreted using the new rules.
- Optional roles use new versioned signed schemas and a new ruleset. All four
  assurance minima are mandatory in the definition and are projected by
  proof-tool into Relay's authenticated journey state.
- The implementation introduces definition v3, journey projection v2,
  operational bundle v3, final transcript v2 and production decision v2 under
  a new `two-phase-v3` ruleset. If implementation review shows that a release
  manifest's canonical inventory also changes, it receives its own new schema
  rather than conditional parsing of the old one.
- Tessera's existing setup contracts remain unchanged and cannot create an
  optional-role ceremony. A new versioned setup contract and compatibility
  release are required before Tessera may enable this workflow.
- Relay rejects importing an old Tessera setup or ruleset into the new
  definition schema. It never infers zero minima, adds a local assurance policy
  to an old export, or converts missing fields into defaults.
- Existing `state/<ceremony>/<phase>/head.json` pointers and content-addressed
  transcript blobs remain readable.
- A future adoption tool may import only authenticated, completed protocol
  state. It must show what cannot be inferred and require an explicit new
  checkpoint; it must not manufacture missing custody or acceptance records.
- The experimental branch is retained for reusable manifest, archive, exact
  approval, privacy and adversarial-test work.

## Implementation sequence

1. Preserve the experimental branch and create a clean branch from current
   `main`.
2. Add the versioned signed assurance policy and make definition, operational
   evidence, final transcript, release and decision verification derive their
   exact requirements from it.
3. Implement the dependency graph and deterministic per-role next-action
   function before changing menus.
4. Add signed immutable checkpoints, one discovery root, digest high-water
   state and provider-tested conditional update support.
5. Implement and test one complete storage-backed Phase 1 turn.
6. Extend the same submission and acceptance mechanism to enrollments and each
   enabled witness, mirror and audit requirement.
7. Add exact final-file approval, rejection archive and release publication.
8. Add the final-signer ZIP fallback.
9. Add the new versioned Tessera contract without changing old contracts.
10. Run model, unit, all-policy-combination, guided-role, live-provider and
    released-version tests.
11. Update concise role documentation only after the CLI journey is stable.

### Component ownership

- **proof-tool** owns canonical signed checkpoint, transition, submission,
  acknowledgement and decision schemas plus their cryptographic and protocol
  verification. It remains network-free.
- **Relay** owns storage synchronization, bounded transport, conditional writes,
  local high-water/cache state, Docker execution, recovery and deterministic
  role guidance. It never substitutes its own parser for proof-tool at a signed
  boundary.
- **Tessera** optionally delivers typed temporary grants, exact expected attempt
  notifications and recent checkpoint confirmations. Those messages are hints
  or private access, not ceremony acceptance.
- **Storage configuration** owns provider permissions, public/private separation,
  caching and retention. Relay preflight checks the properties it relies on.

## Definition of done

The redesign is complete only when:

- every connected role can infer its authenticated public position and next
  required action from storage plus its local identity, trust bootstrap and any
  necessary private/local facts;
- no normal connected-role step asks the user to copy individual public files
  or choose an internal destination path;
- every claimed completion is backed by the exact authenticated artifact that
  defines it;
- rollback, concurrency, partial upload and interruption tests pass;
- the offline fallback binds both directions to one exact checkpoint;
- the final approval authorizes only the exact files reviewed; and
- a clean released-version ceremony succeeds without hidden fixture handoffs;
- both a fully enabled ceremony and a ceremony with every optional assurance
  control disabled succeed without hidden role work; and
- every omitted optional role is justified by an explicit zero in the signed
  definition and displayed as `NOT_REQUIRED` at final review.

## Explicit limits

- Storage availability and first-use freshness are not solved by signatures.
- Relay verifies distinct keys, not independent people or organizations.
- Docker cleanup and participant confirmation do not prove physical erasure.
- A compromised role machine can misuse that role's key or active temporary
  grant.
- V1 supports one state-changing coordinator workspace. It does not provide
  automatic coordinator failover, safe concurrent mutation from cloned
  workspaces, or protection from a malicious host administrator.

## Adversarial review record

The first independent review found that a loose unsigned catalog could combine
valid artifacts from incompatible snapshots. This revision therefore uses one
mutable hint pointing to an immutable signed checkpoint chain. The review also
added digest-aware rollback protection, a single-writer coordinator rule,
provider-tested conditional writes, typed submission envelopes and
acknowledgements, bounded exact-key inbox retrieval, a pre-initialization draft lane,
protected release staging, explicit observer assignments, witness timing rules,
dependency-graph guidance and a narrower statement of what storage can infer.

The second independent pass separated ancestry from freshness, strengthened the
bootstrap digest, split receipt and candidate grants, replaced inbox discovery
with coordinator-preallocated exact manifest keys, defined legal checkpoint
transitions and permanent ancestry, added a setup-complete bridge, witness
readiness, typed protected-read/promotion grants, a frozen review checkpoint,
closed-world publication and a coordinator-verified publication checkpoint. It
also expanded the crash model so signing, upload, conditional commit and local
high-water persistence cannot collapse into one falsely atomic action.

A later usability review removed mandatory expiring freshness notifications.
Tessera performs an authenticated on-demand status lookup; standalone V1
rereads verified storage and preserves digest-aware rollback history. The design
now explicitly discloses the first-use stale-view risk. A nonce-bound live
confirmation remains an optional stricter policy, not part of the normal CLI
journey.

A fresh three-round restart review then added sequential verification of every
missing checkpoint, durable high-water state before mutation, staged coordinator
signature intents, idempotent grant recovery, separate attempt and credential
lifetimes, explicit same-workspace restart limits, review cancellation, a
restricted outage fallback, role-specific setup-complete entries, and an exact
parent/root-version check for every conditional root update. The final targeted
checks found no remaining blocker-level contradiction. This is a design review,
not an implementation test or security certification.

### Implementation adversarial review

The first implementation review rejected shallow checkpoint sync, unscoped
local completion flags, ambiguous accepted candidates, unrelated root children,
and guidance that could skip the end of a participant schedule. The
implementation now downloads the signed evidence inventory, requires
proof-tool's full stored-evidence result before advancing local high-water
state, binds local facts to exact checkpoints/attempts/digests, compares exact
candidate acceptance, and conditionally publishes only a deeply verified child
of the exact current root.

The second review found and fixed an artifact-root path mismatch, replay of a
candidate submission across sibling allocation checkpoints, duplicate attempt
or manifest names, grants not bound to an authenticated slot, excessive grant
lifetimes, shallow projections driving guidance, and cross-platform filename
collisions. Storage-first artifact names are consequently portable lowercase
ASCII, submission envelopes name their exact allocating checkpoint, temporary
grants last at most one hour and must match a fully verified slot, and only a
checkpoint returned by full sync can drive role guidance.

The review also confirmed that the current code is a protocol foundation, not
the completed journey described above. Production remains unavailable until a
real Relay coordinator/participant path performs cp0 through cp3, rejected or
damaged submissions can be retired and replaced, coordinator journal recovery
is integrated, returning workspaces verify incrementally from a durable trusted
anchor, and live S3/R2 conditional semantics pass. The small TLA+ module is
only an ordering sketch; it is not evidence that those implementation
properties hold.

A final implementation pass found three additional failures and added
regressions for each. Production-size Phase 1 contributions are now verified
with streaming digest checks rather than the 16 MiB operational-record limit;
small JSON records and signatures retain their strict bounds. Workspace
high-water updates now lock the complete read/check/write transaction, so a
delayed synchronization cannot overwrite a newer authenticated checkpoint.
Finally, a root conditional write is not reported as committed until a bounded
reread returns the exact intended bytes and version; restart reconciliation
distinguishes the intended root, the unchanged prior root, an unexpected root,
and an unreadable ambiguous result. The proof-tool command regression now
drives cp0 through cp3, requires full stored-evidence verification, and rejects
independent corruption of the candidate, manifest, acknowledgement signature,
and accepted chain.

### Optional-role design review

Three adversarial passes reviewed the policy that permits zero witnesses,
mirrors, ceremony audits and external security-audit signoffs. The first pass
corrected an overclaim about no-witness beacons: without an independent witness
or a separately trusted commitment timestamp frozen in advance, a malicious
coordinator can backdate a closure after learning the beacon. It also made the
definition the sole policy authority, required explicit empty evidence arrays,
bound checkpoint and capsule projections back to the definition, made
`NOT_REQUIRED` deterministic, and froze external-audit evidence into review.

The second pass separated core enrollment, witness readiness and mirror timing.
Core enrollments gate the first turn; witnesses gate an enabled closure; mirrors
reserve phase/index slots before candidate acceptance and later sign the exact
accepted head. It also made external security audits production-only, excluded
unused draft invitations from ceremony authority, and prohibited retroactive
timestamp assurance. The final pass found no remaining material contradiction
or downgrade path.

The remaining tradeoffs are explicit product choices: all-zero production has
no independent publication-timing, retention, ceremony-replay or external-
review assurance; mirror retention is eventual before final review rather than
turn-blocking; the coordinator selects post-initialization observer identities;
and standalone first-use freshness still depends on the configured provider.
The recommended UI default keeps the current nonzero assurances while allowing
the coordinator to choose zero deliberately before signing the definition.
