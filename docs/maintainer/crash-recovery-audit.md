# V1 crash-recovery implementation audit

Status: open findings against the accepted
[simple recovery design](crash-recovery-design.md). Updated 2026-09-12.
Priorities, implementation order and design risks are in the
[remaining recovery plan](crash-recovery-remaining-plan.md).

## Implemented foundation on the current development branch

- Participant launcher profiles retain the exact verified image and platform
  from their phase profile. Existing profiles migrate with private backups, and
  conflicting runtimes are rejected.
- Workflow state and create-only JSON records sync both their file and parent
  directory before Relay proceeds.
- A V2 workflow state carries a random workspace ID and an initialization state.
  A matching create-only marker in the role work directory makes missing or
  mismatched recovery state visible. V1 state migrates with a retained backup,
  and an interrupted marker initialization resumes safely.
- V2 progress records also store a stable stage ID. A later menu-catalog change
  remaps that ID into the new ordering, retains a digest-named backup, and keeps
  old attempts. An unresolved saved command must still match the current task
  before it can continue; older state without a stable stage ID blocks if its
  catalog differs.
- Existing participant workflow state may fill only the known legacy omissions
  from the current verified profile; conflicting saved values still block.
- Every authored guided task has a closed recovery classification. Tests reject
  an unclassified task.
- Before child execution, the workflow record now includes the resolved command,
  recovery class, exact image/platform, public mount paths, expected output
  paths, input hashes and turn scope.
- A fully resolved operation is first synced as `prepared`, then separately
  synced as `running` immediately before child launch. After a restart, a
  retained `prepared` record is safely closed as not started and the ordinary
  review is shown again; it is never treated as an uncertain child execution.
- Coordinator initialization now freezes and reuses its exact creation time,
  session nonce, roster, policy, trust key and allowlisted binary bytes. An
  interrupted attempt is resumed under its real action name with create-or-
  verify setup files, reruns proof-tool's atomic initialization contract, and
  verifies the signed definition afterward.
- Guided role recovery no longer presents a generic retry/investigation/mark-
  complete menu. A read-only operation can be rechecked after its exact inputs
  and real action are reviewed. An interrupted participant contribution can
  continue one authenticated retained candidate; other unresolved state-changing
  operations currently stop with a concrete blocker instead of repeating the
  mutation.
- An unresolved older participant/head scope is not hidden by a newer local
  scope for the same authored task and stage.
- The isolated contributor now saves its intended unique container name before
  `docker create`, labels the container with its operation, workspace and mount
  digest, and resolves a lost create response by that identity. Cleanup checks
  those labels and the pinned image before removal. A concurrent lifecycle-state
  replacement is preserved and the newly created container is removed.
- Participant cleanup confirmation and the exact erasure-signing timestamp are
  now persisted in the authenticated Docker lifecycle record before erasure
  signing. A retained Docker candidate can finish a missing erasure pair and
  create its upload manifest without recomputing the contribution. Legacy
  half-written erasure output without a saved timestamp blocks instead of
  inventing new signed inputs.
- The guided participant workflow discovers one exact phase/index/attempt
  candidate after an interrupted contribution, asks for current upload access,
  and resumes that candidate under the original operation ID. New guided runs
  allocate the participant candidate/upload attempt from that operation ID
  before launch, so recovery selects the exact candidate. Legacy runs use the
  single-candidate fallback and refuse to recompute automatically or choose
  between multiple retained candidates.
- Guided witness, mirror, auditor and release evidence uploads now allocate a
  stable attempt ID and manifest timestamp before launch. Retries reuse that
  identity, verify matching immutable objects, and write or verify the manifest
  last before repeating the same Tessera notification.

This is intentionally not marked complete. In particular, state-changing task
reconcilers for ordinary state-changing role containers, participant checkpoint
unification with the guided state document, grant reconciliation, compact
completion tombstones, workspace retirement, and the full fault matrix below
remain open. Proof-tool atomic initialization and input-bound identity
continuation plus Tessera assignment-scoped notification idempotency are
implemented in companion working trees and still require their own review and
release. Composite findings remain listed until every part is integrated and
tested.

## Required V1 work

### Shared operation state

- Replace the separate workflow/activity attempt interpretations with one stable
  operation ID or an explicit mapping between them. **Done for new guided
  participant turns: the guided operation, Docker lifecycle, candidate directory,
  upload prefix, manifest and Tessera notification use the same 32-hex identity.
  Ordinary role-container activity remains separate.**
- Migrate old records only after the complete new state document is synced and
  verified; retain the old records until migration completion.
- Save the final invocation after Relay resolves participant, head, timestamps,
  output paths and container names—not the earlier recipe. **Done for guided
  commands and stable evidence-upload identities; participant inner lifecycle
  fields remain split between workflow and candidate lifecycle state.**
- Persist the resolved non-secret arguments, mounts and environment names; retain
  only protected paths for keys/credentials, never their contents.
- Record the operation schema, pinned image digest and expected signer key ID so
  resume cannot silently use upgraded code or a replaced private key.
- Atomically write and directory-sync operation records, local high-water state
  and create-only completion markers.
- Add the workspace ID to recovery state and the role work directory, plus retained
  completion tombstones, so deleted state does not look like first use.
- Store unresolved operations and tombstones in one atomic recovery-state document
  outside role-container mounts; the work marker makes a missing document visible.
- Give online, offline-signer and keygen profiles for one installed role folder the
  same workspace ID, state document and lock.
- When several role identities share one host, reject overlapping canonical work,
  trust, key or recovery-state paths and keep their workspace/container IDs
  distinct. Do not describe that arrangement as independent operation.
- Make first workspace-ID creation resumable through `initializing -> marker ->
  ready`; distinguish an interrupted first setup from later marker deletion.
- Add explicit workspace retirement that refuses while operations, containers or
  potentially valid unseen grants remain and never deletes public artifacts.
- Scan unresolved records from older turn scopes before recommending a new task.
  A newer status success must not hide an older uncertain mutation.
- Replace generic exit-code recovery and `Inspect existing state` with registered
  task-specific verification.
- Run verification without signing keys or cloud write credentials. Model cleanup
  and continuation as explicit operations, not side effects of an inspector.
- Enumerate every setup and ceremony task in the recovery registry and reject an
  unclassified mutation. **All guided ceremony tasks are classified; `status`
  is explicitly a safely repeatable local-checkpoint operation because it may
  advance authenticated high-water state. Setup/onboarding tasks are not yet in
  the same registry.**
- Treat cancellation before mutation as not started, rather than a failed child.
- Define a bounded verified-effect set for each compound task such as acceptance,
  publication, evidence upload and Tessera notification.

### Docker and participant lifecycle

- Persist the intended contributor name before Docker can create it. **Done for
  the isolated participant contributor.**
- Use a lock based on ceremony, participant and candidate root—not configuration
  filename—so copied local profiles cannot overlap. **Done conservatively at
  the workspace-directory level; separate participant workspaces remain
  independent.**
- Persist cleanup and lifecycle facts before removing active-container state or
  promoting a candidate. **Done for the isolated participant contributor.**
- Persist participant cleanup confirmation, erasure signing, manifest, upload and
  Tessera notification as separate checkpoints, including exact `destroyed_at`.
  **Cleanup confirmation and `destroyed_at` are durable in the lifecycle record;
  the candidate manifest supplies a durable upload identity. Guided-state
  checkpoint unification and an explicit notification-pending checkpoint remain.**
- Replace `docker run --rm` for state-changing roles with persisted
  `create -> record ID -> start -> inspect -> verify -> remove`. Run without
  interactive stdin/TTY. Read-only disposable containers need no change.
- Verify workspace/operation labels, image and mounts before acting on a recorded
  container; its name alone is insufficient. **Done for the isolated participant
  contributor.**
- Split commands that mutate and then wait for another confirmation into separate
  prepare/review and apply/sign actions.

### Local and remote results

- Verify task semantics, signatures and exact output sets after both success and
  failure; current output bindings are recorded only after a zero exit.
- Allocate evidence/candidate attempt IDs before launch and reuse them for exact
  immutable uploads and Tessera notification. **Done for guided non-participant
  evidence uploads. New guided participant runs use one identity for the guided
  operation, candidate directory, manifest and upload prefix; legacy retained
  candidates remain resumable. Detailed participant lifecycle checkpoints are
  not yet unified with guided recovery state.**
- Use one submission attempt ID for the storage prefix, manifest and Tessera
  notification. Treat manifest presence as readiness only; authenticate every
  referenced object before accepting it.
- Preserve time-derived signed inputs such as `accepted_at` and `destroyed_at`.
- If credential issuance may have succeeded before the grant file was saved,
  revoke it or wait through its saved maximum lifetime using provider-confirmed
  time and conservative clock skew before reissuing. **Relay now adopts a
  complete protected grant file only after checking its saved ceremony, role,
  identity, storage coordinates, TTL and minimum window. Missing-output
  issuance remains blocked and displays a conservative local bound; automatic
  provider-time confirmation, revocation and reissuance remain open.**
- Reauthenticate the candidate and current published head immediately before
  coordinator mutation; block if the expected parent changed.
- Give storage probes durable IDs and reconcile/delete only their exact objects.
- Update profile and workflow credential references through one recoverable
  operation instead of two unrelated writes.
- Change proof-tool ceremony initialization to stage and atomically promote the
  complete tree; definition-only verification cannot approve a partial root.
  **Implemented in the proof-tool companion working tree.**
- Continue interrupted identity generation from a valid retained private key and
  saved identity inputs; never generate a replacement key automatically.
  **Implemented in the proof-tool companion working tree with a protected,
  exact-input recovery record. A private-key-only interruption derives the same
  public identity, while a completed exact pair is verified and adopted.**
- Make Tessera deduplicate an identical repeated attempt ID and reject the same ID
  with a different authenticated notification body. Scope dedupe to protocol and
  assignment rather than a refreshable connection ID. **Implemented in the
  Tessera companion working tree, including database-conflict reconciliation.**
- Preserve a completed upload as `notification pending`; accept a refreshed
  Tessera connection only when protocol, assignment, role and identity match.

## Deferred, with an explicit V1 boundary

These are real limitations, but not implementation requirements while V1 enforces
one honest active workspace per role identity:

- two coordinator machines signing or publishing from the same head;
- two participant machines sharing one identity or upload grant;
- participant turn claims, fencing generations and automatic takeover;
- coordinator remote leases, HSM signing and automatic failover;
- recovery after complete loss or snapshot rollback of the role folder;
- unusual filesystem lock/rename semantics;
- preserving an unsigned witness observation across a crash; and
- malicious key holders or local-host compromise.

Documentation and the UI must not imply that Relay handles these cases.

## Focused fault matrix

For every V1 state-changing task, interrupt at these boundaries:

1. Before and after saving the operation record.
2. Before and after child/container start.
3. Before and after each local output promotion.
4. Before and after Docker create, exit, removal and candidate promotion.
5. Before and after credential issuance and grant persistence.
6. Before and after each immutable upload, manifest, head recheck/update and
   Tessera notification.
7. Before and after final verified-completion persistence.

Restart after each interruption. Relay must do exactly one of:

- verify the completed result;
- continue the same retained candidate/upload;
- establish that no effect occurred and use a fresh output path; or
- stop with one concrete blocker.

It must not recompute a retained participant candidate, overlap a local container,
replace a signed artifact, duplicate an immutable submission, reissue an uncertain
grant, or advance from a conflicting parent head.

Cover SIGINT, SIGTERM, SIGKILL, terminal loss with a live named container, Docker
daemon restart, lost response after a successful upload, disk full, rename
failure, corrupt/truncated state, clock change, expired credentials and a changed
published head. Also cover release upgrade during recovery, signing-key
replacement, deleted operation state, private-key-only identity generation and a
duplicate Tessera notification. Cover interruption at each workspace-initialization
step, a name collision with an unrelated Docker container, a refreshed Tessera
connection after upload, and multiple role workspaces sharing one host.

## User-journey checks

For each role, verify that:

- ordinary success never exposes recovery terminology;
- restart first says `Checking the previous action`;
- safe continuation names the real ceremony action, not `Retry`;
- a blocker states the exact missing fact and preserves files;
- no screen asks for an investigation narrative or offers `mark complete`;
- a human handoff clearly says it is only a local report; and
- after resolution, the authored workflow order—not file-presence heuristics—
  selects the next required action.
