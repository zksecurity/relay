# Remaining crash-recovery plan

Status: proposed follow-up to the accepted
[design](crash-recovery-design.md) and current
[audit](crash-recovery-audit.md). This is an implementation candidate—not a
production-approved baseline—until independent review, fault testing and a
released-image rehearsal pass.

## What the current candidate provides

- Durable guided-operation intent and workspace identity.
- One participant attempt ID across Docker, candidate storage and Tessera.
- Participant container cleanup and retained-candidate continuation.
- Stable immutable evidence uploads and Tessera notification deduplication.
- Adoption of a complete protected grant file.
- Atomic proof-tool initialization and resumable identity generation.
- Compatible migration or a fail-closed error for older local folders.

Unknown mutations stop rather than being repeated. That protects correctness but
can abort a production ceremony after an ordinary crash. The remaining work is
mainly about safe availability.

## Priority

| Decision | Work |
| --- | --- |
| Required before production | Task-specific reconciliation, explicit participant/notification checkpoints, and deterministic fault tests. |
| Conditional | Durable containers for long-running mutations still unresolved after reconciliation. The participant contributor already qualifies. |
| Policy choice | Wait after a completely lost grant response, or permit an explicit same-scope replacement. |
| Later | Broader setup coverage, workspace retirement and record compaction. |
| Outside V1 | One identity active on two machines, automatic failover, total role-folder loss, and malicious hosts/operators. |

## 1. Recovery contracts and reconcilers

Inventory every guided mutation in code beside the workflow catalog. Each stable,
versioned contract declares:

```text
exact public inputs and expected signer
local and remote effects
atomic/idempotent guarantees
authoritative result verifier
safe continuation, or one concrete blocker
whether a live child must be rediscovered
```

Tests reject duplicate task IDs and mutations without a contract. If completion
semantics change, use a new task/version or explicitly migrate and reverify the
old result. Stable stage IDs alone are insufficient.

| Effect | Restart behavior |
| --- | --- |
| Fresh local artifact | Adopt only a complete, exact, correctly signed output set. |
| Signature | Verify saved input hash, signer ID and detached signature. |
| Immutable upload | Verify existing bytes, continue missing files, publish manifest last. |
| Acceptance | Reauthenticate candidate and parent; adopt an exact desired signed head already published. |
| Mutable publication | Write only from the saved expected parent using provider conditional writes. |
| Download/sync | Authenticate complete staging before promotion; remove only operation-owned incomplete staging. |

Save timestamps, signer IDs, runtime digest, mounts and expected outputs before
mutation. Verification gets no signing key or cloud write credentials. A changed
head, input, key, runtime or output blocks.

An ETag is only a concurrency token, not a cryptographic digest. Multipart and
provider-specific ETags may not hash content. Measure the largest production
artifact against S3/R2 single-request limits; multipart upload, if needed, must
persist its upload ID, verify parts and abort only its own operation.

A failed create-only upload followed by `HEAD` proves only that an object exists.
Identity-scoped callers must download and hash it; an authorization error must
not become “already uploaded.”

## 2. Participant and Tessera checkpoints

Use one operation ID and derive status from authenticated evidence:

```text
container allocated -> container removed -> candidate verified
cleanup confirmed -> erasure signed -> manifest verified
upload complete -> Tessera notification complete
```

Guided state references exact lifecycle/manifest digests instead of copying their
claims. Cached checkpoint flags are hints and advance only after re-verification.
After upload, a failed Tessera call is `notification pending`, not `contribution
failed`.

Recovery may accept a fresh Tessera connection or grant only after matching the
same protocol, assignment, role, identity and upload prefix. It reuses the
original manifest key and attempt ID. Apply this to participant, witness, mirror,
auditor and release submissions.

Migration first syncs the complete replacement state and retains old activity
records. It never merges by choosing the newest wall-clock timestamp.

## 3. Durable containers only where needed

Do not copy the participant lifecycle to every command automatically. A container
record cannot resolve a lost cloud response, and atomic local output is usually
better recovered by verification. A blanket conversion creates another state
machine without making bytes transactional.

For a command that remains long-running or holds hidden state:

1. Save operation ID, image, mounts, environment names and intended container.
2. `docker create` without starting user code or allocating a TTY.
3. Inspect and save the exact ID plus workspace/operation/mount labels.
4. Mark running, then start that exact container.
5. On restart, inspect only the recorded daemon/container.
6. Verify task-specific effects, then remove and verify absence.
7. Never start a second child while the first is unresolved.

Collect every approval in the host guide before launch. Reattaching may not
recover output when logging is disabled, and an exit code is never proof of
completion. If the pinned old image is absent from both local cache and its
authenticated release, block rather than substitute a newer image.

## 4. Lost grant response is a policy choice

A saved grant is authenticated and adopted today. If issuance may have succeeded
but no file exists, Relay currently blocks until conservative expiry.

Strict policy:

- Save provider-observed request time and maximum TTL before issuance.
- On restart, obtain authenticated provider time and wait through TTL plus skew.
- Broad role/session revocation remains an explicit administrator incident action.

Simpler V1 policy:

- After explicit warning, issue a replacement with the exact same role, identity,
  prefix and maximum permissions.
- Record that the first credential may remain live until conservative expiry.
- Never silently broaden the scope.

The second credential can place bytes in the same inbox, but cannot create the
role's signature or make the coordinator accept them. Residual risks are bounded
write access, clutter/resource abuse, and later exposure of another live token.
The choice must be consistent between standalone and Tessera-managed issuance.
AWS STS secrets generally cannot be recovered or selectively listed after a lost
response; storing them in Tessera merely to replay a response would expand secret
custody.

## 5. Validation

At every durable boundary, inject interruption before and after intent, child
start, output promotion, Docker create/exit/removal, grant issuance, each upload,
manifest, pointer update, notification and final completion.

Every restart must do exactly one:

1. Verify and adopt the exact result.
2. Continue the same retained operation.
3. Prove no effect and show the normal fresh action.
4. Stop with one concrete missing fact.

Use layered tests rather than one enormous CI job:

- Every PR: deterministic fake-Docker/storage interruption tests.
- Protected main: one real tiny Docker ceremony.
- Scheduled: released images, both architectures and dedicated AWS/R2 resources.
- UI: all-role LLM journeys through a real PTY.
- Before production: manual released-version dress rehearsal.

Cover daemon restart, lost responses, disk full, truncated/deleted state, changed
head/input/key/image, refreshed access and upgrades from every released local
schema. A skipped lane is not passing evidence.

LLMs receive only synthetic credentials and scripted handoffs. They do not control
real signing confirmations. Treat display names and ceremony text as untrusted
prompt-like input, and normalize ANSI/terminal width in UI assertions. LLM tests
find usability bugs; they do not establish cryptographic or crash correctness.

## 6. Later work

- Extend recovery registration to identity, enrollment, storage/profile updates
  and initialization; leave harmless UI preferences outside it.
- Atomically update profile and workflow credential references.
- Detect overlapping role paths within one settings root. Canonical paths cannot
  reliably expose every hard link, bind mount or separate settings root.
- Add explicit workspace retirement only after proving no unresolved operation,
  container or possibly live grant remains. Preserve public artifacts and leave a
  retired marker.
- Keep full completion records for now. Compact tombstones only after measuring a
  real storage/retention need.

## Important limits

- Several roles on one machine prove neither independent people nor machines.
- Offline signer/upload-station continuity comes from signed artifact digests,
  not shared local recovery state.
- Snapshot rollback or deletion of state plus marker can hide history.
- File/directory sync improves consistency but cannot guarantee every controller,
  filesystem or power-loss mode. NFS/cloud-synced role folders are unsupported.
- Lost unsigned witness observations are not reconstructed or backdated.
- A malicious key holder, host or Docker daemon can bypass Relay.

## Order of work

1. Add focused crash tests and independently review the current three repositories.
2. Merge/release proof-tool; pin its exact AMD64/ARM64 assets in Relay.
3. Merge Tessera idempotency; run Tessera integration on the exact Relay head.
4. Merge/release Relay and validate the released pairing.
5. Implement contracts/reconcilers, then explicit checkpoints/refreshed access.
6. Add durable containers only for remaining live-child uncertainty.
7. Run the layered fault and role-journey suites.
8. Choose the lost-grant policy; then consider setup coverage and retirement.

Do not approve production from a happy-path rehearsal alone. Require the
production-critical work, independent review, released-image tests and a complete
released-version rehearsal.
