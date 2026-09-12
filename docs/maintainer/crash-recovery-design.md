# Simple crash recovery for guided operations

Status: accepted V1 design. The current development branch implements the
recovery foundation, exact read-only/upload continuation, participant-candidate
continuation, Docker contributor identity, grant adoption and initialization
recovery described below. Remaining work is tracked in the implementation audit.
This is not current released behavior.

## Goal

Make an interrupted action feel simple without guessing whether it changed
ceremony state.

Ordinary users see `Checking the previous action`, followed by one of:

- the verified next ceremony action;
- the exact operation that is still running or can safely continue; or
- one concrete reason Relay must stop.

There is no generic retry menu, investigation form, operator-authored recovery
log, or `mark complete` override. Relay may replace a resolved local checklist
entry, but never overwrites ceremony artifacts or immutable uploads.

## V1 operating boundary

V1 assumes:

- operators are honest and follow Relay's prompts;
- each role identity has one active workspace;
- one machine may host several role identities, but each uses separate work,
  trust, key and recovery-state paths;
- one role identity's workspace and signing key are not cloned and run on another
  machine concurrently;
- role folders live on a normal local macOS or Linux filesystem;
- the local OS and protected role folders are not actively compromised; and
- lost machines are handled manually rather than by automatic failover.

The design prevents accidental duplicate actions on the supported machine. It
does not stop a key holder from bypassing Relay, copying a key, or deliberately
signing conflicting artifacts. It also does not coordinate two machines sharing
one role identity, participant grant or coordinator key. Hosting several roles on
one machine is useful for rehearsals, but establishes neither independent people
nor independent machines.

Object storage and Tessera may fail, time out, or return late. Relay therefore
uses fixed operation identifiers and immutable object names where it performs
remote writes. A compromised service can cause denial of service, but signed
artifacts still require independent verification.

## Safety rule

Before starting work that may change state, Relay durably saves enough public
information to find and verify that exact operation.

After interruption, Relay proceeds only when it can establish one of these:

1. The intended result exists and verifies.
2. The exact retained operation has a safe continuation.
3. The operation did not create an effect and a fresh attempt is safe.

Otherwise Relay stops. A non-zero exit, missing success message, or absent output
path does not by itself prove that nothing happened.

## Minimal operation record

Keep one current record per installed role workspace, task and ceremony scope
inside one protected recovery-state document. A workspace may include online,
offline-signer and key-generation launcher profiles; they share this state and
lock rather than using their profile names as separate recovery domains.

```text
schema and operation ID
ceremony or pre-initialization draft, role, stage and stable task ID
operation schema, pinned release and exact image digest
phase, participant and authenticated parent head when applicable
checkpoint: prepared, running, complete or blocked
bounded verified-effect flags for a compound operation when needed
fully resolved non-secret command, mounts and environment names
exact public-input hashes
expected local outputs and remote object names
expected signer key ID when applicable
Docker daemon identity and container name, or grant expiry when applicable
Tessera protocol/assignment identity when applicable
started and last-checked times
```

The record is internal safety state, not an audit trail. Do not store credentials,
private keys, tokens, secret environment values, or user-written narratives.
Keep it outside every role-container mount; a child cannot edit its own checkpoint
or completion status.

Store protected credential/key file references when necessary, never their
contents. Save the executor specification only after Relay fills defaults and
derived values. Recovery does not rebuild an old invocation from today's workflow
catalog.

Write the recovery-state document atomically as a mode `0600` file beneath a
role-owned `0700` directory. Sync the file and parent directory. It contains all
unresolved operations and compact completion tombstones, so deleting an individual
operation file cannot silently erase uncertainty.

To detect wholesale state deletion, setup writes the same random workspace ID into
that document and a fixed marker in the role work directory before the first
action. A missing state document beside an existing marker—or mismatched copies—
means recovery state was lost; Relay does not treat that as first use. Snapshot
rollback or deletion of both copies is outside the V1 boundary.

First creation is itself resumable: create state as `initializing`, create the
matching work marker without replacement, then mark state `ready`. A crash with
only initializing state may complete that exact marker creation; ready state with
a missing marker blocks as possible deletion. The workspace ID never changes.

Allocate one submission attempt ID and its object names before each candidate or
evidence upload, then retain it across restart. Storage paths and the later Tessera
notification use that same ID. Time-derived signed inputs such as `accepted_at`
and `destroyed_at` must also be selected and saved before the command that consumes
them.

Compound commands keep only their concrete effect flags, such as `local output
verified`, `manifest uploaded`, `head updated`, or `Tessera notified`. These are
not a generic transaction language; each task defines and verifies its own small
set.

Keep a compact completed tombstone containing the operation ID and verified result
hashes until the workspace is explicitly retired. Otherwise deleting a successful
current record could make a one-time action appear new. This remains internal
safety state, not a narrative audit history.

Workspace retirement is allowed only after Relay finds no running or blocked
operation, no recorded container, and no possibly valid unseen grant. It preserves
the public ceremony/archive paths and removes only launcher recovery state after
an explicit user confirmation.

Resume a state-changing operation with its recorded image digest, not whichever
release is current after an upgrade. Setup should retain that image locally. If it
is missing, retrieve and verify the exact digest; if that is impossible, block
rather than substitute another runtime. A newer release may inspect old public
outputs only through an explicitly tested compatibility path.

## Launch protocol

1. Acquire the installed-workspace lock shared by its online, offline and keygen
   profiles.
2. Validate the final command, pinned image, expected signer identity, trust
   anchors, input hashes and output paths.
3. Allocate stable output, container and remote attempt identifiers.
4. Save the operation as `prepared`.
5. Create the executor without running user code and durably save its identity.
6. Durably change the operation to `running`, then start that exact executor.
7. Reconcile its real effects after it returns, including after an error.
8. Mark it complete only after task-specific verification succeeds.

An atomic host-only settings update skips the executor steps: write its
operation-owned temporary file, sync, rename and verify. It still has a record so
a restart can distinguish the old or new complete document.

For every state-changing role container, including the isolated contributor, use
Docker's durable boundary:

```text
save prepared intent and intended name
docker create without running user code
inspect and save the exact container ID
durably mark the operation running
docker start that container
inspect/reconcile its result
remove it only after verification
```

Persist the Docker daemon identity and unique name before `create`. Do not use
`docker run` or `--rm` for mutations. A lost `create` response is reconciled by
name; a lost `start` response is reconciled against the same container, so neither
case launches a second child. Do not allocate interactive stdin or a TTY. Read-only
commands may remain disposable.

Before attaching, stopping or removing a named container, verify its operation ID,
workspace ID, image digest and expected mount labels. A matching name alone is not
authority to act on a Docker object.

Collect review and approval before launching a state-changing child. When users
must review material produced by one command, model preparation and signing as
two separate actions. Do not leave a mutating child waiting at a hidden second
confirmation prompt. Revalidate the displayed inputs immediately after approval;
if they changed, stop instead of approving different bytes.

Network calls use bounded timeouts. Long cryptographic computation is not killed
merely for being slow. If its recorded container is still running, Relay shows
that exact operation. An explicit stop removes that exact container and then runs
normal reconciliation; it never starts a second computation automatically.

Automatic inspection may continue an immutable upload or adopt an already
verified result. It does not silently reuse an old approval to create a new
signature, publish a new head, issue credentials, or stop a container. Those
consequential actions are shown again by their real action name for confirmation.

## Recovery rules by operation

Verification is read-only: it receives public inputs and trust anchors, but no
signing key or cloud write credential, and writes only to an operation-owned
temporary directory. Container removal, upload continuation and identity-public-
file derivation are separate, explicitly registered continuations rather than
being disguised as inspection.

| Operation | V1 behavior after interruption |
| --- | --- |
| Read-only inspection | Rerun after reauthenticating inputs. |
| Fresh local output | Verify every declared output. If none exists and the command has no other effect, use a new fresh path. Never replace an existing artifact. |
| Identity key generation | Verify the private/public pair. If only the private key exists, continue the exact generation by deriving the saved identity's public file from that key; never generate another private key automatically. |
| Multi-file proof output | Verify the complete set. A partial final directory blocks unless the producer has an atomic staging or exact-prefix continuation contract. |
| Participant contribution | Inspect and remove the exact container, verify cleanup, then verify retained candidate and lifecycle files. Resume a complete candidate; never recompute merely because the launcher failed. |
| Candidate upload | Reuse the saved candidate and submission attempt ID. Create-only upload files, verify matching existing bytes, and publish the manifest last. |
| Evidence/release upload | Allocate the submission attempt ID before upload. Finish the exact manifest, then retry Tessera notification with that same ID. |
| Temporary grant | Before expensive work, reuse a saved grant only if it has the required remaining lifetime. For an existing candidate, use a still-valid grant only for upload. If unseen issuance may have succeeded, revoke it or wait for conservative expiry before issuing another. |
| Candidate acceptance or publish | Reauthenticate the candidate and current head immediately before mutation. Upload immutable content first. A changed or conflicting head blocks. |
| Human handoff | Ask whether the exact named public artifact was delivered. This updates only the local checklist and is not cryptographic verification. |
| Download/synchronization | Download into temporary or fresh paths and authenticate the complete result before promotion. |
| Ceremony initialization | Build in an operation-owned staging directory and atomically publish the complete initialized tree. |
| Enrollment import | Reverify complete public files. Ignore an incomplete operation-owned import directory and start a fresh import. |

Scratch files may be removed only after Relay proves they belong to the resolved
operation, were never promoted, and are not externally referenced. It never
deletes an authenticated artifact based on directory naming alone.

## Participant-specific checkpoints

The participant operation keeps these internal checkpoints:

```text
container allocated
container removed and absence verified
candidate promoted
participant cleanup confirmation recorded
erasure record signed
candidate manifest created
candidate uploaded
Tessera notified
```

Persist verified Docker lifecycle facts before removing active-container state.
Keep the state until the lifecycle receipt is durably present in the public
candidate. Persist the chosen `destroyed_at` before erasure signing so a detached
signature written before a crash can be continued with the exact same timestamp.

The participant confirms only facts Relay cannot measure, such as whether they
manually copied a secret or created a snapshot. This remains an authenticated
honest-participant statement, not proof of physical erasure.

V1 keeps the existing ceremony-and-identity upload grant scope. Preventing two
machines from sharing that grant requires a turn-claim/fencing protocol and is
explicitly deferred.

## Remote writes

Immutable uploads use create-only writes and verify existing bytes on retry. A
manifest is always uploaded last: its presence means all named files were offered,
while its absence means the attempt is incomplete. The manifest is not trusted as
proof of completeness; receivers still fetch, hash and authenticate every file it
names.

Tessera treats `(protocol ID, assignment ID, submission attempt ID)` as the
idempotency key. The same authenticated notification body returns the existing
submission; different contents under that key are rejected. Dedupe is not scoped
only to a temporary connection ID, because the connection may be refreshed before
notification succeeds.

If upload succeeds but Tessera notification fails, Relay retains the manifest key
and submission attempt ID and reports the upload complete with notification
pending. It retries that notification without re-uploading. If the role connection
expired, a replacement must authenticate the same protocol, assignment, role and
identity before Relay uses it. A manual webpage fallback submits the same manifest
key and attempt ID, so it cannot create a second logical submission.

For a lost grant response, save the requested maximum lifetime before issuance and
use provider-confirmed time plus a conservative skew before reissuing. A corrected
or rolled-back local clock alone cannot prove that the unseen grant expired.

Recovery uses the authenticated storage endpoint, not a cached public URL, to
check an exact object or current head. It does not infer completion from a prefix
listing.

V1 assumes one active workspace for the coordinator identity. It reauthenticates
the current head just before accepting or publishing and blocks on conflict.
Cross-machine compare-and-swap, coordinator signing leases and cryptographic fork
prevention are deferred rather than implied.

## Startup behavior

Before recommending the next authored task, Relay checks unresolved operations
from the current and older participant/head scopes. A later status success cannot
hide an older uncertain mutation.

```text
verified complete       -> update the local checklist and continue
safe continuation       -> show that exact continuation
still running           -> show the exact active operation
definitely no effect    -> discard only the stale checklist marker
cannot determine        -> stop with the exact missing fact
```

Examples of useful blockers are `Cannot contact the recorded Docker daemon to
verify contributor removal` and `A temporary grant may remain valid until 14:05
UTC`. Do not show `Inspect existing state`, a generic retry menu, or a prose box.

Every guided task after workspace creation—including role setup, identity
generation, enrollment, storage preparation and final archive actions—must declare
whether it is read-only, local-only, Docker lifecycle, credential issuance,
immutable upload, mutable publication or human handoff. Tests reject an
unclassified state-changing task. Calling a command `status` does not make it
read-only if it updates high-water or other local safety state. Launcher download
before workspace creation remains independently rerunnable through checksum
verification and fresh-path/atomic installation.

## Compatibility

Existing successful output bindings and participant candidate manifests remain
usable. Existing `running` or `failed` attempts receive task-specific inspection:

- verify and adopt a complete result;
- continue an existing participant candidate or immutable upload;
- clear a local-only attempt only after proving it produced no output; or
- wait for or revoke a possibly issued temporary grant.

If an old record lacks enough information to resolve a potentially consequential
effect, Relay blocks that operation and explains why. Deleting workflow state does
not turn uncertainty into permission to start again.

Migration first reads all existing workflow and launcher activity records, writes
and syncs the complete new recovery-state document, then marks migration complete.
It preserves the old files as a backup until the migrated state and referenced
outputs verify. An interrupted migration always restarts from the retained old
records; it never merges by choosing whichever record has the newest timestamp.

For example, if an old participant attempt contains a verified Phase 1 candidate
but no completed upload, migration records the original image, candidate hashes
and submission attempt ID with `candidate verified` and `upload pending`. Restart
then shows `Upload the completed Phase 1 contribution`; it does not regenerate the
contribution or ask the participant to interpret the old files.

Most of this work belongs in Relay. The proof tool needs atomic staging for
commands—currently ceremony initialization—that can leave an ambiguous partial
final directory, plus exact-prefix continuation when identity generation leaves a
valid private key before its public identity file. No Groth16 ceremony schema
change is required for V1.

## Explicitly deferred

- multiple active machines/workspaces for one role identity;
- participant turn claims and fencing generations;
- remote coordinator signing leases and automatic coordinator failover;
- non-clonable/HSM coordinator signing;
- automatic recovery from complete machine or role-folder loss;
- special handling for NFS, Dropbox or other non-local filesystems;
- durable capture of an unsigned witness observation before receipt preparation;
- a generic distributed transaction framework across Relay and Tessera; and
- cryptographic prevention of a malicious participant or coordinator bypassing
  Relay.

Implementation is complete only when the focused fault matrix in the
[implementation audit](crash-recovery-audit.md) passes.
