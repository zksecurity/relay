# Interrupted work during a Relay update

Target design. “No restart” means preserving valid ceremony progress, not skipping
failed verification or promising that missing secrets/evidence can be recovered.

## Establish that old work has stopped

Never hot-swap a running operation. Normal exit waits for child completion; hold
workspace/profile locks through review and activation. Inspect all containers,
including created/stopped/paused ones, for overlapping work/trust/key mounts on
the authenticated local daemon. Check ancestor mounts, including `/`.

For older releases, a killed parent can release its lock before its child creates
a container. A container snapshot is not proof of safety. The clean-exit path
requires honest confirmation that all source sessions/actions finished normally
and no direct commands will be started concurrently.

If termination was uncertain, activation blocks until a release-specific local
maintenance procedure establishes that old clients cannot submit further work
and no retained container can run. Never silently kill unrelated containers or
restart Docker. A host restart alone is insufficient if containers auto-restart
or a remote daemon is involved. Unverifiable cases remain blocked.

Future releases persist execution intent before spawning and require a shared
execution lease across all entry points. An unresolved intent blocks upgrades
even if its lock is free. Reconciliation accounts for descendants, daemon tasks
and containers before clearing it. This cannot be retrofitted by a target marker
that the released source binary never reads.

## Classify every operation

| Observed facts | Upgrade handling |
| --- | --- |
| Definitely not started; no effects | Run later under qualified target code with normal confirmation |
| Complete with a verified outcome | Retain completion, exact bytes and IDs; never repeat |
| Partial/uncertain, compatible adapter exists | Bind operation to its original inputs/runtime and the named adapter; explain resume action |
| Partial/uncertain, no adapter | Finish/reconcile using the old runtime, or block with a specific explanation |
| Conflict, failed authentication or missing required evidence | Stop; neither upgrade nor a checkbox repairs it |

Inventory all sources: generic journal, coordinator intent/checkpoint directories,
saved subprocess actions, grants, download receipts, contributor lifecycle state,
cleanup records, review/signature outputs and provider publication records.
An empty generic journal or an existing file alone proves neither success nor
absence of side effects. Unrecognized retained state blocks activation.

Inventory also reads the durable local activity log and fingerprints its bytes.
Missing history, an incomplete final record and actions without recorded
completion are displayed as limitations, never rewritten as successful actions.
Corrupt records stop inventory. This unauthenticated history does not replace
protocol reconciliation or establish that an old child process has stopped.

Adapters are narrowly enumerated code paths, not arbitrary commands from release
JSON. They authenticate local bytes and the exact remote attempt/version where
relevant. Store original operation ID, input digests, runtime, adapter and outcome;
no operator-written audit essay. Upgrading does not execute the adapter: normal
resume offers the concrete action and any required signing/upload confirmation.

## Stage-specific rules

| Stage / role | Facts that determine safe continuation |
| --- | --- |
| Setup and identities | Preserve existing keypair and signed initialization. Resolve partial initialization with its original tool; never regenerate keys or reinitialize over outputs |
| Enrollment, all enabled roles | Reverify record, signature, disclosure and exact ceremony assignment; reconcile inbox upload and signed enrollment acceptance separately |
| Grants | Preserve allocated attempt and scope. Renew access for that attempt only; resolve uncertain issuance or wait for a verified upper expiry bound. Unknown expiry is not permission to guess a wait; never broaden access |
| Contribution, either phase | Preserve allocation, candidate and execution/cleanup records. No automatic repeat of uncertain randomness generation. A replacement allocation requires a fresh separate contribution through normal protocol approval |
| Candidate transfer | Check fixed inventory and exact remote bytes. Resume missing immutable files, manifest last; collisions stop. Successful upload is not acceptance |
| Coordinator acceptance/rejection | Authenticate retained signed checkpoint and predecessor. If its exact digest is in verified accepted ancestry, treat publication as complete; otherwise apply original conditional-write rules, never replace a competing head |
| Closure / beacon | Preserve signed round and timing. Authenticate existing closure/seal artifacts; a CLI update cannot change the chosen round, shorten a wait or backdate evidence |
| Witness / mirror | Preserve exact event/head and observation times. Expired or missed duties cannot be completed by retrospective statements |
| Auditor / coordinator full verification | Reuse a result only if verifier, full inputs and scope match and the fixed bug does not invalidate that result; otherwise rerun verification, not contributions |
| Final signer | Preserve review package and existing signature. Reverify before using either; new or changed signing requests require fresh explicit approval and original offline procedure |
| Release upload / publication | Reconcile exact reviewed package, approval and stored versions. Publish only approved bytes; rejected/superseded packages stay unpublished |

Public backend synchronization authenticates signed history and relevant bytes;
it cannot reconstruct private keys, local cleanup facts or unknown process state.
Use backend state plus retained local facts to choose the role's next instruction.
Remote advancement by another role is normal: recompute the plan if it changes
the pending operation's validity. Do not reset every role to the same stage.

## State-machine properties to test

`Observe(local, authenticated_backend) → classify → plan → confirm → activate`.
`Resume(selection, operation) → verify → reconcile or explicitly execute`.

- No selection change without an exact authorized source/target/role match.
- An uncertain outcome never authorizes blind repetition of an operation.
- No second computation for one allocation and no copied candidate under another.
- Verified remote success survives loss of the local completion checkpoint.
- Activation crashes leave an old or complete new selection, never half of each.
- Upgrades do not mark signing, cleanup, delivery, acceptance or observations done.
- Safe old-version reentry covers state produced after the update, not just before.

Incompatible local-state migrations are not included. Preserve existing formats
with readers/adapters and sidecar selection records. If an update cannot do that,
refuse it until a separate migration and predecessor-exclusion design is qualified.
