# Participant cleanup lifecycle

## Trust boundary

Production and rehearsal participants use the same Docker cleanup sequence.
Whole-machine wiping and separate post-wipe statements are not required.
Container removal is logical cleanup, not proof of physical erasure. Even an
honest participant may unknowingly leave secret remnants in host/VM memory,
swap, backing storage, snapshots, or backups. A later compromise could recover
them. Accepting this residual risk is an explicit ceremony design choice.

A dedicated controlled machine can reduce risk. A disposable VM still depends
on its host; deleting its disk does not establish secure erasure. Stronger
cleanup cannot undo a secret already copied elsewhere. No VM driver ships here.

## Sequence

1. Authenticate the public head and inputs; validate the pinned local daemon.
2. Hold the participant profile lock for the complete operation.
3. Create the exact tracked contributor container with network disabled,
   read-only inputs, bounded tmpfs, disabled core dumps and container swap,
   dropped capabilities, and only a narrow writable public-output handoff.
4. Inspect the effective security configuration before starting the container.
5. Run the contribution; record its exit status.
6. Force-remove the exact container, including its anonymous volumes.
7. Require inspection to stop resolving it and a successful container-list
   query showing that its exact ID is absent.
8. Validate the public handoff and record the lifecycle receipt.
9. Show the participant the measured cleanup and unassessed host risks.
10. Require `CLEANUP PRECAUTIONS CONFIRMED` before signing the cleanup statement.
11. Recheck the authenticated public head and upload the public candidate,
    with the manifest last. Failure preserves resumable public output.

The public candidate and cached software images are intentionally retained.
Relay does not prune unrelated containers, volumes, images, or host files.

## Automated checks versus participant claims

Relay records the daemon endpoint and identity, image digest, platform,
container ID, security settings, exit status, removal time, and absence result.
It checks actual daemon security options; an empty user-namespace setting is
not evidence of a separate user namespace. Remote endpoints are rejected.
The receipt must not contain random values, key bytes, credential values, or
memory dumps. It is a local operational log, not physical proof of erasure.

The participant confirms they did not deliberately retain snapshots, memory
dumps, or other secret copies and did not configure contribution-environment
backups. Relay cannot establish those facts by inspecting Docker.

Proof-tool's v2 contribution/cleanup records scope controls to the contributor
environment and explicitly require `host_remnants_not_excluded: true`.
The cleanup record authenticates process termination, ephemeral environment
removal, and `no_deliberate_copies_confirmed`; it does not claim that every
host byte was overwritten. It is signed and bound to the exact contribution,
participant, output, phase, and timestamp. The local lifecycle log is not
cryptographically bound into that record.

## Platform precautions

On Linux, Relay requires native Docker Engine through a local Unix socket and
disabled host swap. Docker Desktop on Linux is rejected because the host check
would not establish the guest's configuration. These checks still do not rule
out snapshots, backups, hibernation, or a compromised host.

On macOS, Docker Desktop runs the contributor in a Linux VM. Container swap
controls do not establish that macOS or the VM retained no memory copies.
Relay records Mac host swap as unassessed; it must never describe it as disabled.
Do not snapshot, back up, hibernate, or debug/dump the contribution environment.
Use a separately reviewed dedicated environment if this residual risk is not
acceptable to the ceremony organizers.

## Recovery and failure handling

| Condition | Required behavior |
| --- | --- |
| SIGINT/SIGTERM | Cancel work, force-remove the exact tracked container, and verify absence. |
| Abrupt kill or host crash | Preserve lifecycle state; resolve the tracked orphan before new work. |
| Removal fails or absence cannot be checked | Stop before attestation/upload. |
| Participant declines confirmation | Leave the candidate local; do not attest/upload. |
| Upload fails after signing | Revalidate the public candidate and unchanged head before resuming. |

Final release still requires mathematical replay, valid contribution and
cleanup signatures, audits, witnesses, mirrors, beacon evidence, and release
authorization. It has no separate whole-machine-wipe gate.

## Tests

Cover effective Docker controls, read-only inputs and narrow handoff, local
daemon binding, interruption/orphan cleanup, exclusive profile locking,
removal/absence failures, exact confirmation, immutable public resume, and
rejection of missing or mismatched signed cleanup records. Tiny same-host
ceremonies test functionality, not independent participants or production
security approval.
