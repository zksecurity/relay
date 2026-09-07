# Participant cleanup and host-wipe lifecycle

## Lifecycle state machine

Relay must use an explicit container lifecycle rather than treating
`docker run --rm` as sufficient evidence:

```text
preflight
  ↓
create container and persist its exact ID
  ↓
inspect effective configuration
  ↓
start and attach
  ↓
wait for successful exit
  ↓
remove exact container ID
  ↓
inspect exact ID and require "not found"
  ↓
validate public handoff
  ↓
participant no-copy confirmation
  ↓
signed erasure attestation
  ↓
recheck public ceremony head
  ↓
upload candidate manifest last (provisional on a production Mac)
  ↓
after the participant's final turn: erase the whole Mac and cleanly reinstall
  ↓
sign and upload the separate host-wipe attestation
  ↓
release verification checks every required wipe and may release parameters
```

Relay must inspect the effective container configuration before starting it.
It must not infer safety merely from the arguments it intended to pass.

The persisted cleanup record contains the container ID and non-secret
lifecycle state. If Relay or the host restarts, the next `participant run`
must finish cleanup for any recorded container before starting or resuming
other work.

All handled error and signal paths after container creation must attempt termination
and removal. Failure to verify removal is terminal: Relay must not attest or
upload.

Relay registers SIGINT and SIGTERM before creating the contributor. If either
arrives while the attached contribution is running, Relay cancels the Docker
client, force-removes the exact recorded container ID with its anonymous
volumes, verifies that both `inspect` and an all-containers query find no such
ID, removes the matching lifecycle state, and only then exits without
attesting or uploading. If absence cannot be verified, Relay fails closed and
retains the lifecycle state for recovery.

SIGKILL, power loss, and kernel/daemon failure cannot run Relay's signal handler.
Immediate removal is not guaranteed in these cases. Recover with the same
profile's `participant run`, which checks recorded orphan state before further
work; a status query alone does not perform this recovery. Do not attest or
upload while container absence remains unverified.

## Participant confirmation

After verified removal, require `NO COPIES RETAINED`. The participant confirms
no snapshots, memory dumps, contribution-secret copies, or backup copies were
retained. Wrong input, EOF, or uncertainty blocks attestation and upload.
The host supervisor has already performed the container cleanup.

## Evidence decision

For the first implementation, write a local lifecycle log containing image and
binary digests, the resolved local daemon endpoint and daemon ID, inspected
daemon security options, container ID, effective non-secret container security
configuration, timestamps, exit status, removal result, and the final
participant response.
The log must never contain command environment variables, key bytes, random
values, or container memory.

The immediate proof-tool erasure schema remains unchanged. Under the stated
honest-participant threat model, binding the lifecycle log into that signed
record would add audit integrity but would not prevent the accidental retention
or later-compromise risks in scope.

The existing erasure command may run only after Relay has measured successful
cleanup and received `NO COPIES RETAINED`. A future protocol revision may bind
a lifecycle-log digest if the ceremony adopts a malicious-participant audit
requirement.

## macOS assurance levels

### Rehearsal

Docker Desktop with a disposable contributor container is acceptable for
functional rehearsal. The evidence must describe this as container-level
cleanup, not physical erasure.

### Production

A production Mac may contribute through the same pinned Docker workflow. Its
candidate can be cryptographically verified and accepted into the chain before
the whole-device wipe, but that acceptance is provisional for release purposes.
The signed ceremony definition lists every participant subject to this policy
in `host_wipe_participants`.

After that participant's final scheduled contribution:

1. Preserve the public ceremony files and participant signing/config material
   only on separately approved storage. Do not preserve Docker Desktop state or
   any contribution-environment copy.
2. Use the supported macOS whole-device erase procedure and perform a clean
   reinstall.
3. Do not restore a pre-wipe backup, snapshot, Docker Desktop data, or
   private contribution-environment or contribution-randomness copy.
4. Restore only the approved public files, signing/config material, Relay, and
   the pinned proof-tool image.
5. Obtain an identity-scoped `host-wipe` grant and run
   `relay participant attest-host-wipe`. Type the exact confirmation only when
   all displayed assertions are true.

The proof tool signs a separate `host-wipe.json` record with the participant's
ceremony key. Operational-evidence verification requires exactly one valid
record for every participant named by the signed policy and checks that its
`wiped_at` is later than that participant's latest `contributed_at` among the
accepted chains (not the coordinator's `accepted_at`). Operationally, wait for
final-turn acceptance before wiping, as above. The
release signer therefore cannot sign or release final parameters while a
required wipe is missing, invalid, duplicated, or too early.

Relay prints `accepted provisionally` when the coordinator accepts a candidate
from a participant covered by this policy. That status is derived from the
signed definition and accepted chain, not stored as a separate mutable boolean.
Likewise, an inbox upload is only `submitted for review`; “wipe confirmed” is
authoritative only when proof-tool verifies the signed record inside the final
operational-evidence bundle. This avoids a dashboard or local state file
accidentally overriding the cryptographic release gate.

This is authenticated evidence of an honest participant's statement, not
physical or cryptographic proof of deletion. A malicious operator could copy
the secret before wiping and then sign a false statement. The design here is
for honest participants and primarily prevents an accidental long-lived copy
from remaining on a Mac that is compromised later.

A dedicated disposable Linux VM is a potential stronger boundary when the delay
between contribution and whole-host destruction is unacceptable. It requires a
separately reviewed lifecycle procedure; no VM driver ships here. It should not
be configured for snapshots, backups, hibernation, or swap.

A future VM-backed execution design must keep a trusted Relay supervisor and
the persistent participant signing-key file outside the disposable VM disk.
If the current proof-tool signs inside the guest, key bytes still enter guest
memory temporarily; keeping them entirely outside requires splitting signing
from contribution. The supervisor must authenticate and copy out only the
public candidate plus non-secret lifecycle evidence, destroy the exact VM and
verify the runtime no longer registers it, and only then permit participant
confirmation, erasure attestation, public-head recheck, and upload. It must
also specify crash recovery and authenticate every item crossing from the VM
before production use.

Removing a Docker container alone cannot establish that Docker Desktop's VM
memory, backing storage, host swap, SSD snapshots, or backups contain no
remnants. That is why production Mac release is gated on the later whole-device
wipe rather than container removal alone.

## Linux production profile

A VM driver is not required on a dedicated Linux machine using native Docker
Engine through a local Unix socket. Remote contexts and Docker Desktop on Linux
are rejected because Relay cannot bind its host swap check to those execution
hosts. The production procedure must still disable host swap, hibernation,
and core-dump persistence; exclude ceremony storage from backups and snapshots;
use the restricted mounts above; and power off or wipe the dedicated host at
the ceremony's required assurance level. Relay records container-level facts;
the participant remains responsible for host-level facts Relay cannot observe.

## Failure behavior

| Failure | Required behavior |
| --- | --- |
| Image or binary digest mismatch | Do not create the contributor. |
| Unsafe effective container configuration | Remove it without starting; do not contribute. |
| Contribution exits nonzero or is interrupted | Terminate and remove; do not attest or upload. |
| Public handoff is malformed | Remove contributor; retain no unverified output as resumable state. |
| Container removal fails | Stop; do not attest or upload. |
| Exact container ID still resolves after removal | Stop; do not attest or upload. |
| Participant declines or cannot confirm | Stop; do not attest or upload. |
| Upload fails after erasure | Retain the public candidate and use the existing resumable upload flow. |
| Required Mac wipe is outstanding | Contributions may remain accepted, but do not sign or publish the final release. |
| Host-wipe evidence is missing, duplicated, invalid, or predates the participant's final contribution | Reject operational evidence and block release. |

## Acceptance tests

The implementation is not complete until automated tests demonstrate:

- an unpinned or mismatching image is rejected;
- a mismatching ceremony binary is rejected;
- networked, privileged, root, writable-root, core-enabled, or broadly mounted
  containers are rejected before start;
- only the expected regular public files cross the handoff boundary;
- nonzero exit, cancellation, and simulated Relay termination invoke cleanup;
- a recorded orphan is cleaned before the next run;
- removal failure and a still-inspectable container block attestation/upload;
- an incorrect confirmation phrase blocks attestation/upload;
- a required post-wipe record is participant-signed, identity-scoped, and
  cannot be created for a rehearsal or an unlisted participant;
- missing or too-early host-wipe evidence blocks operational-evidence and
  release verification;
- logs and process arguments contain no random value or key material;
- upload failure preserves only the verified public resumable candidate; and
- a complete macOS Docker rehearsal uses the pinned Linux binary and exercises
  the measured-cleanup-before-confirmation order.
