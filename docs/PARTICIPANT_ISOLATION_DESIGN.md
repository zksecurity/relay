# Participant contribution isolation

Status: implemented by Relay's explicit `docker` participant execution mode.
On macOS, production use additionally requires a delayed whole-device wipe
attestation before the final parameters may be approved or released.

This document defines the Docker-backed participant workflow that Relay
implements for Groth16 ceremonies. It narrows the design to the threat we care
about: an honest participant should not accidentally preserve contribution
randomness that a later compromise could recover.

It does not claim cryptographic proof of erasure. A participant or host that is
malicious during the contribution can copy memory before cleanup and then
produce an apparently valid erasure statement.

## Security objective

The Groth16 contribution randomness must exist only inside a short-lived
contributor environment. Relay must automatically destroy that environment
before it creates an erasure attestation or uploads the public candidate.

The safe path must not depend on the participant knowing which Docker objects,
temporary files, or processes to remove manually.

## Roles and trust boundaries

Relay is the **participant supervisor**. It runs on the participant's host and:

- downloads and authenticates ceremony inputs;
- creates and validates the contributor container;
- starts the contribution and validates its public output;
- terminates and removes the contributor on every exit path;
- verifies that the exact container ID no longer exists;
- asks the participant only about copies Relay cannot observe;
- invokes the existing signed erasure command; and
- uploads only after the erasure record exists.

The participant supervisor is not the ceremony coordinator. The coordinator
must not receive the participant's private signing key or create the
participant's erasure statement.

The **contributor** is a fresh, one-shot container. It runs the pinned
`mpc-ceremony` contribution command and has no storage or network role.

```text
participant host
└── Relay supervisor
    ├── authenticated input cache
    ├── participant signing key
    ├── public candidate handoff
    └── disposable contributor
        ├── mpc-ceremony contribute
        ├── contribution randomness in process memory
        ├── no network
        └── temporary state destroyed on removal
```

Do not run Relay inside a container with `/var/run/docker.sock` mounted. Access
to the Docker socket is effectively control of the Docker host and defeats the
intended boundary. Relay should run on the host and invoke the local Docker
engine directly.

## Threat model

### In scope

- an honest participant forgetting or misunderstanding cleanup steps;
- contribution randomness remaining in a stopped container, writable layer,
  temporary file, swap, or core dump;
- a later compromise of the participant's ordinary workstation;
- accidental network access during contribution;
- accidental broad host mounts;
- interruption, contribution failure, or Relay termination during cleanup;
- use of an unapproved image or ceremony binary; and
- accidentally uploading before cleanup and confirmation.

### Out of scope

- a malicious participant deliberately copying the randomness;
- a host, kernel, hypervisor, or Docker daemon compromised during execution;
- physical RAM recovery from a machine that remains powered on; and
- cryptographic proof that no copy exists.

Production operators that need a shorter retention window or stronger physical
boundary should use a dedicated disposable Linux VM and destroy that VM after
copying out the public candidate.

## Image and binary model

Use a reproducible ceremony-tool image for each allowed participant platform,
selected by an immutable repository digest or local image ID. Other roles do
not generate toxic waste and do not need this contributor container.

The proof-tool v2 definition binds a canonical allowlist of exact executables,
including each binary's GOOS, GOARCH, architecture level, SHA-256, BLAKE2b-256,
and size. It can authorize both `linux/amd64` and `linux/arm64` in one ceremony,
provided both binaries have identical source, toolchain, dependency, and build
policy metadata. Each contribution attestation identifies the exact binary
that ran. A legacy v1 definition is treated as a one-binary allowlist.

Relay verifies both:

1. the configured immutable image digest; and
2. the `mpc-ceremony` binary digest allowed for the configured platform by the
   signed ceremony definition.

The image must already be present before the sensitive container is created.
The contributor runs with no network and cannot pull an image.

The generic `--ceremony-binary` hook is not used as an opaque Docker wrapper.
Relay's structured Docker execution driver owns and observes every contribution
lifecycle transition while continuing to use the existing ceremony inspection
and attestation interfaces.

## Container configuration

Relay must create the contributor with all of these controls:

- immutable image digest, never a mutable tag;
- non-root user;
- read-only root filesystem;
- `network=none`;
- no host PID, IPC, or user namespace sharing;
- all Linux capabilities dropped;
- `no-new-privileges` enabled;
- core dump soft and hard limits set to zero;
- a bounded, memory-backed temporary directory;
- authenticated ceremony inputs mounted read-only;
- the environment declaration mounted read-only;
- the participant signing key mounted as a single read-only file;
- one fresh, mode-`0700` public candidate handoff mounted writable; and
- no home directory, repository root, Docker socket, cloud credential, or
  unrelated host directory mounted.

The signing key is not Groth16 toxic waste, but it remains sensitive. The
approved and digest-pinned ceremony binary needs it to sign the contribution
attestation. It must never be copied into the image or writable container
storage.

Memory-backed files can still be swapped by the host or VM. Relay's preflight
must therefore require swap to be disabled at the Linux host/VM level. A
container flag alone is not enough.

## Mount contract

```text
host                                  contributor
────────────────────────────────────────────────────────────
authenticated ceremony inputs  ─RO─> /input
environment.json              ─RO─> /config/environment.json
participant signing key       ─RO─> /key/participant.key
fresh candidate handoff       ─RW─> /output
                                      /tmp  (bounded tmpfs)
```

Only public candidate files may cross from `/output` to the host. Relay must
reject symlinks, devices, sockets, unexpected filenames, files outside the
handoff directory, and outputs that fail the existing proof-tool verification
and digest checks.

The public candidate and its attestations are intentionally retained for
interrupted-upload recovery. They are not toxic waste.

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
lifecycle state. If Relay or the host restarts, the next participant command
must finish cleanup for any recorded container before starting or resuming
other work.

All error and signal paths after container creation must attempt termination
and removal. Failure to verify removal is terminal: Relay must not attest or
upload.

## Measured facts and participant assertion

Relay is responsible for measuring and displaying:

- approved image and ceremony-binary digests;
- effective network and mount configuration;
- core dump limit;
- contribution exit status;
- container removal; and
- absence of the exact container ID after removal.

The participant is responsible only for facts outside Relay's visibility:

- no VM or container snapshot was created or retained;
- no debugger or memory-dump mechanism copied the contributor's memory;
- no manual copy of private temporary state was retained; and
- the disposable environment was not enrolled in a backup system.

After verified cleanup, Relay must display the measured results and require
this exact production confirmation:

```text
Contribution completed.

Relay verified:
  ✓ contributor exited
  ✓ container <short-id> was removed
  ✓ container <short-id> no longer exists
  ✓ its writable layer and tmpfs were removed

Confirm that you:
  • did not create or retain a VM/container snapshot;
  • did not dump or copy the contributor's memory;
  • did not retain any other copy of the contribution randomness; and
  • did not configure the disposable environment for backup.

Type NO COPIES RETAINED to continue:
```

Any other input, EOF, or uncertainty stops the workflow without producing an
erasure attestation or uploading. There is no non-interactive bypass in
production mode.

This replaces the current ambiguous `DESTROYED` prompt. The participant does
not manually remove the container at the prompt; Relay has already done and
verified the mechanical cleanup.

## Evidence decision

For the first implementation, write a local lifecycle log containing image and
binary digests, container ID, effective non-secret security configuration,
timestamps, exit status, removal result, and the final participant response.
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
`wiped_at` is later than that participant's final accepted contribution. The
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

A dedicated disposable Linux VM remains the stronger option when the delay
between contribution and whole-host destruction is unacceptable. It should not
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
Engine. The production procedure must still disable host swap, hibernation,
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

## Implementation scope

The implementation changes Relay, proof-tool's signed definition and
operational-evidence schemas, participant documentation, Docker assets, and
tests. It provides container-level isolation for Linux and macOS and adds the
delayed whole-Mac wipe gate required for production macOS. It does not change
Groth16 arithmetic or the immediate contribution-erasure schema.

The implementation uses a small, testable execution-driver interface instead
of embedding Docker command construction throughout the participant workflow.
Native Linux execution remains available, but
production profiles must state their execution mode explicitly and must not
silently fall back from Docker to native execution.
