# Participant contribution isolation

Status: implemented by Relay's explicit `docker` participant execution mode.
Production Mac and Linux participation use guided container cleanup and signed
participant confirmation, without mandatory whole-machine wiping.

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
- attempts contributor removal on normal/error exits and handled SIGINT/SIGTERM;
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
boundary can plan a dedicated disposable Linux VM and destroy it after copying
out the public candidate. Relay does not yet implement the VM lifecycle driver
described below; this is not an automated alternative supplied by this release.

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
- no host PID or IPC namespace sharing, and explicit `--userns=host` rejected;
- the selected Docker context resolved to an absolute local Unix socket and
  pinned for every later Docker command;
- Docker daemon ID, version, operating system, architecture, and effective
  `userns`/`rootless` security options inspected and recorded;
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

An empty container `UsernsMode` means the daemon default; it does not prove UID
remapping. Relay derives `daemon-remapped`, `rootless-daemon`, or
`daemon-default-unremapped` from the daemon's actual `SecurityOptions` and
records that result without claiming remapping where none exists. Running as a
non-root UID, dropping capabilities, and rejecting explicit host-user-namespace
mode remain mandatory.

Memory-backed files can still be swapped by the host or VM. Relay rejects
remote `tcp://` and `ssh://` Docker endpoints before checking Linux host swap,
then pins all commands to the resolved local Unix endpoint. Native Docker
Engine on Linux must have host swap disabled. Docker Desktop on Linux is
rejected because Relay cannot apply that host check to its hidden VM. On macOS,
VM and host swap remain explicitly unassessed. The workflow accepts residual
host-remnant risk; logical container removal does not establish physical erasure.

## Mount contract

```text
host                                  contributor
────────────────────────────────────────────────────────────
authenticated ceremony inputs  ─RO─> /relay/input
definition/signature/trust key ─RO─> /relay/trust/<file>
environment.json              ─RO─> /relay/config/environment.json
participant signing key       ─RO─> /relay/key/participant.key
fresh candidate handoff       ─RW─> /relay/output
                                      /tmp  (bounded tmpfs)
```

Only public candidate files may cross from `/relay/output` to the host. Relay must
reject symlinks, devices, sockets, unexpected filenames, files outside the
handoff directory, and outputs that fail the existing proof-tool verification
and digest checks.

The public candidate and its attestations are intentionally retained for
interrupted-upload recovery. They are not toxic waste.


Cleanup, confirmation, host wiping, and recovery: [lifecycle](lifecycle.md).
