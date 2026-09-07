# Run ceremony role tools with Docker

For a reusable command that remembers these settings and asks for confirmation,
use [saved setup and guided opening](../../docs/GUIDED_SETUP.md).

`relay role` is a host-side launcher. It runs the tools for your role in a
preloaded Docker image, so ordinary online roles do not need a host installation
of AWS CLI or proof-tool. The host still needs Relay and Docker. This is a new
launcher, not a published multi-platform installer or production-approved image.

| Role | Where the tools run | Network |
| --- | --- | --- |
| Coordinator, witness, mirror, auditor | Online tools image | Enabled |
| Upload station (release or production decision) | Online tools image; no signing-key mount | Enabled |
| Release signer, decision signer | Minimal offline image | Disabled |
| Key generation, for any role | Minimal offline image | Disabled |
| Participant turn | Host Relay supervises the existing disposable contributor image | Contributor has no network |

The participant supervisor and its AWS upload CLI still run on the host. This
exception preserves Relay's checked contributor cleanup without putting a Docker
socket inside another container. The launcher rejects native participant profiles;
older direct Relay commands remain available for compatibility and tests.

## Coordinator preparation

Provide each operator with the approved host Relay, the correct platform's
immutable image digest, matching tool-identity receipt, public trust files, and
prefilled role commands/profile. Image digests must come through the ceremony's
authenticated channel, not just from the registry being downloaded from.

For each Linux platform, stage the approved static `relay` and `mpc-ceremony`
binaries in a fresh build directory. Use the Dockerfile here with that directory
as its build context. Do not build with a directory containing keys or credentials.
Verify the binaries against their approved release manifests before building.
Check that proof-tool's `go version -m` output includes its Git revision and
other required ceremony build settings. A binary that can print help or generate
a key may still be rejected when it initializes or joins a ceremony. The real
rehearsal test below covers that stronger boundary.

```sh
# IMAGE_BUILD_ROOT contains only the verified binaries.
# AWS_CLI_IMAGE must be the approved official AWS CLI repository@sha256:digest.
docker build --platform linux/arm64 --target online \
  --build-arg AWS_CLI_IMAGE="$AWS_CLI_IMAGE" \
  --file docker/roles/Dockerfile --tag ceremony-online:REVIEWED "$IMAGE_BUILD_ROOT"
docker build --platform linux/arm64 --target offline \
  --build-arg AWS_CLI_IMAGE="$AWS_CLI_IMAGE" \
  --file docker/roles/Dockerfile --tag ceremony-offline:REVIEWED "$IMAGE_BUILD_ROOT"
```

Use `linux/amd64` instead for that platform. The online image includes AWS CLI
because Relay uses it for S3/R2 transport. The offline target contains only
proof-tool, with no shell or AWS CLI. The participant contributor still uses
[`../ceremony-tool/Dockerfile`](../ceremony-tool/Dockerfile), not the online image.

Review and distribute one immutable digest per image/platform. Local rehearsal
may use the full `sha256:...` image ID from `docker image inspect`. Mutable tags
are for build organization only; the launcher rejects them. Load images before
disconnecting an offline signer. The launcher never pulls images.

The existing kit packages Linux/amd64 host Relay only; see
[installation platform limits](../../docs/INSTALL.md#platform-scope). This PR does
not publish signed Mac/ARM64 host installers or change ceremony binary approval.

## Directory setup

Give each role a separate directory and identity. Create private directories
(mode `0700`) for work, public trust inputs, and signing keys. Do not use your
home, repository, or a shared multi-role directory. The mounts must not overlap
and must contain only regular files/directories, not sockets or symlinks.

| Launcher option | Path inside the container | Access |
| --- | --- | --- |
| `--work /absolute/role-work` | `/work` | Read/write |
| `--trust /absolute/role-trust` | `/trust` | Read-only |
| `--keys /absolute/role-keys` | `/keys` | Read-only |
| `--aws-credentials /absolute/credentials` | `/credentials/aws` | Read-only; coordinator only |

Place only the current role's files in these directories. An upload station's
work directory must contain signed public output and its scoped grant, never
the signer's private key. The role label does not authenticate a ceremony role:
the signed roster, key checks, enrollments, and grants still do that.

Use **container paths** in non-participant commands and saved profiles. For
example, use `/work/ceremony`, `/trust/coordinator.hex`, and `/keys/signing.hex`.
Create those profiles inside the online image with `relay ceremony init-config`,
using the matching Linux tool receipt from `/trust`. Existing host-path profiles
need to be recreated for these mount paths; do not overwrite working profiles.

## Run online role commands

Prefix the existing runbook command with the launcher settings, then `--`:

```sh
relay role --role witness --image "$ONLINE_IMAGE" --platform linux/arm64 \
  --work "$ROLE_WORK" --trust "$ROLE_TRUST" -- \
  relay witness run --config /work/ceremony/config/witness-phase1.json --once
```

Use the corresponding role and command for coordinator, mirror, or auditor.
Coordinators may also run `aws` commands, such as `aws --version`, after `--`.
The coordinator can mount a dedicated mode-`0600` AWS shared-credentials file
with `--aws-credentials`. Match its named profile to the storage configuration.
Do not mount your entire `.aws` directory. This initial launcher supports that
credentials-file path, not interactive AWS SSO login or host credential-process
configuration. Other online roles receive short-lived grant files in `/work`.

For an upload station, use `--role upload-station` followed by the runbook's
`relay release run` or `relay submit-evidence` command. No `--keys` is permitted.
Command arguments are passed directly, not evaluated by a shell. Use key/grant
file paths, never paste secret contents into arguments.

## Generate a keypair

For any role, choose its own dedicated private work directory and run:

```sh
relay role --role keygen --image "$OFFLINE_IMAGE" --platform linux/arm64 \
  --work "$IDENTITY_WORK" -- \
  mpc-ceremony identity generate --identity-id participant-03 \
    --display-name "Participant Three" \
    --private-key-out /work/participant-03.private.hex \
    --public-identity-out /work/participant-03.identity.json
```

The private key intentionally persists in that protected directory. Send only
the public identity JSON to the coordinator. See the
[key-generation guide](../../PARTICIPANT_KEY_GENERATION.md) for custody rules.
For offline signers, generate their keys on their offline machines.

## Sign offline

On the offline machine, use `--role release-signer` or `--role decision-signer`,
the offline image, and the existing `mpc-ceremony` signing recipe after `--`.
Mount public review files in `/work` and the role's key directory at `/keys`.
These roles always use `--network=none` and reject AWS credential mounts.
Transfer only the signed public output to the separate online upload station.
Container network isolation does not replace keeping the signing machine offline.

## Participant turns

Initialize a Docker participant profile using the
[installation guide](../../docs/INSTALL.md), with host paths and the approved
contributor image/platform. Then use:

```sh
relay role --role participant --config "$PARTICIPANT_CONFIG" -- status
relay role --role participant --config "$PARTICIPANT_CONFIG" -- \
  run --grant /absolute/path/participant.grant.json
```

The host supervisor handles the contribution, cleanup, confirmation, and upload.
It is not wrapped in another Docker container. Resume and `attest-host-wipe`
use the same existing participant command flags after `--`.
Production Mac contributions still require the later whole-device wipe and
verified signed confirmation before final release.

## Limits and recovery

All role containers use a read-only root, a non-root UID, dropped capabilities,
disabled core dumps, and bounded temporary memory. Only the explicitly supplied
directories/files are mounted. The launcher resolves and pins a local Docker
Unix endpoint; remote daemons are rejected. It forwards no host AWS environment
credentials, Docker socket, or arbitrary Docker run options.

Ordinary role containers use `--rm`; this is convenience cleanup, **not** a
participant erasure receipt. After an interrupted job, check its public outputs
before retrying. Power loss or Docker failure can leave containers needing
operator cleanup. Participant recovery continues to use the existing tracked
lifecycle and must not be replaced with this ordinary role-container workflow.

The launcher does not establish that host memory, swap, snapshots, or backups
contain no secrets. Key directories and identity outputs need the same custody
policy inside Docker as outside it.

References: [Docker run options](https://docs.docker.com/reference/cli/docker/container/run/)
and [official AWS CLI images](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-docker.html).

## Tests

`go test ./...` runs the launcher policy tests without Docker. For the opt-in
real-container smoke test, build the two images above, then run as a non-root user:

```sh
RELAY_ROLE_ONLINE_IMAGE="$ONLINE_IMAGE" \
RELAY_ROLE_OFFLINE_IMAGE="$OFFLINE_IMAGE" \
RELAY_ROLE_PLATFORM=linux/arm64 \
go test ./cmd/relay -run TestDockerRoleImages -v -count=1
```

This checks all eight container role presets, effective container settings,
AWS CLI availability, and real key generation with mode-`0600` private output.
It is not a full ceremony, audit, signing, or upload integration rehearsal. The
Docker smoke test is opt-in; the normal CI run does not download these images.

To also compute and accept three real tiny-circuit phase-1 contributions, set
`RELAY_ROLE_REHEARSAL=1` with the same image variables and run
`go test ./cmd/relay -run TestDockerRolesTinyPhase1Rehearsal -v -count=1`.
This uses the participant Docker driver and the coordinator role-container policy.
It remains a same-host rehearsal, not an object-storage, phase-2, audit, or final
release test.
