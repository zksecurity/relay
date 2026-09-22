# Launcher and saved-action reference

Operators use [installation](../install.md) and their role guide.
Shared saved settings also support the [resumable role workflow](../role-workflow.md).
A host-native Relay controls local Docker; ceremony commands run in Linux
images. Participant cleanup uses a separate host supervisor, never a nested
Docker socket.

## Settings and mounts

| Option | Container path | Contents |
| --- | --- | --- |
| `--work` | `/work` | Current role's inputs, outputs, config, and grants |
| `--trust` | `/trust` | Public inputs, read-only |
| `--keys` | `/keys` | Role key files, read-only |
| `--aws-credentials` | `/credentials/aws` | Coordinator-only shared-credentials file |

Use disjoint, narrow directories containing regular files and directories.
No symlinks, sockets, repository roots, home-directory mounts, or key mounts
on upload stations. Commands name files, never inline private values.
Non-participant commands use container paths; participants use host paths.

Ordinary containers use a read-only root, non-root UID, dropped capabilities,
disabled core dumps, bounded temporary memory, and a pinned local Docker
endpoint. Offline roles disable network; their host must also be disconnected
during signing. Removing an ordinary role container is not an erasure receipt.

## Proof runtime limits

Every role-image and participant proof container defaults to two CPUs, a 6 GiB
hard memory and swap limit, `GOMAXPROCS=2`, `GOMEMLIMIT=4GiB`, and `GOGC=25`.
These bounds also cover transcript inspection, coordinator verification and
sealing, and release signing; a heavy operation cannot bypass them by entering
through another role command. The Docker host needs at least 6 GiB available to
the daemon plus memory for the host and other services. Relay retains the exact
participant create arguments so interruption cleanup continues to identify the
original bounded container.

Maintainers can tune a host before launching Relay with integer environment
variables:

```text
RELAY_DOCKER_RUNTIME_CPUS
RELAY_DOCKER_RUNTIME_MEMORY_GIB
RELAY_DOCKER_RUNTIME_GO_MEMORY_GIB
RELAY_DOCKER_RUNTIME_GOGC
```

Relay rejects malformed values, fewer than 4 GiB of container memory, disabled
or extremely infrequent garbage collection, and a Go heap target that leaves
less than 2 GiB of container headroom. Before proof work it also rejects a
Docker daemon whose reported CPU/memory capacity is smaller than the requested
limits or whose cgroup configuration cannot enforce CPU, memory and swap limits.
Overrides apply to subsequent
invocations only. Record them in the operator runbook and capacity-test the
exact circuit before production; raising a limit does not create host capacity.

## Save an action

`ceremony setup NAME --role ROLE --release role-images-COMMIT -- TOOL ARGS`
verifies the map through GitHub CLI, checks the launcher commit, selects the
role/platform image, prepares directories, and downloads a missing digest.

Explicit alternatives are `--image`, or `--image-amd64` and `--image-arm64`.
They cannot be combined with `--release`. These alternatives rely on the
operator authenticating supplied digests separately.
`--download=false` supports preloaded explicit images on disconnected hosts;
release import requires online verification.

The selected platform follows the native launcher's architecture.
Images remain cached between actions; `open` never downloads images.
Settings live under the OS user config directory at
`relay/ceremonies/NAME/ROLE`, with files mode 0600 and directories 0700.
Use the same `--settings-root` on setup and open if overriding it.

Omit the command during non-participant setup to save shared role settings.
Then use `ceremony open NAME --role ROLE --action ACTION -- TOOL ARGS`.
Each action retains an immutable command and separate attempt history; omit the
command to reopen it. All actions sharing a profile use the same execution lock.
The launcher never infers ceremony progress. Setup refuses overwrites.
Profiles contain paths and public intent, not key/grant contents.
Existing authentication receipts and [role profiles](profiles.md) are still
required; image availability alone does not authenticate a role.

## Open and recover

`ceremony open NAME --role ROLE` displays the saved command and asks for
confirmation. A participant open without a grant checks status.
A saved action is not permission to repeat a signature or state transition.

`--reviewed-retry` is a low-level maintainer acknowledgement for an exact named
action, not proof that rerunning a mutation is safe. The guided workflow does not
offer it as generic recovery; preserve failed activity records.
Participants use their existing tracked cleanup and candidate-resume flow;
status alone does not remove an orphan container.

The launcher does not forward host AWS environment credentials or interactive
SSO/credential-process state. The shared-credentials mount alone does not
solve R2 control-token or parent-secret delivery.

The explicit `relay role` interface accepts the same role/image/mount settings
and runs one command without saving it. It requires an already loaded image.
Older direct native APIs remain for compatibility; guided participant launches
require a Docker profile and never silently fall back to native contribution.
