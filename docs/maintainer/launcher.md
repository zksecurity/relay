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

The default allocation is two CPUs, a 6 GiB hard memory and swap limit,
`GOMAXPROCS=2`, `GOMEMLIMIT=4GiB`, and `GOGC=25`. The V4 guide's `[L]`
menu saves explicit CPU and memory preferences for subsequent operations. It
shows total Docker capacity, which is not a measurement of free memory. Leave
capacity for the host and other services; qualify the exact circuit before
increasing parallelism. Automatic resource recommendations are not yet enabled.

The `[B]` menu sets aggregate Docker resource policy. Before onboarding, use
`relay resources` to configure the same host-local policy without a ceremony
workspace. Noninteractive setup verification fails closed with this recovery
command when capacity cannot be established. Strict mode rejects
unbounded workloads. Operator-budget mode explicitly acknowledges the listed
unbounded external workloads and assigns a total Relay CPU/memory budget; it
disables automatic recommendations. A replacement workload, relevant resource
change, or daemon capacity change requires renewed review. Missing or corrupt
policy never grants permission to ignore unbounded workloads. Resource-policy
records currently live beside the shared daemon lock; removal requires renewed
acknowledgment. This policy does not cap unrelated services.

Admission is wired into contributor and ordinary role creation. Ordinary roles
retain a deterministic container name and created ID before attaching. A retained
container stops duplicate launch; a verified absent container allows a subsequent
execution through the existing workflow checks. Inspection, setup verification, release-tool checks, and renewable-login paths
also use admission. Short credential probes hold admission for their bounded
runtime; longer action containers carry their own claims after creation. Real
Docker lifecycle and release qualification remain required.

Direct role launches accept `--cpus`, `--memory-gib`, `--go-memory-gib`, and
`--go-gc-percent`. The Go memory target must remain at least 2 GiB below the
container ceiling. Docker CPU quota and `GOMAXPROCS` use the same CPU count;
the memory and swap limits remain equal. Relay rejects invalid settings and
Docker daemons that cannot enforce the requested limits.

Contribution plans, named actions, and V4 proof-command resource records retain
the allocation selected before launch. Retrying a recorded operation uses those
limits, even after preferences change. Legacy records without a resource field
retain the released default. Corrupt resource records stop recovery rather than
silently selecting different limits. Running containers are not resized. The
child-command heartbeat reports elapsed waiting time, not a completion estimate.

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

In the guide's resource menu, `[S]` offers the validated 2-CPU/6-GiB allocation
only when strict accounting finds enough unclaimed capacity and it fits saved
limits. This is a snapshot, not a reservation; admission checks again at launch.
Suggestions are disabled under operator-budget policy or uncertain inventory.
Larger automatic CPU recommendations require exact-circuit measurements. The
operator can still explicitly adjust limits using the existing controls.
