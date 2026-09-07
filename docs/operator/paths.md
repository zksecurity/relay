# Choose how to run your role

For the Docker launcher introduced in PR #18, prefer
[saved setup and guided opening](../setup/GUIDED_SETUP.md): save a reviewed action once,
then reopen it and confirm before it runs. The [role launcher](../../docker/roles/README.md)
is the explicit alternative when you need to supply every option yourself.
Neither interface is a complete ceremony navigator or a published installer.
Use a release that actually contains these commands; older signed kits do not
gain them by following newer documentation.

## What goes on each machine

| Role | Host requirements | Where ceremony tools run |
| --- | --- | --- |
| Coordinator, witness, mirror, auditor, upload station | Approved host Relay and Docker | Online image, including Relay, proof-tool, and AWS CLI |
| Release signer, decision signer, key generation | Approved host Relay and Docker; prepare the image before disconnecting | Minimal proof-tool image, with container networking disabled |
| Participant | Approved host Relay, Docker, host AWS CLI, matching Linux proof-tool file and tool receipt | Host supervisor manages a separate, network-disabled contributor |

Provider provisioning is separate: AWS/R2 setup scripts still need their
documented host tools, such as Bash, jq, curl, AWS CLI, or Wrangler. The role
launcher runs reviewed tool commands, not arbitrary shell scripts.

Offline signing still requires the ceremony's disconnected-machine and key
custody procedure. A network-disabled container is not a disconnected host.
Distinct keys are checked by the protocol where required; Docker roles and
different keys do not prove that different people control them.

The guided layer supports native host Relay builds on macOS and Linux,
AMD64 and ARM64, and chooses a Linux image matching that Relay build. The
coordinator must supply a reviewed image for that platform. The current kit
builder only packages Linux/amd64 host tools; see
[installation scope](../setup/INSTALL.md#platform-scope). Participant Linux machines
require a local native Docker Engine and disabled host swap; Linux Docker
Desktop is unsupported. Production Macs require the signed host-wipe policy
and the separate release-time wipe gate described in the
[isolation design](../design/participant-isolation.md).

## Three different setup operations

1. **Authenticate tools:** the kit's `./setup verify` checks the authenticated
   kit and emits a tool-identity receipt. For separately distributed host/image
   builds, the coordinator must supply matching authenticated materials.
2. **Authenticate a role:** `relay ceremony init-config` checks the ceremony,
   role identity, and effective tool hashes against that receipt and writes a
   role config. It does not download images.
3. **Remember a task:** `relay ceremony setup` saves launcher settings and an
   operator-selected action. It can download a supplied repository digest and
   check the image platform. It does not replace either authentication step.

Non-participants may save settings first, then stage files and initialize their
role config inside the online image before opening the saved action. Participant
setup instead requires an existing Docker role config on the host. The kit's
`./setup` script is not included in the minimal role images.

**An image check is not a signature check.** Setup checks that Docker has the
immutable image reference supplied by the operator and that its platform
matches. It does not verify a publisher signature or a coordinator-signed image
approval manifest. Obtain approved digests through the independent authenticated
coordinator channel. The CLI phrase “Configured image is available” means only
that the supplied image is available; setup did not establish its approval.
Separately, the participant workflow checks the proof-tool binary against the
signed ceremony binary policy. A signed release tag does not sign a Docker image.

## Paths and existing command recipes

The runbooks retain low-level recipes so every ceremony operation remains
explicit. For non-participant Docker tasks, run their `relay`, `mpc-ceremony`,
or allowed `aws` command through the role launcher, or save that command with
guided setup. Use these paths **inside** the command and its role config:

| Host option | Container path | Contents |
| --- | --- | --- |
| `--work /absolute/role-work` | `/work` | This role's inputs, outputs, config, and scoped grants; writable |
| `--trust /absolute/role-trust` | `/trust` | Public trust inputs; read-only |
| `--keys /absolute/role-keys` | `/keys` | Separately protected signing keys; read-only |
| `--aws-credentials /absolute/credentials` | `/credentials/aws` | Coordinator-only shared credentials file; read-only |

For example, a host file `role-work/ceremony/config/witness-phase1.json` becomes
`/work/ceremony/config/witness-phase1.json`. Paths such as `/var/lib/...`,
`/trusted/...`, and `/secure/...` in direct recipes are not automatically mounted
or translated. Recreate profiles with the correct container paths and matching
Linux tool receipt; preserve existing working profiles. Host `install`, `cd`,
and `export` steps are preparation instructions, not launcher tool commands.
The launcher does not forward host AWS credential environment variables or
provide an interactive SSO/credential-process setup flow.

Participants use **host paths** throughout. Initialize explicitly with
`--execution-mode docker`, the immutable contributor image, and its Linux
platform. The initializer currently also needs the approved Linux proof-tool
file on the host at the same resolved absolute path used inside the image
(default `/usr/local/bin/mpc-ceremony`); its hash must match the receipt.
The host hashes that file; the container executes the Linux binary.

Older direct commands remain supported. In particular, direct `init-config`
defaults to native execution if the mode is omitted. Guided/role participant
launches reject native profiles. Do not remove Docker flags from participant
examples or interpret non-participant container packaging as participant
isolation.

## What opening and cleanup mean

One alias stores one action per role, not an inferred next ceremony step. Use
separate aliases for different phases/tasks. Opening rechecks settings, displays
the saved action, and asks for confirmation. For a participant, opening without
a grant checks status; it does not contribute. Image readiness does not establish
that ceremony files, enrollments, credentials, or role prerequisites are ready.

Images remain cached between tasks. Ordinary task containers are disposable;
mounted outputs, keys, and saved settings remain. Container removal is not proof
that no secret survives in host memory, swap, backups, or snapshots. Participant
cleanup has its own tracked removal checks and separate erasure confirmation;
the initial “continue” answer is not that confirmation.

Local activity records help detect unfinished tasks; they are not signed ceremony
evidence or automatic website progress updates. Review failed ordinary tasks
before `--reviewed-retry`. For participants, resume a verified completed public
candidate with a fresh grant; incomplete work needs supervisor recovery and
coordinator review. Status does not remove orphan containers.

The opt-in Docker tests cover role launches, a guided saved action, and a tiny
three-contribution Phase 1 rehearsal. They do not establish a full Docker
Phase 1/2, storage, audit, and final-release ceremony. The separate
[three-machine scripts](../../scripts/three-machine-rehearsal/README.md) remain a
direct-CLI rehearsal, not an all-role Docker test. Normal CI does not run the
opt-in real-image tests.
