# Saved Docker setup and guided opening

Use `relay ceremony setup` once to save a role's Docker settings. Then use
`relay ceremony open` to review and run the saved action without retyping image
names, architecture flags, or mount paths.

This is the first guided CLI layer, not the complete Tessera task navigator.
The coordinator still supplies reviewed commands and approved image digests
through an authenticated channel. Setup does not obtain or approve them from a
registry automatically. The website does not control your signing key.

## One-time setup for an online role

For example, save a witness action using the two approved platform images:

```sh
relay ceremony setup demo-witness-phase1 --role witness \
  --image-amd64 "$APPROVED_AMD64_IMAGE" \
  --image-arm64 "$APPROVED_ARM64_IMAGE" -- \
  relay witness run --config /work/ceremony/config/witness-phase1.json --once
```

Setup selects the Linux image matching the architecture of your host Relay
binary. Use a native host Relay build on your Mac or Linux machine. If the
approved map has no matching image, setup stops. A single `--image DIGEST` is
also supported when the coordinator already selected the appropriate image.

Setup checks Docker and the local endpoint, downloads the exact repository
digest if absent, and checks its platform. It never chooses a newer version or
pulls a mutable tag. A local `sha256:...` image ID must already be loaded.
Use `--download=false` for an already-disconnected signing machine.

The command creates private `work` and public-input `trust` directories and
prints their location. Stage the authenticated files and create the existing
role profile with container paths as described in the
[role launcher guide](../../docker/roles/README.md). Setup does not invent missing
ceremony files, role enrollments, or signing keys. Image readiness is not a claim
that these later role-specific prerequisites are complete.

If you already have dedicated directories, supply `--work DIR` and `--trust DIR`.
For signing, use `--keys DIR` to reference an existing protected role key directory;
setup neither copies nor deletes its contents. Coordinators may supply a dedicated
`--aws-credentials FILE`. Never place secret bytes in the saved command arguments.

Settings are stored under the operating system's user configuration directory,
in `relay/ceremonies/ALIAS/ROLE/`. `--settings-root DIR` overrides that location
for tests or a separately approved storage layout; use the same override when
opening. Files use mode `0600`, and new directories use `0700`.

An alias is a local convenience name, not a signed ceremony ID. Currently it
stores one action per role. Use separate aliases for phase-specific profiles or
different tasks. Setup refuses to overwrite existing saved intent. Multi-phase
task navigation and importing the full coordinator template remain future work.

## Reopen and confirm

```sh
relay ceremony open demo-witness-phase1 --role witness
```

The tool checks the saved settings, Docker, and the already-cached image. It shows
the role, output location, key directory if used, and the exact saved command,
then asks `Continue? [y/N]`. It starts nothing unless you type `y` and press Enter.
No image is downloaded during `open`.

For ordinary roles, this is labeled a **saved action**, not a verified next step.
The underlying tools still authenticate the ceremony and enforce their own
preconditions. Reopening is not permission to blindly repeat a signing or upload
operation. Use a new reviewed task/alias when the ceremony moves to another step.

## Participants

First create the existing Docker participant profile using
[INSTALL.md](INSTALL.md). Then save its location:

```sh
relay ceremony setup demo-phase1 --role participant \
  --config /absolute/path/to/participant-phase1.json
relay ceremony open demo-phase1 --role participant
```

The first open offers a status check. It does not claim it is your turn based on
saved metadata and does not generate a contribution. Once the authenticated
status and coordinator handoff indicate your turn, run:

```sh
relay ceremony open demo-phase1 --role participant \
  --grant /absolute/path/to/fresh.grant.json
```

The summary shows the configured ceremony ID, participant identity, signing-key
file path, and output location. After your confirmation, the existing host
supervisor independently rechecks the ceremony, grant, turn, and Docker controls
before contributing. Its separate post-cleanup erasure confirmation remains
required; the initial `y` is not an erasure statement.

Native participant profiles are rejected. The approved image and platform come
from the existing participant profile; setup does not replace the ceremony's
signed binary policy or guess a different participant image.

## Interruptions and recovery

The guided tool records task starts and completions in a private `activity`
directory. It serializes concurrent opens of the same saved profile and forwards
SIGINT/SIGTERM to the child tool. It retains outputs and recovery records, not
secret memory or container snapshots.

For participants, existing candidate or partial lifecycle data blocks a fresh
contribution. For a completed public candidate, use:

```sh
relay ceremony open demo-phase1 --role participant \
  --grant /absolute/path/to/fresh.grant.json \
  --resume-candidate /absolute/path/to/saved-public-candidate
```

This uses the existing resume path: verify current state and candidate files,
then upload without recomputing the contribution. If the files are incomplete
or the public chain has moved on, it stops. `--status` offers a status check;
it is not an orphan-container cleanup command. Partial contributions and
unverifiable cleanup require the existing supervisor recovery procedure and
coordinator review, not deleting records to force a new turn.

For ordinary roles, an interrupted/failed latest task stops a blind rerun. Review
the actual outputs, any remaining container, and ceremony state first. If repeating
the saved action is appropriate, `--reviewed-retry` acknowledges that review and
still requires the confirmation prompt. The flag does not prove that retrying an
arbitrary action is safe. A successful retry provides a new checkpoint while
retaining earlier records. Generic automatic recovery for all role commands is
not implemented.

The existing Docker layer removes ordinary task containers and keeps the image
cached. It does not remove signing keys or saved public outputs. Participant
cleanup retains its stronger tracked lifecycle checks. Whole-Mac wipe and
offline-signing requirements are unchanged.

## Validation

Unit tests cover profile permissions, immutable image selection/download policy,
confirmation handling, task records, and blocking unknown participant state.
The opt-in `TestGuidedDockerOpen` test uses a real online image to exercise
setup, refusal to overwrite settings, a cancelled open, a confirmed open, and
completion recording. It runs `aws --version`, not a production ceremony action.
