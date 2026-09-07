# Install once

## Prepare your computer

Start with [guided Mac or Linux setup](setup-host.md). It checks your computer
without changing it, then offers installation with your approval if needed.
If your prerequisites are already ready, continue to **Download and verify**.

- **Supported computer:** macOS or Linux, with an Intel/AMD64 or ARM64 processor
  (including Apple silicon).
- **Docker:** install and run Docker locally. On a Mac, use Docker Desktop.
  Linux participants need native Docker Engine and disabled host swap; the
  setup guide explains how to check this and offers a prompted swap-off step.
- **GitHub CLI:** install a current version of `gh` and sign in with
  `gh auth login`. Relay uses it to download and verify release files.
- **Shell tools:** have Bash and `shasum` available for the commands below.
- **No Go installation needed:** you will use prebuilt release binaries.
- **Agreed release:** get the exact release commit through the authenticated
  channel agreed with your coordinator, so you can confirm who supplied it.
  The release must include the launcher installer and the image map with
  GitHub build provenance used to verify its origin.

## Download and verify

Run in Bash, replacing the commit placeholder:

```bash
set -euo pipefail
RELAY_COMMIT=REPLACE_WITH_FULL_40_CHARACTER_RELEASE_COMMIT
RELAY_RELEASE="role-images-$RELAY_COMMIT"
RELAY_DOWNLOAD=$(mktemp -d)
gh release download "$RELAY_RELEASE" --repo zksecurity/relay \
  --pattern install-launcher.sh --dir "$RELAY_DOWNLOAD"
gh attestation verify "$RELAY_DOWNLOAD/install-launcher.sh" \
  --repo zksecurity/relay \
  --signer-workflow zksecurity/relay/.github/workflows/publish-role-images.yml \
  --source-ref refs/heads/main --source-digest "$RELAY_COMMIT" \
  --deny-self-hosted-runners
bash "$RELAY_DOWNLOAD/install-launcher.sh" "$RELAY_RELEASE"
RELAY="$HOME/.local/share/relay/releases/$RELAY_COMMIT/relay"
```

Success prints the installed versioned path. The installer selects your machine,
verifies provenance and checksums, and checks Docker. It refuses to overwrite
an existing installation. If already installed, use that exact versioned path.
The Mac binary is GitHub-attested, not Apple-notarized.

## Prepare your role's directories

Choose a fresh, narrow directory for this ceremony and role.
Replace the example names; do not reuse another role's folder:

```bash
ROLE_ROOT="$HOME/ceremonies/example-ceremony/participant-03"
mkdir -p "$(dirname "$ROLE_ROOT")"
mkdir -m 0700 "$ROLE_ROOT"
ROLE_WORK="$ROLE_ROOT/work"
ROLE_TRUST="$ROLE_ROOT/trust"
ROLE_KEYS="$ROLE_ROOT/keys"
mkdir -m 0700 "$ROLE_WORK" "$ROLE_TRUST" "$ROLE_KEYS"
```

Keep these paths and the release ID with your private local settings.
Public trust files go in `trust`; signing keys stay in `keys`.
Grants are private files in `work`, never pasted into command arguments.
These directories must be disjoint and contain no sockets or symlinks.

## Follow your role guide

Open your guide from the [role index](README.md).
Its `setup --release` command verifies the map and automatically selects the
image for your role and machine. `open` displays the saved action and asks
for confirmation before running it in Docker.

One saved name represents one action, not the next step of the whole ceremony.
Use fresh names for different phases/tasks. Keep using the same launcher path.
Before disconnecting a signing machine, prepare its images and saved actions;
opening a prepared action needs no GitHub access or image download.

If installation, identity, or verification fails, preserve the error output and
contact the coordinator. Do not bypass verification or substitute another build.
