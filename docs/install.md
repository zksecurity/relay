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
- **Shell tools:** have Bash and `shasum` installed. You can keep using Zsh;
  Executable scripts select Bash automatically; no shell switch is needed.
- **No Go installation needed:** you will use prebuilt release binaries.
- **Agreed release:** get the exact release commit through the authenticated
  channel agreed with your coordinator, so you can confirm who supplied it.
  The release must include the launcher installer and the image map with
  GitHub build provenance used to verify its origin.

## Guided installation

From the authenticated source checkout used for computer setup, run:

```bash
./scripts/install-launcher.sh --guided
```

The installer asks for the exact release URL or tag from your coordinator,
your ceremony name, role, and a fresh role folder. It verifies the downloaded
launcher, selects your machine type, and saves your settings after confirmation.
It does not start a ceremony, generate keys, or configure storage/profiles.

Use a reviewed source version supplied through your agreed authenticated channel,
not an arbitrary downloaded script. If using the published installer instead,
verify it before running it as shown below. Guided mode requires an installer
containing this change; older published installers accept only a release tag.

<details>
<summary>Alternative: download and verify the published installer</summary>

Run in Bash or Zsh, replacing the placeholder with the coordinator's release commit:

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
chmod u+x "$RELAY_DOWNLOAD/install-launcher.sh"
"$RELAY_DOWNLOAD/install-launcher.sh" --guided
```

</details>

An existing launcher is reused only if its hash matches the verified release.
Existing role folders are never overwritten. The Mac binary is GitHub-attested,
not Apple-notarized.

## Load your saved settings

The installer prints one `source` command. Run it in your current Bash or Zsh
terminal, including whenever you open a new terminal. No shell switch is needed:

```bash
source "$HOME/ceremonies/example-ceremony/coordinator/relay-env.sh"
```

This sets `$RELAY_COMMIT`, `$RELAY_RELEASE`, `$RELAY`, and the `$ROLE_*` paths
used by the role guides. You do not need to fill them in manually. Only source
your own installer-created file: sourcing a file executes shell code.
The private role folder contains `work`, `trust` (public trust files), and
`keys` (private signing keys). Keep grants in `work`, never command arguments.

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
