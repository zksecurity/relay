# Install Relay and select the role image

Use a release that includes `install-launcher.sh`, four native launcher files,
and `relay-role-images.release.json` with a `launcher_commit` field. Older
releases do not acquire these assets retroactively.

You need Docker running locally and a current GitHub CLI (`gh`) authenticated
with `gh auth login`. The launcher supports macOS and Linux on ARM64 and AMD64.
On macOS, use Docker Desktop. Participant Linux hosts still require native
Docker Engine and the existing swap checks. The installer needs Bash and
`shasum`; it does not require Go or administrator privileges.

Obtain the full release commit through the ceremony's authenticated channel.
Set it below, then run this Bash block. Stop if any verification fails.

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

The installer detects your architecture, verifies the selected binary and
checksums against GitHub provenance, and installs a versioned launcher. It
refuses to overwrite an existing installation. GitHub provenance is distinct
from Apple notarization; these binaries are not Apple-notarized installers.

For a coordinator, save and run a harmless first action:

```bash
"$RELAY" ceremony setup coordinator-check --role coordinator \
  --release "$RELAY_RELEASE" -- aws --version
"$RELAY" ceremony open coordinator-check --role coordinator
```

Setup verifies the release map, checks its commit against the running launcher,
selects the online image for this machine, downloads it if needed, and creates
private work/trust directories. Opening asks for confirmation and runs the
saved command in Docker. Later ceremony actions need their own reviewed
commands, files, and credentials; this initial check does not create a ceremony.

Other roles use the same `--release` option with their role and command.
Key generation and signers automatically select the offline image. Prepare
these images and saved actions before disconnecting a signing machine;
`open` needs neither GitHub access nor an image download.

Participants first create the existing authenticated Docker participant
profile. Then use `ceremony setup NAME --role participant --config FILE
--release "$RELAY_RELEASE"`. Setup verifies that the profile already names
the release's contributor image and machine platform. It never rewrites the
ceremony's signed binary policy or substitutes a different contribution tool.

Keep the versioned launcher path with the ceremony records and use it for
every subsequent `open`. A profile saved with `--release` rejects a launcher
from another commit. Existing explicit-digest profiles remain supported.

Follow the [coordinator runbook](../operator/COORDINATOR_RUNBOOK.md) for identity
collection, ceremony initialization, storage, and grants. The
[guided setup reference](GUIDED_SETUP.md) explains mounts and saved tasks.
