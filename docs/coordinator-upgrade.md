# Upgrade an existing coordinator

Relay v0.4.0 and later let you select a published coordinator update without a
separate release-pair approval. Run the upgrade command from the **new** launcher.
Relay verifies the release and records your choice; it does not claim the version
pair passed compatibility testing.

This path supports initialized coordinators between completed operations. It refuses an
unfinished upload, acceptance, publication, lifecycle transition, or release-signer
handoff; resolve that work with the original Relay first.
Participants and release signers can keep their current versions for a
coordinator-only fix. Their contributor and signing images remain pinned, as do
the signed definition, circuit, proof-tool, identities and existing progress.

For a V5 ceremony started on v0.6.0 and still before Phase 2, finish the
current Phase 1 operation before upgrading. The new coordinator release can
later receive the signer's public release package and publish the final
decision without installing an upload station. Qualification of the exact
v0.6.0-to-target release pair and the full guided continuation is required
before applying that change to an ongoing production ceremony. Do not use the
new launcher as a substitute for the `ceremony upgrade` command below.

## 1. Finish the current operation and save

Wait for any upload, acceptance or publication to finish. Resolve interrupted
actions using the current guide before upgrading. Refresh signed progress when
possible, then choose **Q — Save and exit** in operations and **0 — Save and exit**
in setup. Exit other local sessions using the same coordinator workspace.

Keep Docker available and retain the original launcher and ceremony folders.
Record the existing local ceremony name, settings-root path printed by the guide,
and installer-created `start.sh` path. Do not initialize another ceremony.

## 2. Download and verify the new launcher

Choose an exact published version from [Relay releases](https://github.com/zksecurity/relay/releases).
This Bash example uses v0.6.2 after it is published; substitute the exact
version you intend to install.
Use `relay-darwin-arm64` for Apple Silicon, `relay-darwin-amd64` for Intel Mac,
`relay-linux-amd64` for x86 Linux or `relay-linux-arm64` for ARM Linux.
GitHub CLI (`gh`) must be available.

```bash
set -euo pipefail
version=v0.6.2
binary=relay-darwin-arm64
upgrade_dir="$HOME/.local/share/relay/upgrades/$version"
mkdir -p "$HOME/.local/share/relay/upgrades"
mkdir "$upgrade_dir" # A fresh directory; retain existing installations.
cd "$upgrade_dir"

gh release download "$version" --repo zksecurity/relay \
  --pattern relay-release-version.txt
test "$(sed -n '1p' relay-release-version.txt)" = "$version"
commit=$(sed -n '2p' relay-release-version.txt)
[[ "$commit" =~ ^[0-9a-f]{40}$ ]]
gh attestation verify relay-release-version.txt --repo zksecurity/relay \
  --signer-workflow zksecurity/relay/.github/workflows/publish-role-images.yml \
  --source-ref refs/heads/main --source-digest "$commit" --deny-self-hosted-runners

gh release download "role-images-$commit" --repo zksecurity/relay --pattern "$binary"
gh attestation verify "$binary" --repo zksecurity/relay \
  --signer-workflow zksecurity/relay/.github/workflows/publish-role-images.yml \
  --source-ref refs/heads/main --source-digest "$commit" --deny-self-hosted-runners
chmod 755 "$binary"
```

Stop if any command fails. Keep the download directory permanently: the updated
shortcut refers to that executable. Downloading alone does not upgrade a ceremony.

## 3. Select the update

In the same shell, replace the name and settings root below with your existing
values. The name is the saved local name, not the ceremony's human-readable title.

```bash
"$upgrade_dir/$binary" ceremony upgrade YOUR_SAVED_CEREMONY_NAME \
  --role coordinator \
  --settings-root "/absolute/path/to/your/existing/settings-root" \
  --release "role-images-$commit"
```

No `--approval-release` is needed. The command uses the exact commit release tag,
even when you downloaded by numbered version.

Confirm that sessions have exited only after doing so. Review the source/target
commits and retained-state inventory before confirming the update. Relay rechecks
the frozen inputs, records the selection and updates a recognized `start.sh`.
Wait for **Application update selected**; a download or confirmation alone does
not establish successful installation.

## 4. Resume and verify

Run the printed `start.sh`. Choose **Open ceremony operations and progress**.
Confirm the update is active, storage refresh succeeds, and the expected phase
and accepted contribution count are present. Continue with the next displayed
action. The original ceremony release name can remain visible; the new local
application selection does not rewrite the signed definition.

## If the upgrade stops

| Result | Next step |
| --- | --- |
| Interrupted before selection | Retain all files and rerun the same command with the same target. |
| Selection committed but shortcut repair interrupted | Rerun the same command from the same new launcher to repair the shortcut. |
| Custom shortcut preserved | Use the explicit resume command printed by Relay; custom shell logic is not overwritten. |
| Missing `start.sh` | Directly launched setups currently need their original-release shortcut restored. Preserve the saved profile and request setup assistance; creating another ceremony is not a repair. |
| Unfinished action, changed inputs, unknown state or proof-tool mismatch | Resolve the reported cause using retained evidence. Do not delete records or edit pins to pass the check. |
| Failed first refresh after initial AWS publication | The first coordinator upgrade can authenticate the published sequence-zero checkpoint using the existing host AWS login binding and local signed files. Missing or conflicting evidence still rejects. |

Keep the original release and `.relay-upgrades` records for diagnosis. Older
launchers cannot interpret operator-selected upgrades; switching back to an old
executable is not a supported rollback. Use the selected launcher for recovery.

Historical qualified selections remain supported. Maintainers can still run
[release-pair tests](maintainer/ceremony-upgrade-qualification.md), but they are
separate from permission to select an operator-controlled coordinator update.
