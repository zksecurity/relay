# Prepare your computer

These optional scripts prepare prerequisites, not ceremony keys or cloud storage.
Run them as your normal user from an authenticated Relay source checkout.
Ask your coordinator for the reviewed source version and how to obtain it;
these scripts are not yet bundled into the launcher installer. Open a terminal
in that checkout's top-level `relay` directory before running the commands below.
Keep `scripts/setup/` together: each platform script uses `common.sh`.
Do not pipe an unverified download into a shell or run the entire script with sudo.

## Mac

Check your setup without installing or changing anything:

```bash
bash scripts/setup/macos.sh --check
```

To offer installation of missing tools:

```bash
bash scripts/setup/macos.sh --install
```

Already-installed tools are kept. On a prepared Mac, the installer may have
nothing to install. Neither command starts a ceremony.

The script can install GitHub CLI and Docker Desktop using an existing Homebrew
installation. If Homebrew is missing, follow its [official installation guide](https://docs.brew.sh/Installation)
or install the prerequisites manually, then rerun. It does not run a downloaded
Homebrew bootstrap script. Existing Docker installations are not replaced.
Docker Desktop onboarding and any licensing/administrator prompts remain yours
to review. Finish onboarding, wait for Docker to start, and rerun the check.
If GitHub CLI is outdated, update it using its original installation method.

The script never disables Mac swap or wipes anything. Docker Desktop's VM and
macOS can retain memory/storage remnants; container cleanup does not exclude them.

## Ubuntu / Debian

Automated installation supports Ubuntu 22.04/24.04 and Debian 12/13 on AMD64/ARM64.
It requires a systemd host and `sudo` for individually approved installation steps.
Other distributions, WSL, and custom setups need administrator review.

```bash
bash scripts/setup/linux.sh --check --participant
```

If checks report missing prerequisites, offer installation and swap preparation:

```bash
bash scripts/setup/linux.sh --install --participant
```

Omit `--participant` for coordinator, witness, mirror, auditor, or signer setup;
those roles do not need host swap disabled merely to run their role tools.

The installer asks separately before adding official Docker/GitHub APT sources,
installing packages, starting Docker, or changing Docker group membership.
The **docker group grants root-equivalent access**. If you accept membership,
log out fully and back in before continuing. Do not run Relay as root.
Docker installation can start services at boot and change host networking.

Existing Docker installations, conflicting packages, and repository definitions
are preserved; ambiguous cases stop for manual review. Approved earlier steps
are not rolled back if you decline a later prompt. Repository key downloads
rely on the publishers' HTTPS endpoints; APT then verifies package signatures.

For participants, the script reports available RAM and swap use. Ask the
coordinator for your circuit's RAM requirement and close other workloads first.
It refuses to offer swap disabling if available RAM cannot hold the current
swapped data plus a 1 GiB margin. This is a precaution, not a capacity guarantee.
`swapoff --all` affects every workload and can still cause out-of-memory failures.

Swap disabling requires explicit confirmation and affects the current boot only.
The script does not delete swap files or edit boot configuration. Services or a
reboot may re-enable swap, so recheck before contributing. After the ceremony,
ask your administrator to restore the previous configuration. Relay repeats
its host-swap and Docker checks before contribution.

## Finish

Sign in yourself with `gh auth login`, rerun the check, then follow
[Install once](install.md). No tokens, private keys, or credentials should be sent to
the coordinator. Passing setup checks is not production ceremony approval.
If a step stops, read its message, resolve the issue, and rerun; do not bypass
checks. Package installation on fresh machines has not yet been tested.

Manual references: [Docker Ubuntu](https://docs.docker.com/engine/install/ubuntu/),
[Docker Debian](https://docs.docker.com/engine/install/debian/),
[Docker access permissions](https://docs.docker.com/engine/install/linux-postinstall/),
[Docker Mac](https://docs.docker.com/desktop/setup/install/mac-install/),
[GitHub CLI Linux](https://github.com/cli/cli/blob/trunk/docs/install_linux.md).
