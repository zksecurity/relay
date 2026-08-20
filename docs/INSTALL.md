# Installing ceremony tools

This is the normal installation path for coordinators, participants, witnesses,
mirrors, auditors, and release upload stations. It installs published production
binaries; it does not build either project from source.

Release maintainers and independent build auditors use
[RELEASE.md](RELEASE.md) instead.

## Information to obtain first

Obtain these values through the ceremony's authenticated trust channel:

- the approved Relay release tag and Linux/amd64 binary SHA-256;
- the SHA-256 values of Relay's installer script and installer `.env`
  template;
- the approved proof-tool GitHub repository, release tag, and `mpc-ceremony`
  Linux/amd64 binary SHA-256;
- for a three-machine rehearsal, the rehearsal archive SHA-256; and
- the expected AWS CLI major version, currently v2.

The expected hashes must come from a channel independent of the binary
downloads. A checksum copied from the same GitHub release as its binary detects
download corruption, but it does not protect against a compromised release.

## Download the verified installer

Install `curl` and `sha256sum` through the operating system first. A source
checkout is not required. Set the Relay tag and the two independently approved
download hashes, then fetch the installer and its dotenv template:

```bash
: "${RELAY_TAG:?Set RELAY_TAG from the authenticated release announcement}"
: "${RELAY_INSTALLER_SHA256:?Set the approved installer script SHA-256}"
: "${RELAY_INSTALL_ENV_SHA256:?Set the approved installer env SHA-256}"
DOWNLOAD_ROOT=$(mktemp -d /tmp/ceremony-tools-download.XXXXXXXX)

curl --proto '=https' --tlsv1.2 --fail --location --show-error \
  "https://github.com/zksecurity/relay/releases/download/$RELAY_TAG/install-ceremony-tools.sh" \
  --output "$DOWNLOAD_ROOT/install-ceremony-tools.sh"
curl --proto '=https' --tlsv1.2 --fail --location --show-error \
  "https://github.com/zksecurity/relay/releases/download/$RELAY_TAG/install.env.example" \
  --output "$DOWNLOAD_ROOT/install.env"

printf '%s  %s\n' "$RELAY_INSTALLER_SHA256" \
  "$DOWNLOAD_ROOT/install-ceremony-tools.sh" | sha256sum --check
printf '%s  %s\n' "$RELAY_INSTALL_ENV_SHA256" \
  "$DOWNLOAD_ROOT/install.env" | sha256sum --check
chmod 0700 "$DOWNLOAD_ROOT/install-ceremony-tools.sh"
chmod 0600 "$DOWNLOAD_ROOT/install.env"
```

Do not pipe a network response directly into Bash. Verifying the saved script
before running it makes the code being executed an explicit authenticated
input.

## Choose the `.env` file

For a general installation, edit the downloaded template and use it directly:

```bash
INSTALL_ENV="$DOWNLOAD_ROOT/install.env"
${EDITOR:-vi} "$INSTALL_ENV"
```

For the scripted three-machine rehearsal, download the versioned archive and
use its machine `.env` for both installation and later role commands. Replace
`N` with `1`, `2`, or `3`, and select a persistent, access-controlled directory:

```bash
: "${REHEARSAL_ARCHIVE_SHA256:?Set the approved rehearsal archive SHA-256}"
curl --proto '=https' --tlsv1.2 --fail --location --show-error \
  "https://github.com/zksecurity/relay/releases/download/$RELAY_TAG/three-machine-rehearsal.tar.gz" \
  --output "$DOWNLOAD_ROOT/three-machine-rehearsal.tar.gz"
printf '%s  %s\n' "$REHEARSAL_ARCHIVE_SHA256" \
  "$DOWNLOAD_ROOT/three-machine-rehearsal.tar.gz" | sha256sum --check

CEREMONY_TOOLS_ROOT="$HOME/ceremony-tools"
mkdir -m 0700 -p "$CEREMONY_TOOLS_ROOT"
chmod 0700 "$CEREMONY_TOOLS_ROOT"
test ! -e "$CEREMONY_TOOLS_ROOT/three-machine-rehearsal"
tar -xzf "$DOWNLOAD_ROOT/three-machine-rehearsal.tar.gz" \
  -C "$CEREMONY_TOOLS_ROOT"
REHEARSAL_ROOT="$CEREMONY_TOOLS_ROOT/three-machine-rehearsal"
cp "$REHEARSAL_ROOT/machine-N/.env.example" \
  "$REHEARSAL_ROOT/machine-N/.env"
chmod 0600 "$REHEARSAL_ROOT/machine-N/.env"
INSTALL_ENV="$REHEARSAL_ROOT/machine-N/.env"
${EDITOR:-vi} "$INSTALL_ENV"
```

Fill these seven fields first:

```text
RELAY_TAG
MPC_RELEASE_REPOSITORY
MPC_TAG
RELAY_SHA256
MPC_SHA256
RELAY_BIN
MPC_BIN
```

The example installs into `/usr/local/bin`. Change the two absolute binary paths
before installation if this machine uses another existing installation
directory. Then run:

```bash
"$DOWNLOAD_ROOT/install-ceremony-tools.sh" "$INSTALL_ENV"
```

The installer reads only those seven dotenv assignments without executing the
file as shell code. It rejects missing values, placeholders, duplicate fields,
malformed tags, repositories, hashes, or destination paths. It downloads both
binaries into a private temporary directory, verifies both SHA-256 values
before installing either binary, installs them with mode `0755`, and checks that
both installed programs start. It uses `sudo` only when the destination is not
writable by the current user.

For an upstream production release, the authenticated announcement should name
`Emurgo/proof-tool`. Before that release pipeline is merged upstream, a test
announcement may explicitly name `zksecurity/proof-tool` and a prerelease tag.
Never switch repositories merely because the announced asset is missing.

For example, a fork rehearsal announcement sets
`MPC_RELEASE_REPOSITORY=zksecurity/proof-tool`; the final upstream production
announcement sets `MPC_RELEASE_REPOSITORY=Emurgo/proof-tool`. These are explicit
trust inputs, not installer defaults.

If an approved release has not published these assets yet, stop and ask its
maintainer to publish a reviewed release. Do not silently replace a production
binary with `go run`, an unreviewed local build, or a binary from another
channel.

## Install AWS CLI v2

Install `unzip` and `gpg` through the operating system first. Verify
the AWS download using the signature procedure in the
[official AWS CLI verification instructions](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#install-linux-verify-signature),
then install it. For Linux/amd64:

    AWS_INSTALL_ROOT=$(mktemp -d /tmp/aws-cli-install.XXXXXXXX)
    curl --fail --location \
      https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip \
      --output "$AWS_INSTALL_ROOT/awscliv2.zip"
    curl --fail --location \
      https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip.sig \
      --output "$AWS_INSTALL_ROOT/awscliv2.zip.sig"

After completing the documented GPG verification:

    unzip -q "$AWS_INSTALL_ROOT/awscliv2.zip" -d "$AWS_INSTALL_ROOT"
    sudo "$AWS_INSTALL_ROOT/aws/install" --update

Do not configure a provider credential yet. The coordinator and each role
receive different profiles or temporary grants later in their runbooks.

## Final verification

Finish every installation with:

    relay --help
    mpc-ceremony help
    aws --version
    command -v relay mpc-ceremony aws

Confirm that `aws --version` reports `aws-cli/2...` and that all commands resolve
to the reviewed paths. Record the commands, release tags, and binary hashes in
the local operator log. Do not begin a role handoff if anything differs from the
approved values.

## Record verified inputs for the tiny rehearsal

This section applies only to the
[scripted three-machine rehearsal](../scripts/three-machine-rehearsal/README.md).
The production runbooks do not depend on these `.env` files.

Install Bash, Python 3, and GNU coreutils on every rehearsal machine. Python is
used only by the rehearsal helpers to read the tiny ceremony definition; it is
not a Relay runtime dependency.

If the machine `.env` was not used during installation, create it now from the
appropriate machine example in the extracted archive and copy the seven
verified installer fields into it. Confirm the recorded binary paths and
hashes before filling its remaining ceremony-specific fields:

```bash
command -v relay mpc-ceremony
sha256sum "$(command -v relay)" "$(command -v mpc-ceremony)"
```

The output must match `RELAY_BIN`, `MPC_BIN`, `RELAY_SHA256`, and `MPC_SHA256`
already recorded in `.env`. Recording a digest there does not make it trusted:
obtain the expected value through the authenticated release channel before
installation. For a local test build without a published release, record its
exact digest and clearly treat the run as a rehearsal rather than production
evidence.

Fill the remaining machine-specific paths, identities, and storage names, then
run that machine's `00-check-machine.sh` command from the rehearsal guide. Do
not store temporary grants, cloud secret keys, R2 control-plane or parent
tokens, ceremony private keys, or build-signing private keys in `.env`.
