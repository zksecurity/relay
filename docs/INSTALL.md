# Installing ceremony tools

This is the normal installation path for coordinators, participants, witnesses,
mirrors, auditors, and release upload stations. It installs published production
binaries; it does not build either project from source.

Release maintainers and independent build auditors use
[RELEASE.md](RELEASE.md) instead.

## Information to obtain first

Obtain these values through the ceremony's authenticated trust channel:

- the approved Relay release tag and Linux/amd64 binary SHA-256;
- the approved proof-tool GitHub repository, release tag, and `mpc-ceremony`
  Linux/amd64 binary SHA-256; and
- the expected AWS CLI major version, currently v2.

The expected hashes must come from a channel independent of the binary
downloads. A checksum copied from the same GitHub release as its binary detects
download corruption, but it does not protect against a compromised release.

## Download and install Relay and `mpc-ceremony`

Install `curl` and `sha256sum` through the operating system first. For a general
installation, create the installer dotenv file:

```bash
cd /path/to/relay
cp scripts/install.env.example scripts/install.env
chmod 0600 scripts/install.env
INSTALL_ENV=scripts/install.env
```

For the scripted three-machine rehearsal, use its machine `.env` for both
installation and the later role commands. Replace `N` with `1`, `2`, or `3`:

```bash
cd /path/to/relay
cp scripts/three-machine-rehearsal/machine-N/.env.example scripts/three-machine-rehearsal/machine-N/.env
chmod 0600 scripts/three-machine-rehearsal/machine-N/.env
INSTALL_ENV=scripts/three-machine-rehearsal/machine-N/.env
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
scripts/install-ceremony-tools.sh "$INSTALL_ENV"
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
appropriate machine example and copy the seven verified installer fields into
it. Confirm the recorded binary paths and hashes before filling its remaining
ceremony-specific fields:

```bash
cd /path/to/relay
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
