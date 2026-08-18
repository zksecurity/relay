# Installing ceremony tools

This is the normal installation path for coordinators, participants, witnesses,
mirrors, auditors, and release upload stations. It installs published production
binaries; it does not build either project from source.

Release maintainers and independent build auditors use
[RELEASE.md](RELEASE.md) instead.

## Information to obtain first

Obtain these values through the ceremony's authenticated trust channel:

- the approved Relay release tag and Linux/amd64 binary SHA-256;
- the approved proof-tool release tag and `mpc-ceremony` Linux/amd64 binary
  SHA-256; and
- the expected AWS CLI major version, currently v2.

The expected hashes must come from a channel independent of the binary
downloads. A checksum copied from the same GitHub release as its binary detects
download corruption, but it does not protect against a compromised release.

## Download and install Relay and `mpc-ceremony`

Install `curl`, `grep`, and `sha256sum` through the operating system first.
Set the four values received through the authenticated release announcement.
The following checks stop immediately if any value is absent:

    : "${RELAY_TAG:?Set RELAY_TAG from the authenticated release announcement}"
    : "${MPC_TAG:?Set MPC_TAG from the authenticated release announcement}"
    : "${RELAY_SHA256:?Set RELAY_SHA256 from the authenticated release announcement}"
    : "${MPC_SHA256:?Set MPC_SHA256 from the authenticated release announcement}"
    INSTALL_ROOT=$(mktemp -d /tmp/ceremony-tools-install.XXXXXXXX)

    curl --fail --location \
      "https://github.com/zksecurity/relay/releases/download/$RELAY_TAG/relay" \
      --output "$INSTALL_ROOT/relay"
    curl --fail --location \
      "https://github.com/Emurgo/proof-tool/releases/download/$MPC_TAG/mpc-ceremony" \
      --output "$INSTALL_ROOT/mpc-ceremony"

Reject placeholders or malformed hashes before checking the downloads:

    printf '%s\n' "$RELAY_SHA256" | grep -Eq '^[0-9a-f]{64}$'
    printf '%s\n' "$MPC_SHA256" | grep -Eq '^[0-9a-f]{64}$'
    printf '%s  %s\n' "$RELAY_SHA256" "$INSTALL_ROOT/relay" | sha256sum --check
    printf '%s  %s\n' "$MPC_SHA256" "$INSTALL_ROOT/mpc-ceremony" | sha256sum --check

Both checks must report `OK`. Only then install the binaries:

    sudo install -m 0755 "$INSTALL_ROOT/relay" /usr/local/bin/relay
    sudo install -m 0755 \
      "$INSTALL_ROOT/mpc-ceremony" /usr/local/bin/mpc-ceremony

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

After installing and verifying both binaries, copy the example for the machine
being prepared. Replace `N` with `1`, `2`, or `3`:

```bash
cd /path/to/relay
cp scripts/three-machine-rehearsal/machine-N/.env.example scripts/three-machine-rehearsal/machine-N/.env
chmod 0600 scripts/three-machine-rehearsal/machine-N/.env
command -v relay mpc-ceremony
sha256sum "$(command -v relay)" "$(command -v mpc-ceremony)"
```

Paste the absolute paths reported by `command -v` into `RELAY_BIN` and
`MPC_BIN`. Paste the independently approved digests into `RELAY_SHA256` and
`MPC_SHA256`. Recording a digest in `.env` does not make it trusted: obtain the
expected value through the authenticated release channel before comparing it.
For a local test build without a published release, record its exact digest and
clearly treat the run as a rehearsal rather than production evidence.

Fill the remaining machine-specific paths, identities, and storage names, then
run that machine's `00-check-machine.sh` command from the rehearsal guide. Do
not store temporary grants, cloud secret keys, R2 parent tokens, ceremony
private keys, or build-signing private keys in `.env`.
