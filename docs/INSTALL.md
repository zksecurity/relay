# Installing ceremony tools

Both coordinator and role machines need `relay`, AWS CLI v2, and the trusted
`mpc-ceremony` binary. Relay uses AWS CLI for AWS S3 and Cloudflare R2.

These instructions target Linux. Production `mpc-ceremony` releases are built
for Linux/amd64 with Go 1.26.5. For another AWS CLI platform, follow the
[official AWS CLI installation guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).

## Information to agree before installation

The coordinator must publish through authenticated channels:

- the exact 40-character Relay source commit and expected binary SHA-256;
- the approved proof-tool signed tag, tag-signer fingerprint, source commit,
  and expected `mpc-ceremony` SHA-256;
- the approved Go version, currently `go1.26.5`; and
- the expected AWS CLI major version, currently v2.

A checksum obtained from the same download location as a binary proves only
download consistency. Confirm the expected binary digests through the
ceremony's independent trust channel before running either program.

## Install AWS CLI v2

Install `curl`, `unzip`, and `gpg` through the operating system first. Verify
the AWS download using the signature procedure in the
[official AWS CLI verification instructions](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#install-linux-verify-signature),
then install it. The AWS installer is the only workflow here that uses a
temporary directory: it contains disposable download and extraction files, not
ceremony source, build evidence, keys, or release artifacts. For Linux/amd64:

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
    aws --version

The final command must report `aws-cli/2...`. Do not configure a provider
credential yet; the coordinator and each role receive different profiles or
temporary grants later in their runbooks.

## Install Go 1.26.5 for source builds

Binary-only role machines do not need Go. A machine building Relay or
proof-tool must install Go using the [official Go installation
guide](https://go.dev/doc/install), then verify the exact version:

    go version

Expected on the production build host:

    go version go1.26.5 linux/amd64

Do not allow `GOTOOLCHAIN` to silently select a different production toolchain.
The proof-tool production build script independently checks the version and
toolchain digests.

## Prepare a source-build workspace

Choose a persistent, access-controlled filesystem with enough space for both
source trees, Go caches, and the proof-tool release package. Record the path in
the coordinator log. Do not put it inside the ceremony transcript, a signing-key
directory, or a system temporary directory.

The final path must not already exist. Replace `CEREMONY_ID` with the actual
ceremony identifier or another unique recorded label. For example, if
`/secure/builds` is an existing protected parent directory:

    CEREMONY_BUILD_ROOT=/secure/builds/ceremony-tools-CEREMONY_ID
    test ! -e "$CEREMONY_BUILD_ROOT"
    mkdir -m 0700 "$CEREMONY_BUILD_ROOT"

Use a new path for every build attempt. Retain the approved source commits,
build logs, checksums, manifests, SBOMs, and final release package according to
the ceremony evidence-retention policy. Intermediate Go caches and rejected
build attempts are not release evidence, but remove them only after recording
the failed attempt and confirming that no investigation requires them.

## Build Relay from the reviewed commit

Set `RELAY_COMMIT` to the approved full commit ID, not a branch name:

    RELAY_COMMIT=REPLACE_WITH_APPROVED_40_CHARACTER_COMMIT
    git clone https://github.com/zksecurity/relay.git \
      "$CEREMONY_BUILD_ROOT/relay-source"
    git -C "$CEREMONY_BUILD_ROOT/relay-source" \
      checkout --detach "$RELAY_COMMIT"
    test -z "$(git -C "$CEREMONY_BUILD_ROOT/relay-source" status --porcelain)"
    (
      cd "$CEREMONY_BUILD_ROOT/relay-source"
      CGO_ENABLED=0 go build -trimpath -buildvcs=true \
        -o "$CEREMONY_BUILD_ROOT/relay" ./cmd/relay
    )
    sha256sum "$CEREMONY_BUILD_ROOT/relay"
    go version -m "$CEREMONY_BUILD_ROOT/relay"

Confirm that `go version -m` reports the approved VCS revision, then compare the
binary digest with the independently distributed value. After they match:

    sudo install -m 0755 "$CEREMONY_BUILD_ROOT/relay" /usr/local/bin/relay
    relay --help

## Build `mpc-ceremony`

Never use `go run` for `mpc-ceremony`: it omits required VCS build metadata.

For a local rehearsal, build from an approved exact commit in a clean checkout:

    PROOF_TOOL_COMMIT=REPLACE_WITH_APPROVED_40_CHARACTER_COMMIT
    git clone https://github.com/Emurgo/proof-tool.git \
      "$CEREMONY_BUILD_ROOT/proof-tool-source"
    git -C "$CEREMONY_BUILD_ROOT/proof-tool-source" \
      checkout --detach "$PROOF_TOOL_COMMIT"
    test -z "$(git -C "$CEREMONY_BUILD_ROOT/proof-tool-source" status --porcelain)"
    (
      cd "$CEREMONY_BUILD_ROOT/proof-tool-source"
      CGO_ENABLED=0 go build -trimpath -buildvcs=true \
        -o "$CEREMONY_BUILD_ROOT/mpc-ceremony" ./cmd/mpc-ceremony
    )
    sha256sum "$CEREMONY_BUILD_ROOT/mpc-ceremony"
    go version -m "$CEREMONY_BUILD_ROOT/mpc-ceremony"

For production, use proof-tool's release builder instead. It requires a clean
checkout at the approved signed tag, Go 1.26.5 on Linux/amd64, the approved tag
signer fingerprint, and an offline build-signing key:

    PROOF_TOOL_TAG=REPLACE_WITH_APPROVED_SIGNED_TAG
    TAG_SIGNER_FINGERPRINT=REPLACE_WITH_APPROVED_FINGERPRINT
    cd "$CEREMONY_BUILD_ROOT/proof-tool-source"
    git checkout --detach "$PROOF_TOOL_TAG"
    mkdir "$CEREMONY_BUILD_ROOT/mpc-release-parent"
    scripts/build-mpc-ceremony-release.sh \
      --mode production \
      --signed-tag "$PROOF_TOOL_TAG" \
      --tag-signer-fingerprint "$TAG_SIGNER_FINGERPRINT" \
      --build-signing-key /offline/build-signing-key \
      --out-dir "$CEREMONY_BUILD_ROOT/mpc-release-parent/release"

The release directory contains `mpc-ceremony`, checksums, VCS/build metadata,
SBOMs, and the signed build-package manifest. Independently reproduce it with
`scripts/verify-mpc-ceremony-reproducible.sh` before distribution.

After verifying the release package and its independently published digest:

    sudo install -m 0755 \
      "$CEREMONY_BUILD_ROOT/mpc-release-parent/release/mpc-ceremony" \
      /usr/local/bin/mpc-ceremony
    mpc-ceremony help

## Install prebuilt binaries on role machines

A role may install the coordinator's reviewed binaries instead of compiling
them. First compare both binary hashes with the values received through the
independent trust channel:

    sha256sum ./relay ./mpc-ceremony

Only after both values match:

    sudo install -m 0755 ./relay /usr/local/bin/relay
    sudo install -m 0755 ./mpc-ceremony /usr/local/bin/mpc-ceremony

Finish every installation with:

    relay --help
    mpc-ceremony help
    aws --version
    command -v relay mpc-ceremony aws

Record these outputs with the ceremony's local operator log. Do not begin a
role handoff while any command resolves to an unexpected binary path or version.
