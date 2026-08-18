# Installing ceremony tools

Both coordinator and role machines need `relay`, AWS CLI v2, and the trusted
`mpc-ceremony` binary. Relay uses AWS CLI for AWS S3 and Cloudflare R2.

These instructions target Linux. Production Relay and `mpc-ceremony` releases
are built for Linux/amd64 with Go 1.26.5. For another AWS CLI platform, follow
the [official AWS CLI installation guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).

## Information to agree before installation

The coordinator must publish through authenticated channels:

- the approved Relay signed tag, tag-signer fingerprint, source commit,
  build-signing public key, and expected binary SHA-256;
- the approved proof-tool signed tag, tag-signer fingerprint, source commit,
  build-signing public key, and expected `mpc-ceremony` SHA-256;
- the approved Go version, currently `go1.26.5`; and
- the expected AWS CLI major version, currently v2.

A checksum obtained from the same download location as a binary proves only
download consistency. Confirm the expected binary digests through the
ceremony's independent trust channel before running either program.

## Install AWS CLI v2

Install `curl`, `unzip`, and `gpg` through the operating system first. Verify
the AWS download using the signature procedure in the
[official AWS CLI verification instructions](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#install-linux-verify-signature),
then install it. Its temporary directory contains only disposable download and
extraction files. For Linux/amd64:

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

Source-build machines also need Git, GnuPG, ripgrep, `sed`, GNU coreutils, and
GNU findutils from the operating system. The Relay builder performs no network
module download because Relay has no third-party Go dependencies.

Do not allow `GOTOOLCHAIN` to silently select a different production toolchain.
Both production builders independently check the version and toolchain
digests.

## Prepare a source-build workspace

Choose a persistent, access-controlled filesystem with enough space for both
source trees and release packages. Record the path in the coordinator log. Do
not put it inside the ceremony transcript or a signing-key directory.

The final path must not already exist. Replace `CEREMONY_ID` with the actual
ceremony identifier or another unique recorded label. For example, if
`/secure/builds` is an existing protected parent directory:

    CEREMONY_BUILD_ROOT=/secure/builds/ceremony-tools-CEREMONY_ID
    test ! -e "$CEREMONY_BUILD_ROOT"
    mkdir -m 0700 "$CEREMONY_BUILD_ROOT"

Retain the approved source checkouts, build logs, checksums, manifests, SBOMs,
and final release packages according to the ceremony evidence-retention policy.
The release builders separately create mode-`0700` clean checkouts, compiler
caches, and intermediate files under `/tmp`; they remove that scratch after
success or failure. No signing key or required release evidence is stored
there.

## Build Relay

For a local rehearsal, check out an exact reviewed commit and produce an
explicitly unsigned rehearsal package. Replace
`REPLACE_WITH_APPROVED_40_CHARACTER_COMMIT` below with the full 40-character
hexadecimal commit ID; do not run the placeholder literally:

    RELAY_COMMIT=REPLACE_WITH_APPROVED_40_CHARACTER_COMMIT
    test "${#RELAY_COMMIT}" -eq 40
    printf '%s\n' "$RELAY_COMMIT" | grep -Eq '^[0-9a-f]{40}$'
    git clone https://github.com/zksecurity/relay.git \
      "$CEREMONY_BUILD_ROOT/relay-source"
    git -C "$CEREMONY_BUILD_ROOT/relay-source" \
      checkout --detach "$RELAY_COMMIT"
    test -z "$(git -C "$CEREMONY_BUILD_ROOT/relay-source" status --porcelain)"
    mkdir "$CEREMONY_BUILD_ROOT/relay-rehearsal-parent"
    cd "$CEREMONY_BUILD_ROOT/relay-source"
    scripts/build-relay-release.sh \
      --mode rehearsal \
      --out-dir "$CEREMONY_BUILD_ROOT/relay-rehearsal-parent/release"

For production, use the approved signed tag and the Relay build-signing key.
The tag-signing key authenticates the source commit; the separate Ed25519 build
key authenticates the finished package.

Provision that build key once on the offline build-signing machine. Retain the
private file there and distribute the public file through the ceremony's
independent trust channel:

    umask 077
    go run ./scripts/relay-release-tool keygen \
      --private-key-out /offline/relay-build-signing-key \
      --public-key-out /offline/relay-build-public-key.hex

Never reuse this key as a ceremony-role or proof-tool build-signing key. The
production build then uses it as follows:

    RELAY_TAG=REPLACE_WITH_APPROVED_SIGNED_TAG
    RELAY_TAG_SIGNER_FINGERPRINT=REPLACE_WITH_APPROVED_FINGERPRINT
    cd "$CEREMONY_BUILD_ROOT/relay-source"
    git checkout --detach "$RELAY_TAG"
    RELAY_COMMIT=$(git rev-parse "$RELAY_TAG^{commit}")
    mkdir "$CEREMONY_BUILD_ROOT/relay-release-parent"
    scripts/build-relay-release.sh \
      --mode production \
      --signed-tag "$RELAY_TAG" \
      --tag-signer-fingerprint "$RELAY_TAG_SIGNER_FINGERPRINT" \
      --build-signing-key /offline/relay-build-signing-key \
      --out-dir "$CEREMONY_BUILD_ROOT/relay-release-parent/release"

Verify the package using the build public key obtained through the independent
trust channel, then reproduce the binary without access to the build-signing
private key:

    scripts/verify-relay-release.sh \
      --mode production \
      --expected-commit "$RELAY_COMMIT" \
      --expected-tag "$RELAY_TAG" \
      --tag-signer-fingerprint "$RELAY_TAG_SIGNER_FINGERPRINT" \
      --trusted-build-public-key-file /trusted/relay-build-public-key.hex \
      "$CEREMONY_BUILD_ROOT/relay-release-parent/release"
    scripts/verify-relay-reproducible.sh \
      --expected-commit "$RELAY_COMMIT" \
      --expected-tag "$RELAY_TAG" \
      --tag-signer-fingerprint "$RELAY_TAG_SIGNER_FINGERPRINT" \
      --trusted-build-public-key-file /trusted/relay-build-public-key.hex \
      --rebuild-dir "$CEREMONY_BUILD_ROOT/relay-reproduction-01" \
      "$CEREMONY_BUILD_ROOT/relay-release-parent/release"

The release directory contains `relay`, checksums, exact Go/VCS metadata, a
CycloneDX SBOM, source and toolchain checksums, and a signed package manifest.
After verification:

    sudo install -m 0755 \
      "$CEREMONY_BUILD_ROOT/relay-release-parent/release/relay" \
      /usr/local/bin/relay
    relay --help

## Build `mpc-ceremony`

Never use `go run` for `mpc-ceremony`: it omits required VCS build metadata.

For a local rehearsal, build from an approved exact commit in a clean checkout.
Replace `REPLACE_WITH_APPROVED_40_CHARACTER_COMMIT` below with the full
40-character hexadecimal commit ID; do not run the placeholder literally:

    PROOF_TOOL_COMMIT=REPLACE_WITH_APPROVED_40_CHARACTER_COMMIT
    test "${#PROOF_TOOL_COMMIT}" -eq 40
    printf '%s\n' "$PROOF_TOOL_COMMIT" | grep -Eq '^[0-9a-f]{40}$'
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

For production, use proof-tool's release builder. It requires a clean
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

A role may install the coordinator's reviewed release binaries instead of
compiling them. First compare both binary hashes with the values received
through the independent trust channel:

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
