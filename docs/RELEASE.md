# Building and auditing ceremony tool releases

This guide is for Relay release maintainers and independent build auditors.
Coordinators and ceremony roles normally install published binaries using
[INSTALL.md](INSTALL.md); they do not need Go, a source checkout, or a build
signing key.

## Trust inputs and prerequisites

Production Relay and `mpc-ceremony` releases target Linux/amd64 with Go 1.26.5.
Install Go using the [official Go installation guide](https://go.dev/doc/install)
and confirm:

    go version

Expected:

    go version go1.26.5 linux/amd64

The build host also needs Git, GnuPG, `grep`, `sed`, GNU coreutils, and GNU
findutils. Do not allow `GOTOOLCHAIN` to silently select another production
toolchain. Both production builders verify the Go version and toolchain
digests.

Before a production build, agree through authenticated channels on:

- the approved signed tag and tag-signer fingerprint;
- the exact source commit referenced by that tag; and
- the independently trusted build-package signing public key.

## CI and offline-signing boundary

Relay CI runs tests, checks shell syntax, builds an unsigned rehearsal package,
and semantically verifies that package. The workflow has read-only repository
permissions, receives no production signing input, and confirms that the
rehearsal package contains no build signature or bundled build public key.

CI must never receive the tag-signing key or build-signing private key. A
production release is created only from the approved signed tag on the offline
release machine described below. GitHub hosts the resulting public artifacts;
it does not establish their production identity.

## Prepare retained release storage

Choose a fresh, persistent, access-controlled directory for source checkouts,
build logs, and completed release packages. Do not put it inside a ceremony
transcript or signing-key directory. Export its path, then require it explicitly:

    : "${RELEASE_EVIDENCE_ROOT:?Set RELEASE_EVIDENCE_ROOT to a fresh retained directory}"
    test ! -e "$RELEASE_EVIDENCE_ROOT"
    mkdir -m 0700 "$RELEASE_EVIDENCE_ROOT"

The builders separately create mode-`0700` clean checkouts, compiler caches,
and intermediate files under `/tmp`. They remove that scratch after success or
failure. No signing key or required release evidence is stored there.

## Build an unsigned Relay rehearsal package

Use this path for development and ceremony rehearsals:

    : "${RELAY_COMMIT:?Set RELAY_COMMIT to the approved full commit ID}"
    printf '%s\n' "$RELAY_COMMIT" | grep -Eq '^[0-9a-f]{40}$'
    git clone https://github.com/zksecurity/relay.git \
      "$RELEASE_EVIDENCE_ROOT/relay-source"
    git -C "$RELEASE_EVIDENCE_ROOT/relay-source" \
      checkout --detach "$RELAY_COMMIT"
    mkdir "$RELEASE_EVIDENCE_ROOT/relay-rehearsal-parent"
    cd "$RELEASE_EVIDENCE_ROOT/relay-source"
    scripts/build-relay-release.sh \
      --mode rehearsal \
      --out-dir "$RELEASE_EVIDENCE_ROOT/relay-rehearsal-parent/release"

Rehearsal packages are deliberately unsigned and must not be published as
production releases.

## Produce an official Relay release

Create a dedicated clean production checkout at the approved signed tag:

    : "${RELAY_TAG:?Set RELAY_TAG to the approved signed tag}"
    : "${RELAY_TAG_SIGNER_FINGERPRINT:?Set the approved Relay tag-signer fingerprint}"
    printf '%s\n' "$RELAY_TAG_SIGNER_FINGERPRINT" | \
      grep -Eq '^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$'
    git clone https://github.com/zksecurity/relay.git \
      "$RELEASE_EVIDENCE_ROOT/relay-production-source"
    cd "$RELEASE_EVIDENCE_ROOT/relay-production-source"
    git checkout --detach "$RELAY_TAG"
    RELAY_COMMIT=$(git rev-parse "$RELAY_TAG^{commit}")

The Relay release maintainer provisions a dedicated Ed25519 build key once on
the offline build-signing machine. If the approved release line already has
one, reuse that existing key rather than generating another:

    umask 077
    go run ./scripts/relay-release-tool keygen \
      --private-key-out /offline/relay-build-signing-key \
      --public-key-out /offline/relay-build-public-key.hex

Retain the private key offline. Publish the public key through an authenticated
channel independent of GitHub. Never reuse it as a ceremony-role or proof-tool
build-signing key.

Build the production package:

    mkdir "$RELEASE_EVIDENCE_ROOT/relay-release-parent"
    scripts/build-relay-release.sh \
      --mode production \
      --signed-tag "$RELAY_TAG" \
      --tag-signer-fingerprint "$RELAY_TAG_SIGNER_FINGERPRINT" \
      --build-signing-key /offline/relay-build-signing-key \
      --out-dir "$RELEASE_EVIDENCE_ROOT/relay-release-parent/release"

The output contains `relay`, the ceremony-kit setup component, the provider
storage setup archive, the versioned three-machine rehearsal archive, their
checksums, exact Go/VCS metadata, a
CycloneDX SBOM, source and toolchain checksums, and a signed package manifest.
Create an archive that preserves the verified file modes:

    RELAY_RELEASE_DIR="$RELEASE_EVIDENCE_ROOT/relay-release-parent/release"
    RELAY_RELEASE_ARCHIVE="$RELEASE_EVIDENCE_ROOT/relay-release-package.tar"
    SOURCE_DATE_EPOCH=$(<"$RELAY_RELEASE_DIR/source-date-epoch.txt")
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" \
      --owner=0 --group=0 --numeric-owner \
      -cf "$RELAY_RELEASE_ARCHIVE" -C "$RELAY_RELEASE_DIR" .
    sha256sum "$RELAY_RELEASE_ARCHIVE"

Publish these GitHub Release assets from the verified release directory:

- the standalone `$RELAY_RELEASE_DIR/relay` file with the asset name `relay`,
  used when assembling the coordinated ceremony kit;
- `storage-setup.tar.gz`, containing the versioned AWS and R2 provisioning
  guides and scripts;
- `three-machine-rehearsal.tar.gz`, the standalone versioned rehearsal kit;
- `checksums.sha256`, containing the directly downloadable asset hashes;
  and
- `$RELAY_RELEASE_ARCHIVE`, used by independent auditors to verify the complete
  signed package.

Publish the release tag, source commit, every value in `checksums.sha256`, the
complete-package archive SHA-256, tag-signer fingerprint, and build-package
public key through the project's authenticated release channel. Normal
auditors authenticate the Relay asset and rehearsal archive against values
obtained through that channel. Normal operators use the coordinated ceremony
kit assembled after both projects have independently published.

A coordinated ceremony-tools release is usable only after proof-tool also
publishes its approved signed tag and a standalone asset named
`mpc-ceremony`. The authenticated announcement must name the exact proof-tool
repository, tag, and binary SHA-256. Use `Emurgo/proof-tool` for the upstream
production release. A `zksecurity/proof-tool` prerelease is test-only unless
that fork is separately approved as a production trust input.

The Relay and proof-tool tag names do not need to match. The coordinated
release announcement pairs their independently signed tags, commits, and
binary hashes. Merging proof-tool changes upstream does not copy a fork tag or
GitHub Release; build and publish the production asset again from the approved
tag created in `Emurgo/proof-tool`.

## Verify and reproduce a Relay release

An independent auditor downloads and extracts the complete release-package
archive, obtains the build public key through a separate channel, and creates
their own clean checkout:

    : "${RELAY_TAG:?Set RELAY_TAG to the approved signed tag}"
    : "${RELAY_TAG_SIGNER_FINGERPRINT:?Set the approved Relay tag-signer fingerprint}"
    : "${PUBLISHED_RELAY_ARCHIVE:?Set the downloaded release-package archive path}"
    : "${PUBLISHED_RELAY_ARCHIVE_SHA256:?Set the independently approved archive SHA-256}"
    printf '%s\n' "$RELAY_TAG_SIGNER_FINGERPRINT" | \
      grep -Eq '^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$'
    printf '%s\n' "$PUBLISHED_RELAY_ARCHIVE_SHA256" | \
      grep -Eq '^[0-9a-f]{64}$'
    printf '%s  %s\n' \
      "$PUBLISHED_RELAY_ARCHIVE_SHA256" "$PUBLISHED_RELAY_ARCHIVE" | \
      sha256sum --check
    PUBLISHED_RELAY_PACKAGE="$RELEASE_EVIDENCE_ROOT/published-relay-package"
    mkdir -m 0700 "$PUBLISHED_RELAY_PACKAGE"
    tar -xf "$PUBLISHED_RELAY_ARCHIVE" -C "$PUBLISHED_RELAY_PACKAGE"
    git clone https://github.com/zksecurity/relay.git \
      "$RELEASE_EVIDENCE_ROOT/relay-audit-source"
    cd "$RELEASE_EVIDENCE_ROOT/relay-audit-source"
    git checkout --detach "$RELAY_TAG"
    RELAY_COMMIT=$(git rev-parse "$RELAY_TAG^{commit}")

Verify the package:

    scripts/verify-relay-release.sh \
      --mode production \
      --expected-commit "$RELAY_COMMIT" \
      --expected-tag "$RELAY_TAG" \
      --tag-signer-fingerprint "$RELAY_TAG_SIGNER_FINGERPRINT" \
      --trusted-build-public-key-file /trusted/relay-build-public-key.hex \
      "$PUBLISHED_RELAY_PACKAGE"

Then rebuild without access to the build-signing private key:

    scripts/verify-relay-reproducible.sh \
      --expected-commit "$RELAY_COMMIT" \
      --expected-tag "$RELAY_TAG" \
      --tag-signer-fingerprint "$RELAY_TAG_SIGNER_FINGERPRINT" \
      --trusted-build-public-key-file /trusted/relay-build-public-key.hex \
      --rebuild-dir "$RELEASE_EVIDENCE_ROOT/relay-reproduction-01" \
      "$PUBLISHED_RELAY_PACKAGE"

Retain the verification output and reproduced package with the release audit
evidence.

## Verify the independent `mpc-ceremony` release

The proof-tool repository owns the `mpc-ceremony` release process. Obtain the
standalone binary and complete verification package from the approved
proof-tool release. Authenticate its repository, signed tag, and published
hashes through the release trust channel, then follow proof-tool's
`docs/mpc-ceremony-release.md` and reproducible-release procedure. The
proof-tool release maintainer, not the ceremony coordinator or a participant,
owns its build-signing private key.

Retain the verification output with the release audit evidence and set
`MPC_BINARY` below to that verified binary. Record its approved repository,
tag, and SHA-256 independently; do not select or pin a proof-tool source commit
in Relay's release process. Relay's source-coupled proof-tool integration test
is a developer diagnostic, not a coordinated-release gate. Compatibility is
tested from the exact released binaries during ceremony-kit assembly.

## Assemble the coordinated ceremony kit

The kit is a convenience distribution assembled only after the Relay and
proof-tool releases have been independently verified. It does not replace
either project's signed release package or reproducibility evidence. Neither
repository release is gated on a commit from the other repository. Compatibility
is a property of the exact released binary pair selected for this kit.

Set the exact approved inputs:

```bash
: "${RELAY_TAG:?Set the approved Relay tag}"
: "${RELAY_SHA256:?Set the approved Relay binary SHA-256}"
: "${MPC_RELEASE_REPOSITORY:?Set the approved proof-tool OWNER/REPOSITORY}"
: "${MPC_TAG:?Set the approved mpc-ceremony tag}"
: "${MPC_SHA256:?Set the approved mpc-ceremony binary SHA-256}"
: "${MPC_BINARY:?Set the verified local mpc-ceremony binary path}"
KIT_PARENT="$RELEASE_EVIDENCE_ROOT/ceremony-kit-parent"
mkdir "$KIT_PARENT"
```

The kit builder runs `scripts/verify-ceremony-kit-compatibility.sh` before it
packages anything. The verifier authenticates both supplied hashes, initializes
a fresh signed tiny rehearsal with the supplied `mpc-ceremony`, and has the
supplied Relay create participant profiles for both phases from authenticated
definition and participant projections. Relay then uses its operational
contribution, erasure, and candidate-verification command builders to produce
and accept the first tiny phase 1 contribution, after which it authenticates
the resulting chain projection. It performs no storage or network operation.
On success, the kit includes `compatibility.json`, binding the test name to the
two binary hashes; `setup verify` checks that binding.

Maintainers may exercise a proposed pair before offline assembly with the
manual `Ceremony kit binary compatibility` GitHub Actions workflow. Supply the
two approved repositories, tags, and independently authenticated binary hashes.
The workflow contains no default commit pin and prints the resulting evidence
and its hash in the job summary. This hosted preview does not replace the
independent release verification or the gate rerun by the kit builder.

For production, assemble only the two binaries and their release manifest:

```bash
scripts/build-ceremony-kit.sh \
  --mode production \
  --relay-release-dir "$RELAY_RELEASE_DIR" \
  --relay-repository zksecurity/relay \
  --relay-tag "$RELAY_TAG" \
  --relay-sha256 "$RELAY_SHA256" \
  --mpc-binary "$MPC_BINARY" \
  --mpc-repository "$MPC_RELEASE_REPOSITORY" \
  --mpc-tag "$MPC_TAG" \
  --mpc-sha256 "$MPC_SHA256" \
  --out-dir "$KIT_PARENT/ceremony-kit"
```

For an unsigned rehearsal, use `--mode rehearsal --include-rehearsal`. This
adds the versioned three-machine scripts and lets `setup --machine N` create a
prefilled local rehearsal `.env`.

Create the reproducible downloadable archive:

```bash
KIT_SOURCE_DATE_EPOCH=$(<"$RELAY_RELEASE_DIR/source-date-epoch.txt")
CEREMONY_KIT_ARCHIVE="$RELEASE_EVIDENCE_ROOT/ceremony-kit-linux-amd64.tar.gz"
tar --sort=name --mtime="@$KIT_SOURCE_DATE_EPOCH" \
  --owner=0 --group=0 --numeric-owner \
  -cf - -C "$KIT_PARENT" ceremony-kit | \
  gzip -n >"$CEREMONY_KIT_ARCHIVE"
sha256sum "$CEREMONY_KIT_ARCHIVE"
```

Extract the archive into a fresh directory and run `ceremony-kit/setup verify`
before publishing it. Retain `compatibility.json` and the verifier output with
the coordinated release evidence. Publish the archive with the exact asset name
`ceremony-kit-linux-amd64.tar.gz`. Announce only its tag and SHA-256 to normal
operators through the independent authenticated channel; `release.json`
inside the kit records all underlying repositories, tags, and hashes.
