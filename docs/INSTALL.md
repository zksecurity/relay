# Installing ceremony tools

This is the normal installation path for coordinators, participants, witnesses,
mirrors, auditors, and release operators. It installs a coordinated Relay and
`mpc-ceremony` kit; it does not require Go or either source repository.

Release maintainers and independent build auditors use
[RELEASE.md](RELEASE.md) instead.

## Obtain two authenticated values

Obtain the approved ceremony-kit tag and Linux/amd64 archive SHA-256 through the
ceremony's authenticated trust channel:

```bash
CEREMONY_KIT_TAG=REPLACE_WITH_APPROVED_KIT_TAG
CEREMONY_KIT_SHA256=REPLACE_WITH_APPROVED_64_CHARACTER_SHA256
```

The hash must come from a channel independent of the GitHub download. A hash
copied from the same release page detects download corruption but does not
protect against a compromised release account.

The kit manifest records the independently approved Relay and proof-tool
repositories, tags, and binary hashes. Operators do not enter those values
again.

## Download and verify the kit

Install `curl`, `sha256sum`, and `tar` through the operating system, then run:

```bash
: "${CEREMONY_KIT_TAG:?Set the authenticated ceremony-kit tag}"
: "${CEREMONY_KIT_SHA256:?Set the authenticated ceremony-kit SHA-256}"
DOWNLOAD_ROOT=$(mktemp -d /tmp/ceremony-kit-download.XXXXXXXX)

curl --proto '=https' --tlsv1.2 --fail --location --show-error \
  "https://github.com/zksecurity/relay/releases/download/$CEREMONY_KIT_TAG/ceremony-kit-linux-amd64.tar.gz" \
  --output "$DOWNLOAD_ROOT/ceremony-kit-linux-amd64.tar.gz"
printf '%s  %s\n' "$CEREMONY_KIT_SHA256" \
  "$DOWNLOAD_ROOT/ceremony-kit-linux-amd64.tar.gz" | sha256sum --check
```

Expected:

```text
/tmp/ceremony-kit-download.../ceremony-kit-linux-amd64.tar.gz: OK
```

Do not extract or execute a kit whose hash does not report `OK`.

## Install the coordinated binaries

Extract the verified archive into a persistent, access-controlled directory:

```bash
CEREMONY_TOOLS_ROOT="$HOME/ceremony-tools"
mkdir -m 0700 -p "$CEREMONY_TOOLS_ROOT"
chmod 0700 "$CEREMONY_TOOLS_ROOT"
test ! -e "$CEREMONY_TOOLS_ROOT/ceremony-kit"
tar --no-same-owner -xzf \
  "$DOWNLOAD_ROOT/ceremony-kit-linux-amd64.tar.gz" \
  -C "$CEREMONY_TOOLS_ROOT"
cd "$CEREMONY_TOOLS_ROOT/ceremony-kit"
./setup verify
./setup
```

`./setup verify` checks every internal file against the authenticated kit. The
install command places the two pinned binaries in `/usr/local/bin`, using
`sudo` only if necessary, and confirms both programs start. To use an existing
user-writable directory instead:

```bash
mkdir -p "$HOME/.local/bin"
./setup --prefix "$HOME/.local/bin"
```

No ceremony credentials, role keys, cloud secrets, or temporary grants belong
in the kit.

Coordinators can extract the authenticated provider guides and setup scripts
without a source checkout:

```bash
./setup --storage-setup-root "$CEREMONY_TOOLS_ROOT"
cd "$CEREMONY_TOOLS_ROOT/storage-setup"
```

Then follow `docs/AWS_SETUP.md` or `docs/R2_SETUP.md`. The extracted scripts
and guides are covered by the ceremony-kit checksum.

## Three-machine rehearsal

An approved rehearsal kit also contains the versioned rehearsal scripts.
Replace `N` with `1`, `2`, or `3`:

```bash
cd "$CEREMONY_TOOLS_ROOT/ceremony-kit"
./setup \
  --machine N \
  --rehearsal-root "$CEREMONY_TOOLS_ROOT"
```

This installs both binaries, extracts the standalone rehearsal, and creates:

```text
~/ceremony-tools/three-machine-rehearsal/machine-N/.env
```

The kit automatically fills the approved repositories, tags, binary hashes,
and installed paths. Set the one absolute `WORK_ROOT`, then edit the remaining
Machine 1 storage selections or role profile name. Ceremony, configuration,
key, trust, run, and storage-config paths derive from `WORK_ROOT`:

```bash
REHEARSAL_ROOT="$CEREMONY_TOOLS_ROOT/three-machine-rehearsal"
${EDITOR:-vi} "$REHEARSAL_ROOT/machine-N/.env"
"$REHEARSAL_ROOT/00-check-machine.sh" \
  "$REHEARSAL_ROOT/machine-N/.env"
```

The `.env` is a rehearsal convenience. Keep it at mode `0600`; never put cloud
secret keys, temporary grants, R2 control-plane or parent tokens, ceremony
private keys, or build-signing keys in it.

## Production ceremonies

A production kit contains only the coordinated binaries and release manifest;
it does not contain rehearsal identities or scripts. Production uses validated
JSON profiles, not a shell `.env`. Choose one absolute ceremony home and stage
the public ceremony material under `public/`, the coordinator-supplied
`relay-storage.json` under `config/`, and mutable outputs under `run/`:

```text
/var/lib/mpc-ceremonies/CEREMONY_ID/
├── public/
│   ├── ceremony.json
│   └── ceremony.sig
├── config/
│   └── relay-storage.json
└── run/
```

The independently authenticated coordinator public key and private signing
keys may live outside this tree. Pass their absolute paths explicitly. Initialize
one role profile after staging the authenticated material:

```bash
CEREMONY_HOME=/var/lib/mpc-ceremonies/CEREMONY_ID
relay ceremony init-config \
  --home "$CEREMONY_HOME" \
  --role participant \
  --phase phase1 \
  --coordinator-key /trusted/coordinator-public-key.hex \
  --signing-key /secure/participant.ed25519.private.hex \
  --environment /secure/environment.json
```

For a witness, mirror, auditor, or release operator, replace the participant
key flags with that identity's authenticated `--enrollment` and
`--enrollment-signature`. Relay verifies the local ceremony, storage ceremony,
and role identity before writing the mode-`0600` profile. It stores paths only:
no key bytes, cloud secrets, or temporary grant is written to it. Enrollment is
long-lived and does not require temporary upload credentials. The coordinator
supplies a short-lived grant only when a role is authorized to write.

For participants, the resulting flow is:

```bash
ROLE_CONFIG="$CEREMONY_HOME/config/participant-phase1.json"
relay participant status --config "$ROLE_CONFIG"
relay participant run --config "$ROLE_CONFIG" \
  --grant /secure/handoff/participant.grant.json
```

Relay authenticates the local key through `mpc-ceremony`, checks the signed
published state, and rejects an out-of-turn participant before contribution
work starts.

## Install storage setup prerequisites

The kit does not redistribute AWS CLI. Install `unzip` and `gpg`, follow the
[official AWS CLI signature verification procedure](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#install-linux-verify-signature),
and install AWS CLI v2. Coordinators running the provider setup scripts also
need `jq` and `curl` from the operating system. Do not configure a provider
credential until the coordinator assigns the machine's role-specific profile
or temporary grant.

Create storage using [AWS_SETUP.md](AWS_SETUP.md) or [R2_SETUP.md](R2_SETUP.md)
before running `relay coordinator configure-storage`.

## Final verification

```bash
relay --help
mpc-ceremony help
aws --version
command -v relay mpc-ceremony aws
```

Confirm `aws --version` reports `aws-cli/2...` and that all commands resolve to
the reviewed paths. Record the kit tag and archive hash in the operator log.
