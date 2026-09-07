# Coordinator runbook

> This is the production/manual operator procedure. For the test-only tiny
> ceremony, use the
> [scripted three-machine rehearsal](scripts/three-machine-rehearsal/README.md)
> and its machine-specific `.env` files.

This is the coordinator runbook for operating `relay`. Use the
[automation-aware coordinator checklist](COORDINATOR_CHECKLIST.md) as the live
execution aid and [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md) for copy-oriented
command recipes. Participants, witnesses, mirrors, auditors, release upload
stations, and decision signers use [ROLE_RUNBOOK.md](ROLE_RUNBOOK.md) and the
role-specific checklists indexed by [CHECKLISTS.md](CHECKLISTS.md).

The [proof-tool repository](https://github.com/Emurgo/proof-tool) remains the
authority for ceremony commands and validity rules. Relay transports bytes and
asks the trusted `mpc-ceremony` binary to authenticate them; storage state is
only a scheduling hint. The full trust model and low-level command reference
are in [README.md](README.md).

## 1. Install and verify the tools

For Docker-packaged Relay, proof-tool, and AWS CLI, follow the
[role launcher guide](docker/roles/README.md). Use its container paths and
coordinator launcher prefix with the commands below.

Follow [docs/INSTALL.md](docs/INSTALL.md). It gives exact instructions for
downloading one coordinated ceremony kit, verifying its independently supplied
hash, installing Relay and `mpc-ceremony`, and then installing AWS CLI v2. The
coordinator does not need Go or either project's build-signing private key.

Do not continue until all of these succeed and resolve to the reviewed paths:

    relay --help
    mpc-ceremony help
    aws --version
    command -v relay mpc-ceremony aws

Record the ceremony-kit tag and SHA-256, its pinned Relay and `mpc-ceremony`
metadata, and the AWS CLI version in the coordinator log. Distribute these
trust inputs independently of ceremony storage:

- the coordinator public key;
- the approved ceremony-kit tag; and
- the ceremony-kit archive digest.

## 2. Prepare the ceremony

Choose one absolute ceremony home and initialize proof-tool's public output
under its `public/` directory:

    CEREMONY_HOME=/var/lib/mpc-ceremonies/CEREMONY_ID
    install -d -m 0700 "$CEREMONY_HOME/public" "$CEREMONY_HOME/config" "$CEREMONY_HOME/run"

Before initialization, have every participant, auditor, and the release signer
generate its own Ed25519 keypair on its own machine using
`mpc-ceremony identity generate`, following the
[ceremony identity key-generation guide](PARTICIPANT_KEY_GENERATION.md).
The command generates the private key and public identity JSON, including the
fingerprint and key ID; no separate key-generation tooling is needed.
Collect only each role's
public identity: its identity ID, key ID, public key, public-key fingerprint,
and agreed display name. Authenticate the fingerprint with that role through
the ceremony's agreed independent channel before adding it to the input roster.
Never ask for or accept a role's private key.

Check that identity IDs, key IDs, and public keys are unique across the
coordinator, participants, auditors, and release signer. The ceremony
definition freezes those identities, the participant order, and the auditor
and release roles. For production, also identify every participant using a Mac
and include those identity IDs, sorted, in the initialization input's
`host_wipe_participants` field. Retain the authenticated submissions in the
coordinator record so the roster and wipe policy can be reviewed independently.

Run `mpc-ceremony init`, then confirm that `ceremony.json` contains the intended
coordinator, participant order, at least two auditors, and a distinct release
signer. Return the signed public ceremony material to those roles and require
each one to verify its own identity, public-key fingerprint, and position or
role before the ceremony starts. Keep the coordinator signing key protected.

Public witnesses and mirror operators are enrolled after the ceremony
definition is signed because their proof-of-possession records bind to that
exact definition. Collect each signed enrollment record and detached signature,
authenticate its public-key fingerprint with the role, and retain both for
later evidence grants. Auditors, release upload stations, and decision signers
likewise require an authenticated enrollment when Relay grants their
non-participant upload prefix. An upload-only station uses the enrollment of
the signing identity whose output it transports; it does not receive that
identity's private key. Participants do not send their private keys or need a
separate Relay enrollment record: Relay matches their local private key to the
participant identity already frozen in the signed roster. A `host-wipe` grant
is also roster-authenticated and needs no enrollment; Relay issues it only when
the requested identity appears in the signed `host_wipe_participants` policy.

Relay requires a proof-tool version that supports read-only inspection of
definitions, chains, participants, and operational enrollments, plus the
public-witness receipt builder. Mirror receipt preparation uses
`mpc-ceremony ops prepare-mirror-receipt`.

## 3. Configure storage

Create a published bucket, a private inbox bucket, and a public HTTPS URL for
the published bucket. The inbox must never be public. Give the coordinator a
runtime credential for both buckets and configure the provider-specific
temporary-credential issuer.

Complete one provider guide before continuing:

- [AWS S3, CloudFront, and IAM setup](docs/AWS_SETUP.md)
- [Cloudflare R2 setup](docs/R2_SETUP.md)

[docs/STORAGE.md](docs/STORAGE.md) is the shared security and storage-layout
reference. The provider scripts print the exact non-secret values used below.

For R2:

    read -rsp 'R2 control-plane API token: ' RELAY_R2_CONTROL_TOKEN
    export RELAY_R2_CONTROL_TOKEN
    printf '\n'
    relay coordinator configure-storage \
      --home "$CEREMONY_HOME" \
      --provider r2 \
      --account-id <cloudflare-account-id> \
      --parent-access-key-id <parent-access-key-id> \
      --endpoint https://<account-id>.r2.cloudflarestorage.com \
      --published-bucket <published-bucket> \
      --published-base-url https://ceremony.example.org \
      --inbox-bucket <private-inbox-bucket> \
      --profile r2-coordinator \
      --coordinator-key /trusted/coordinator-public-key.hex
    unset RELAY_R2_CONTROL_TOKEN

The control-plane credential is a Cloudflare API bearer token with the
account-level `Workers R2 Storage Read` permission, called R2 Admin Read only
in the R2 token UI. Cloudflare does not offer bucket-scoped configuration read:
use a dedicated ceremony R2 account if the coordinator must not read other
buckets in the account. Relay uses the token to reject enabled `r2.dev` access
or any attached custom domain. Keep the separate inbox parent token available
only to a grant command's process:

    read -rsp 'R2 inbox parent API token: ' RELAY_R2_PARENT_TOKEN
    export RELAY_R2_PARENT_TOKEN
    printf '\n'
    relay coordinator grant ...
    unset RELAY_R2_PARENT_TOKEN

For AWS:

The guided path in [docs/AWS_SETUP.md](docs/AWS_SETUP.md) provisions storage
with one AWS profile and prints every value used below.

    relay coordinator configure-storage \
      --home "$CEREMONY_HOME" \
      --provider aws \
      --region us-east-1 \
      --published-bucket <published-bucket> \
      --published-base-url https://d111111abcdef8.cloudfront.net \
      --inbox-bucket <private-inbox-bucket> \
      --profile relay-ceremony \
      --issuer-profile relay-ceremony \
      --grant-role-arn arn:aws:iam::<account-id>:role/relay-ceremony-inbox-grant \
      --grant-role-max-ttl 1h \
      --coordinator-key /trusted/coordinator-public-key.hex

With `--home`, Relay reads `public/ceremony.json` and `public/ceremony.sig` and
writes `config/relay-storage.json`. The coordinator trust key stays explicit;
Relay never derives or downloads it.

    STORAGE_CONFIG="$CEREMONY_HOME/config/relay-storage.json"

`configure-storage` authenticates the ceremony, checks coordinator access,
writes and re-reads a disposable published probe, reads it anonymously through
the public URL, confirms that the inbox is private, and removes the probe. For
R2, the privacy check reads the inbox's `r2.dev` and custom-domain settings from
Cloudflare's control-plane API.

Before participant turns begin, send each participant `relay-storage.json`,
the public ceremony material, and the coordinator public key through the agreed
channels. The storage file contains configuration but no temporary credential.
Each participant can enroll their local key and check the signed public position
without inbox write access.

## 4. Run each participant turn

Choose a TTL long enough for replay, contribution, erasure, and upload. Relay
will refuse to start expensive work unless the minimum window remains. For an
initial turn, `MINIMUM_REMAINING` must cover the whole operation, not only the
final upload.

For R2, a typical starting point is:

    CREDENTIAL_TTL=72h
    MINIMUM_REMAINING=2h

For AWS with a direct IAM issuer, the role maximum is 12 hours:

    CREDENTIAL_TTL=12h
    MINIMUM_REMAINING=2h

An AWS SSO/assumed-role issuer is limited to one hour by role chaining. Use it
only when the full operation fits comfortably inside that window, such as the
included rehearsal (`1h` credential, `15m` minimum).

    relay coordinator grant \
      --storage "$STORAGE_CONFIG" \
      --role participant \
      --identity participant-03 \
      --credential-ttl "$CREDENTIAL_TTL" \
      --minimum-remaining "$MINIMUM_REMAINING" \
      --out participant-03.grant.json

Send the participant these items through the agreed private channel when their
turn begins:

- their mode-`0600` grant file;
- a link or copy of [ROLE_RUNBOOK.md](ROLE_RUNBOOK.md).

The grant is a bearer credential limited to that participant's candidate
prefix. Replace it immediately if it leaks. Contact the participant when their
turn begins; `relay participant run` independently rejects an out-of-turn attempt.

If computation finishes but the credential or network fails during upload,
issue another grant for the same participant using a fresh output filename.
The replacement grant does not change signed ceremony state. Its
`--minimum-remaining` value only needs to cover local integrity checks and the
remaining upload, although a conservative buffer is recommended. The
participant resumes the saved attempt with `--resume-candidate`; do not ask
them to repeat the contribution unless Relay reports that the authenticated
public head advanced or that local/remote bytes conflict.

List complete submissions:

    relay coordinator candidates --storage "$STORAGE_CONFIG" --phase phase1

Review, verify, and publish the selected candidate:

    relay coordinator accept \
      --storage "$STORAGE_CONFIG" \
      --candidate-key candidates/<ceremony-id>/participant-03/phase1/0003/<attempt>/manifest.json \
      --coordinator-signing-key /secure/coordinator.ed25519.private.hex \
      --verify-publish

Relay checks the manifest scope and hashes, scheduled participant, and current
head. It downloads into a fresh review directory and invokes
`mpc-ceremony <phase> verify`. Only a successful proof-tool acceptance becomes
the new head. Inbox submissions remain available for review or provider
lifecycle cleanup.

By default Relay records `accepted_at` from the coordinator clock after the
candidate download, preserving subsecond precision so it is strictly later
than the participant's signed `destroyed_at`. Keep participant and coordinator
clocks synchronized. Use `--accepted-at RFC3339` only for a controlled replay;
the explicit value must still be strictly later than the signed erasure and
the preceding accepted record.

Repeat for every participant and phase.

## 5. Publish lifecycle changes

Coordinator publication reads ceremony paths, the trust key, provider routing,
bucket, and profile from `STORAGE_CONFIG`. `--phase` defaults to `phase1`.

After closure, beacon, seal, or another coordinator-signed chain update:

    relay coordinator publish \
      --storage "$STORAGE_CONFIG" \
      --chain /ceremony/public/phase1/chain-0003.json \
      --chain-signature /ceremony/public/phase1/chain-0003.sig

For a closed phase:

    relay coordinator publish \
      --storage "$STORAGE_CONFIG" \
      --chain <final-chain> \
      --chain-signature <final-chain-signature> \
      --closed

Relay uploads every referenced artifact before moving the public pointer. The
`--closed` marker tells public witnesses that a closure is ready to observe.

## 6. Grant access to other roles

Witnesses, mirrors, auditors, release upload stations, and decision signers
receive access only to their own inbox prefix. Every non-participant grant must
authenticate the identity's signed enrollment:

    relay coordinator grant \
      --storage "$STORAGE_CONFIG" \
      --role witness \
      --identity witness-01 \
      --credential-ttl "$CREDENTIAL_TTL" \
      --minimum-remaining "$MINIMUM_REMAINING" \
      --enrollment operations/enrollments/witness-01.json \
      --enrollment-signature operations/enrollments/witness-01.sig \
      --out witness-01.grant.json

Substitute the appropriate role, identity, enrollment, and TTL. Send the grant
privately with the role's handoff material and [ROLE_RUNBOOK.md](ROLE_RUNBOOK.md).
Storage access does not make evidence valid; proof-tool records and signatures
do.

Keep the release signing machine offline. Give its scoped grant only to the
separate online station that uploads the signed output. Use the same separation
for production-decision signatures.

### Production Mac post-wipe evidence

After a required Mac participant's final scheduled contribution is accepted,
tell the participant to perform the documented whole-device erase and clean
reinstall. Do not issue this grant before the reinstall is complete:

    relay coordinator grant \
      --storage "$STORAGE_CONFIG" \
      --role host-wipe \
      --identity participant-03 \
      --credential-ttl 2h \
      --minimum-remaining 30m \
      --out participant-03.host-wipe.grant.json

The participant uses `relay participant attest-host-wipe` after reinstall.
The normal accepted chain does not roll back while this is pending; instead,
the final operational-evidence bundle and release remain blocked. If a
participant contributes again after attesting, the old record is too early and
the participant must wipe again after the new final contribution.

## 7. Review role evidence

List complete submissions, optionally filtering by role:

    relay coordinator evidence --storage "$STORAGE_CONFIG" [--role witness]

Each submission manifest is intake metadata, not proof. Before publishing or
relying on evidence:

1. Check that its manifest has the expected role and identity prefix.
2. Download it into a fresh review location.
3. Run the corresponding proof-tool verification command.
4. Promote only authenticated, coherent evidence to the published artifact
   set.

Before releasing final results, every participant required to wipe their
machine must provide a signed wipe confirmation. For each participant in the
signed definition's `host_wipe_participants`:

1. Verify their confirmation (`host-wipe.json`) and signature (`host-wipe.sig`)
   with `mpc-ceremony`.
2. Include references to those exact files in the final operational-evidence
   bundle's `host_wipes` list.
3. Require successful verification of the complete bundle before release signing.

The tool requires exactly one valid confirmation per required participant.
The recorded wipe time must be later than that participant's latest contribution
time in the accepted chains. An accepted contribution or uploaded confirmation
alone is not enough. Verification checks the signer and recorded timing; it
cannot prove the machine was actually wiped. Release signing is blocked if any
required confirmation is missing or fails verification.

Incomplete uploads do not appear because each role uploads `manifest.json`
last. Never treat possession of a storage credential as a ceremony signature.

## 8. Failure and recovery

- Replace a grant that is expired or below its minimum remaining window. R2
  grants may not exceed `168h`; AWS grants must fit the configured STS limits.
- A replacement participant grant can resume an interrupted upload from the
  completed local candidate. It cannot revive a candidate built from an older
  authenticated head.
- Relay records the highest public index seen under `~/.relay` and refuses a
  pointer that moves backward. Investigate a rollback warning; do not tell a
  role to delete local state to bypass it.
- Relay refuses to overwrite a mismatching transcript file or upload outside
  the published allowlist.
- A bucket can hide, delay, or equivocate about state, but proof-tool signatures
  and digests still authenticate artifacts.
- The pointer makes the next turn checkable; it does not replace contacting the
  participant out of band.

The older one-bucket `relay advanced push` and `relay advanced pull` commands
remain for recovery and debugging. They use long-lived AWS CLI profiles and
are documented under “Usage” and “Provider notes” in [README.md](README.md).
New ceremonies should use the two-bucket workflow above.
