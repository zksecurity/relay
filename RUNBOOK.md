# Ceremony runbook

This is the operator checklist for `relay`. The
[proof-tool repository](https://github.com/Emurgo/proof-tool) remains the
authority for ceremony commands and validity rules. Relay transports bytes and
asks the trusted `mpc-ceremony` binary to authenticate them; storage state is
only a scheduling hint. The full trust model and low-level command reference
are in [README.md](README.md).

## 1. Prepare the ceremony and trust inputs

Install the reviewed `relay`, AWS CLI, and `mpc-ceremony` binaries. Record and
distribute these two trust inputs independently of ceremony storage:

- the coordinator public key; and
- the hash of the trusted `mpc-ceremony` binary.

Run `mpc-ceremony init`, then confirm that `ceremony.json` contains the intended
coordinator, participant order, at least two auditors, and a distinct release
signer. Keep the coordinator signing key protected.

Relay requires a proof-tool version that supports read-only inspection of
definitions, chains, participants, and operational enrollments, plus the
public-witness receipt builder. Mirror receipt preparation uses
`mpc-ceremony ops prepare-mirror-receipt`.

## 2. Configure storage

Create a published bucket, a private inbox bucket, and a public HTTPS URL for
the published bucket. The inbox must never be public. Give the coordinator a
runtime credential for both buckets and configure the provider-specific
temporary-credential issuer.

Before continuing, read [docs/STORAGE.md](docs/STORAGE.md). It contains the
required R2 and AWS setup, IAM permissions, caching rules, credential limits,
and preflight checks.

For R2:

    relay coordinator configure-storage \
      --provider r2 \
      --account-id <cloudflare-account-id> \
      --parent-access-key-id <parent-access-key-id> \
      --endpoint https://<account-id>.r2.cloudflarestorage.com \
      --published-bucket <published-bucket> \
      --published-base-url https://ceremony.example.org \
      --inbox-bucket <private-inbox-bucket> \
      --profile r2-coordinator \
      --ceremony ceremony.json \
      --ceremony-signature ceremony.sig \
      --coordinator-key coordinator-public-key.hex \
      --out relay-storage.json

Expose the parent R2 token only to this process when issuing grants:

    RELAY_R2_PARENT_TOKEN=<parent-api-token> relay coordinator grant ...

For AWS:

    relay coordinator configure-storage \
      --provider aws \
      --region us-east-1 \
      --published-bucket <published-bucket> \
      --published-base-url https://d111111abcdef8.cloudfront.net \
      --inbox-bucket <private-inbox-bucket> \
      --profile aws-coordinator \
      --issuer-profile aws-grant-issuer \
      --grant-role-arn arn:aws:iam::<account-id>:role/relay-inbox-grant \
      --grant-role-max-ttl 12h \
      --ceremony ceremony.json \
      --ceremony-signature ceremony.sig \
      --coordinator-key coordinator-public-key.hex \
      --out relay-storage.json

`configure-storage` authenticates the ceremony, checks coordinator access,
writes and re-reads a disposable published probe, reads it anonymously through
the public URL, confirms that the inbox is not anonymously readable, and
removes the probe.

## 3. Run a participant turn

### Coordinator: issue access

Choose a TTL long enough for replay, contribution, erasure, and upload. Relay
will refuse to start expensive work unless the configured minimum window
remains.

    relay coordinator grant \
      --storage relay-storage.json \
      --role participant \
      --identity participant-03 \
      --credential-ttl 72h \
      --minimum-upload-window 2h \
      --out participant-03.grant.json

Send `relay-storage.json` and the participant's grant through the agreed
private channel. The grant is a bearer credential, is written with mode `0600`,
and permits writes only under that participant's candidate prefix. Replace it
immediately if it leaks.

### Participant: enroll once

    relay enroll \
      --storage relay-storage.json \
      --grant participant-03.grant.json \
      --phase phase1 \
      --root /ceremony/public \
      --ceremony /ceremony/public/ceremony.json \
      --ceremony-signature /ceremony/public/ceremony.sig \
      --coordinator-key /trusted/coordinator-public-key.hex \
      --signing-key /secure/participant-03.ed25519.private.hex \
      --environment /secure/participant-03.environment.json \
      --candidate-parent /ceremony/candidates \
      --out participant-03.relay.json

Enrollment asks proof-tool to match the local signing key to the authenticated
participant roster. It does not trust a filename or coordinator assertion for
the participant's identity.

### Participant: run one command

When contacted by the coordinator:

    relay participate --config participant-03.relay.json

Relay checks the grant lifetime and public head before computation. It refuses
if this participant is out of turn. Otherwise it downloads and verifies the
transcript, invokes the proof-tool contribution, asks the participant to
destroy the contribution environment, and requires `DESTROYED` before creating
the signed erasure attestation. It rechecks the head and uploads the candidate
manifest last, so an interrupted upload never appears complete.

Long operations print UTC start, completion, and failure times, plus a
one-minute elapsed-time heartbeat while otherwise silent. Proof-tool replay
counts and Relay transfer progress remain visible. A heartbeat is not a
percentage or ETA.

### Coordinator: review and accept

List complete candidates:

    relay coordinator candidates --storage relay-storage.json --phase phase1

Then review, verify, and publish the selected candidate:

    relay coordinator accept \
      --storage relay-storage.json \
      --candidate-key candidates/<ceremony-id>/participant-03/phase1/0003/<attempt>/manifest.json \
      --root /ceremony/public \
      --candidate-dir /ceremony/review/participant-03-<attempt> \
      --coordinator-signing-key /secure/coordinator.ed25519.private.hex \
      --verify-publish

Relay verifies the manifest scope and hashes, checks the scheduled participant
and current head, downloads into a fresh review directory, and invokes
`mpc-ceremony <phase> verify`. Only a successful proof-tool acceptance becomes
the new head. Inbox submissions are retained for review or provider lifecycle
cleanup.

Repeat this section for every participant and phase.

## 4. Publish lifecycle changes

After closure, beacon, seal, or another coordinator-signed chain update:

    relay coordinator publish \
      --chain /ceremony/public/phase1/chain-0003.json \
      --chain-signature /ceremony/public/phase1/chain-0003.sig

For a closed phase:

    relay coordinator publish \
      --chain <final-chain> \
      --chain-signature <final-chain-signature> \
      --closed

Relay uploads every referenced artifact before moving the public pointer. The
`--closed` marker tells public witnesses that a closure is ready to observe.

Commands that inspect ceremony documents share these flags where applicable:

    --root DIR --ceremony FILE --ceremony-signature FILE \
    --coordinator-key FILE --bucket NAME --endpoint URL --profile PROFILE

`--phase` defaults to `phase1`. `--ceremony-binary` defaults to
`mpc-ceremony`; pin an explicit trusted path if `PATH` is not trusted.

## 5. Run the other roles

### Issue a scoped evidence grant

Witnesses, mirrors, auditors, release upload stations, and decision signers
receive access only to their own inbox prefix. Every non-participant grant must
also authenticate the identity's signed enrollment:

    relay coordinator grant \
      --storage relay-storage.json \
      --role witness \
      --identity witness-01 \
      --credential-ttl 24h \
      --minimum-upload-window 2h \
      --enrollment operations/enrollments/witness-01.json \
      --enrollment-signature operations/enrollments/witness-01.sig \
      --out witness-01.grant.json

Substitute the appropriate role, identity, enrollment, and TTL. Storage access
does not make evidence valid; proof-tool records and signatures do.

### Public witness

    relay witness watch --interval 60s

`--once` polls once and exits. After observing closure, confirm that its beacon
round has not occurred and is at least the definition's witness lead away.
Then build and sign the public-witness receipt with proof-tool and upload it as
described under “Submit evidence.” Relay cannot make the real-world timing
claim for the witness.

### Mirror

    relay mirror sync

After retaining the authenticated chain prefix, draft a receipt for that head:

    relay mirror receipt \
      --root <transcript-root> \
      --chain <chain> \
      --chain-signature <chain-signature> \
      --index 3 \
      --location s3://mirror/... \
      --stored-at 2026-09-01T12:00:00Z \
      --out receipt-0003.json

Authenticate and canonicalize the draft, then sign the canonical bytes offline:

    mpc-ceremony ops prepare-mirror-receipt \
      --draft receipt-0003.json \
      --ceremony ceremony.json \
      --ceremony-signature ceremony.sig \
      --coordinator-public-key-file coordinator.pub \
      --transcript-root . \
      --chain phase1/chain-0003.json \
      --chain-signature phase1/chain-0003.sig \
      --mirror-enrollment operations/enrollments/mirror-01.json \
      --mirror-enrollment-signature operations/enrollments/mirror-01.sig \
      --out-dir receipt-0003-signing

Only the location's SHA-256 enters the record; the location itself is not
published or fetched.

### Auditor

    relay auditor sync --phase phase1
    relay auditor sync --phase phase2

Replay with `mpc-ceremony audit` using independently checked mirrors, not the
coordinator's copy, then upload the signed audit output.

### Release signer and decision signers

Keep the release signing machine offline. Move only the signed output to a
separate upload station and give that station the release signer's scoped
grant. Use the same separation for production-decision signatures.

### Submit evidence

Each role uploads its already signed proof-tool output:

    relay submit-evidence --grant witness-01.grant.json --dir ./signed-witness-output

or:

    relay submit-evidence --grant auditor-01.grant.json \
      --file audit.json --file audit.sig

Relay rejects unsafe files and uploads `manifest.json` last. The coordinator
lists complete submissions with:

    relay coordinator evidence --storage relay-storage.json [--role witness]

The manifest is intake metadata, not proof. Run the corresponding proof-tool
verification before publishing or relying on the evidence.

## 6. Failure and recovery

- An expired grant, or one below its minimum remaining window, must be replaced
  before work begins. R2 grants may not exceed `168h`; AWS grants must fit the
  role's configured STS limits.
- Relay records the highest public index seen under `~/.relay` and refuses a
  pointer that moves backward. Older high-water state is migrated on first
  use. Ask the coordinator about a rollback warning; do not delete the local
  state to bypass it.
- Relay refuses to overwrite a mismatching local transcript file and refuses
  to upload files outside the published allowlist.
- A bucket can hide, delay, or equivocate about state, but artifacts remain
  authenticated by proof-tool signatures and digests.
- Out-of-band communication is still required. The public pointer makes whose
  turn it is checkable; it does not replace the coordinator contacting roles.

The older one-bucket `relay advanced push` and `relay advanced pull` commands
remain for recovery and debugging. They use long-lived AWS CLI profiles and
are documented under “Usage” and “Provider notes” in [README.md](README.md).
New ceremonies should use the two-bucket workflow above.
