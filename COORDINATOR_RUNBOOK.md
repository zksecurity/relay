# Coordinator runbook

This is the coordinator checklist for operating `relay`. Participants,
witnesses, mirrors, auditors, release upload stations, and decision signers use
[ROLE_RUNBOOK.md](ROLE_RUNBOOK.md).

The [proof-tool repository](https://github.com/Emurgo/proof-tool) remains the
authority for ceremony commands and validity rules. Relay transports bytes and
asks the trusted `mpc-ceremony` binary to authenticate them; storage state is
only a scheduling hint. The full trust model and low-level command reference
are in [README.md](README.md).

## 1. Install and verify the tools

Follow the coordinator/source-build path in
[docs/INSTALL.md](docs/INSTALL.md). It gives exact instructions for installing
AWS CLI v2 and creating signed, reproducible release packages for both Relay
and proof-tool.

Do not continue until all of these succeed and resolve to the reviewed paths:

    relay --help
    mpc-ceremony help
    aws --version
    command -v relay mpc-ceremony aws

Record the Relay and `mpc-ceremony` SHA-256 values, signed tags, source commits,
build metadata, package-signing public keys, and AWS CLI version in the
coordinator log. Distribute these trust inputs independently of ceremony
storage:

- the coordinator public key;
- both approved binary digests;
- both signed tags, tag-signer fingerprints, and source commits; and
- both independently trusted package-signing public keys.

## 2. Prepare the ceremony

Run `mpc-ceremony init`, then confirm that `ceremony.json` contains the intended
coordinator, participant order, at least two auditors, and a distinct release
signer. Keep the coordinator signing key protected.

Relay requires a proof-tool version that supports read-only inspection of
definitions, chains, participants, and operational enrollments, plus the
public-witness receipt builder. Mirror receipt preparation uses
`mpc-ceremony ops prepare-mirror-receipt`.

## 3. Configure storage

Create a published bucket, a private inbox bucket, and a public HTTPS URL for
the published bucket. The inbox must never be public. Give the coordinator a
runtime credential for both buckets and configure the provider-specific
temporary-credential issuer.

Complete the provider setup in [docs/STORAGE.md](docs/STORAGE.md) before
continuing. It covers IAM permissions, caching, credential limits, and
preflight checks.

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

Expose the parent R2 token only to a grant command's process:

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
the public URL, confirms that the inbox is private, and removes the probe.

## 4. Run each participant turn

Choose a TTL long enough for replay, contribution, erasure, and upload. Relay
will refuse to start expensive work unless the minimum window remains.

    relay coordinator grant \
      --storage relay-storage.json \
      --role participant \
      --identity participant-03 \
      --credential-ttl 72h \
      --minimum-upload-window 2h \
      --out participant-03.grant.json

Send the participant these items through the agreed private channel:

- `relay-storage.json`;
- their mode-`0600` grant file;
- the coordinator public key and trusted binary hash through the independent
  channels selected for those trust inputs; and
- a link or copy of [ROLE_RUNBOOK.md](ROLE_RUNBOOK.md).

The grant is a bearer credential limited to that participant's candidate
prefix. Replace it immediately if it leaks. Contact the participant when their
turn begins; `relay participate` independently rejects an out-of-turn attempt.

List complete submissions:

    relay coordinator candidates --storage relay-storage.json --phase phase1

Review, verify, and publish the selected candidate:

    relay coordinator accept \
      --storage relay-storage.json \
      --candidate-key candidates/<ceremony-id>/participant-03/phase1/0003/<attempt>/manifest.json \
      --root /ceremony/public \
      --candidate-dir /ceremony/review/participant-03-<attempt> \
      --coordinator-signing-key /secure/coordinator.ed25519.private.hex \
      --verify-publish

Relay checks the manifest scope and hashes, scheduled participant, and current
head. It downloads into a fresh review directory and invokes
`mpc-ceremony <phase> verify`. Only a successful proof-tool acceptance becomes
the new head. Inbox submissions remain available for review or provider
lifecycle cleanup.

Repeat for every participant and phase.

## 5. Publish lifecycle changes

Commands that inspect ceremony documents share these flags where applicable:

    --root DIR --ceremony FILE --ceremony-signature FILE \
    --coordinator-key FILE --bucket NAME --endpoint URL --profile PROFILE

`--phase` defaults to `phase1`. `--ceremony-binary` defaults to
`mpc-ceremony`; pin an explicit trusted path if `PATH` is not trusted.

After closure, beacon, seal, or another coordinator-signed chain update:

    relay coordinator publish \
      --chain /ceremony/public/phase1/chain-0003.json \
      --chain-signature /ceremony/public/phase1/chain-0003.sig \
      <shared flags>

For a closed phase:

    relay coordinator publish \
      --chain <final-chain> \
      --chain-signature <final-chain-signature> \
      --closed \
      <shared flags>

Relay uploads every referenced artifact before moving the public pointer. The
`--closed` marker tells public witnesses that a closure is ready to observe.

## 6. Grant access to other roles

Witnesses, mirrors, auditors, release upload stations, and decision signers
receive access only to their own inbox prefix. Every non-participant grant must
authenticate the identity's signed enrollment:

    relay coordinator grant \
      --storage relay-storage.json \
      --role witness \
      --identity witness-01 \
      --credential-ttl 24h \
      --minimum-upload-window 2h \
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

## 7. Review role evidence

List complete submissions, optionally filtering by role:

    relay coordinator evidence --storage relay-storage.json [--role witness]

Each submission manifest is intake metadata, not proof. Before publishing or
relying on evidence:

1. Check that its manifest has the expected role and identity prefix.
2. Download it into a fresh review location.
3. Run the corresponding proof-tool verification command.
4. Promote only authenticated, coherent evidence to the published artifact
   set.

Incomplete uploads do not appear because each role uploads `manifest.json`
last. Never treat possession of a storage credential as a ceremony signature.

## 8. Failure and recovery

- Replace a grant that is expired or below its minimum remaining window. R2
  grants may not exceed `168h`; AWS grants must fit the configured STS limits.
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
