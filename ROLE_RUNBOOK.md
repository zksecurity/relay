# Ceremony role runbook

This runbook is for participants, public witnesses, mirror operators, auditors,
release upload stations, and production-decision signers. The coordinator uses
[COORDINATOR_RUNBOOK.md](COORDINATOR_RUNBOOK.md).

The [proof-tool repository](https://github.com/Emurgo/proof-tool) remains the
authority for ceremony validity. Relay transports bytes and reports public
position; the trusted `mpc-ceremony` binary authenticates definitions, chains,
identities, and evidence.

## 1. Install and verify the tools

Follow the role-machine path in [docs/INSTALL.md](docs/INSTALL.md). It contains
the official AWS CLI v2 installation procedure and exact steps for verifying
and installing prebuilt `relay` and `mpc-ceremony` binaries. Advanced operators
may instead reproduce the binaries from the approved source commits.

Do not continue until these commands resolve to the reviewed paths and versions:

    relay --help
    mpc-ceremony help
    aws --version
    command -v relay mpc-ceremony aws

Record the outputs in your local operator log.

## 2. Receive and verify the handoff

Obtain these trust inputs independently of ceremony storage:

- the coordinator public key;
- the expected hash of the reviewed Relay binary; and
- the expected hash of the trusted `mpc-ceremony` binary.

Verify both binary hashes before using them. Do not accept these trust inputs
merely because they appeared in the same bucket as the artifacts they are meant
to check.

The coordinator will also provide the public ceremony material and, if your
role uploads anything, a secret temporary grant. A grant is a bearer credential
limited to your identity's inbox prefix. Store it with mode `0600`, never paste
it into chat or logs, and request a replacement immediately if it leaks.

Read-only role commands use these shared flags where applicable:

    --root DIR --ceremony FILE --ceremony-signature FILE \
    --coordinator-key FILE --bucket NAME --endpoint URL --profile PROFILE

`--phase` defaults to `phase1`. `--ceremony-binary` defaults to
`mpc-ceremony`; pin an explicit trusted path if `PATH` is not trusted.

## 3. Participant

### Enroll once per phase

The coordinator sends `relay-storage.json` and a grant naming your
authenticated participant identity. Enroll with your local signing key:

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

Enrollment asks proof-tool to match your key to the authenticated participant
roster. It does not trust the key's filename or the coordinator's assertion
about your identity.

### Participate when contacted

    relay participate --config participant-03.relay.json

This is the only command required for the turn. Relay first checks the grant
lifetime and public head. If it is not your turn, it exits before expensive
work. Otherwise it:

1. downloads and verifies the accepted transcript;
2. invokes the proof-tool contribution;
3. asks you to destroy the contribution environment;
4. requires you to type `DESTROYED` before creating the signed erasure record;
5. confirms that the public head has not changed; and
6. uploads the candidate manifest last for coordinator review.

Long operations print UTC start, completion, and failure times, plus a
one-minute elapsed-time heartbeat while otherwise silent. Proof-tool replay
counts and Relay transfer progress remain visible. A heartbeat is not a
percentage or ETA.

`relay participant status` is available as a diagnostic, but running it first
is not required: `participate` performs the same out-of-turn check.

## 4. Public witness

Wait for a published closure:

    relay witness watch --interval 60s <shared flags>

Use `--once` to poll once and exit. After observing closure, independently
confirm that its beacon round has not occurred and is at least the definition's
witness lead away. Relay cannot make that real-world timing claim for you.

Prepare the authenticated receipt with proof-tool, review and sign its canonical
bytes, then upload the signed output using “Submit evidence” below. Your grant
must name your signed public-witness enrollment.

## 5. Mirror operator

Synchronize the current authenticated chain prefix into an independently
operated storage location:

    relay mirror sync <shared flags>

Draft a receipt for the exact retained head:

    relay mirror receipt \
      --root <transcript-root> \
      --chain <chain> \
      --chain-signature <chain-signature> \
      --index 3 \
      --location s3://mirror/... \
      --stored-at 2026-09-01T12:00:00Z \
      --out receipt-0003.json

Authenticate and canonicalize the draft:

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

Review and sign the exported canonical bytes offline, then submit the signed
output. Only the location's SHA-256 enters the receipt; the location itself is
not published or fetched.

## 6. Auditor

Synchronize both phases from independently checked mirrors, not the
coordinator's local copy:

    relay auditor sync --phase phase1 <shared flags>
    relay auditor sync --phase phase2 <shared flags>

Replay the ceremony with `mpc-ceremony audit`. Upload the resulting signed
audit record using your auditor grant.

## 7. Release signer and decision signers

The signing machine should remain offline and receive no storage credential.
Review and sign the proof-tool output there, then move only the signed output
to a separate online upload station. Give the scoped release or decision grant
to that station and submit the evidence from it.

A storage upload proves only possession of the scoped grant. The release bundle
or production decision is authoritative only after proof-tool verifies its
record and ceremony signatures.

## 8. Submit evidence

Witnesses, mirrors, auditors, release upload stations, and decision signers all
use the same transport command after producing signed proof-tool output:

    relay submit-evidence \
      --grant witness-01.grant.json \
      --dir ./signed-witness-output

or:

    relay submit-evidence \
      --grant auditor-01.grant.json \
      --file audit.json \
      --file audit.sig

Relay rejects symlinks, non-regular files, duplicate names, and filenames that
look like private keys, credentials, or grants. It uploads `manifest.json`
last, so an interrupted upload never appears complete.

Send the printed manifest key to the coordinator through the agreed channel.
The coordinator will discover it independently and run the relevant proof-tool
verification before using the evidence.

## 9. Failure and recovery

- If a grant is expired or below its minimum remaining window, stop and request
  a replacement before beginning expensive work.
- If Relay says it is not your turn, do not retry the contribution manually.
  Wait for the coordinator and a new public head.
- If the public head changes during a contribution, Relay keeps the candidate
  local and refuses to upload it. Ask the coordinator how to proceed.
- Relay records the highest public index seen under `~/.relay` and rejects a
  pointer that moves backward. Do not delete this state to silence a warning;
  contact the coordinator.
- Relay refuses to overwrite a local file whose bytes differ from the
  authenticated digest.
- Keep private signing keys, contribution environments, grants, and provider
  credentials out of published and evidence directories.
