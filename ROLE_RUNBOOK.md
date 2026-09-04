# Ceremony role runbook

> This is the production/manual operator procedure. For the test-only tiny
> ceremony, use the
> [scripted three-machine rehearsal](scripts/three-machine-rehearsal/README.md)
> and its machine-specific `.env` files.

This runbook is for participants, public witnesses, mirror operators, auditors,
release upload stations, and production-decision signers. The coordinator uses
[COORDINATOR_RUNBOOK.md](COORDINATOR_RUNBOOK.md).

[CHECKLISTS.md](CHECKLISTS.md) indexes the separate live checklist for every
role, including the offline release and decision signers and their distinct
online upload station.

Participants should also receive a prefilled
[lifecycle checklist](PARTICIPANT_CHECKLIST.md) and one fresh
[turn checklist](PARTICIPANT_TURN_CHECKLIST.md) for each phase. These are
execution aids; [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md) contains
copy-oriented commands, and this runbook remains authoritative if their
wording differs.

The [proof-tool repository](https://github.com/Emurgo/proof-tool) remains the
authority for ceremony validity. Relay transports bytes and reports public
position; the trusted `mpc-ceremony` binary authenticates definitions, chains,
identities, and evidence.

## 1. Install and verify the tools

Follow the role-machine path in [docs/INSTALL.md](docs/INSTALL.md). It contains
the official AWS CLI v2 installation procedure and exact steps for verifying
and installing published `relay` and `mpc-ceremony` binaries. Release
maintainers and independent build auditors use
[docs/RELEASE.md](docs/RELEASE.md); ceremony roles do not need Go.

During installation, run `./setup verify --receipt-out /trusted/tool-identity-receipt.env`.
Setup authenticates the complete kit and
emits a secret-free receipt containing resolved binary paths, versions, release
identifiers, compatibility evidence, and hashes. Every `init-config` command
below consumes that receipt, independently hashes the running Relay and
`mpc-ceremony` executables, and prints the resolved identities it accepted.
Stop if either hash or the ceremony mode differs.

### Register your public identity

If you are a participant or a role that signs ceremony evidence, follow the
[ceremony identity key-generation guide](PARTICIPANT_KEY_GENERATION.md) on your
own machine. The approved `mpc-ceremony identity generate` command creates the
proof-tool-compatible private seed, public identity, fingerprint, and key ID.
Keep the private key local; never send it to the coordinator or another role.
An upload-only release or decision station does not generate or receive the
offline signer's private key.

Before ceremony initialization, each participant, auditor, and release signer
sends the coordinator the generated public identity JSON through the ceremony's
agreed authenticated channel. After initialization, `init-config` asks
proof-tool to match the local key to the signed `ceremony.json`; review the
authenticated mode and assignment it prints and stop if those human-facing
terms differ from what you agreed to.

Public witnesses and mirror operators instead create a signed
proof-of-possession enrollment after receiving the signed ceremony definition;
the enrollment is bound to that ceremony. Send the enrollment record and its
detached signature to the coordinator, but retain the private key. Auditors,
release signers, and decision-signing identities also provide their signed
enrollment when their output requires a non-participant Relay upload grant. An
upload-only station uses that authenticated enrollment without receiving the
signing key. A participant does not need a separate Relay enrollment record:
Relay matches its local key to the participant identity in the signed roster.

## 2. Receive and verify the handoff

Obtain these trust inputs independently of ceremony storage:

- the coordinator public key;
- the approved ceremony-kit tag and archive hash.

Verify the kit before installation. Its authenticated `release.json` pins the
Relay and proof-tool repositories, tags, and binary hashes. Do not accept these
trust inputs merely because they appeared in the same bucket as the artifacts
they are meant to check.

The coordinator also provides `relay-storage.json`, the public ceremony
material, and each non-participant role's signed enrollment record. Stage them
under one absolute ceremony home:

    CEREMONY_HOME=/var/lib/mpc-ceremonies/CEREMONY_ID
    install -d -m 0700 "$CEREMONY_HOME/public" "$CEREMONY_HOME/config" "$CEREMONY_HOME/run"
    install -m 0600 relay-storage.json "$CEREMONY_HOME/config/relay-storage.json"
    # Place ceremony.json and ceremony.sig under "$CEREMONY_HOME/public".

Keep the independently obtained coordinator public key and private signing keys
at their separately approved absolute paths. A deterministic local path does
not authenticate a trust anchor.

If your role uploads anything, the coordinator later supplies a secret
temporary grant. A grant is a bearer credential limited to your identity's
inbox prefix. Store it with mode `0600`, never paste it into chat or logs, and
request a replacement immediately if it leaks. Grants and cloud secrets never
belong in the persistent role config.

## 3. Participant

### Initialize once per phase

Create a validated production profile with your local signing key before any
temporary upload credential is issued:

    relay ceremony init-config \
      --home "$CEREMONY_HOME" \
      --role participant \
      --phase phase1 \
      --coordinator-key /trusted/coordinator-public-key.hex \
      --tool-identity-receipt /trusted/tool-identity-receipt.env \
      --signing-key /secure/participant-03.ed25519.private.hex \
      --environment /secure/participant-03.environment.json

    ROLE_CONFIG="$CEREMONY_HOME/config/participant-phase1.json"

Initialization asks proof-tool to match your key to the authenticated participant
roster. It does not trust the key's filename or the coordinator's assertion
about your identity. Relay prints the authenticated ceremony mode, identity,
key ID, fingerprint, and both phase positions. Confirm only that the mode and
assignments match what you agreed to; proof-tool has already performed the
cryptographic key comparison.

Check the signed public position without an upload credential:

    relay participant status --config "$ROLE_CONFIG"

### Participate when contacted

After confirming it is the participant's turn, the coordinator supplies a
short-lived scoped grant. Run:

    relay participant run --config "$ROLE_CONFIG" \
      --grant participant-03.grant.json

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

Running status first is optional: `participant run` independently repeats the
same out-of-turn check before expensive work.

The grant's minimum remaining window must cover the whole operation when
starting a new contribution: transcript download, computation, erasure, and
upload. It is not merely an estimate for the final upload.

## 4. Public witness

Use one [public-witness checklist](PUBLIC_WITNESS_CHECKLIST.md) per assigned
phase.

Initialize the profile using the signed public-witness enrollment:

    relay ceremony init-config \
      --home "$CEREMONY_HOME" --role witness --phase phase1 \
      --coordinator-key /trusted/coordinator-public-key.hex \
      --tool-identity-receipt /trusted/tool-identity-receipt.env \
      --enrollment /trusted/witness-01.json \
      --enrollment-signature /trusted/witness-01.sig
    ROLE_CONFIG="$CEREMONY_HOME/config/witness-phase1.json"

Wait for a published closure:

    relay witness run --config "$ROLE_CONFIG" --interval 60s

Use `--once` to poll once and exit; it exits non-zero when no closure has
been published yet, so a single check that observed nothing is never mistaken
for an observation. After observing closure, independently
confirm that its beacon round has not occurred and is at least the definition's
witness lead away. Relay cannot make that real-world timing claim for you.

Prepare the authenticated receipt with proof-tool, review and sign its canonical
bytes, then upload the signed output using “Submit evidence” below. Your grant
must name your signed public-witness enrollment.

## 5. Mirror operator

Use one [mirror-operator checklist](MIRROR_OPERATOR_CHECKLIST.md) per assigned
phase and retained head.

Initialize `mirror-phase1.json` as above with `--role mirror` and the signed
mirror enrollment, then set `ROLE_CONFIG` to that path.

Synchronize the current authenticated chain prefix into an independently
operated storage location:

    relay mirror run --config "$ROLE_CONFIG"

Draft a receipt for the exact retained head:

    relay mirror receipt \
      --config "$ROLE_CONFIG" \
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

Use one [auditor checklist](AUDITOR_CHECKLIST.md) for each independent audit.

Initialize one authenticated auditor profile per phase using `--role auditor`
and the signed auditor enrollment.

Synchronize both phases from independently checked mirrors, not the
coordinator's local copy:

    relay auditor run --config "$CEREMONY_HOME/config/auditor-phase1.json"
    relay auditor run --config "$CEREMONY_HOME/config/auditor-phase2.json"

Replay the ceremony with `mpc-ceremony audit`. Upload the resulting signed
audit record using your auditor grant.

## 7. Release signer and decision signers

The offline roles use the [release-signer checklist](RELEASE_SIGNER_CHECKLIST.md)
and one [decision-signer checklist](DECISION_SIGNER_CHECKLIST.md) per accountable
decision signature. The separate online operator uses the
[upload-station checklist](UPLOAD_STATION_CHECKLIST.md).

The signing machine should remain offline and receive no storage credential.
Review and sign the proof-tool output there, then move only the signed output
to a separate online upload station. Give the scoped release or decision grant
to that station and submit the evidence from it.

On the release upload station, initialize a `release-phase1.json` profile with
`--role release` and the authenticated release-signer enrollment. It contains
no release signing key. Submit with:

    relay release run \
      --config "$CEREMONY_HOME/config/release-phase1.json" \
      --grant release-signer.grant.json \
      --dir ./signed-release-output

A storage upload proves only possession of the scoped grant. The release bundle
or production decision is authoritative only after proof-tool verifies its
record and ceremony signatures.

## 8. Submit evidence

Witnesses, mirrors, auditors, release upload stations, and decision signers all
use the same transport command after producing signed proof-tool output:

    relay witness submit \
      --config "$ROLE_CONFIG" \
      --grant witness-01.grant.json \
      --dir ./signed-witness-output

or:

    relay auditor submit \
      --config "$ROLE_CONFIG" \
      --grant auditor-01.grant.json \
      --file audit.json \
      --file audit.sig

Production-decision evidence retains the generic compatibility command because
one decision grant may be authorized by a coordinator, auditor, or release
signer enrollment rather than one fixed Relay role profile:

    relay submit-evidence \
      --grant decision-signer.grant.json \
      --dir ./signed-decision-output

Relay rejects symlinks, non-regular files, duplicate names, and filenames that
look like private keys, credentials, or grants. It uploads `manifest.json`
last, so an interrupted upload never appears complete.

Send the printed manifest key to the coordinator through the agreed channel.
The coordinator will discover it independently and run the relevant proof-tool
verification before using the evidence.

## 9. Failure and recovery

- If a grant is expired or below its minimum remaining window, stop and request
  a replacement before beginning expensive work.
- If computation and erasure completed but upload was interrupted, keep the
  candidate directory printed by Relay. After receiving a replacement grant,
  resume without recomputing:

      relay participant run --config "$ROLE_CONFIG" \
        --grant participant-03.grant-02.json \
        --resume-candidate /absolute/path/printed/by/relay

  For a resume grant, the minimum remaining window needs to cover the local
  checks and remaining upload. Relay verifies the saved files, confirms that
  the authenticated head is unchanged, verifies the exact bytes of previously
  uploaded objects, and uploads `manifest.json` last. It rejects stale or
  conflicting candidates.
- If Relay says it is not your turn, do not retry the contribution manually.
  Wait for the coordinator and a new public head.
- If the public head changes during a contribution, Relay keeps the candidate
  local and refuses to upload it. Ask the coordinator how to proceed.
- Relay records the highest public index seen under `~/.relay` and rejects a
  pointer that moves backward. Do not delete this state to silence a warning;
  contact the coordinator.
- Relay refuses to overwrite an existing local transcript file. The mirror and
  auditor sync path does not yet re-hash every pre-existing artifact, so require
  mirror receipt preparation or the full audit to authenticate the complete
  retained set before relying on it.
- Keep private signing keys, contribution environments, grants, and provider
  credentials out of published and evidence directories.
