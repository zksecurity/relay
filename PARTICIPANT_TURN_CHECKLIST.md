# MPC Ceremony Participant Turn Checklist

> Use a fresh, prefilled copy for one participant in one phase. This is the
> short live-turn companion to [PARTICIPANT_CHECKLIST.md](PARTICIPANT_CHECKLIST.md)
> and [ROLE_RUNBOOK.md](ROLE_RUNBOOK.md). It contains no secret fields. Never
> paste a private key, contribution randomness, grant contents, or cloud
> credential into this document or the coordination website.
> See [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md) for the complete participant
> status, contribution, and interrupted-upload recipes.

Use the evidence labels in [CHECKLISTS.md](CHECKLISTS.md). In particular,
**MANUAL — PLATFORM TODO** means a mechanical record must be attached manually
until reviewed platform automation consumes and preserves it.

## Turn record

- [ ] **MANUAL — PLATFORM TODO** Prefill the ceremony, mode, phase, participant
      identity, frozen position, authenticated starting head, grant issue and
      expiry times, and minimum-remaining window from authenticated inputs. The
      future platform must populate one append-only turn record rather than ask
      anyone to copy these values between systems.
- [ ] **HUMAN** I selected and can access this protected role config path on my
      machine:
      `_______________________________________________________`
- [ ] **HUMAN** I selected and can access this protected grant filename on my
      machine, not its contents:
      `___________________________________________`

## Before starting

- [ ] **HUMAN** I received the fresh grant through the agreed authenticated
      private channel. Any website notification was only a reminder.
- [ ] **HUMAN** My signing key and environment remain local and protected.
- [ ] **MANUAL — PLATFORM TODO** Confirm the grant file is a regular local file
      with mode `0600`. Relay does not yet enforce its filesystem mode.
- [ ] **HUMAN** The grant has not been copied into logs, chat, source control,
      browser storage, or persistent configuration.
- [ ] **MANUAL — PLATFORM TODO** Run the approved readiness checks for UTC time,
      disk, sleep settings, and expected runtime and attach their output.
- [ ] **HUMAN** My machine has stable power and networking and uses the approved
      contribution isolation.
- [ ] **HUMAN** I am not snapshotting, backing up, debugging, or crash-dumping
      the contribution environment.
- [ ] **MANUAL — PLATFORM TODO** Attach the complete secret-free status output
      to this turn. Future platform automation should bind the authenticated
      head, identity, and position without manual digest transcription.
- [ ] **HUMAN** The displayed ceremony, phase, identity, and position match the
      assignment I agreed to perform.

Stop if any value differs from the signed definition or the assignment you
agreed to perform. Do not ask the coordinator to change signed state manually.

## Run the turn

Run the single guided command using the prevalidated profile and fresh grant:

```sh
relay participant run --config ROLE_CONFIG --grant GRANT.json
```

Relay must automatically:

- authenticate grant scope and remaining lifetime;
- authenticate the public definition, chain, head, phase, position, and your
  local ceremony identity;
- refuse an out-of-turn run before expensive work;
- download and verify the accepted transcript;
- invoke the pinned proof-tool contribution;
- create the contribution attestation;
- require the approved destruction/erasure procedure and signed erasure
  record;
- recheck that the authenticated public head has not advanced; and
- upload every candidate file with `manifest.json` last.

Long operations emit UTC timestamps and a one-minute heartbeat. A heartbeat is
not a completion percentage or an ETA.

## Erasure gate

- [ ] **HUMAN** I followed the authenticated kit's destruction procedure for
      the environment containing contribution randomness.
- [ ] **HUMAN** I did not retain a snapshot, memory dump, debugger capture,
      backup, or other copy of contribution randomness.
- [ ] **HUMAN** I understand that the candidate output and signed attestations
      are public and intentionally retained for verification and interrupted
      upload recovery; they are not the contribution randomness.
- [ ] **HUMAN** I entered the exact confirmation requested by the approved
      Relay workflow only after the preceding statements were true. Docker
      mode requests `NO COPIES RETAINED` after measured removal; native mode
      follows the ceremony kit's `DESTROYED` procedure.

If cleanup is incomplete or uncertain, stop without uploading and contact the
coordinator. Do not make an erasure statement you cannot honestly support.

## Successful submission

- [ ] **MANUAL — PLATFORM TODO** Preserve the complete secret-free Relay output
      and attach its attempt ID, candidate manifest key, local resumable
      directory, signed `destroyed_at`, and submission time as one submission
      receipt. Do not transcribe five separate fields; future Relay/platform
      integration should emit and ingest the receipt directly.
- [ ] **MANUAL — PLATFORM TODO** Deliver the manifest key and approved public
      status to the coordinator. Future platform integration should ingest the
      secret-free submission receipt directly.
- [ ] **HUMAN** I confirmed that no grant contents, private key, contribution
      randomness, or other private material was included.
- [ ] **HUMAN** I retained the intact public candidate directory until acceptance is
      independently confirmed.

Storage appearance or website progress does not establish successful
submission. The manifest-last upload and successful Relay exit do.

## If computation succeeded but upload failed

Do not delete or modify the printed candidate directory and do not recompute.

- [ ] **MANUAL — PLATFORM TODO** Attach the exact secret-free Relay error:
      `_______________________________________________________________`
- [ ] **HUMAN** Contact the coordinator and report the candidate directory, attempt ID,
      manifest key if printed, and failure time—never the grant contents.
- [ ] **HUMAN** Receive a replacement grant in a fresh mode-`0600` filename.

Resume with:

```sh
relay participant run \
  --config ROLE_CONFIG \
  --grant REPLACEMENT-GRANT.json \
  --resume-candidate SAVED-CANDIDATE-DIRECTORY
```

- **STOP** If Relay reports a stale head, changed local file, or conflicting
  remote byte, do not work around it. Preserve the secret-free error and ask
  the coordinator whether a new contribution is required.

## Acceptance and cleanup

- [ ] **MANUAL — PLATFORM TODO** Deliver the coordinator's acceptance reminder
      through the authenticated channel. The reminder triggers a native status
      check; it is not itself acceptance evidence.
- [ ] **MANUAL — PLATFORM TODO** Attach the complete secret-free status output
      and correlate it with the submitted candidate. Future Relay/platform
      integration should emit an acceptance receipt binding the participant,
      index, accepted output digest, chain digest, and `accepted_at` without
      manual transcription.
- [ ] **HUMAN** I removed expired grant files and temporary credentials under the
      approved procedure.
- [ ] **HUMAN** I retained or removed the public candidate and secret-free log according
      to the ceremony's stated evidence and retention policy.
- [ ] **HUMAN — PRODUCTION MAC ONLY** If this was my final scheduled
      contribution, I completed the separate whole-device erase, clean
      reinstall, and `relay participant attest-host-wipe` steps in
      [PARTICIPANT_CHECKLIST.md](PARTICIPANT_CHECKLIST.md). Until then, my
      accepted contribution remains provisional for final release.
- [ ] **HUMAN** I reported every interruption, deviation, retry, or suspected exposure.
- [ ] **MANUAL — PLATFORM TODO** Record administrative checklist completion.
      This is not a ceremony signature.
