# MPC Ceremony Participant Turn Checklist

> Use a fresh, prefilled copy for one participant in one phase. This is the
> short live-turn companion to [PARTICIPANT_CHECKLIST.md](PARTICIPANT_CHECKLIST.md)
> and [ROLE_RUNBOOK.md](ROLE_RUNBOOK.md). It contains no secret fields. Never
> paste a private key, contribution randomness, grant contents, or cloud
> credential into this document or the coordination website.
> See [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md) for the complete participant
> status, contribution, and interrupted-upload recipes.

## Turn record

- Ceremony ID: `____________________________________________________________`
- Mode: `production / rehearsal`
- Phase: `phase1 / phase2`
- Participant display name: `_______________________________________________`
- Participant identity ID: `________________________________________________`
- Frozen position: `________________________________________________________`
- Authenticated starting head: `____________________________________________`
- Role config path: `_______________________________________________________`
- Coordinator start notice (UTC): `_________________________________________`
- Grant filename, not contents: `___________________________________________`
- Grant expiry (UTC): `_____________________________________________________`
- Minimum remaining window: `______________________________________________`

## Before starting

- [ ] **HUMAN** I received the start notice and grant through the agreed
      authenticated private channel.
- [ ] **HUMAN** My signing key and environment remain local and protected.
- [ ] **HUMAN** The grant file is mode `0600`, has not been copied into logs,
      chat, source control, browser storage, or persistent configuration, and
      has enough remaining lifetime for the entire operation.
- [ ] **HUMAN** My machine has stable power and networking, correct UTC time,
      adequate disk, disabled sleep, and the approved contribution isolation.
- [ ] **HUMAN** I am not snapshotting, backing up, debugging, or crash-dumping
      the contribution environment.
- **AUTO** `relay participant status --config ROLE_CONFIG` must exit
  successfully, print the authenticated head digest, and report my exact
  identity as next.
- [ ] **HUMAN** I copied the printed head digest into this turn record and
      compared the identity and position with the authenticated start notice.

Stop if any value differs from the signed definition or authenticated start
notice. Do not ask the coordinator to change signed state manually.

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
      native tool only after the preceding statements were true.

If cleanup is incomplete or uncertain, stop without uploading and contact the
coordinator. Do not make an erasure statement you cannot honestly support.

## Successful submission

- [ ] Relay exited successfully and printed `candidate submitted for
      coordinator review`.
- Attempt ID printed by Relay: `____________________________________________`
- Candidate manifest key printed by Relay: `_______________________________`
- Local resumable candidate directory printed by Relay:
  `________________________________________________________________________`
- Signed `destroyed_at` printed by Relay (UTC):
  `________________________________________________________________________`
- Submission completed (UTC): `____________________________________________`
- [ ] I sent only the manifest key and other approved public status to the
      coordinator, not the grant or private material.
- [ ] I retained the intact public candidate directory until acceptance is
      independently confirmed.

Storage appearance or website progress does not establish successful
submission. The manifest-last upload and successful Relay exit do.

## If computation succeeded but upload failed

Do not delete or modify the printed candidate directory and do not recompute.

- [ ] Record the exact secret-free Relay error:
      `_______________________________________________________________`
- [ ] Contact the coordinator and report the candidate directory, attempt ID,
      manifest key if printed, and failure time—never the grant contents.
- [ ] Independently confirm the authenticated public head has not advanced.
- [ ] Receive a replacement grant in a fresh mode-`0600` filename.

Resume with:

```sh
relay participant run \
  --config ROLE_CONFIG \
  --grant REPLACEMENT-GRANT.json \
  --resume-candidate SAVED-CANDIDATE-DIRECTORY
```

- **AUTO** Relay must re-hash every saved file, authenticate its ceremony,
  phase, participant, position, attempt, and starting head, compare any
  existing remote bytes, and still upload `manifest.json` last.
- **STOP** If Relay reports a stale head, changed local file, or conflicting
  remote byte, do not work around it. Preserve the secret-free error and ask
  the coordinator whether a new contribution is required.

## Acceptance and cleanup

- [ ] The coordinator sent the accepted head and chain index through the
      authenticated channel.
- [ ] `relay participant status --config ROLE_CONFIG` independently
      authenticated that head and showed the expected next position or phase
      closure.
- Accepted head: `__________________________________________________________`
- Accepted chain/index: `__________________________________________________`
- Acceptance observed (UTC): `_____________________________________________`
- [ ] I removed expired grant files and temporary credentials under the
      approved procedure.
- [ ] I retained or removed the public candidate and secret-free log according
      to the ceremony's stated evidence and retention policy.
- [ ] I reported every interruption, deviation, retry, or suspected exposure.
- Participant turn sign-off: `______________________________________________`
