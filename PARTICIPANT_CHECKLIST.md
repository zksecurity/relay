# MPC Ceremony Participant Checklist

> Give one prefilled copy of this checklist to every participant. It covers the
> participant's full ceremony lifecycle; use a fresh
> [PARTICIPANT_TURN_CHECKLIST.md](PARTICIPANT_TURN_CHECKLIST.md) for each phase.
> [ROLE_RUNBOOK.md](ROLE_RUNBOOK.md) and the authenticated proof-tool ceremony
> documentation remain authoritative. Stop and ask the coordinator if they
> differ from this checklist.
> Exact Relay recipes and their success output are in
> [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md).
> Generate the role key with
> [PARTICIPANT_KEY_GENERATION.md](PARTICIPANT_KEY_GENERATION.md).

## How to use this checklist

- **AUTO** — Relay or proof-tool performs the check and emits evidence. You do
  not need to reproduce it manually, but you must stop if it fails.
- **HUMAN** — you must personally verify or attest to something software cannot
  know.
- **STOP** — do not continue, retry with altered inputs, or work around the
  failure. Preserve non-secret output and contact the coordinator.

Relay transports and schedules ceremony data. The authenticated
`mpc-ceremony` binary decides whether definitions, chains, identities,
contributions, erasure records, and transitions are valid. Website status and
Google login do not replace your Ed25519 ceremony identity.

## Participant record

- [ ] **HUMAN** Ceremony ID: `______________________________________________`
- [ ] **HUMAN** Mode: `production / rehearsal`
- [ ] **HUMAN** Display name: `_____________________________________________`
- [ ] **HUMAN** Participant identity ID:
      `________________________________________`
- [ ] **HUMAN** Frozen roster position:
      `_________________________________________`
- [ ] **HUMAN** Ed25519 key ID:
      `_______________________________________________`
- [ ] **HUMAN** Ed25519 public-key fingerprint:
      `________________________________`
- [ ] **HUMAN** Coordinator and emergency contact:
      `________________________________`
- [ ] **HUMAN** Authenticated out-of-band channel:
      `__________________________________`

Never put the participant private key, contribution randomness, temporary
grant contents, or cloud secrets in this checklist.

## Immediate stop conditions

- **STOP** The coordinator key, kit tag, or kit digest came only from ceremony
  storage, the coordination website, or the release download.
- **STOP** A tool, archive, definition, signature, circuit, chain, artifact, or
  environment fails authentication or digest verification.
- **STOP** The signed definition does not contain your exact identity, public
  key, fingerprint, and roster position.
- **STOP** Relay says it is not your turn or the public head moves backward,
  changes unexpectedly, or conflicts with an independent observation.
- **STOP** Your clock is materially wrong.
- **STOP** A private key, contribution secret, temporary grant, or cloud
  credential may have leaked.
- **STOP** The temporary grant is expired, below its minimum remaining window,
  or names the wrong ceremony, phase, role, identity, or prefix.
- **STOP** Contribution cleanup is incomplete or you are uncertain whether a
  copy of contribution randomness remains.
- **STOP** Relay or proof-tool exits unsuccessfully. Do not infer success from
  files in storage or a website progress indicator.

## 1. Establish your ceremony identity

- [ ] **HUMAN** Follow the authenticated
      [key-generation guide](PARTICIPANT_KEY_GENERATION.md) on your own trusted
      machine. The command automatically creates the key ID, public key, and
      fingerprint.
- [ ] **HUMAN** Protect the private key at the approved local path. Never send
      it to the coordinator, paste it into the website, or place it in cloud
      storage, chat, logs, source control, or a persistent Relay profile.
- [ ] **HUMAN** Send only your identity ID, key ID, public key, fingerprint,
      and agreed display name through the approved channel.
- **AUTO** During `init-config`, proof-tool must authenticate the signed
  definition, derive the public key from your local signing key, and match it
  to your exact roster identity, key ID, fingerprint, and Phase 1/2 positions.
- [ ] **HUMAN** Review the authenticated assignment printed by `init-config`
      and confirm that the ceremony mode, scheduled phases, and positions match
      what you agreed to.

## 2. Install and authenticate the tools

- [ ] **HUMAN** Obtain the coordinator public key, ceremony-kit tag, and kit
      archive SHA-256 through the agreed channel independently of ceremony
      storage.
- [ ] **HUMAN** Follow [docs/INSTALL.md](docs/INSTALL.md) on the machine that
      will perform the contribution.

- **AUTO** Verify the archive digest before extraction. `./setup verify` must
  authenticate every kit file, release identifier, binary hash, and
  compatibility record; retain its complete output as the secret-free tool
  identity receipt instead of transcribing values manually.
- **AUTO** `init-config` must resolve and hash both running executables against
  the setup receipt, authenticate the ceremony with the approved proof-tool,
  and emit the participant's secret-free tool and assignment receipt.

## 3. Prepare the contribution machine

- [ ] **HUMAN** Use the approved dedicated machine, disposable VM, or other
      isolation procedure for this ceremony.
- [ ] **HUMAN** Confirm adequate free disk space, stable power and networking,
      correct UTC time, and disabled sleep for the expected turn duration.
- [ ] **HUMAN** Confirm the machine is not backing up, snapshotting, debugging,
      or crash-dumping the environment that may contain contribution
      randomness.
- [ ] **HUMAN** Create one narrow absolute ceremony home with private
      permissions. Do not use `/`, `$HOME`, or another broad directory.
- [ ] **HUMAN** Keep the signing key and environment declaration at separately
      approved protected paths.

The participant isolation design is being developed in
[docs/PARTICIPANT_ISOLATION_DESIGN.md](docs/PARTICIPANT_ISOLATION_DESIGN.md).
Until that design is implemented and approved, follow the production isolation
and destruction procedure supplied with the authenticated ceremony kit. Do not
claim that Relay has automatically erased a container or VM unless the
approved implementation actually measured and recorded that result.

## 4. Initialize once per phase

Create a grant-free validated profile before your turn. Substitute the paths
and identity assigned to you:

```sh
relay ceremony init-config \
  --home /var/lib/mpc-ceremonies/CEREMONY_ID \
  --role participant \
  --phase phase1 \
  --coordinator-key /trusted/coordinator-public-key.hex \
  --tool-identity-receipt /trusted/tool-identity-receipt.env \
  --signing-key /secure/participant-NN.ed25519.private.hex \
  --environment /secure/participant-NN.environment.json

relay participant status \
  --config /var/lib/mpc-ceremonies/CEREMONY_ID/config/participant-phase1.json
```

- **AUTO** `init-config` must authenticate the local ceremony, coordinator
  trust key, participant signing key, environment, identity, and frozen roster
  positions, then print the ceremony mode, identity, key ID, fingerprint, and
  both phase assignments.
- **AUTO** The persistent role config must contain validated public metadata
  and approved paths, but no private-key bytes, cloud credentials, or temporary
  grant.
- **AUTO** `participant status` must authenticate the public head and report
  the expected phase, index, and next identity.

- [ ] **HUMAN** Phase 1 profile path:
      `____________________________________________`
- [ ] **HUMAN** Phase 1 profile validation passed and the reported identity
      and position are correct.
- [ ] **HUMAN** Phase 2 profile path:
      `____________________________________________`
- [ ] **HUMAN** Phase 2 profile validation passed and the reported identity
      and position are correct.

Do not initialize Phase 2 against an unauthenticated or unsealed Phase 1
result.

## 5. Wait for your turn

- [ ] **HUMAN** Tell the coordinator how to reach you and when your prepared
      machine will be available.
- [ ] **HUMAN** Wait for the coordinator's authenticated start notice. A
      website notification alone does not authorize computation.
- [ ] **HUMAN** Keep the persistent role profile free of upload credentials.

- **AUTO** You may run `relay participant status --config ROLE_CONFIG` without
  a grant whenever you need to authenticate public position.
- **AUTO** `relay participant run` repeats the out-of-turn check before any
  expensive computation even if you skip the separate status command.

## 6. Execute Phase 1

- [ ] Complete one prefilled
      [participant turn checklist](PARTICIPANT_TURN_CHECKLIST.md) for Phase 1.
- [ ] Record the submitted candidate manifest key:
      `_________________________________`
- [ ] Record the local resumable candidate directory:
      `_____________________________`
- [ ] Independently confirm the accepted public head names the expected Phase
      1 chain and next position.
- [ ] Retain the public candidate and secret-free logs until the coordinator
      confirms acceptance or tells you the candidate is stale.

## 7. Execute Phase 2

- [ ] Confirm authenticated Phase 1 closure, beacon/seal transition, and the
      signed Phase 2 initialization all pass before accepting a Phase 2 grant.
- [ ] Complete a fresh prefilled
      [participant turn checklist](PARTICIPANT_TURN_CHECKLIST.md) for Phase 2.
- [ ] Record the submitted candidate manifest key:
      `_________________________________`
- [ ] Record the local resumable candidate directory:
      `_____________________________`
- [ ] Independently confirm the accepted public head names the expected Phase
      2 chain and next position.
- [ ] Retain the public candidate and secret-free logs until the coordinator
      confirms acceptance or tells you the candidate is stale.

## 8. Participant closeout

- [ ] **HUMAN** Confirm the coordinator recorded both of your required turns
      as accepted, or record why a phase did not apply.
- [ ] **HUMAN** Delete expired grant files and any local credential copies only
      under the approved retention and destruction procedure.
- [ ] **HUMAN** Destroy the disposable contribution environment and any
      remaining secret temporary state under the approved procedure.
- [ ] **HUMAN** Preserve only the approved public candidate, signed receipts,
      and secret-free participant log for the required retention period.
- [ ] **HUMAN** Report every retry, interruption, deviation, suspected leak,
      or manual recovery action to the coordinator.
- [ ] **HUMAN** Participant completion sign-off:
      `____________________________________`
- [ ] **HUMAN** Completion time (UTC):
      `___________________________________________`
