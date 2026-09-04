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

- **MANUAL — PLATFORM TODO** — the check is mechanical, but the coordination
  platform does not yet perform and record it through a reviewed integration.
  Run the cited procedure and attach its secret-free output until it does.
- **HUMAN** — you must personally verify or attest to something software cannot
  know.
- **STOP** — do not continue, retry with altered inputs, or work around the
  failure. Preserve non-secret output and contact the coordinator.

See [CHECKLISTS.md](CHECKLISTS.md) for the shared classification rules. A
dashboard rendering is not automatic verification.

Relay transports and schedules ceremony data. The authenticated
`mpc-ceremony` binary decides whether definitions, chains, identities,
contributions, erasure records, and transitions are valid. Website status and
Google login do not replace your Ed25519 ceremony identity.

## Participant assignment

- [ ] **MANUAL — PLATFORM TODO** Prefill the ceremony ID, mode, display name,
      identity ID, key ID, public-key fingerprint, and Phase 1/2 positions from
      the canonical roster. The platform should populate these values and later
      bind them to the authenticated `init-config` receipt without transcription.
- [ ] **HUMAN** Signed policy requires my post-wipe Mac attestation: `yes / no`
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
- [ ] **MANUAL — PLATFORM TODO** Submit the public identity document through the
      approved onboarding procedure. Future platform automation should parse
      and validate it without manual field copying.
- [ ] **HUMAN** I confirmed that the submitted document contains only my public
      identity, key ID, public key, fingerprint, and agreed display name.
- [ ] **HUMAN** Review the authenticated assignment printed by `init-config`
      and confirm that the ceremony mode, scheduled phases, and positions match
      what you agreed to.

## 2. Install and authenticate the tools

- [ ] **HUMAN** Obtain the coordinator public key, ceremony-kit tag, and kit
      archive SHA-256 through the agreed channel independently of ceremony
      storage.
- [ ] **HUMAN** Follow [docs/INSTALL.md](docs/INSTALL.md) on the machine that
      will perform the contribution.


## 3. Prepare the contribution machine

- [ ] **HUMAN** Use the approved dedicated machine, disposable VM, or other
      isolation procedure for this ceremony.
- [ ] **MANUAL — PLATFORM TODO** Run the approved readiness checks for free
      disk, UTC clock, sleep settings, and expected runtime, and attach their
      secret-free results. Future native/platform integration should populate
      these checks directly.
- [ ] **HUMAN** Confirm stable power and networking for the expected turn.
- [ ] **HUMAN** Confirm the machine is not backing up, snapshotting, debugging,
      or crash-dumping the environment that may contain contribution
      randomness.
- [ ] **HUMAN** Create one narrow absolute ceremony home with private
      permissions. Do not use `/`, `$HOME`, or another broad directory.
- [ ] **HUMAN** Keep the signing key and environment declaration at separately
      approved protected paths.

Relay's Docker participant isolation is documented in
[docs/PARTICIPANT_ISOLATION_DESIGN.md](docs/PARTICIPANT_ISOLATION_DESIGN.md).
It provides container-level isolation on Linux and macOS. For a production Mac,
the signed definition must list your identity in `host_wipe_participants`, and
the final parameters cannot be released until you complete the separate
whole-device wipe flow. Native profiles must continue to follow the production
isolation and destruction procedure supplied with the authenticated ceremony
kit.

If you are a production Mac participant:

- [ ] **HUMAN** Before contributing, place only the approved participant
      signing/config material, coordinator trust key, and public ceremony-kit
      recovery material on separately protected storage. Do not preserve the
      contribution environment or Docker Desktop data.
- [ ] **HUMAN** Confirm you can cleanly reinstall macOS and reinstall the
      approved Relay/proof-tool image without restoring a whole-machine backup
      or snapshot.

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

For Docker execution, the coordinator-supplied profile command also includes
`--execution-mode docker`, a locally preloaded immutable `--docker-image`, and
the ceremony's exact `--docker-platform`.

- **AUTO** `init-config` must authenticate the local ceremony, coordinator
  trust key, participant signing key, environment, identity, and frozen roster
  positions, then print the ceremony mode, identity, key ID, fingerprint, and
  both phase assignments.
- **AUTO** The persistent role config must contain validated public metadata
  and approved paths, but no private-key bytes, cloud credentials, or temporary
  grant.
- **AUTO** `participant status` must authenticate the public head and report
  the expected phase, index, and next identity.

- [ ] **MANUAL — PLATFORM TODO** Attach the secret-free Phase 1 and Phase 2
      profile/assignment receipts to this participant record. Do not copy their
      paths, identities, fingerprints, or positions into separate fields.
- [ ] **HUMAN** The authenticated ceremony mode and Phase 1/2 assignments match
      what I agreed to perform.

Do not initialize Phase 2 against an unauthenticated or unsealed Phase 1
result.

## 5. Wait for your turn

- [ ] **HUMAN** Tell the coordinator how to reach you and when your prepared
      machine will be available.
- [ ] **HUMAN** Treat a website notification as a reminder. Start only after
      native Relay authenticates the current head, confirms you are next, and
      validates the fresh grant delivered through the approved private channel.


## 6. Execute Phase 1

- [ ] **HUMAN** Complete one prefilled
      [participant turn checklist](PARTICIPANT_TURN_CHECKLIST.md) for Phase 1.
- [ ] **MANUAL — PLATFORM TODO** Attach that turn's secret-free submission and
      acceptance evidence to this lifecycle record. Do not transcribe the same
      manifest, head, index, or timestamp fields again.
- [ ] **HUMAN** Retain the local public candidate until authenticated acceptance
      or staleness is confirmed.

## 7. Execute Phase 2

- [ ] **MANUAL — PLATFORM TODO** Before starting Phase 2, run the full
      prerequisite inspection in [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md)
      against the complete local transcript and attach its output. Future Relay
      and platform integration should fetch, verify, and record this preflight.
- [ ] **HUMAN** Complete a fresh prefilled
      [participant turn checklist](PARTICIPANT_TURN_CHECKLIST.md) for Phase 2.
- [ ] **MANUAL — PLATFORM TODO** Attach that turn's secret-free submission and
      acceptance evidence to this lifecycle record without duplicating fields.
- [ ] **HUMAN** Retain the local public candidate until authenticated acceptance
      or staleness is confirmed.

## 8. Participant closeout

- [ ] **MANUAL — PLATFORM TODO** Confirm from authenticated public state that
      both required turns were accepted, or attach the signed assignment showing
      why a phase did not apply. Future platform automation should derive this.
- [ ] **HUMAN — PRODUCTION MAC ONLY** After my final scheduled contribution, I
      used the supported whole-device erase and clean macOS reinstall.
- [ ] **HUMAN — PRODUCTION MAC ONLY** I did not restore a pre-wipe backup,
      snapshot, Docker Desktop state, private contribution environment, or copy
      of contribution randomness. Public candidates may follow the approved
      public-evidence retention policy.
- [ ] **HUMAN — PRODUCTION MAC ONLY** I received an authenticated `host-wipe`
      grant and successfully ran:

      ```sh
      relay participant attest-host-wipe \
        --config ROLE_CONFIG \
        --grant HOST_WIPE_GRANT.json \
        --out-dir /absolute/path/to/fresh/host-wipe-evidence
      ```

- [ ] **HUMAN — PRODUCTION MAC ONLY** I entered `MAC WIPED AND CLEANLY
      REINSTALLED` only after every displayed statement was true, and recorded
      the returned evidence manifest key: `_______________________________`
- [ ] **HUMAN** Delete expired grant files and any local credential copies only
      under the approved retention and destruction procedure.
- [ ] **HUMAN** Destroy the disposable contribution environment and any
      remaining secret temporary state under the approved procedure.
- [ ] **HUMAN** Preserve only the approved public candidate, signed receipts,
      and secret-free participant log for the required retention period.
- [ ] **HUMAN** Report every retry, interruption, deviation, suspected leak,
      or manual recovery action to the coordinator.
- [ ] **MANUAL — PLATFORM TODO** Record checklist completion time and attach all
      referenced secret-free receipts. This is administrative completion, not
      an Ed25519 ceremony signature.
