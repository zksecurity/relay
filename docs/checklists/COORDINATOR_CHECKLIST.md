# MPC Ceremony Coordinator Checklist

> This is a human execution aid for a production or rehearsal
> ceremony. The authoritative procedures remain
> [COORDINATOR_RUNBOOK.md](../operator/COORDINATOR_RUNBOOK.md),
> [role reference](../operator/roles-reference.md), and the authenticated proof-tool ceremony
> documentation. Stop and consult those sources whenever this checklist and a
> runbook appear to differ. For the test-only tiny ceremony, use the
> [scripted rehearsal](../../scripts/three-machine-rehearsal/README.md).
> Copy-oriented Relay commands, expected evidence, and retry rules are in
> [CEREMONY_COMMANDS.md](../operator/CEREMONY_COMMANDS.md).
> [CHECKLISTS.md](index.md) indexes the execution checklist for every
> ceremony and operational role.

## How to use this checklist

The checklist deliberately separates mechanical verification from human trust
decisions:

- **MANUAL — PLATFORM TODO** — the check is mechanical and is intended for
  future platform automation, but no reviewed implementation exists today. A
  named operator must run the cited procedure, attach its secret-free evidence,
  and check the item manually.
- **HUMAN** — a named person must make or attest to a decision that software
  cannot establish, such as an out-of-band fingerprint check or physical key
  custody.
- **AUTHORIZE** — software has prepared and verified an exact action, but a
  named human must explicitly permit the state transition or signature.
- **STOP** — a live invariant failed. Pause the ceremony and investigate.

Automated controls are intentionally absent from this checklist. The platform
shows them as non-interactive `passed`, `failed`, or `pending` system status;
their requirements and evidence are in the
[automation control matrix](../design/automation-control-matrix.md). A failed or pending
blocking control cannot be overridden with a checkbox.

A **MANUAL — PLATFORM TODO** item is not automatic merely because a dashboard
renders it: use the authoritative runbook procedure until both the integration
and its emitted evidence have been reviewed. Dashboard state is operational
convenience; signed artifacts and independently authenticated records remain
authoritative.

## Ceremony record

### Human-supplied intent

- [ ] **HUMAN** Ceremony name and ID:
      `____________________________________________`
- [ ] **HUMAN** Mode: `production / rehearsal`
- [ ] **HUMAN** Coordinator: `___________________________________________________`
- [ ] **HUMAN** Planned start (UTC):
      `___________________________________________`
- [ ] **HUMAN** Storage provider: `AWS / R2`
- [ ] **HUMAN** Published origin:
      `______________________________________________`
- [ ] **HUMAN** Published bucket:
      `______________________________________________`
- [ ] **HUMAN** Private inbox bucket:
      `__________________________________________`
- [ ] **HUMAN** Role-image-map GitHub Release URL received through the
      independent trust channel: `________________________________________`
- [ ] **HUMAN** Selected immutable image digests and map source commit recorded:
      `__________________________________________________________________`

### Ceremony evidence record

- [ ] **MANUAL — PLATFORM TODO** Attach the applicable provider CLI path and
      version until the platform emits one combined setup/storage identity
      record.
- [ ] **MANUAL — PLATFORM TODO** Bind the record to the ceremony ID, mode, coordinator identity,
  storage configuration digest, and creation timestamp.
- [ ] **MANUAL — PLATFORM TODO** Preserve changes as append-only operator events; do not silently
  replace earlier values.

## Immediate stop conditions

Stop the ceremony and investigate if any of the following occurs:

- **STOP** A trust input came only from ceremony storage or a release download.
- **STOP** A binary, ceremony definition, signature, circuit, chain, or
  artifact fails authentication or digest verification.
- **STOP** A participant identity, key fingerprint, or roster position differs
  from the independently authenticated record.
- **STOP** The public head moves backward, unexpectedly advances, or conflicts
  between observers.
- **STOP** The inbox is publicly reachable or a scoped credential escapes its
  assigned identity prefix.
- **STOP** A mutable `state/*` response is stale through the public origin.
- **STOP** A grant, private key, parent credential, or control-plane token
  leaks.
- **STOP** A coordinator or participant clock is materially wrong.
- **STOP** A witness cannot independently confirm the required observation
  window.
- **STOP** Required automatic evidence is absent, incomplete, contradictory,
  or cannot be reproduced.

Do not bypass a stop by deleting Relay high-water state, overwriting files,
loosening storage policy, manually editing signed records, or changing a failed
automatic result in the coordination platform.

## 1. People, roles, and trust channels

### Human gates

- [ ] **HUMAN** Name the coordinator, exact ordered participants, at least two
      independent auditors, and a distinct release signer.
- [ ] **HUMAN** Name public witnesses, independently operated mirrors, upload
      stations, production-decision signers, emergency contacts, and the people
      authorized to pause or abort.
- [ ] **HUMAN** Record the authenticated out-of-band channel used for
      fingerprints, the coordinator public key, kit tag, and kit digest.
- [ ] **HUMAN** Independently authenticate every role-key fingerprint with its
      owner.
- [ ] **HUMAN** Confirm each participant, auditor, and release signer generated
      its own Ed25519 keypair on its own machine.
- [ ] **HUMAN** Identify every production participant using macOS and confirm
      the initialization input names exactly those participants in
      `host_wipe_participants`, with the identity IDs sorted as required.
- [ ] **HUMAN** Confirm no role private key was requested, received, shared, or
      centralized.

## 2. Install and authenticate the toolchain

### Human gates

- [ ] **HUMAN** Obtain the kit tag and archive SHA-256 through the independent
      trust channel described in [docs/INSTALL.md](../setup/INSTALL.md).
- [ ] **HUMAN** Approve the exact release intended for this ceremony.
- [ ] **HUMAN** Distribute the authenticated kit tag, archive digest, and
      coordinator public key independently of ceremony storage.

## 3. Prepare and freeze the ceremony

### Human gates

- [ ] **HUMAN** Select one narrow absolute `CEREMONY_HOME`; do not use `/`,
      `$HOME`, or another broad directory.
- [ ] **HUMAN** Protect the coordinator signing key outside published
      directories and record its custody policy.
- [ ] **HUMAN** Confirm the canonical circuit, ceremony inputs, roster, beacon
      policies, future rounds, and witness lead express the intended ceremony.
- [ ] **HUMAN** Retain the independently authenticated roster submissions.
- [ ] **AUTHORIZE** Review the exact definition digest and sign the frozen
      definition with the approved native coordinator tool.

### Platform TODOs

- [ ] **MANUAL — PLATFORM TODO** Track signed role acknowledgements. Every
      frozen role must confirm its identity, fingerprint, and position before
      its first action.

## 4. Configure and validate storage

### Human gates

- [ ] **HUMAN** Complete and review exactly one provider guide:
      [AWS](../setup/AWS_SETUP.md) or [R2](../setup/R2_SETUP.md).
- [ ] **HUMAN** Confirm published artifacts and the private inbox use separate
      buckets and separate intended exposure policies.
- [ ] **HUMAN** Confirm coordinator and credential-issuer permissions follow
      the approved least-privilege design.
- [ ] **AUTHORIZE** Approve the generated secret-free
      `relay-storage.json` after all storage probes pass.

### Platform TODOs

- [ ] **MANUAL — PLATFORM TODO** Confirm the inbox has no other public policy,
  website endpoint, CDN behavior, or custom public hostname permitted by the
  selected provider.
- [ ] **MANUAL — PLATFORM TODO** Write, publicly read, overwrite, and publicly
      read a mutable probe; require the second read to return the new bytes
      without a stale cache.
- [ ] **MANUAL — PLATFORM TODO** From an independent machine or execution
      environment, prove a scoped test credential cannot list, read, or write
      outside its exact role prefix.

## 5. Complete role handoffs

### Human gates

- [ ] **HUMAN** Confirm each role received the coordinator public key, kit
      identity, and fingerprints through the agreed independent channel.
- [ ] **HUMAN** Confirm witnesses are actively monitoring before phase closure.
- [ ] **HUMAN** Confirm mirrors and auditors operate destinations independent
      of the coordinator and one another as required by policy.

### Platform TODOs

- [ ] **MANUAL — PLATFORM TODO** Deliver or make available the signed public definition,
  `relay-storage.json`, and each applicable signed enrollment without including
  grants or private signing keys.
- [ ] **MANUAL — PLATFORM TODO** Track acknowledgement of the exact handoff
      digest from every role.
- [ ] **MANUAL — PLATFORM TODO** Assign every person the applicable checklist
      from [CHECKLISTS.md](index.md). Give every participant one lifecycle
      checklist and a separate turn sheet for each scheduled phase. The future
      platform should prefill only authenticated public assignment data.

## 6. Run participant turns

Repeat this section for every participant in frozen order and for both phases.
Never issue overlapping turns.

### Turn record: manual today, platform-populated later

- [ ] **MANUAL — PLATFORM TODO** Phase and participant index.
- [ ] **MANUAL — PLATFORM TODO** Participant identity ID, key ID, and authenticated fingerprint.
- [ ] **MANUAL — PLATFORM TODO** Starting authenticated head and chain index.
- [ ] **MANUAL — PLATFORM TODO** Grant issue and expiry timestamps and minimum-remaining window.
- [ ] **MANUAL — PLATFORM TODO** Participant execution mode and assurance
      level; for Docker record the immutable image digest/ID, selected Linux
      platform, and whether the host is Linux or macOS. For a production Mac,
      record that the contribution can be accepted, but final results cannot
      be released until the required signed wipe confirmation is verified.
- [ ] **MANUAL — PLATFORM TODO** Attempt ID and candidate manifest key.
- [ ] **MANUAL — PLATFORM TODO** Candidate manifest and digests, erasure timestamp, acceptance
  timestamp, publication timestamp, and accepted chain index.

The platform must render this as one append-only turn record. It must not ask
the coordinator to copy these values between systems.

### Human gates

- [ ] **HUMAN** Confirm the intended participant is available through the
      authenticated contact channel and both clocks are synchronized.
- [ ] **AUTHORIZE** Approve temporary upload permission (a grant) for this
      participant only. Set its lifetime (TTL) and `--minimum-remaining`
      window to allow enough time for download, replay verification,
      contribution, erasure, and upload.
- [ ] **AUTHORIZE** After Relay and proof-tool verify the exact candidate,
      review the candidate digest and permit `relay coordinator accept
      --verify-publish` to use the protected coordinator signing key.
- [ ] **MANUAL — PLATFORM TODO** Notify the next participant only after an
      independent authenticated read agrees with the newly signed public head.
      Future platform automation should enforce this ordering and preserve the
      notification event.

### Platform TODOs

- [ ] **MANUAL — PLATFORM TODO** Before grant issuance, require the signed
      public head to name this participant next and require no other live
      participant grant.
- [ ] **MANUAL — PLATFORM TODO** Record delivery acknowledgement without
  recording the credential.
- [ ] **MANUAL — PLATFORM TODO** Independently read and authenticate the new
      public head before the next turn can become eligible.

### Interrupted-upload recovery

- [ ] **HUMAN** Confirm the participant reports that computation and erasure
      completed and that the printed public candidate directory remains
      intact.
- [ ] **AUTHORIZE** Approve a replacement grant with a fresh filename and a
      conservative window for integrity checks and the remaining upload.


## 7. Close, witness, beacon, and advance each phase

### Human gates

- [ ] **AUTHORIZE** After exact roster completion is proven, permit the
      authenticated proof-tool closure and coordinator signature.
- [ ] **HUMAN** Confirm required witnesses independently observed the closed
      phase before the target beacon round and checked the required lead time.
- [ ] **AUTHORIZE** After the pinned beacon and seal verify, permit publication
      and Phase 2 initialization or final Phase 2 completion.

### Platform TODOs

- [ ] **MANUAL — PLATFORM TODO** Produce, authenticate, publish, and independently re-read the
  beacon/seal transition.

## 8. Mirrors, audits, and operational evidence

### Human gates

- [ ] **HUMAN** Confirm each mirror and auditor acts independently and uses the
      approved independently controlled destination or source.
- [ ] **HUMAN** Confirm auditors obtained both phases from independently
      checked mirrors rather than only the coordinator's local copy.
- [ ] **HUMAN** Confirm each auditor personally initiated and reviewed a full
      proof-tool replay.
- [ ] **AUTHORIZE** Promote only the exact evidence set whose automatic
      verification and identity review both pass.

### Platform TODOs

- [ ] **MANUAL — PLATFORM TODO** Verify manifest role, identity, ceremony,
      prefix, file hashes, and corresponding proof-tool evidence in a fresh
      review directory.
- [ ] **MANUAL — PLATFORM TODO** Record missing, rejected, duplicated, and superseded submissions.
- [ ] **HUMAN** For every required production Mac, confirm the participant's
      final scheduled contribution is accepted before requesting the
      whole-device wipe and clean reinstall.
- [ ] **MANUAL — PLATFORM TODO** Block release until the signed definition's independent audit
      threshold is satisfied.

## 9. Release and production decision

### Human gates

- [ ] **HUMAN** Confirm release and production-decision signing machines remain
      offline and separate from online upload stations.
- [ ] **HUMAN** Transfer the exact unsigned review bundle to the correct
      offline signer through the approved procedure.
- [ ] **HUMAN** Confirm the signer reviewed the exact artifact and ceremony
      evidence set required by proof-tool.
- [ ] **HUMAN** Before releasing the final ceremony results, check that every
      participant required to wipe their machine has submitted a signed
      confirmation, and that `mpc-ceremony` has successfully verified those
      confirmations in the final operational-evidence bundle. The required
      participants are listed in the signed definition's `host_wipe_participants`.

      Accepting a contribution or uploading a confirmation file is not enough.
      The file must be included in the bundle and pass verification. Verification
      checks the signer and recorded timing; it cannot prove the machine was
      actually wiped.
- [ ] **HUMAN** Transfer only signed output back to the separate online upload
      station. Give upload credentials to the station, never the offline
      signer.
- [ ] **AUTHORIZE** Record the explicit production go/no-go decision.
- [ ] **AUTHORIZE** Publish only after every required verification and
      authorization passes.

## 10. Archive and close out

### Human gates

- [ ] **HUMAN** Review every deviation, retry, rejected candidate, incident,
      and manual recovery action.
- [ ] **AUTHORIZE** Permit storage and host cleanup only after archival
      verification passes.
- [ ] **HUMAN** Rotate or revoke any credential suspected of exposure under
      the incident procedure.
- [ ] **HUMAN** Final completion time (UTC):
      `___________________________________________`
- [ ] **HUMAN** Coordinator administrative closeout acknowledged by:
      `___________________________________________________`
- [ ] **HUMAN** Independent administrative review acknowledged by:
      `____________________________________________`

These acknowledgements complete the operator checklist; they are not Ed25519
ceremony signatures.

### Platform TODOs

- [ ] **MANUAL — PLATFORM TODO** Build an authenticated inventory of the signed definition, both
  complete phase chains, closures, beacons, seals, operational evidence,
  audits, decision record, release bundle, and checksums.
- [ ] **MANUAL — PLATFORM TODO** Confirm at least two independently operated
      evidentiary mirrors hold the exact authenticated transcript.
- [ ] **MANUAL — PLATFORM TODO** Record final public locations and immutable
      object/version IDs, and continuously probe that the published origin
      remains independently readable.
- [ ] **MANUAL — PLATFORM TODO** Revoke or expire temporary grants and
      ceremony-only issuer access.
- [ ] **MANUAL — PLATFORM TODO** Remove protected temporary grant files and
      local credential copies only after archival verification and human
      authorization.
- [ ] **MANUAL — PLATFORM TODO** Preserve secret-free coordinator logs and the
      complete append-only decision/evidence history.
