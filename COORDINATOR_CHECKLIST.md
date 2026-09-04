# MPC Ceremony Coordinator Checklist

> This is an automation-aware execution aid for a production or rehearsal
> ceremony. The authoritative procedures remain
> [COORDINATOR_RUNBOOK.md](COORDINATOR_RUNBOOK.md),
> [ROLE_RUNBOOK.md](ROLE_RUNBOOK.md), and the authenticated proof-tool ceremony
> documentation. Stop and consult those sources whenever this checklist and a
> runbook appear to differ. For the test-only tiny ceremony, use the
> [scripted rehearsal](scripts/three-machine-rehearsal/README.md).
> Copy-oriented Relay commands, expected evidence, and retry rules are in
> [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md).
> [CHECKLISTS.md](CHECKLISTS.md) indexes the execution checklist for every
> ceremony and operational role.

## How to use this checklist

The checklist deliberately separates mechanical verification from human trust
decisions:

- **AUTO NOW** — the current Relay, proof-tool, or storage adapter produces a
  pass/fail result. Retain its complete secret-free output as evidence. An
  operator cannot turn a failure into a pass by checking a box.
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

Do not replace an **AUTO NOW** result with an unauthenticated checkbox. A
**MANUAL — PLATFORM TODO** item is not automatic merely because a dashboard
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
- [ ] **HUMAN** Ceremony-kit tag received through the independent trust
      channel: `__________________________________________________________`
- [ ] **HUMAN** Ceremony-kit archive SHA-256 received through that channel:
      `__________________________________________________________________`

### Ceremony evidence record

- **AUTO NOW** `./setup verify` emits the effective Relay and `mpc-ceremony`
  versions, resolved executable paths, release identifiers, and binary SHA-256
  values as a secret-free tool-identity receipt. Retain the complete receipt.
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
- [ ] **HUMAN** Confirm no role private key was requested, received, shared, or
      centralized.

### Mechanical checks and evidence

- **AUTO NOW** Reject a roster with no participant, fewer than two auditors, no
  release signer, or an ambiguous participant order.
- **AUTO NOW** Reject duplicate identity IDs, key IDs, or public keys across frozen
  roles.
- **AUTO NOW** Reject a release signer who is also the coordinator, a participant,
  or an auditor under the approved identity policy.
- **AUTO NOW** Store only public identity data: identity ID, key ID, public key,
  fingerprint, and agreed display name.
- **AUTO NOW** Export the exact canonical roster and digest for native review and
  signing. A browser draft is not a frozen definition.

## 2. Install and authenticate the toolchain

### Human gates

- [ ] **HUMAN** Obtain the kit tag and archive SHA-256 through the independent
      trust channel described in [docs/INSTALL.md](docs/INSTALL.md).
- [ ] **HUMAN** Approve the exact release intended for this ceremony.
- [ ] **HUMAN** Distribute the authenticated kit tag, archive digest, and
      coordinator public key independently of ceremony storage.

### Mechanical checks and evidence

- **AUTO NOW** Verify the downloaded archive SHA-256 before extraction.
- **AUTO NOW** Run `./setup verify` and require every internal file and
  compatibility record to pass.
- **AUTO NOW** Require the pinned Relay, `mpc-ceremony`, and provider CLI versions.
- **AUTO NOW** Resolve and record the reviewed command paths, versions, tags, and
  binary hashes. At minimum capture the output of:

  ```sh
  relay --help
  mpc-ceremony help
  aws --version
  command -v relay mpc-ceremony aws
  ```

- **AUTO NOW** Refuse ceremony actions when the effective tool identity differs
  from the approved record.

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

### Mechanical checks and evidence

- **AUTO NOW** Create `public/`, `config/`, and `run/` beneath the approved home
  with coordinator-controlled permissions.
- **AUTO NOW** Run the authenticated proof-tool initialization procedure.
- **AUTO NOW** Verify the signed `ceremony.json` and detached signature, ceremony
  ID and mode, circuit ID, constraint-system digests, software binding,
  coordinator identity, coordinator fingerprint, participant identities and
  order, auditors, release signer, and beacon policies.
- **AUTO NOW** Bind the signed definition to the exact canonical roster digest.
- [ ] **MANUAL — PLATFORM TODO** Track signed role acknowledgements. Every
      frozen role must confirm its identity, fingerprint, and position before
      its first action.
- **AUTO NOW** Authenticate and retain signed enrollments for witnesses, mirrors,
  and every non-participant identity that can receive a grant.

## 4. Configure and validate storage

### Human gates

- [ ] **HUMAN** Complete and review exactly one provider guide:
      [AWS](docs/AWS_SETUP.md) or [R2](docs/R2_SETUP.md).
- [ ] **HUMAN** Confirm published artifacts and the private inbox use separate
      buckets and separate intended exposure policies.
- [ ] **HUMAN** Confirm coordinator and credential-issuer permissions follow
      the approved least-privilege design.
- [ ] **AUTHORIZE** Approve the generated secret-free
      `relay-storage.json` after all storage probes pass.

### Mechanical checks and evidence

- **AUTO NOW** Confirm the published origin is anonymously readable over HTTPS.
- **AUTO NOW** For R2, reject an inbox with `r2.dev` access or a custom public
  domain; for every provider, require the anonymous inbox-read probe to fail.
- [ ] **MANUAL — PLATFORM TODO** Confirm the inbox has no other public policy,
  website endpoint, CDN behavior, or custom public hostname permitted by the
  selected provider.
- [ ] **MANUAL — PLATFORM TODO** Write, publicly read, overwrite, and publicly
      read a mutable probe; require the second read to return the new bytes
      without a stale cache.
- [ ] **MANUAL — PLATFORM TODO** From an independent machine or execution
      environment, prove a scoped test credential cannot list, read, or write
      outside its exact role prefix.
- **AUTO NOW** Run `relay coordinator configure-storage` with the explicit trusted
  coordinator public key and require published read/write/delete, anonymous
  public-origin, and inbox-privacy probes to pass.
- **AUTO NOW** Confirm disposable probes were removed.
- **AUTO NOW** Set the storage config to mode `0600` and reject any persistent
  temporary credentials or secrets in it.

## 5. Complete role handoffs

### Human gates

- [ ] **HUMAN** Confirm each role received the coordinator public key, kit
      identity, and fingerprints through the agreed independent channel.
- [ ] **HUMAN** Confirm witnesses are actively monitoring before phase closure.
- [ ] **HUMAN** Confirm mirrors and auditors operate destinations independent
      of the coordinator and one another as required by policy.

### Mechanical checks and evidence

- [ ] **MANUAL — PLATFORM TODO** Deliver or make available the signed public definition,
  `relay-storage.json`, and each applicable signed enrollment without including
  grants or private signing keys.
- [ ] **MANUAL — PLATFORM TODO** Track acknowledgement of the exact handoff
      digest from every role.
- **AUTO NOW** Require every role profile to validate before it becomes ready.
- **AUTO NOW** Reject persistent role profiles containing grants, cloud secrets,
  or private-key bytes. A validated profile may contain an approved private-key
  path, but not the key contents.
- [ ] **MANUAL — PLATFORM TODO** Assign every person the applicable checklist
      from [CHECKLISTS.md](CHECKLISTS.md). Give every participant one lifecycle
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
- [ ] **MANUAL — PLATFORM TODO** Attempt ID and candidate manifest key.
- [ ] **MANUAL — PLATFORM TODO** Candidate manifest and digests, erasure timestamp, acceptance
  timestamp, publication timestamp, and accepted chain index.

The platform must render this as one append-only turn record. It must not ask
the coordinator to copy these values between systems.

### Human gates

- [ ] **HUMAN** Confirm the intended participant is available through the
      authenticated contact channel and both clocks are synchronized.
- [ ] **AUTHORIZE** Approve one identity-scoped grant with a TTL and
      `--minimum-remaining` window that covers download, replay, contribution,
      erasure, and upload.
- [ ] **AUTHORIZE** After Relay and proof-tool verify the exact candidate,
      review the candidate digest and permit `relay coordinator accept
      --verify-publish` to use the protected coordinator signing key.
- [ ] **MANUAL — PLATFORM TODO** Notify the next participant only after an
      independent authenticated read agrees with the newly signed public head.
      Future platform automation should enforce this ordering and preserve the
      notification event.

### Mechanical checks and evidence

- [ ] **MANUAL — PLATFORM TODO** Before grant issuance, require the signed
      public head to name this participant next and require no other live
      participant grant.
- **AUTO NOW** Generate the grant into a fresh mode-`0600` file and bind it to
  the exact participant prefix.
- [ ] **MANUAL — PLATFORM TODO** Record delivery acknowledgement without
  recording the credential.
- **AUTO NOW** Relay's participant uploader writes `manifest.json` last and
  `relay coordinator candidates` treats the manifest as the submission marker.
  Do not infer cryptographic validity or referenced-object completeness from
  the listing; acceptance performs those checks.
- **AUTO NOW** `relay coordinator candidates` discovers schema-valid manifests
  for the configured ceremony and reports their claimed participant, phase,
  index, and object key. Treat `ready` as ready for acceptance review, not as a
  valid contribution; exact path, attempt, object bytes, hashes, schedule, and
  chain-head binding are checked by `relay coordinator accept`.
- **AUTO NOW** Review into a fresh local directory.
- **AUTO NOW** `relay coordinator accept --verify-publish` must verify manifest
  scope, every file hash, scheduled identity, current head, contribution,
  signed erasure record, and chain transition, then produce the
  coordinator-signed accepted transition before publishing a new signed head.
- **AUTO NOW** Require `accepted_at` to be strictly after signed `destroyed_at`,
  preserve subsecond timestamps, and retain the complete native receipt.
- [ ] **MANUAL — PLATFORM TODO** Independently read and authenticate the new
      public head before the next turn can become eligible.

### Interrupted-upload recovery

- [ ] **HUMAN** Confirm the participant reports that computation and erasure
      completed and that the printed public candidate directory remains
      intact.
- [ ] **AUTHORIZE** Approve a replacement grant with a fresh filename and a
      conservative window for integrity checks and the remaining upload.

- **AUTO NOW** Require the authenticated public head to remain unchanged.
- **AUTO NOW** `--resume-candidate` must re-hash every saved file and bind the
  candidate to the ceremony, phase, participant, position, attempt, and
  starting head.
- **AUTO NOW** Verify already uploaded objects byte-for-byte and upload
  `manifest.json` last.
- **AUTO NOW** Refuse resume on a stale head or conflicting local/remote bytes. Do
  not recompute unless Relay reports that the saved candidate cannot be used.

## 7. Close, witness, beacon, and advance each phase

### Human gates

- [ ] **AUTHORIZE** After exact roster completion is proven, permit the
      authenticated proof-tool closure and coordinator signature.
- [ ] **HUMAN** Confirm required witnesses independently observed the closed
      phase before the target beacon round and checked the required lead time.
- [ ] **AUTHORIZE** After the pinned beacon and seal verify, permit publication
      and Phase 2 initialization or final Phase 2 completion.

### Mechanical checks and evidence

- **AUTO NOW** Prove every required participant was accepted exactly once and in
  frozen order.
- **AUTO NOW** Publish the closed chain with `relay coordinator publish --closed`
  and verify the public pointer and all referenced immutable artifacts.
- **AUTO NOW** Verify every witness record, signature, ceremony binding, observed
  head, beacon round, and lead-time claim with proof-tool.
- **AUTO NOW** Fetch and verify only the pinned future beacon round.
- [ ] **MANUAL — PLATFORM TODO** Produce, authenticate, publish, and independently re-read the
  beacon/seal transition.
- **AUTO NOW** After Phase 1, verify the seal and authenticated Phase 2
  initialization before enabling any Phase 2 grant.
- **AUTO NOW** After Phase 2, require both complete phases and both authenticated
  beacon transitions.

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

### Mechanical checks and evidence

- **AUTO NOW** Authenticate every signed non-participant enrollment before issuing
  a grant, and constrain the grant to that identity's exact evidence prefix.
- **AUTO NOW** Verify mirror receipts bind the exact retained head, file set,
  location digest, and independently authenticated mirror identity.
- **AUTO NOW** Discover only manifest-last evidence submissions with
  `relay coordinator evidence`.
- [ ] **MANUAL — PLATFORM TODO** Verify manifest role, identity, ceremony,
      prefix, file hashes, and corresponding proof-tool evidence in a fresh
      review directory.
- [ ] **MANUAL — PLATFORM TODO** Record missing, rejected, duplicated, and superseded submissions.
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
- [ ] **HUMAN** Transfer only signed output back to the separate online upload
      station. Give upload credentials to the station, never the offline
      signer.
- [ ] **AUTHORIZE** Record the explicit production go/no-go decision.
- [ ] **AUTHORIZE** Publish only after every required verification and
      authorization passes.

### Mechanical checks and evidence

- **AUTO NOW** Verify uploaded release and decision records with proof-tool. A
  successful storage upload is not authorization.
- **AUTO NOW** Require every release artifact, checksum, signature, audit, and
  decision to refer to one ceremony and coherence set.
- **AUTO NOW** Reject production labeling for a rehearsal, centralized fixture, or
  incomplete evidence set.

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

### Mechanical checks and evidence

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
