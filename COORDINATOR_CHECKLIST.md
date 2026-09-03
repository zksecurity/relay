# MPC Ceremony Coordinator Checklist

> This is a concise execution aid for a production/manual ceremony. The
> authoritative procedures remain [COORDINATOR_RUNBOOK.md](COORDINATOR_RUNBOOK.md),
> [ROLE_RUNBOOK.md](ROLE_RUNBOOK.md), and the authenticated proof-tool ceremony
> documentation. Stop and consult those sources whenever this checklist and a
> runbook appear to differ. For the test-only tiny ceremony, use the
> [scripted rehearsal](scripts/three-machine-rehearsal/README.md).

## Ceremony record

- [ ] Ceremony name and ID: `____________________________________________`
- [ ] Mode: `production / rehearsal`
- [ ] Coordinator: `___________________________________________________`
- [ ] Planned start (UTC): `___________________________________________`
- [ ] Published origin: `______________________________________________`
- [ ] Storage provider: `AWS / R2`
- [ ] Published bucket: `______________________________________________`
- [ ] Private inbox bucket: `__________________________________________`
- [ ] Ceremony-kit tag: `______________________________________________`
- [ ] Ceremony-kit archive SHA-256: `__________________________________`
- [ ] Relay tag and binary SHA-256 recorded in operator log.
- [ ] `mpc-ceremony` tag and binary SHA-256 recorded in operator log.
- [ ] AWS CLI version recorded in operator log.

## Immediate stop conditions

Stop the ceremony and investigate if any of the following occurs:

- [ ] A trust input came only from ceremony storage or the release download.
- [ ] A binary, ceremony definition, signature, circuit, chain, or artifact
      fails authentication or digest verification.
- [ ] A participant identity, key fingerprint, or roster position differs from
      the independently authenticated record.
- [ ] The public head moves backward, unexpectedly advances, or conflicts
      between observers.
- [ ] The inbox is publicly reachable or a scoped credential escapes its
      assigned identity prefix.
- [ ] The mutable `state/*` pointer is stale through the public origin.
- [ ] A grant, private key, parent credential, or control-plane token leaks.
- [ ] A coordinator or participant clock is materially wrong.
- [ ] A witness cannot independently confirm the required observation window.

Do not bypass a stop by deleting Relay high-water state, overwriting files,
loosening storage policy, or manually editing signed records.

## 1. People, roles, and trust channels

- [ ] Name the coordinator, ordered participants, at least two auditors, and a
      distinct release signer.
- [ ] Name the public witnesses, independent mirror operators, upload stations,
      and production-decision signers.
- [ ] Confirm which authenticated out-of-band channel is used for fingerprints,
      the coordinator public key, kit tag, and kit archive digest.
- [ ] Each participant, auditor, and release signer generated its own Ed25519
      keypair on its own machine.
- [ ] Collect only public identity data: identity ID, key ID, public key,
      fingerprint, and agreed display name.
- [ ] Independently authenticate each fingerprint with its owner.
- [ ] Confirm identity IDs, key IDs, and public keys are unique across all
      frozen roles.
- [ ] Confirm no role private key was requested, received, or centralized.
- [ ] Record emergency contacts and the authority permitted to pause or abort.

## 2. Install and authenticate the toolchain

- [ ] Obtain the kit tag and archive SHA-256 through the independent trust
      channel described in [docs/INSTALL.md](docs/INSTALL.md).
- [ ] Download the exact approved kit.
- [ ] Verify the archive SHA-256 before extraction.
- [ ] Run `./setup verify` and confirm every internal file and compatibility
      record passes.
- [ ] Install the exact pinned Relay and `mpc-ceremony` binaries.
- [ ] Install and authenticate AWS CLI v2 using the documented procedure.
- [ ] Confirm all commands resolve to reviewed paths:

      ```sh
      relay --help
      mpc-ceremony help
      aws --version
      command -v relay mpc-ceremony aws
      ```

- [ ] Record command paths, versions, tags, and hashes in the coordinator log.
- [ ] Distribute the authenticated kit tag, archive digest, and coordinator
      public key independently of ceremony storage.

## 3. Prepare and freeze the ceremony

- [ ] Select one specific absolute `CEREMONY_HOME`; do not use `/`, `$HOME`, or
      another broad directory.
- [ ] Create `public/`, `config/`, and `run/` with coordinator-controlled
      permissions.
- [ ] Protect the coordinator signing key outside published directories.
- [ ] Prepare the canonical circuit and ceremony inputs from the reviewed
      proof-tool release.
- [ ] Run the authenticated proof-tool initialization procedure.
- [ ] Verify the signed `ceremony.json` and detached signature.
- [ ] Verify the ceremony ID and mode.
- [ ] Verify the exact circuit ID, constraint-system digests, and software
      binding.
- [ ] Verify the coordinator identity and public-key fingerprint.
- [ ] Verify every participant identity and the exact participant order.
- [ ] Verify at least two auditors and a distinct release signer.
- [ ] Verify both beacon policies, future-round requirements, and witness lead.
- [ ] Retain the independently authenticated roster submissions.
- [ ] Return the signed public definition to every frozen role and require each
      role to confirm its identity, fingerprint, and position.
- [ ] After definition signing, authenticate and retain signed enrollments for
      witnesses, mirrors, and every non-participant identity receiving a grant.

## 4. Configure and validate storage

- [ ] Complete exactly one provider guide:
      [AWS](docs/AWS_SETUP.md) or [R2](docs/R2_SETUP.md).
- [ ] Use separate published and private inbox buckets.
- [ ] Confirm the published origin is anonymously readable over HTTPS.
- [ ] Confirm the inbox has no public policy, public development URL, website
      endpoint, CDN behavior, or custom public hostname.
- [ ] Confirm mutable `state/*` responses are not cached.
- [ ] Perform the freshness test: write, read publicly, overwrite, then confirm
      the next public read returns the new bytes.
- [ ] Confirm coordinator credentials are limited to the required buckets.
- [ ] Confirm the temporary-credential issuer is limited to the inbox.
- [ ] From another machine, confirm a scoped test credential cannot list, read,
      or write outside its exact role prefix.
- [ ] Run `relay coordinator configure-storage` with the explicit trusted
      coordinator public key.
- [ ] Confirm the published read/write/delete probe passes.
- [ ] Confirm the anonymous public-origin probe passes.
- [ ] Confirm the inbox privacy probe passes.
- [ ] Confirm the disposable probes were removed.
- [ ] Set and protect:

      ```sh
      STORAGE_CONFIG="$CEREMONY_HOME/config/relay-storage.json"
      chmod 0600 "$STORAGE_CONFIG"
      ```

- [ ] Verify `relay-storage.json` contains no temporary credentials or secrets.

## 5. Complete role handoffs

- [ ] Send each role the signed public ceremony material.
- [ ] Send `relay-storage.json` through the agreed channel.
- [ ] Send the coordinator public key through the independent trust channel.
- [ ] Send each non-participant its signed enrollment and signature.
- [ ] Require every role to create and validate its own role profile.
- [ ] Require every participant to check public status before its turn.
- [ ] Confirm grants and signing keys are absent from persistent role profiles.
- [ ] Confirm witnesses are monitoring before phase closure.
- [ ] Confirm independent mirror and auditor destinations are ready.

## 6. Run participant turns

Repeat this section for every participant in the frozen order and for both
phases. Never issue overlapping turns.

### Turn record

- [ ] Phase: `phase1 / phase2`
- [ ] Index: `________`
- [ ] Participant identity: `__________________________________________`
- [ ] Starting authenticated head: `__________________________________`
- [ ] Grant issued at (UTC): `________________________________________`
- [ ] Grant expiry (UTC): `___________________________________________`
- [ ] Minimum remaining window: `____________________________________`
- [ ] Candidate manifest key: `______________________________________`
- [ ] Accepted chain and index: `____________________________________`

### Turn procedure

- [ ] Confirm the published signed head names this participant next.
- [ ] Confirm coordinator and participant clocks are synchronized.
- [ ] Choose a credential TTL and `--minimum-remaining` window covering
      transcript download, replay, contribution, erasure, and upload.
- [ ] Generate a new identity-scoped grant into a fresh mode-`0600` file.
- [ ] Send the grant privately only when the participant's turn begins.
- [ ] Remind the participant that the grant is a bearer credential and must
      never enter logs, chat, source control, or persistent configuration.
- [ ] Wait for the participant's manifest key; do not infer completion from an
      object listing or partial upload.
- [ ] Run `relay coordinator candidates` for the correct phase.
- [ ] Confirm the manifest path contains the expected ceremony, participant,
      phase, index, and attempt ID.
- [ ] Review into a fresh local directory.
- [ ] Run `relay coordinator accept ... --verify-publish` with the protected
      coordinator signing key.
- [ ] Confirm Relay verified manifest scope, all hashes, scheduled identity,
      current head, contribution, erasure record, and chain transition.
- [ ] Confirm the new signed head was published and independently readable.
- [ ] Record candidate, acceptance, and publication timestamps with subsecond
      precision; acceptance must be strictly after signed erasure.
- [ ] Notify the next participant only after the new head is verified.

### Interrupted-upload recovery

- [ ] Confirm computation and erasure completed and the participant retained
      the printed candidate directory.
- [ ] Confirm the authenticated public head has not advanced.
- [ ] Issue a replacement grant using a fresh filename.
- [ ] Set `--minimum-remaining` to cover integrity checks and the remaining
      upload, with a conservative buffer.
- [ ] Instruct the participant to use `--resume-candidate`; do not recompute
      unless Relay reports a stale head or conflicting bytes.
- [ ] Confirm the resumed candidate still uploads `manifest.json` last.

## 7. Close, witness, beacon, and advance each phase

- [ ] Confirm every required participant was accepted in exact roster order.
- [ ] Produce and sign the phase closure using the authenticated proof-tool
      procedure.
- [ ] Publish the closed chain with `relay coordinator publish --closed`.
- [ ] Verify the public pointer and all referenced immutable artifacts.
- [ ] Obtain the required independent witness observations and signed receipts.
- [ ] Confirm each witness observed the closed phase before the target beacon
      round and independently checked the required lead time.
- [ ] Verify each witness record and signature with proof-tool before relying
      on it.
- [ ] At the designated future round, fetch and verify the pinned beacon.
- [ ] Produce the authenticated beacon/seal transition with proof-tool.
- [ ] Publish and independently verify the updated chain.
- [ ] After Phase 1, verify the seal and authenticated Phase 2 initialization
      before issuing any Phase 2 grant.
- [ ] After Phase 2, verify both phases and both beacons are complete.

## 8. Mirrors, audits, and operational evidence

- [ ] Issue each non-participant grant only after authenticating the identity's
      signed enrollment.
- [ ] Keep every grant limited to the identity's exact evidence prefix.
- [ ] Confirm mirrors synchronized the authenticated transcript into
      independently operated storage.
- [ ] Confirm mirror receipts bind the exact retained head, file set, and
      location digest.
- [ ] Confirm auditors obtained both phases from independently checked mirrors,
      not only the coordinator's local copy.
- [ ] Confirm each auditor replayed the complete ceremony with proof-tool.
- [ ] Discover complete submissions with `relay coordinator evidence`.
- [ ] For each submission, verify the manifest role, identity, ceremony, and
      prefix.
- [ ] Download into a fresh review directory.
- [ ] Run the corresponding proof-tool verification command.
- [ ] Promote only authenticated and coherent evidence to the published set.
- [ ] Record missing, rejected, duplicated, or superseded submissions.
- [ ] Confirm at least the definition's required independent audit threshold.

## 9. Release and production decision

- [ ] Keep release and production-decision signing machines offline.
- [ ] Transfer unsigned review material to the appropriate offline signer.
- [ ] Confirm the signer reviewed the exact candidate artifact set and ceremony
      evidence required by proof-tool.
- [ ] Transfer only signed output back to a separate online upload station.
- [ ] Give upload credentials to the station, never to the offline signer.
- [ ] Verify uploaded release and decision records with proof-tool; successful
      storage upload alone is not authorization.
- [ ] Confirm every release artifact, checksum, signature, audit, and decision
      refers to the same ceremony and coherence set.
- [ ] Obtain the required explicit production go/no-go record.
- [ ] Do not label rehearsal, centralized fixtures, or incomplete evidence as
      production MPC evidence.
- [ ] Publish only after every required verification and authorization passes.

## 10. Archive and close out

- [ ] Preserve the final signed definition, both complete phase chains,
      closures, beacons, seals, operational evidence, audits, decision record,
      release bundle, and checksums.
- [ ] Confirm at least two independently operated evidentiary mirrors hold the
      exact authenticated transcript.
- [ ] Record final public locations and immutable object/version identifiers.
- [ ] Confirm the published origin remains available for independent audit.
- [ ] Revoke or expire temporary grants and any ceremony-only issuer access.
- [ ] Rotate or revoke any credential suspected of exposure.
- [ ] Remove protected temporary grant files and local credential copies under
      the approved retention and destruction procedure.
- [ ] Preserve coordinator logs without secrets.
- [ ] Document every deviation, retry, rejected candidate, incident, and manual
      recovery action.
- [ ] Perform storage and host cleanup only after archival verification and
      explicit authorization.
- [ ] Record final completion time (UTC): `_____________________________`
- [ ] Coordinator sign-off: `__________________________________________`
- [ ] Independent reviewer sign-off: `_______________________________`
