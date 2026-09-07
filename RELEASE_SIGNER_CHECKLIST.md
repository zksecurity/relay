# MPC Ceremony Release-Signer Checklist

> Use one prefilled copy for the distinct release signer. Follow the evidence
> labels in [CHECKLISTS.md](CHECKLISTS.md), the authoritative
> [role runbook](ROLE_RUNBOOK.md), and the release recipes in
> [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md). The offline signer must never
> receive an S3/R2 grant or expose its private key to the coordination website.

## Assignment and key custody

- [ ] **HUMAN** I generated and control the release-signing key independently
      and supplied only its public identity to the coordinator.
- [ ] **HUMAN** I obtained the coordinator public key, approved kit tag, and kit
      digest through an independent authenticated channel.
- [ ] **HUMAN** The signing machine is offline, independently controlled, and
      contains no storage credential, browser session, or online upload profile.
- [ ] **MANUAL — PLATFORM TODO** Attach the secret-free setup and assignment
      receipts to the release review record without transcribing their values.

## Review and sign

- [ ] **HUMAN** I received the exact candidate, audit reports, operational
      evidence bundle, and public verification material through the approved
      offline transfer procedure.
- [ ] **HUMAN** I reviewed the exact ceremony ID, release contents, audit
      identities, operational evidence, warnings, and intended public label.
- [ ] **HUMAN** For every identity in the signed definition's
      `host_wipe_participants`, the verified operational-evidence bundle contains
      exactly one valid participant-signed host-wipe record. Its `wiped_at`
      strictly postdates that participant's latest `contributed_at` in the
      accepted chains. An accepted contribution or inbox upload alone is not
      proof of this release gate; the statement is not physical proof of erasure.
- [ ] **AUTHORIZE** I authorize my offline release key to sign exactly the
      verified release manifest and no substitute or later-modified bytes.

## Handoff and closeout

- [ ] **HUMAN** I transferred only the signed release output to the separate
      online upload station and retained the signing key offline.
- [ ] **MANUAL — PLATFORM TODO** Bind the offline verification receipt, signed
      release digest, transfer acknowledgement, upload manifest key, and final
      coordinator disposition in one append-only release record.
- [ ] **HUMAN** I reported every failed verification, transfer deviation,
      unexpected role identity, or suspected signing-key exposure.
- [ ] **HUMAN** I retained or destroyed offline review media according to the
      approved evidence and key-custody procedure.
