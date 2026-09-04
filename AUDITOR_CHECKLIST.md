# MPC Ceremony Auditor Checklist

> Use one prefilled copy per independent auditor. Follow the evidence labels in
> [CHECKLISTS.md](CHECKLISTS.md), the authoritative
> [role runbook](ROLE_RUNBOOK.md), and the audit recipes in
> [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md). Audit output is public; private
> signing keys and upload grants are not.

## Assignment and independence

- [ ] **HUMAN** I generated and control my auditor identity key independently
      and supplied only its public identity to the coordinator.
- [ ] **HUMAN** I obtained the coordinator public key, approved kit tag, and kit
      digest through the agreed independent channel.
- [ ] **HUMAN** I am independent of the coordinator, participants, release
      signer, and other auditors to the extent required by the signed policy.
- [ ] **HUMAN** I reviewed the authenticated identity and audit assignment and
      confirmed that they match what I agreed to perform.
- [ ] **MANUAL — PLATFORM TODO** Attach the setup and assignment receipts to the
      audit record without manually transcribing their values.

## Acquire and audit

- [ ] **HUMAN** I selected independently checked mirror sources rather than
      relying only on the coordinator's local ceremony copy.
- [ ] **MANUAL — PLATFORM TODO** Ensure the full audit, not Relay sync alone,
      re-hashes the complete local transcript. Relay sync does not yet compare
      every pre-existing local artifact with its authenticated digest.
- [ ] **MANUAL — PLATFORM TODO** Record the independent source/mirror evidence
      used for this audit and bind it to the exact local transcript inventory.
      Future platform automation should ingest signed mirror receipts and
      calculate the binding.
- [ ] **HUMAN** I personally initiated the full audit on the approved machine
      and reviewed its scope, progress, warnings, and final result.
- [ ] **AUTHORIZE** I authorize publication only of the exact audit report and
      signature produced by the successful reviewed run.

## Submission and closeout

- [ ] **HUMAN** Only the signed public audit output—not my signing key or grant
      contents—was placed in the upload environment.
- [ ] **MANUAL — PLATFORM TODO** Attach the printed manifest key and the
      coordinator's accepted/rejected/superseded result. The future platform
      should also calculate whether the independent-auditor threshold is met.
- [ ] **HUMAN** I reported every missing artifact, source conflict, failed
      replay, retry, deviation, or suspected key/grant exposure.
- [ ] **HUMAN** I retained the audit inputs, signed output, and secret-free logs
      for the required evidence period.
