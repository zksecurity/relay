# MPC Ceremony Production-Decision Signer Checklist

> Use one prefilled copy for each accountable signer of a production GO/NO-GO
> record. An eligible signer acts with its existing coordinator, auditor, or
> release-signer identity; this checklist does not create a new identity. Follow
> the evidence labels in [CHECKLISTS.md](CHECKLISTS.md), the authoritative
> [role runbook](ROLE_RUNBOOK.md), and the decision recipes in
> [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md).

## Assignment and custody

- [ ] **HUMAN** I control the private key for the eligible ceremony identity
      named in this decision assignment.
- [ ] **HUMAN** I obtained the coordinator key, approved kit identity, decision
      draft, and evidence set through the approved authenticated procedure.
- [ ] **MANUAL — PLATFORM TODO** Attach the tool receipt, canonical decision
      digest, signer role, and exact evidence-inventory digest to this assignment.

## Decide and sign

- [ ] **HUMAN** I reviewed the complete decision statement, every recorded gate,
      incidents and deviations, and the exact evidence relevant to my role.
- [ ] **AUTHORIZE** I explicitly choose the stated `GO` or `NO-GO` result and
      authorize my key to sign only the canonical decision bytes I reviewed.
- [ ] **HUMAN** I did not treat a storage upload, dashboard status, or another
      person's approval as my own decision.

## Handoff and closeout

- [ ] **HUMAN** I transferred only the canonical decision, my detached
      signature, and approved public evidence to the separate upload station;
      my private key remained offline.
- [ ] **MANUAL — PLATFORM TODO** Correlate my signature with the exact canonical
      decision, the other required signatures, the upload manifest, and the
      final verified decision without manual digest transcription.
- [ ] **HUMAN** I reported every unavailable item, failed gate, conflicting
      decision byte string, or suspected signing-key exposure.
