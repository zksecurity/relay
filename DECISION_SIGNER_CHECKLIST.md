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
- [ ] **MANUAL — PLATFORM TODO** Attach the tool receipt, the hash of the
      tool-generated decision file, my signer role, and the hash of the exact
      evidence inventory to this assignment.

## Decide and sign

- [ ] **HUMAN** I reviewed the complete decision statement, every recorded gate,
      incidents and deviations, and the exact evidence relevant to my role.
- [ ] **AUTHORIZE** I explicitly choose the stated `GO` or `NO-GO` result and
      authorize my key to sign only the exact tool-generated decision file I
      reviewed, without editing or reformatting it.
- [ ] **HUMAN** I did not treat a storage upload, dashboard status, or another
      person's approval as my own decision.

## Handoff and closeout

- [ ] **HUMAN** I transferred only the unchanged decision file, its separate
      signature file, and approved public evidence to the separate upload station;
      my private key remained offline.
- [ ] **MANUAL — PLATFORM TODO** Record which exact decision file my signature
      belongs to, together with the other required signatures, upload manifest,
      and final verified decision. Import the hashes rather than copying them
      by hand.
- [ ] **HUMAN** I reported every missing item, failed required check, conflicting
      version of the decision file, or suspected signing-key exposure.
