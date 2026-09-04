# MPC Ceremony Mirror-Operator Checklist

> Use one prefilled copy per mirror assignment and phase. Follow the evidence
> labels in [CHECKLISTS.md](CHECKLISTS.md), the authoritative
> [role runbook](ROLE_RUNBOOK.md), and the mirror recipes in
> [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md). Never record a private key,
> grant contents, or a private mirror location in this checklist.

## Assignment and independence

- [ ] **HUMAN** I obtained the coordinator public key, approved kit tag, and kit
      digest independently of ceremony storage.
- [ ] **HUMAN** The mirror destination and its administrative control are
      independent of the coordinator and other mirrors as required by policy.
- [ ] **HUMAN** I control the mirror signing key; the coordinator, website, and
      upload station do not.
- [ ] **HUMAN** I reviewed the authenticated assignment and confirmed that its
      ceremony, phase, mirror identity, and retention obligation match what I
      agreed to operate.
- [ ] **MANUAL — PLATFORM TODO** Attach the secret-free setup and assignment
      receipts. Future platform automation should populate their identities and
      digests directly.

## Synchronize and attest

- [ ] **MANUAL — PLATFORM TODO** Require the subsequent proof-tool receipt
      preparation to re-hash the complete retained set. Relay sync does not yet
      compare every pre-existing local artifact with its authenticated digest.
- [ ] **HUMAN** I confirmed the exact synchronized bytes are durably retained at
      the independently controlled destination named by my private records.
- [ ] **AUTHORIZE** After reviewing the head, index, file set, location digest,
      and retention claim, I authorize my mirror key to sign exactly those
      canonical bytes.

## Submission and retention

- [ ] **HUMAN** Only signed public mirror evidence was transferred to the upload
      environment; the mirror signing key and destination credentials remained
      separate.
- [ ] **MANUAL — PLATFORM TODO** Attach the submitted manifest key and the
      coordinator's accepted/rejected/superseded result. A future platform
      should correlate those records automatically.
- [ ] **HUMAN** I will preserve the authenticated transcript for the required
      period and report loss, mutation, access-control change, or any break in
      independent control.
