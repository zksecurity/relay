# MPC Ceremony Public-Witness Checklist

> Use one prefilled copy per witness and phase. Follow the evidence labels in
> [CHECKLISTS.md](CHECKLISTS.md), the authoritative
> [role runbook](ROLE_RUNBOOK.md), and the public-witness recipes in
> [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md). Never place a signing key or
> grant contents in this document or the coordination website.

## Assignment and trust

- [ ] **HUMAN** I obtained the coordinator public key, approved kit tag, and kit
      digest through the agreed channel independently of ceremony storage.
- [ ] **HUMAN** I control the witness signing key and did not provide it to the
      coordinator, website, or upload station.
- **AUTO NOW** `./setup verify` authenticates the kit and emits the approved
  tool-identity receipt.
- **AUTO NOW** `relay ceremony init-config --role witness` authenticates the
  signed witness enrollment, ceremony, phase, tools, and public storage profile.
- [ ] **HUMAN** I reviewed the authenticated assignment and confirmed that the
      ceremony, phase, witness identity, and expected observation window match
      what I agreed to monitor.
- [ ] **MANUAL — PLATFORM TODO** Attach the secret-free setup and assignment
      receipts to this witness assignment. The future platform should ingest
      them without asking anyone to transcribe identities or digests.

## Independent observation

- [ ] **HUMAN** My observation machine and network path are independently
      controlled as required by the ceremony policy.
- [ ] **MANUAL — PLATFORM TODO** Register that I am actively monitoring the
      assigned phase and make that readiness visible to the coordinator. The
      platform must not claim an observation merely because I am online.
- **AUTO NOW** `relay witness run --config ROLE_CONFIG` detects the public
  pointer's closure claim, authenticates the signed chain it names, and reports
  the accepted index and chain digest. The pointer alone is not a signed closure.
- [ ] **MANUAL — PLATFORM TODO** Fetch the exact closure bytes from the public
      origin during the observation window and attach the retrieval evidence.
      Relay does not yet fetch and preserve that closure record for the witness.
- [ ] **HUMAN** I personally observed the closure while it was publicly
      available before the named beacon round existed and with at least the
      signed witness lead remaining.
- [ ] **HUMAN** My recorded `observed_at` truthfully describes that independent
      observation; it was not copied from the coordinator or inferred later.
- **AUTO NOW** `mpc-ceremony ops prepare-public-witness-receipt` authenticates
  the definition, coordinator-signed closure, schedule, enrollment, publication
  location, and claimed observation time, then exports exact canonical signing
  bytes. It does not make the real-world observation claim for the witness.
- [ ] **AUTHORIZE** After reviewing those canonical bytes, I authorize my
      witness key to sign exactly that receipt.
- **AUTO NOW** `mpc-ceremony ops import-signature` and `ops verify` must accept
  the detached signature and exact related evidence.

## Submission and closeout

- [ ] **HUMAN** Only signed public witness output—not my private key, raw grant,
      or unrelated files—was transferred to the upload environment.
- **AUTO NOW** `relay witness submit` validates the role-scoped grant, rejects
  secret-looking or unsafe files, and uploads the evidence manifest last.
- [ ] **MANUAL — PLATFORM TODO** Attach the printed manifest key and the
      coordinator's accepted/rejected/superseded result to this assignment. A
      future platform should correlate them automatically.
- [ ] **HUMAN** I reported any missed window, clock problem, interruption,
      conflicting view, or suspected key/grant exposure instead of signing an
      observation I could not support.
- [ ] **HUMAN** I retained the signed receipt and secret-free output according
      to the ceremony evidence policy and removed expired upload credentials
      under the approved procedure.
