# MPC Ceremony Online Evidence Upload-Station Checklist

> Use one prefilled copy for each station transporting already signed witness,
> mirror, audit, release, or production-decision evidence. The station is not a
> ceremony signer and must never receive a signer's private key. Follow the
> evidence labels in [CHECKLISTS.md](index.md), the authoritative
> [role reference](../operator/roles-reference.md), and the submission recipes in
> [CEREMONY_COMMANDS.md](../operator/CEREMONY_COMMANDS.md).

## Station assignment

- [ ] **HUMAN** The signer and station operator agreed on the exact evidence
      type and authenticated transfer procedure.
- [ ] **HUMAN** I obtained the coordinator public key, approved kit tag, and kit
      digest independently of ceremony storage.
- [ ] **HUMAN** The station contains no witness, mirror, auditor, release, or
      decision private signing key.
- [ ] **MANUAL — PLATFORM TODO** Record which authenticated signer enrollment
      authorizes this transport assignment and attach the setup/profile receipt.

## Verify and submit

- [ ] **HUMAN** I received only the expected signed public output through the
      approved transfer procedure.
- [ ] **MANUAL — PLATFORM TODO** Run the evidence-type-specific proof-tool
      verification from [CEREMONY_COMMANDS.md](../operator/CEREMONY_COMMANDS.md), attach its
      secret-free result, and require its ceremony and signer identity to match
      this assignment. Relay currently validates transport, not ceremony
      semantics, for generic evidence submissions.
- [ ] **MANUAL — PLATFORM TODO** Attach the printed manifest key and track the
      coordinator's accepted/rejected/superseded result. Future platform
      automation should populate this append-only status directly.

## Cleanup

- [ ] **HUMAN** I reported every interrupted upload, unexpected file, failed
      verification, credential exposure, or mismatch instead of editing the
      signed evidence.
- [ ] **HUMAN** I removed expired grant material and temporary transfer copies
      only under the approved retention procedure.
- [ ] **HUMAN** I retained the signed public evidence and secret-free logs for
      the required period and did not claim that upload alone made it valid.
