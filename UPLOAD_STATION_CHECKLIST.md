# MPC Ceremony Online Evidence Upload-Station Checklist

> Use one prefilled copy for each station transporting already signed witness,
> mirror, audit, release, or production-decision evidence. The station is not a
> ceremony signer and must never receive a signer's private key. Follow the
> evidence labels in [CHECKLISTS.md](CHECKLISTS.md), the authoritative
> [role runbook](ROLE_RUNBOOK.md), and the submission recipes in
> [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md).

## Station assignment

- [ ] **HUMAN** The signer and station operator agreed on the exact evidence
      type and authenticated transfer procedure.
- [ ] **HUMAN** I obtained the coordinator public key, approved kit tag, and kit
      digest independently of ceremony storage.
- **AUTO NOW** `./setup verify` authenticates the station's Relay and proof-tool
  binaries and emits the tool-identity receipt.
- **AUTO NOW** Where a role profile exists, `relay ceremony init-config`
  authenticates the signer enrollment, ceremony, role, tools, and public source
  without storing a signing-key path or grant.
- [ ] **HUMAN** The station contains no witness, mirror, auditor, release, or
      decision private signing key.
- [ ] **MANUAL — PLATFORM TODO** Record which authenticated signer enrollment
      authorizes this transport assignment and attach the setup/profile receipt.

## Verify and submit

- [ ] **HUMAN** I received only the expected signed public output through the
      approved transfer procedure.
- [ ] **MANUAL — PLATFORM TODO** Run the evidence-type-specific proof-tool
      verification from [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md), attach its
      secret-free result, and require its ceremony and signer identity to match
      this assignment. Relay currently validates transport, not ceremony
      semantics, for generic evidence submissions.
- **AUTO NOW** Relay validates the temporary grant's role, identity, ceremony,
  prefix, expiry, and minimum remaining window before upload.
- **AUTO NOW** The applicable `relay witness submit`, `relay mirror submit`,
  `relay auditor submit`, `relay release run`, or `relay submit-evidence`
  command rejects unsafe inputs and uploads `manifest.json` last.
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
