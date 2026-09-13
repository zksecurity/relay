# CLI handoff and prerequisite audit

Reviewed 2026-09-13 against local `feat/diagnostic-reports`.
The guidance implementation now addresses the listed cases. This document
retains the original findings; it is not a release approval or whole-CLI proof.

## Reviewed gaps addressed by the implementation

| # | Journey point | Guidance gap |
|---|---|---|
| 1 | Role identity generated | Sending `identity.json` is printed once; the next recommendation asks for ceremony files without explicitly describing the intervening coordinator exchange. |
| 2 | Role enrollment signed | Local enrollment files advance onboarding without a persistent next action to send the public enrollment directory to the coordinator. Applies to participant, witness, mirror, auditor and final signer. |
| 3 | Online profile creation | The recommendation does not check for the public `relay-storage.json` first. Participants, witnesses, mirrors, auditors and upload stations need it. |
| 4 | Coordinator post-initialization | The recommendation can advance to operations without guiding generation and distribution of the public storage configuration. Saved infrastructure settings are not that generated file. |
| 5 | Participant grant issued | Private delivery to the named participant is help text, not a separate next action showing the exact output and recipient. |
| 6 | Evidence grant issued | The same delivery gap affects grants for other submitting roles. |
| 7 | Standalone evidence upload completed | Witness/mirror/auditor workflows lack an explicit manifest-location handoff to the coordinator. Tessera notification is automatic; standalone coordination is not. |
| 8 | Audit/final-signing inputs | Commands request candidate, audit and evidence paths, but receiving-side guidance does not clearly enumerate the package to request and stage first. |
| 9 | Phase 2 begins | Onboarding recommends creating only a Phase 1 profile. Later phase-specific commands expect a Phase 2 profile without a dedicated transition action. |
| 10 | Auditor stages upload | Audit outputs default to `/work/audit.json` and `/work/audit.sig`; upload defaults to `/work/signed-output`. Preparing that public-only directory is left to the user. |
| 11 | Standalone roles need grants | Evidence-grant issuance is optional and placed in closure areas, although later auditor/release uploads also need access. Optional navigation is not equivalent to an unnecessary prerequisite. |
| 12 | Coordinator assembles evidence | Inbox listing/download actions are optional closure-area actions; later bundle preparation expects records locally without a distinct outstanding-submissions collection step. |
| 13 | Production decision | Preparing, signing and verifying the decision exist, but explicit distribution of the exact canonical decision/evidence and return of accountable signatures do not. Not exercised by a tiny rehearsal. |

Sources: `cmd/relay/role_prepare.go` (`nextPreparationAction`, `initProfile`),
`role_enrollment.go`, `coordinator_navigation.go`, `coordinator_prepare.go`,
`role_flow_catalog.go`, and `flow_readiness.go`.

These findings concern guidance, not demonstrated cryptographic bypasses.
File presence, reported delivery, signature verification and acceptance are
different facts. Fixing navigation must not collapse those distinctions.

## Already explicit or locally corrected

- Coordinator definition sharing now precedes enrollment collection and shows
  the three public files. This local change is not yet a published release.
- Input custody, participant receipt return, and contribution return handoffs
  already have authored tasks.
- Final signer has an explicit public-release handoff to the upload station.
- Tessera setup export explicitly asks the coordinator to return to Tessera;
  it does not claim website acceptance.

## Historical validation before the guidance fixes

- `go test ./cmd/relay -count=1`: passed on 2026-09-13.
- Targeted authored setup-order, legacy participant-profile migration, and
  handoff-waiting tests passed. The setup-order test explicitly expects
  enrollment -> profile without providing storage: it then codified part
  of the problematic guidance, rather than protecting against it.
- Full Docker ceremony integration: passed in 95.01 seconds on 2026-09-13.
  Exercised three contributions per phase, container removal and signed cleanup,
  two real future Quicknet beacons, both-phase replay, public proof, audits,
  operational-bundle preparation/signing/verification and final release
  signing/verification. Wrong release signer ID was rejected as expected.
  Transport was local public-file handoff, not live S3/R2.
- The full integration invokes selected recipes and supplies intervening
  handoffs/synchronization through fixtures. Passing it is not proof that a
  user following only recommended menu actions can finish.
- Interactive onboarding also explicitly supplies storage and creates both
  phase profiles in its scripted answers. That can conceal gaps 3 and 9.
- A no-assistance, all-role recommended-path journey was not verified by these
  tests; the known onboarding gaps prevented calling that journey complete.
- No live cloud authorization, independent operators, physical erasure or
  production decision is established by local tiny-ceremony tests.

The first full integration attempt reached preliminary final keys, then failed
to build a test-only helper because the isolated pinned proof-tool checkout
lacked `vendor/`. Its supported `scripts/bootstrap-vendor.sh` completed before
the rerun. No existing proof-tool working-tree changes were used or overwritten.

The successful run used the current local Go workflow code with cached ARM64
Docker runtimes, not newly built images containing every local CLI change:

- Online image ID: `sha256:a5fc7029615d2e4985611ff5944d98be85751ae0f944d86e6ad2ef5827824ba5`.
- Offline image ID: `sha256:c67ef564b69aab446fc39cf5834a77b183fac0ad2b8e80bc0bd57612eeecb94b`.
- Isolated proof-tool helper source: `7ba406f0a6066f10b668ae8c553ab45e897f9fe4`.
- Online proof-tool hash was checked against `release/role-images.json`:
  `764038152d6f92d7949176b5755e96076481ec29f3dfb3db6c0f2d826c188e77`.

The run above predates the guidance implementation. It is a passing mechanical
integration, not evidence that the new guidance was tested.

## Guidance implementation validation

- Normal Go tests and vet pass, including the formerly failing real-menu storage
  contract. The narrow symbolic pilot is not expanded to all thirteen cases.
- Added regressions for exact public-file handoff reports/reopen/changed files,
  early storage checks for every online role, authored exchange order, private
  grant expiry/reissue and credential non-disclosure, and exact audit-pair staging.
- Updated real-Docker onboarding dialogues to follow defaults for identity and
  enrollment delivery, storage import and both phase profiles.
- Fresh-image onboarding passed in 27.13 seconds, including default identity/
  enrollment handoffs, storage import, both phase profiles, real signing and
  witness/mirror PTY-to-Docker signing prompts. Observation fixtures copy and
  authenticate public files locally; they do not test cloud synchronization.
- Full tiny Docker rehearsal passed in 80.93 seconds: 3+3 contributions,
  removal and signed cleanup, two real future beacons, replay/public proof,
  one signed audit, operational evidence and final release signing/verification.
  Wrong signer ID was rejected. Intervening public exchanges use local fixtures;
  this remains distinct from a no-assistance, all-role complete journey.
- The tested runtime was built from clean Relay `c2b02bc`; subsequent changes
  corrected test fixtures and documentation, not executable code. Online image:
  `sha256:073b9bd1e5485c1efd7e0f92308c28e7628f4515cb9e9f43002979a9e23f01af`.
  Offline image:
  `sha256:d69ef649bd246cbbfa4cc8bd5934f0f847b854e5b710abf5331609dbaf73d333`.
  Both use the pinned proof-tool release identified above. Its checksum and
  protected-main attestation were verified; the real binary-pairing test passed.
- Production decision exchanges have catalog/order coverage; a tiny rehearsal
  does not exercise a production GO decision. Live cloud permissions are not
  changed or retested by these local-only guidance changes.

## Using local code with an existing ceremony

Current `start.sh` pins an installed launcher. A normal local rebuild does not
change that script. Preparation/open commands also check the launcher's source
commit against the saved release. `-tags relaylocal` enables the separate local
test helper; it does not disable this release-match check.

Do not overwrite a released executable, forge its source-commit identity or
edit signed records to make a local build appear approved. Test development
code in a separate rehearsal workspace. An explicit development-resume path
would need to preserve original state and runtime pins and clearly identify
the unapproved launcher; that path is not provided by this audit.
