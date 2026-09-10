# Ceremony automation control matrix

This document is for platform implementers and auditors. It records checks
formerly tagged **AUTO NOW** and performed by Relay, proof-tool, or a reviewed
storage adapter. Automated checks must not appear as operator checkboxes: the
software reports `passed`, `failed`, or `pending`, and a person cannot override
that result.

The [role guides](../README.md) combine today's actions, human decisions,
commands, and recovery. Future automation belongs here, not in operator labels.

## Status and evidence contract

For every applicable control, the coordination platform should display:

- the control ID and `passed`, `failed`, or `pending` status;
- the authenticated ceremony, role, phase, identity, and relevant object IDs;
- the producing tool and approved tool-identity receipt;
- completion time and a digest or location for the secret-free evidence;
- a specific failure reason and reviewed remediation when status is `failed`;
- the dependency keeping a `pending` control from running.

A failed or pending blocking control disables the dependent action. The UI may
link to evidence or rerun the authoritative command, but it must not offer a
manual pass, override checkbox, or editable copy of the result. Full receipts
remain append-only evidence even when the default UI shows only a summary.

## Shared controls

| ID | Stage | Authoritative behavior | Required result and evidence |
| --- | --- | --- | --- |
| `SYS-TOOL-01` | Tool setup | Guided preparation authenticates release downloads and records actual tool paths/hashes against pinned release inputs. Legacy kit verification remains separate. | Local measured-tool receipt; ceremony actions refuse mismatched effective tools. This record is not independent provenance or a compatibility-test claim. |
| `SYS-PROFILE-01` | Role initialization | `relay ceremony init-config` authenticates the signed definition, coordinator trust key, role enrollment or participant key, ceremony, phase, public source, and approved tools. | Passing assignment receipt bound to the exact identity and role; participant receipts also include key ID, fingerprint, and both frozen positions. |
| `SYS-PROFILE-02` | Persistent configuration | Relay creates profiles with mode `0600` containing validated public metadata and approved paths. | Reject private-key bytes, cloud credentials, or temporary grants in a persistent profile. |
| `SYS-SUBMIT-01` | Evidence upload | Relay authenticates the grant's ceremony, role, identity, prefix, expiry, and minimum-remaining window; rejects unsafe inputs; uploads `manifest.json` last. | Passing transport receipt and manifest key. Upload success is not semantic acceptance. |

## Coordinator controls

| ID | Stage | Authoritative behavior | Required result and evidence |
| --- | --- | --- | --- |
| `COORD-ROSTER-01` | Roster draft | Validate at least one ordered participant, at least one auditor, and one distinct release signer. Reject duplicate identity IDs, key IDs, and public keys and prohibited role overlap. | Passing roster-validation report. |
| `COORD-ROSTER-02` | Roster export | Store only public identity fields and export the exact canonical roster and digest for native review and signing. | Canonical roster digest; a browser draft never becomes the frozen definition by itself. |
| `COORD-FREEZE-01` | Initialization | Create the narrow ceremony directory layout, run authenticated proof-tool initialization, and bind the signed definition to the canonical roster digest. | Initialization receipt and signed definition digest. |
| `COORD-FREEZE-02` | Definition verification | Verify definition and detached signature, ceremony ID and mode, circuit and constraint-system digests, software binding, coordinator identity, participant order, auditors, release signer, and beacon policy. | Passing definition-verification receipt. |
| `COORD-ENROLL-01` | Role enrollment | Authenticate signed witness, mirror, auditor, and other grant-recipient enrollments. | Passing enrollment receipts bound to the frozen definition. |
| `COORD-STORAGE-01` | Public/inbox separation | Verify anonymous HTTPS reads from the published origin and reject anonymous or public-domain access to the private inbox. | Provider-specific public-read and inbox-denial probe evidence. |
| `COORD-STORAGE-02` | Storage configuration | `relay coordinator configure-storage` verifies public read/write/delete, public-origin freshness, inbox privacy, trusted coordinator key, cleanup of probes, mode `0600`, and absence of persistent credentials. | Passing storage receipt and secret-free configuration digest. |
| `COORD-TURN-01` | Grant issuance | Generate a fresh mode-`0600`, identity-scoped grant bound to the exact ceremony, phase, participant, and object prefix. | Grant metadata receipt excluding credential contents. |
| `COORD-TURN-02` | Candidate discovery | Accept only schema-valid manifest-last submissions for the configured ceremony and report their claimed role, phase, index, attempt, and object key. | Discovery receipt; `ready` means ready for review, not cryptographically valid. |
| `COORD-TURN-03` | Candidate acceptance | In a fresh directory, `relay coordinator accept --verify-publish` verifies scope, every file hash, scheduled identity, current head, contribution, signed erasure record, chain transition, and timestamp ordering before signing and publishing the next head. | Passing native acceptance receipt; `accepted_at` is strictly after signed `destroyed_at`. |
| `COORD-RESUME-01` | Upload recovery | Require an unchanged authenticated head; re-hash and rebind every saved file; compare existing remote bytes; upload the manifest last; reject stale heads and conflicting bytes. | Passing resumable-upload receipt or a blocking failure. |
| `COORD-CLOSE-01` | Phase closure | Prove each frozen participant was accepted exactly once and in order, publish the closed chain, and verify the public pointer and immutable artifacts. | Passing closure and publication receipts. |
| `COORD-BEACON-01` | Witness and beacon | Verify witness identities, signatures, observed head, round, and lead; fetch only the pinned future beacon; verify the seal transition. | Passing witness-quorum, beacon, and seal receipts. |
| `COORD-PHASE2-01` | Phase transition | Verify authenticated Phase 1 closure, seal, and Phase 2 initialization before any Phase 2 grant; after Phase 2, require both complete chains and beacon transitions. | Passing phase-transition or completion receipt. |
| `COORD-EVIDENCE-01` | Operational evidence | Authenticate evidence enrollments, constrain grants, discover manifest-last submissions, and verify signed mirror receipts against exact heads, file sets, location digests, and identities. | Passing evidence inventory and verification receipts. |
| `COORD-RELEASE-01` | Release decision | Verify uploaded release and decision records, one coherent ceremony evidence set, required artifacts and signatures, and valid production labeling. | Passing release/decision verification receipt; reject rehearsal or incomplete evidence as production. |

## Participant controls

| ID | Stage | Authoritative behavior | Required result and evidence |
| --- | --- | --- | --- |
| `PART-STATUS-01` | Before computation | `relay participant status` authenticates the public head and reports the expected ceremony, phase, index, and next identity without requiring a grant. | Passing status receipt naming the participant as next. |
| `PART-RUN-01` | Contribution | `relay participant run` repeats the turn check before expensive work and authenticates all required chain inputs. For Docker execution it resolves and pins a local daemon endpoint, records daemon security options, and force-removes and verifies the exact container before returning from SIGINT or SIGTERM. For Phase 2 it also verifies Phase 1 closure, beacon, seal, and Phase 2 initialization before sampling contribution randomness. | Passing native contribution and verification receipts; Docker lifecycle evidence names the exact daemon endpoint, daemon ID, user-namespace status, and removed container ID. |
| `PART-SUBMIT-01` | Submission | Relay reports successful candidate submission only after required objects and manifest-last upload complete. | Submission receipt binding attempt, manifest key, public candidate directory, signed erasure time, and starting head. |
| `PART-RESUME-01` | Upload recovery | Relay verifies an unchanged head, re-hashes and rebinds saved files, compares remote bytes, and uploads the manifest last. | Passing resume receipt; stale head or conflicting bytes is a blocking failure. |
| `PART-ACCEPT-01` | Acceptance | `relay participant status` independently authenticates the new public head and identifies accepted position, next position, or phase closure. | Acceptance-status receipt bound to the submitted candidate. |

## Witness, mirror, and auditor controls

| ID | Role | Authoritative behavior | Required result and evidence |
| --- | --- | --- | --- |
| `WITNESS-OBSERVE-01` | Public witness | `relay witness run` detects the closure claim, authenticates the signed chain, and reports accepted index and digest. `mpc-ceremony ops prepare-public-witness-receipt` verifies the definition, signed closure, schedule, enrollment, location, and claimed observation time. | Prepared canonical signing bytes; software validates inputs but does not make the witness's real-world observation claim. |
| `WITNESS-SIGN-01` | Public witness | `mpc-ceremony ops import-signature` and `ops verify` authenticate the detached signature and related evidence. | Passing signed witness receipt. |
| `MIRROR-SYNC-01` | Mirror | `relay mirror run` authenticates the current chain and newly fetched digest-pinned files without overwriting existing bytes. | Sync receipt; the downstream proof-tool step must re-hash the complete retained set. |
| `MIRROR-SIGN-01` | Mirror | `relay mirror receipt` drafts the exact retention claim; `mpc-ceremony ops prepare-mirror-receipt` re-hashes its references and exports canonical bytes; import and verify authenticate the detached signature. | Passing signed mirror receipt bound to head, index, file set, location digest, and storage time. |
| `AUDIT-REPLAY-01` | Auditor | `relay auditor run` authenticates both chains and newly fetched files; `mpc-ceremony audit` independently compiles the circuit, replays both phases, reproduces outputs, verifies coherence, and signs only a passing report. | Passing signed audit report and complete transcript inventory. |

All three roles use `SYS-SUBMIT-01` when transporting their signed evidence.

## Release and production-decision controls

| ID | Role | Authoritative behavior | Required result and evidence |
| --- | --- | --- | --- |
| `RELEASE-ROLE-01` | Release signer | The signed definition identifies a distinct release signer and rejects prohibited overlap. | Passing assignment receipt. |
| `RELEASE-SIGN-01` | Release signer | `mpc-ceremony release sign` verifies the candidate, at least one enrolled auditor report, both phases, witness quorum, independent mirrors, beacon evidence, and ceremony coherence before loading the signing key. | Fresh signed release directory and verification receipt. |
| `RELEASE-VERIFY-01` | Release signer | `mpc-ceremony release verify` authenticates the completed release with the independently trusted release key and key ID. | Passing release-verification receipt. |
| `DECISION-PREPARE-01` | Decision signer | `mpc-ceremony decision prepare` strictly parses the draft, derives release and decision IDs, and verifies ceremony, production circuit, source, and role bindings. | Canonical decision digest and evidence-inventory digest. |
| `DECISION-SIGN-01` | Decision signer | For `GO`, `mpc-ceremony decision sign` hashes and semantically verifies the complete local evidence set before loading the signing key and rejects an identity or role mismatch. | Detached role signature over the exact canonical decision. |
| `DECISION-VERIFY-01` | Decision signer | `mpc-ceremony decision verify` validates each role signature, evidence digest, release/candidate/transcript coherence, and the complete `GO` threshold. | Passing production-decision verification receipt. |
