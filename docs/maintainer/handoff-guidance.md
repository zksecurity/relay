# Handoff guidance coverage

Human handoffs must explain the counterpart, named public outputs or requested
inputs, receiver staging and expected reply before asking for a report.
`flow_handoff_instructions.go` supplies this for every authored handoff task;
private grants keep their separate recipient/path/expiry display.

| Role | Transfers or requests covered |
|---|---|
| Coordinator | Assignments, storage, custody packet, witness evidence, audits, final signing, decision signatures and archive retention |
| Participant | Identity, input receipt, return packet/payload and acceptance request |
| Witness/mirror | Public signed receipt to the online uploader; submission notification |
| Auditor | Candidate/transcript acquisition, submission notification and decision signature |
| Final signer | Offline public package receipt, signed release and decision signature |
| Upload station | Signed release receipt and acceptance request |

Custody files come from the saved successful preparation/signing commands for
the exact phase/turn. Named payloads are checked against packet SHA-256/size,
and the displayed snapshot is compared with report bindings. Missing or changed
files block completion, but waiting and problem reporting remain available.
Receiver paths are staging instructions, not observations of another machine.

Other public locations follow saved command paths where available; otherwise
authored locations are guidance to confirm, not verified directory inventories.
External audit pairs, upload manifest locations and retention destinations
remain explicit exchanges. Never recommend copying an entire role workspace.
Directory completeness and signatures remain the downstream verifier's job.

Tests cover all authored handoff IDs, both custody phases, changed/missing
payloads, phase/turn separation, failed producers, custom paths, and import menu
defaults. This is not a full all-role ceremony test. Existing uncertain-action
recovery may run before the new handoff display on reopening an old attempt.
The opt-in `TestRetainedCustodyHandoffDisplay` also passed against an ongoing
rehearsal's retained outbound packet on 2026-09-14; it read public files without
changing the ceremony or performing a transfer.
