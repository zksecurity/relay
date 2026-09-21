# Updating Relay during an ongoing ceremony

Status: complete target design, revised after independent review. Implementation is
partial; no released source/target pair is enabled. This is not permission to
change a frozen ceremony's release fields manually.

## Promise and limits

When a compatible Relay bug blocks a ceremony, install a qualified update,
approve it for the affected role, and reopen the same `start.sh`. Keep identities,
contributions and accepted progress. Other roles need not update simultaneously.
No separate user-facing “guide version” or new ceremony is required.

This covers application fixes throughout setup, enrollment, both contribution
phases, beacon waiting, review, signing and publication. It does not promise that
every bug is repairable: corrupted or missing evidence, changed cryptography and
incompatible protocol changes can require a separate recovery procedure or a new
ceremony. An upgrade explains that boundary, not silently starts over.

Assumptions: honest operators/coordinator, trusted delivery service and local
host, one active workspace per role. One machine may operate multiple roles in
separate folders. No distributed failover or malicious-host protection is added.

## What changes

| Preserve exactly | Eligible for a reviewed compatible update |
| --- | --- |
| Signed definition, policy, identities, trust anchors, cryptographic artifact bytes | Host Relay application and guidance |
| Approved Proof-tool binaries and original contributor/signing images | Online Relay image, with unchanged approved Proof-tool bytes |
| Attempt/allocation IDs, accepted results, unresolved-operation meaning | Compatible transport and recovery code |
| Storage targets, access scope, required isolation and verification | Credential renewal for the same identity/target/scope |

The native participant supervisor is security-sensitive even with an unchanged
container. Updates must preserve isolation, signal cleanup, secret handling and
attestation ordering. Changes inside pinned signing/contributor images or to
Proof-tool itself are outside this application-update mechanism.

## Operator experience

1. Stop the affected role normally; retain every output. Export a redacted bug
   report if useful. No automatic update or repeated contribution occurs.
2. Install the exact compatible release supplied through the agreed channel.
3. Run `relay ceremony upgrade NAME --role ROLE --release role-images-COMMIT`.
   The command resolves saved folders; users do not edit profile JSON.
   Before a shared profile exists, also supply `--work ROLE_WORK` to locate
   the existing preparation draft. This does not create an identity or ceremony.
4. Relay checks release provenance, original ceremony bindings, current app
   selection, retained work and execution safety. Online roles authenticate
   backend state; offline signers use their verified frozen review package.
5. Show what changes, what stays fixed, any pending operation's handling,
   and whether the ceremony can continue. Ask once to activate.
6. Resume through the same `start.sh`. Normal signing, upload and cleanup
   confirmations remain; upgrade approval does not approve those actions.

An unsupported state shows its specific cause and the safe next action. No
“mark complete”, free-form investigation note or blanket “retry anyway” option.
Failed eligibility checks never change the active software selection.

## Role coverage

| Role | Update behavior |
| --- | --- |
| Coordinator | New host/online Relay; reconcile enrollment, grants, checkpoints, mathematical-review results and publication |
| Participant | New host Relay; original contributor/signing images; retain one computation per signed allocation and exact candidate |
| Release signer | New host Relay; original offline signing runtime; preserve reviewed bytes and offline procedure; upload uses only its separately approved transport context |
| Upload station | New host/online Relay; transfer exact signed package, no new signing authority |
| Auditor | New host/online Relay; existing verifier/signing runtime remains pinned; bind reports to the same reviewed files |
| Witness/mirror | New host/online Relay; preserve per-event/per-head duties and deadlines; do not invent missed observations |

Only roles enabled by the signed ceremony policy appear. Describing a role here
does not implement its currently missing ordinary storage-first journey. A
release cannot advertise upgrade support until that role's whole journey works.

## Supporting specifications

- [Compatibility and activation](ceremony-upgrade-contract.md): release authority,
  per-role software selection, repeated updates, offline use and Tessera.
- [Interrupted-work handling](ceremony-upgrade-recovery.md): exact classification,
  execution safety and stage-by-stage recovery without overwriting evidence.
- [Qualification and implementation](ceremony-upgrade-qualification.md): release
  tests, rollout gates and remaining code changes.

## Current implementation, not the target limit

The branch implements strict v2 authority, original-runtime validation, retained
work inventory, multi-hop atomic selection, preparation/operations/saved-action
resolution, and offline asset bundles. New named online actions pin their selected
image; existing actions and contribution/signing runtimes retain their pins.
Activation preserves the journals; normal recovery still verifies their outputs.
Custom start scripts are preserved, with an explicit resume command.

The connected upgrade paths include standalone drafts and initialized coordinator,
participant, auditor and release-signer profiles. Missing ordinary observer/
upload-station journeys, killed-parent recovery, and rollback remain unsupported.
These are implementation limits, not completed target-design features.
Both release upgrade policies are empty. Actual predecessor/candidate draft-resume
tests and a two-phase native update using local test storage pass. Live-provider,
online-image replacement, offline disconnected-machine and full failure-matrix
qualification remain required. No release pair is enabled.

The review closed inherited-work coverage across repeated updates, unsafe old
launcher reentry, non-circular release qualification, edited-script behavior and
update delivery to an already-offline signer. Review is not implementation testing.
