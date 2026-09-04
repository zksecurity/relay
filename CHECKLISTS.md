# Ceremony checklist index

Use one checklist for every role assignment and retain its secret-free evidence
with the ceremony record. The runbooks remain authoritative; the checklists are
execution aids, and [CEREMONY_COMMANDS.md](CEREMONY_COMMANDS.md) contains the
copy-oriented commands.

## Checklist labels

- **MANUAL — PLATFORM TODO** — the check is mechanical, but the coordination
  platform does not yet perform and record it through a reviewed integration.
  Until then, a named operator must run the cited procedure and attach its
  secret-free output.
- **HUMAN** — a person must verify or attest to something software cannot know,
  such as independent control, physical custody, or an out-of-band agreement.
- **AUTHORIZE** — software has prepared and verified an exact action, but a
  named person must explicitly permit the signature or state transition.
- **STOP** — pause and investigate; do not work around the failed invariant.

Automated controls are not checklist items. The platform presents them as
non-interactive `passed`, `failed`, or `pending` system status, with blocking
failures, remediation, and links to secret-free evidence. The requirements are
maintained separately in the
[automation control matrix](AUTOMATION_CONTROL_MATRIX.md).

Rendering a mechanical item on a dashboard does not make it automatic. The
platform must execute or consume the authoritative check, preserve its exact
inputs and result, and emit reviewable evidence before a **MANUAL — PLATFORM
TODO** item can leave the human checklist and move into that matrix.

## Role checklists

| Assignment | Checklist | Scope |
| --- | --- | --- |
| Coordinator | [Coordinator checklist](COORDINATOR_CHECKLIST.md) | Roster, storage, grants, acceptance, phase transitions, evidence, release, and archive |
| Participant | [Participant lifecycle checklist](PARTICIPANT_CHECKLIST.md) and one [turn checklist](PARTICIPANT_TURN_CHECKLIST.md) per phase | Identity, native contribution, erasure, resumable upload, and acceptance |
| Public witness | [Public-witness checklist](PUBLIC_WITNESS_CHECKLIST.md) | Independent pre-beacon observation and signed witness receipt |
| Mirror operator | [Mirror-operator checklist](MIRROR_OPERATOR_CHECKLIST.md) | Independent transcript retention and signed mirror receipt |
| Auditor | [Auditor checklist](AUDITOR_CHECKLIST.md) | Independent source acquisition, full replay, and signed audit |
| Release signer | [Release-signer checklist](RELEASE_SIGNER_CHECKLIST.md) | Offline review and signature of the audited release |
| Production-decision signer | [Decision-signer checklist](DECISION_SIGNER_CHECKLIST.md) | GO/NO-GO review and signature by each accountable identity |
| Online evidence upload station | [Upload-station checklist](UPLOAD_STATION_CHECKLIST.md) | Transport of already signed evidence without custody of signing keys |

The production-decision signer is an action role performed by an eligible
coordinator, auditor, or release-signer identity; it is not a new ceremony
identity. The upload station is an operational separation, not a cryptographic
signer. It uses the applicable signer enrollment and a temporary scoped grant
but must never receive the signer's private key.
