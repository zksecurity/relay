## What changed

This release combines the guided ceremony and recovery improvements previously
published in `d74604e` and `b461326`. Ceremony behavior is unchanged from `b461326`.

- Role onboarding recommends the next setup step. Ceremony operations follow the
  defined order, and manually selected actions cannot skip required predecessors.
- Coordinator and participant custody profiles retain the correct folders,
  approved Docker image, and platform. Compatible older profiles migrate with
  backups; ambiguous or conflicting profiles stop for review.
- Custody prompts fill the authenticated next participant and handoff direction.
  First-use exports create missing parent folders without overwriting an export.
- Menus explain prerequisites, separate actions from navigation, and show errors
  in red on supported terminals. Only final release signing requires disconnecting
  the host under the standard procedure.
- Recovery preserves operation identity, inputs, runtime, and outputs across
  interruptions. It can recover supported initialization, cleanup, grant, and
  upload cases without repeating a contribution or guessing uncertain completion.
- Uploads retain stable attempt IDs, verify existing immutable objects, and write
  the manifest last before notifying Tessera.
- Final release signing supports the documented one-auditor minimum. The pinned
  proof-tool release is `mpc-ci-7ba406f0a6066f10b668ae8c553ab45e897f9fe4`.
- Documentation includes ceremony-flow diagrams and the implemented recovery scope.

## Tessera compatibility

Setup contracts, ceremony data, and Tessera request fields are unchanged. Tessera
must provision this exact release before offering it for new ceremonies. Existing
ceremony pins are not automatically rewritten. This replacement has a new source
commit and newly attested release assets, so its release identity differs from
the two earlier publications.
