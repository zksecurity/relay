# Guided role workflow

One resumable menu takes you through your role's work and handoffs to others.
It does not operate their machines or approve things for them.

## Open it

Coordinators: after preparation verifies the definition, choose
**Open ceremony operations and progress**. Initialization is not repeated.

Other roles: follow [onboarding](role-onboarding.md), then choose
**Open ceremony operations and progress**. Reopen the same installer-created
`start.sh` to return. Each person uses their own folders and key.
A participant's saved settings reference the first-phase Docker profile;
the guide asks for the matching second-phase profile later.

Existing one-command actions still open with `ceremony open`. Keep them for
recovery; choose a fresh alias for shared workflow settings.

## What you see

- Your current stage and numbered actions, with remembered input values.
- Labeled inputs and local paths before you approve with `RUN`; enter
  `DETAILS` to inspect the exact command.
- A suggested next step based on saved progress, not authorization to act.
- Separate human handoffs, recorded as **reported**, not verified.
- Coordinator enrollment collection lists the authenticated roster and verifies
  each imported public enrollment, signature and disclosure. Observer minimums
  are shown separately; a higher agreed witness quorum still needs review.
- **Save and exit**; reopening the same guide resumes your progress.
- **Review/recover earlier stage** for inspecting earlier results.

Chain prompts discover and authenticate the most advanced consistent **local**
head, rejecting forks and rollback from a previously seen head. Import or sync
the current transcript first: discovery cannot prove that nobody has published
a newer head elsewhere.

Enter local paths inside your saved work/trust/key folders or the displayed
Docker paths. Defaults display local paths when a mount is known; the guide
maps them into Docker. Stage files in these
dedicated folders first; never put another role's keys in them.

## What stays independent

Participants still use the host supervisor and disposable offline contributor.
Cleanup confirmation remains separate, after measured container removal.
Offline release signing remains network-isolated; disconnect the host too.

The guide runs existing verification, contribution, acceptance, phase-transition,
audit and release commands. These checks—not menu progress—establish validity.
A tiny rehearsal cannot satisfy the production GO/NO-GO evidence gates.

Witness and mirror receipt signing uses a separately prepared offline image.
Review your exact record, disconnect the host, and confirm your own observations.
Signing is bound to the displayed bytes. Online observer images receive no keys.

Storage provisioning, public identity exchange, other operational-record authoring,
public-proof generation and actual observations remain
explicit external tasks. The guide explains their handoffs and verifies
returned artifacts where commands exist. It never fabricates observations,
independence, signatures or approval.

## Recovery

An interrupted action is uncertain, even if it printed success before stopping.
Preserve outputs and authenticate the current state before **REVIEWED RETRY**.
Retries retain the exact command. After investigation, you can record the
finding and prepare a corrected action; that does not mark the task complete.
New independent output files get an unused suggested filename; successful
output locations are remembered for later steps. Receipt exports also get fresh
directories, carried forward to signing and upload. Existing files are never
overwritten. Protocol-layout directories and uncertain retries still require
review rather than automatic relocation.

For non-participant actions that actually completed before interruption, first
verify the exact output with the appropriate tool. You can then record that
external verification as a **reported** recovery, preserving the failed attempt.
This is not a waiver of any protocol check. Do not use it to hide a real failure.

Participants: preserve the public candidate and use `resume-candidate` with a
replacement grant if needed. Do not recompute after an upload interruption.

The workflow pins its launcher settings, recipe version and selected public
ceremony/trust inputs. A changed ceremony or incompatible recipe is a stop,
not permission to reuse old progress. Never edit its state to skip a check.
