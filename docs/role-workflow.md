# Guided role workflow

One resumable menu takes you through your role's work and handoffs to others.
It does not operate their machines or approve things for them.

## Open it

Coordinators: after preparation verifies the definition, choose
**12 — Continue the guided coordinator workflow**. Initialization is not repeated.

Other roles: follow [onboarding](role-onboarding.md), then choose
**Continue the ceremony workflow**. Reopen the same installer-created
`start.sh` to return. Each person uses their own folders and key.
A participant's saved settings reference the first-phase Docker profile;
the guide asks for the matching second-phase profile later.

Existing one-command actions still open with `ceremony open`. Keep them for
recovery; choose a fresh alias for shared workflow settings.

## What you see

- Your current stage and numbered actions, with remembered input values.
- The exact command before you approve it with `RUN`.
- Separate human handoffs, recorded as **reported**, not verified.
- **Save and exit**; reopening the same guide resumes your progress.
- **Review/recover earlier stage** for inspecting earlier results.

Enter local paths inside your saved work/trust/key folders or the displayed
Docker paths. The guide maps local paths into Docker. Stage files in these
dedicated folders first; never put another role's keys in them.

## What stays independent

Participants still use the host supervisor and disposable offline contributor.
Cleanup confirmation remains separate, after measured container removal.
Offline release signing remains network-isolated; disconnect the host too.

The guide runs existing verification, contribution, acceptance, phase-transition,
audit and release commands. These checks—not menu progress—establish validity.
A tiny rehearsal cannot satisfy the production GO/NO-GO evidence gates.

Storage provisioning, public identity exchange, operational-record authoring, offline
raw receipt signing, public-proof generation and actual observations remain
explicit external tasks. The guide explains their handoffs and verifies
returned artifacts where commands exist. It never fabricates observations,
independence, signatures or approval.

## Recovery

An interrupted action is uncertain, even if it printed success before stopping.
Preserve outputs and authenticate the current state before **REVIEWED RETRY**.
Retries retain the exact command. After investigation, you can record the
finding and prepare a corrected action; that does not mark the task complete.
Use fresh output paths where required.

For non-participant actions that actually completed before interruption, first
verify the exact output with the appropriate tool. You can then record that
external verification as a **reported** recovery, preserving the failed attempt.
This is not a waiver of any protocol check. Do not use it to hide a real failure.

Participants: preserve the public candidate and use `resume-candidate` with a
replacement grant if needed. Do not recompute after an upload interruption.

The workflow pins its launcher settings, recipe version and selected public
ceremony/trust inputs. A changed ceremony or incompatible recipe is a stop,
not permission to reuse old progress. Never edit its state to skip a check.
