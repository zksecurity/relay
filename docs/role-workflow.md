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

- A named next action. **View this area's actions and requirements** shows the
  complete authored task order for the current area.
- Labeled inputs and local paths before you approve with `RUN`; enter
  `DETAILS` to inspect the exact command.
- A suggested next step based on saved progress, not authorization to act.
- Required/optional labels and missing input paths before opening an action.
  **Ready to review inputs** means local inputs are available, not that their
  signatures or the whole ceremony have been verified. A waiting action can be
  opened to select the correct files; missing inputs still block execution.
- Separate human handoffs, recorded as **reported**, not verified.
- Coordinator enrollment collection lists the authenticated roster and verifies
  each imported public enrollment, signature and disclosure. Observer minimums
  are shown separately; a higher agreed witness quorum still needs review.
- **Save and exit**; reopening the same guide resumes your progress.
- **Ceremony map** opens another area for independent preparation or recovery;
  **Back** returns to the prior local view. Navigation does not complete work
  or waive verification requirements. See the [ceremony flow map](ceremony-flow.md)
  for the role lanes and handoffs across the whole ceremony.

Chain prompts discover and authenticate the most advanced consistent **local**
head, rejecting forks and rollback from a previously seen head. Import or sync
the current transcript first: discovery cannot prove that nobody has published
a newer head elsewhere.
Mirrors can select an authenticated earlier contribution when preparing a receipt.
Finishing a mirror phase requires matching signed/uploaded receipts for every
accepted contribution in the closed local phase—not merely one successful receipt.

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

Witness and mirror receipt signing uses a separately prepared network-disabled
image. Review your exact record and confirm your own observations. Disconnecting
the host is an optional extra precaution unless ceremony policy requires it.
Signing is bound to the displayed bytes. Online observer images receive no keys.

Storage provisioning, public identity exchange, other operational-record authoring,
public-proof generation and actual observations remain
explicit external tasks. The guide explains their handoffs and verifies
returned artifacts where commands exist. It never fabricates observations,
independence, signatures or approval.

## Recovery

Public output files and evidence folders are tracked too. Changes, deletions,
or extra files in an immutable bundle require review. Transcripts may grow with
new signed heads, but previously retained files must not change or disappear.
Private keys and temporary grants are not included in these public snapshots.

On restart, Relay checks the previous action. It automatically closes a saved
pre-launch action because no command ran, repeats an exact read-only check, or
continues a stable immutable upload. A retained participant candidate resumes
without recomputation. A complete matching grant file can be adopted without
issuing another credential. Any other uncertain mutation stops with the specific
missing fact; there is no generic retry, investigation form, or “mark complete.”
New independent output files get an unused suggested filename; successful
output locations are remembered for later steps. Receipt exports also get fresh
directories, carried forward to signing and upload. Existing files are never
overwritten. Protocol-layout directories and uncertain retries still require
review rather than automatic relocation.

For a state-changing action Relay cannot reconcile, preserve its output and stop
at the displayed blocker. There is no manual “mark complete” or generic retry.
Changed or missing bound inputs must be restored from authenticated sources and
reverified through the same workflow.

Participants: preserve the public candidate and use `resume-candidate` with a
replacement grant if needed. Do not recompute after an upload interruption.

The workflow pins its launcher settings, recipe version and selected public
ceremony/trust inputs. A changed ceremony or incompatible recipe is a stop,
not permission to reuse old progress. Never edit its state to skip a check.
