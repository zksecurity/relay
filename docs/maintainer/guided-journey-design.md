# Guided ceremony journey — agreed design

Status: agreed design, not a description of the released UI. Updated 2026-09-08.
Implementation is in progress. Local changes cover enrollment confirmation,
numbered prompts, authenticated roster collection and timing, production-decision
applicability, scheduled-turn checks, storage preparation, and R2 credential handling.
The named-action overview, cross-area navigation, per-head mirror receipt matching,
and file-bound progress invalidation are now implemented locally. Local readiness
labels cover each recipe's inputs; signed schedules still govern coordinator turns.
Public directory/output snapshots and fresh evidence downloads are implemented.
All-role AWS evidence transport passed across separate test runs; final
released-pair validation remains pending approval, merge and automatic release.
Live R2 infrastructure,
grant scope and real expiry validation passed locally; no release approval is implied.

## Entry point and navigation

Each role keeps one `start.sh`, reopening its saved ceremony and release.
Combine preparation, enrollment and ceremony work into one resumable journey.
Use explicit action names; no generic Continue or Advanced for choosing work.
Reserve Advanced settings for technical configuration, never verification bypass.

```text
RELAY | COORDINATOR | release-test
------------------------------------------------------------
NEXT REQUIRED ACTION
  Review and sign your coordinator enrollment
  Ready. Required operational evidence for this ceremony.

1) Review and sign my enrollment
2) Show other available actions
3) Review completed steps
4) Show all steps and requirements
0) Save and exit
------------------------------------------------------------
Choose [1]:
```

Enter opens the named action, never silently signs, initializes or uploads.
Consequential operations retain separate explicit confirmation and exact details.
Use plain ASCII, readable without color; number only selectable actions.
Use `1) Label` consistently in every CLI menu, with `0) Save and exit` or
`0) Cancel` according to the actual behavior. Align numbers on the left.
Indent descriptions beneath their label; separate described options with blank
lines. Use `Choose [1]:` only for a safe navigation default. Requirement labels
follow the action name where useful. Do not use bare `1 Label` numbering.
Hide inapplicable tasks by default; Show all steps explains each omission.
Required tasks awaiting prerequisites remain visible with the missing item/owner.
Recommend one ready action while allowing other ready work in any valid order.

## Structured prompts and handoffs

Use numbered choices by default, not mandatory narrative reports such as
"Record what you checked or who you handed this to." Reserve free text for
actual disclosures, unusual incidents and optional notes; never request secrets.
Keep necessary factual inputs (file paths, locations, actual observation times)
explicit, prefilling only facts the tool can safely establish.
Split compound handoffs into specific questions and independently checked tasks.
For enrollment collection, show each required identity's status: Missing,
Received but unverified, Verified, or Needs attention. Derive the expected list
from authenticated assignments and applicable enrollment requirements, including
witnesses/mirrors where required; flag unresolved assignments rather than omit them.
Offer Import an enrollment, Show what to request, and Add an optional note.
Verify signatures and ceremony/role bindings instead of asking users to narrate
checks or mark the entire enrollment collection complete.
For human-only actions ask a specific question, e.g. "Have you shared the exact
signed definition with everyone assigned?" Choices: Yes through our agreed
channel, or Not yet. Record actor, time and artifact binding automatically as
"Sharing reported by coordinator," never verified delivery or recipient review.
Do not preselect affirmative human claims or infer them from earlier actions.
Tests must distinguish human reports from verified evidence and ensure ordinary
handoffs need no mandatory prose; notes cannot bypass missing or invalid evidence.

## Task model and evidence

- Requirement: Required, Optional, or Not applicable; always explain why.
- Requirement source: authenticated ceremony policy, technical dependency, or
  Relay operating procedure. Recommendations are not cryptographic necessities.
- Status: Ready, Waiting, Needs attention, or Completed with a scoped result.
- Define prerequisites, applicability, outputs, verification, repeat scope,
  human confirmation, deadlines and recovery behavior for each stable task ID.
- Distinguish Signature verified, Upload completed, Handoff reported, and
  Command completed; output verification pending. A click is not proof.
- Store verification time, verifier and artifact bindings. Revalidate relevant
  evidence before consequential actions; invalidate dependent readiness on change.
- Say when only local state was checked; never imply global freshness.
- Unknown applicability stays unresolved/visible, not silently Not applicable.
- Track repeated work by ceremony, role/identity, phase and exact candidate/head.
  One accepted contribution or mirror receipt cannot complete the entire stage.

## Complete ceremony coverage

| Role | Journey and required handoffs |
| --- | --- |
| Coordinator | Review basics/identities/policy/software → select and check storage → initialize and verify → enrollments and ceremony-specific storage checks/publication → Phase 1 turns/closure/beacon/seal → Phase 2 initialization/turns/closure/beacon → finalization/public proof → audits and operational evidence → final signing/verification/authorization → publication and archive. |
| Participant | Prepare/reuse identity → authenticate assignment and applicable enrollment/profile prerequisites → wait for turn → contribute/confirm cleanup/upload → verify acceptance → repeat for assigned phases → retain public evidence. |
| Witness | Prepare/enroll → prepare observation access → observe actual closure in time → review/sign receipt offline → submit; repeat for required phases. |
| Mirror | Prepare/enroll → synchronize/verify/retain required heads → prepare/sign/submit receipts for each required head → maintain retention. |
| Auditor | Prepare/enroll → acquire exact candidate/transcript → replay/audit/sign/submit → accountable production decision when applicable → retain evidence. |
| Final signer | Preload software → enroll → receive candidate/audits/evidence → disconnect → verify/sign/verify output → public-file handoff and applicable production decision. |
| Upload station | Prepare access → receive signed public output → verify/upload → confirm acceptance; never hold signing keys or create its own signing enrollment. |

Independent preparation tasks can proceed together: storage need not wait for
enrollment. Enforce actual prerequisites, not the order of this summary.
For each participant turn show grant, submission and verified acceptance separately.
Meeting a minimum never silently removes remaining scheduled participants.
Production decision requirements follow the applicable authenticated policy;
they are not universally Optional. Tiny rehearsals mark them Not applicable.
External tasks (public proof, beacon-relay evidence, observations, storage admin)
show who supplies what, where public files belong, and how they are checked.

## Storage readiness before initialization

The approved [R2 helper design](r2-helper-design.md) specifies credential import,
verification and Docker delivery; it is not tied to any password manager.
The standard guided flow requires storage readiness before offering initialization.
Label this a Relay operating prerequisite, not a cryptographic requirement.
Offer Use existing storage, Set up storage in my cloud account, or Import
administrator settings. Discover saved resources where possible, show the selected
account/buckets/origin, and obtain confirmation before attaching them to a ceremony.
Never silently reuse another ceremony's publication location or overwrite objects.
Check credential access, published HTTPS access and inbox privacy before
initialization. Validate required write/scope capabilities, not just bucket
existence or read access. Explain and obtain consent for temporary probe writes;
remove probes where possible and report cleanup failures. Resource creation or
billable changes need explicit approval; do not print credentials.
Split infrastructure preflight from checks requiring a signed ceremony definition
or enrollments. Record which checks passed and which remain pending; do not require
post-initialization artifacts to satisfy the pre-initialization gate.
After initialization, complete ceremony-specific storage/grant checks and recheck
relevant access before publication. Save the configuration automatically and offer
Publish initial Phase 1 state; users should not navigate menus or supply generated
configuration paths. Missing/invalid configuration blocks the action before RUN.
Offer an explicit Prepare offline without storage path for deliberate offline
initialization. Record that choice without claiming storage readiness; publication
and participant grants remain blocked until all applicable storage checks pass.
Existing initialized ceremonies missing storage resume at storage setup, never
repeat initialization. Configuration/credential changes invalidate affected checks.
Test missing storage, insufficient permissions, public inboxes, probe failures,
explicit offline preparation, existing-ceremony recovery and successful publication.

## Review, deadlines and recovery

Show readable signing summaries: ceremony, role, identity, fingerprint, disclosure
and what the signature asserts. Exact bytes remain available under Details;
review/signature binding and cryptographic checks still use those exact bytes.
Offer an editable same-person/same-Mac rehearsal disclosure, never assume it true.
Do not claim software verifies independent people, observations or physical erasure.
Ordinary enrollment uses a network-disabled signing container and REVIEWED;
host disconnection is an extra precaution, subject to stricter agreed procedures.
Final signers retain disconnected-host enrollment/signing confirmation.
Witness/mirror observation-receipt offline procedures are unchanged by that choice.
Show committed beacon times and witness deadlines with explicit time zones.
An expired observation window requires investigation, not backdating or blind retry.
After interruption follow the [crash-safe operation design](crash-recovery-design.md).
Relay automatically verifies or continues the exact operation when safe; it does
not show a generic recovery menu or ask for an investigation narrative. Preserve
artifacts, resume existing participant candidates, and never infer success.
Changed evidence, failed verification and missing requirements cannot be bypassed.

## Delivery and acceptance

1. Add shared task/status/evidence model and ASCII renderer with unit/menu tests.
2. Unify coordinator preparation/workflow; model repeated turns and policy gates.
3. Integrate every other role, explicit handoffs, deadlines and recovery.
4. Test all roles interactively, stale/conflicting/missing inputs, interruptions,
   repeated receipts, role/mode applicability, and the full tiny Docker ceremony.

Reuse existing Relay/proof-tool verifiers; identify missing checks explicitly.
Keep installed releases pinned. Validate any migration of saved task/history
bindings, or direct users to their original release; never silently rewrite state.
Update short operator guides when behavior ships, not ahead of implementation.
Success: every screen explains what to do next, what else is ready, what is
waiting, why it is required, and exactly what has actually been verified.

## Design readiness

The user-facing flow is agreed and ready for implementation planning; no further
broad UX redesign is required. Before coding the affected components, review
session-only secret delivery/cleanup, pre-initialization probe isolation, and
compatibility of existing saved workflows. Resolve these with explicit technical
contracts and tests; return to the user only if a product/security choice changes.
Then exercise the implementation through all-role walkthroughs and failure tests.
Design approval does not mean implementation, release or security audit completed.

## Terminal presentation

Guided menus use bold headings and prompts, green success messages, amber
missing-input notices, red stopped-action messages, and muted supporting text.
The wording remains authoritative: color never means a ceremony is verified or
complete. Commands, machine-readable output and child-process output are not
wrapped or rewritten.

Styling is enabled only for detected terminals with a nonempty, non-`dumb`
`TERM`. Set `NO_COLOR` (even to an empty value) to disable it. Redirected output
remains plain. No new terminal library is required; detection uses `/bin/stty`
on the supported Linux/macOS hosts, and falls back to plain text if unavailable.

To exercise real terminal detection separately from Go's captured test output:

```sh
go test -c -o /tmp/relay-terminal-style.test ./cmd/relay
env -u NO_COLOR TERM=xterm-256color RELAY_STYLE_PTY_TEST=1 \
  /tmp/relay-terminal-style.test -test.run '^TestTerminalStylePTY$' -test.v
```

Run that last command in a terminal. The normal test suite covers redirected
output and environment overrides; it skips the opt-in real-terminal check.
