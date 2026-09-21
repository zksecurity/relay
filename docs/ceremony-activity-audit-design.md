# Ceremony activity audit command proposal

Status: independently reviewed design; commands below are proposed, not implemented.

## Purpose

Export a reviewable account of recorded ceremony activity across coordinator,
participant, and offline release-signer machines. Never describe the result as a
complete record of every host action. Shell commands outside Relay, activity
before recording, and events removed by an operator cannot be reconstructed.

## Commands

```
relay audit export --work ROLE_WORK --out FRESH_DIRECTORY
relay audit combine --input COORDINATOR_EXPORT --input PARTICIPANT_1_EXPORT --input PARTICIPANT_2_EXPORT --input SIGNER_EXPORT --out FRESH_DIRECTORY
```

Export is read-only with respect to ceremony state, local by default, and never
needs a signing key or AWS credential. It creates a readable Markdown report,
structured JSON, and an inventory of exact public evidence hashes. Files move
between machines manually, including the offline signer's public export.
An explicit verification step should use the independently trusted coordinator
key and the exact approved proof-tool runtime, following existing Relay trust
validation; a report must not label unverified input as authenticated.

## Evidence and coverage

Keep three distinct levels visible:

1. Authenticated protocol events: signed definition, enrollment, contribution
   acceptance, closure, beacon, phase transition, release review and acceptance.
   Link each event to exact evidence references and signed causal predecessors.
2. Local execution observations: role, approved release identity, operation ID,
   stable allowlisted action ID, start/end time, result and fixed error category.
   These are unauthenticated host observations. Success does not mean acceptance,
   proof of erasure, independence, or production approval.
3. Verification results and coverage: exact checked checkpoint, signature-check
   depth, replay results only when actually performed, available evidence,
   missing/unbundled historical payloads, absent role exports and interrupted
   operations. Offline export cannot assert global freshness.

Current diagnostics keep only 100 events. V4 recovery journals retain up to 8192
operations with execution times, but contain sensitive paths and command details.
Use a strict sanitized projection of those journals, never copy the journal or
workspace wholesale. Existing workspaces must be marked partial. A current public
snapshot is not necessarily a self-contained historical replay archive.

## Recording before the four-machine ceremony

Add stable action IDs and durable start/completion recording for uncovered guided
and direct CLI actions. Reuse journal operation IDs and recovery semantics rather
than creating another execution state machine. Recording must begin before setup
if setup is to appear in the report. Document scope explicitly; no shell history,
raw terminal output, environment values, prompts or secret inputs are collected.

A logging failure after an operation must not repeat the operation. Preserve its
result and expose the recording gap. When recording is required, a failed start
record prevents a new side effect. Partial final records remain visible as gaps.
Local sequences aid ordering; clocks do not establish cross-host causality.
Hash chaining can detect accidental edits, but does not prove completeness against
an operator controlling the machine.

## Export and combination safety

Capture a consistent journal boundary under the existing workspace lock; report a
busy workspace instead of reading torn state. Use fresh output locations, bounded
strict parsers and allowlisted fields. Reject symlinks and traversal. Never copy
keys, profiles, credentials, grants, raw commands, mounts or arbitrary error text.

Combine only matching ceremony/definition identities. Preserve provenance for each
role export, deduplicate exact records, expose conflicting observations, and use
signed dependencies for protocol ordering. Aggregation does not authenticate a
local observation or turn an absent report into evidence of inactivity.

## Implementation and acceptance

First implement export from existing journals and authenticated protocol evidence,
with honest partial-coverage reporting. Add durable instrumentation before the
four-machine ceremony, then combine those role exports into a single report.

Test secret canaries in unexported journal fields; malformed/oversized input;
symlinks/traversal; interrupted records; concurrent action/export; action failure
versus recording failure; repeated and conflicting imports; mixed ceremonies;
missing historical payloads; and legacy workspaces with truncated diagnostics.
Run a complete tiny ceremony and compare the resulting report with independently
verified protocol records before using this reporting for production.

Tessera compatibility: no shared setup contract changes are proposed.
