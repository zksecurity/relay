# Guided workflow: implementation review and test scope

This is a code-level self-review, not an independent security audit.

## Issues found and corrected

- Recipe defaults used `close.json` and `beacon.json`; the real tool writes
  `closure/record.json` and `beacon/record.json`. The Docker rehearsal exposed
  this; regression tests now check the layout.
- Explicit Phase 1 seal paths were not rewritten for a Phase 2 contributor.
  The Docker driver now maps them under the existing read-only transcript
  mount and rejects paths outside it. No additional host mount is exposed.
- Repeated audit flags shared one remembered default. Each prompt now has a
  separate index, so the two reports cannot silently collapse into one default.
- Repeating read-only verification was incorrectly treated like repeating a
  write. Verification/synchronization can now run again; identical completed
  write commands remain guarded.
- Failed commands could strand an operator with already-created outputs.
  Recovery retains the exact attempt, supports reviewed retries/corrected
  actions, and distinguishes externally reported verification from success
  actually returned by the command. Participants still use candidate resume.
- Saved commands are checked against compiled recipes before retry, rather
  than executed as arbitrary stored command lines. Shell fragments are not used.
- Progress now pins launcher settings, recipe contents and selected public
  ceremony/trust inputs, including paths inside transport profiles. It is not
  silently transferred to another ceremony.
- The guide and preparation wrappers forward termination signals and wait for
  child cleanup before releasing their locks; a subprocess regression tests this.
- Fresh-contribution recovery checks now also run inside the supervisor's
  profile lock, so a different UI entry point cannot silently recompute over
  retained candidate/recovery data.
- Production decision actions precede the final archive/retention handoff.
- proof-tool's final release verifier rejected the tiny rehearsal profile even
  after successful finalization and audits. A narrow ceremony-only verifier now
  handles authenticated tiny rehearsals; production key profiles remain unchanged.

## Remaining limitations

- This is guided orchestration over existing commands, not an autonomous
  coordinator. Stage progress is a local checklist, not authenticated global state.
- Identity/profile setup, operational-record authoring, raw offline receipt
  signing, application public-proof generation and actual human observations
  still require their existing tools/processes. The guide makes these explicit.
- Correct input files still need to be staged in each role's dedicated folders.
  The guide does not copy files between people or send emails.
- Recipe changes intentionally stop incompatible saved workflows. There is
  no automatic migration of in-flight workflow records in this initial version.
- Optional production-decision actions are not themselves a release gate;
  proof-tool and the accountable release process enforce the decision policy.

## Tests

Ordinary tests cover consent, required fields, numbered choices, append-only
attempt history, failure/retry/recovery, command tampering, role recipe coverage,
public-input pinning, private state permissions and Docker seal-path confinement.
`TestRoleFlowDockerRecipeFlags` also checks every distinct recipe against the
real Docker CLI parsers without mounting files or invoking the operation.

`TestRoleFlowDockerFullCeremony` is opt-in. Set `RELAY_FLOW_DOCKER=1`,
`RELAY_ROLE_ONLINE_IMAGE`, `RELAY_ROLE_OFFLINE_IMAGE`, `RELAY_ROLE_PLATFORM`,
and `RELAY_PROOF_TOOL_DIR`, then run:

```sh
go test ./cmd/relay -run '^TestRoleFlowDockerFullCeremony$' -v -count=1 -timeout=30m
```

Use immutable preloaded Linux image IDs/digests containing the pinned proof-tool.
The test creates fresh same-host rehearsal identities, computes 3+3 real Docker
contributions, checks cleanup, waits for two actual future Quicknet rounds,
and exercises finalization, two audits, operational evidence and final release
signing/verification. A wrong release identity must be rejected.

It uses public-file handoff, not AWS/R2 transport. Operational witnesses, mirrors
and relay operators are explicitly same-host fixtures—not independent humans.
The separate public-proof and operational-fixture helpers run locally against
proof-tool's own APIs; they are not distributed as production tools.
This lane does not test cloud permissions, production K=21 performance,
real-world independence, physical erasure or the production GO decision.

## Recorded local result — 2026-09-08

- Full tiny Docker lifecycle: **PASS**, 653.43 seconds on Apple-silicon macOS.
- All 52 distinct Docker recipe-parser checks: **PASS**.
- Interactive guide → Docker inspection → save/reopen: **PASS**.
- Relay ordinary/tagged tests, targeted race tests and vet: **PASS**.
- proof-tool keybundle/keyprofile/prover/mpcceremony suites: **PASS** in Linux
  Docker. Native macOS cannot run the suite's Linux-only executable-identity tests.
- No rehearsal containers remained. Existing user ceremonies/keys were not used.

This used unapproved local development images, not a production release:

```text
online  sha256:a1943f2d4510493772ddea19b40ff6e14b0eab22461443555d0136dca3f9a632
offline sha256:693706f3eca64f973428b0450b9b0b7cf024867c998b73ae9f8a20c7f38a43e3
```
