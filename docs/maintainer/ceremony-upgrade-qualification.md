# Qualification and remaining implementation

The compatibility policies are empty: no existing ceremony is approved for
updates yet. Implemented paths below are locally tested, not release-qualified.

See the [ordinary-use regression comparison](ceremony-upgrade-no-selection-tests.md)
for testing against current main without activating an upgrade. Earlier candidate
qualification results below predate that rebase and do not qualify its new bytes.

## Completed-step online coordinator fixes (unapproved)

The reader also supports `relay-upgrade-qualification/v4` for a changed online
coordinator image between completed operations. No pair is enabled. V3 remains
native-only, and legacy V2 evidence does not authorize new admissions. The native
launcher, target online image and unchanged Proof-tool digest must match the exact
reviewed declaration and attested release assets. Original signing/contribution
images, identity, definition and accepted progress remain frozen.

V4 requires all three completed-step checks below plus `online-runtime-retry` and
`predecessor-reentry`. The runner executes `TestUpgradeOnlineRuntimeRetry` and
`TestUpgradeOnlinePredecessorReentry` against exact executable/image inputs. Both
use a real signed two-phase ceremony and the local test storage adapter: stop a
target-image publication after one immutable upload, then retry with the target;
the second scenario first tries the original executable and original image against
the interrupted state. It must either reconcile successfully or refuse without
changing ceremony/journal files. The target retry must complete exactly one root
transition; its successful immutable body must not be retransmitted. The remainder
of each ceremony completes signing, publication and fresh reconstruction.

These scenarios are opt-in and require the private exact-asset request. Skips are
not evidence and cannot produce qualification. Local adapter tests are not live
S3/R2 conformance; the affected provider path also needs isolated acceptance before
advertising provider compatibility. No exact published V4 pair has been qualified.

The test harness performs initial activation, while the real candidate exercises
selection repair and subsequent commands. Compile the harness from the exact
reviewed target checkout and require an isolated smoke through the delivered
`ceremony upgrade` command and approval path before upgrading a real ceremony.
A new reader release must precede qualification/approval: existing v0.2.2 binaries
cannot read V4 evidence. Use the separate-approval sequence below unchanged.

Generic saved actions retain their image. V4 coordinator recovery uses the
currently selected online image; this extension therefore admits only completed
old operations and makes no promise about upgrading unfinished work or arbitrary
future/multi-hop compatibility. Equal Proof-tool hashes do not replace testing
changed orchestration, retained-state interpretation or provider publication.

## Current first-release scope

The initial scope is now **initialized coordinator, native launcher only, between
completed steps**. Keep every Docker image and signed ceremony file unchanged.
An operator exits normally, installs the proposed launcher, and requests the
update. Unfinished or uncertain ceremony operations must be resolved using the
existing version first. An interrupted updater is different: restarting it may
repair selection or `start.sh` without repeating ceremony work.

New admissions use qualification schema `relay-upgrade-qualification/v3`:

1. Update an ongoing ceremony after a completed step, then finish it.
2. Interrupt the updater; repair it safely or retain the previous launcher.
3. Refuse unfinished work and incompatible versions without changing selection
   or ceremony files.

The admission check authenticates recorded accepted progress with the original
runtime and checks retained actions against it. A signed but unpublished output
is not completion. This does not establish current backend freshness; ordinary
ceremony synchronization still runs before subsequent actions.

Test the exact published executables locally; a dedicated Mac CI runner is not
required for this initial scope. Publish the implementation with no pairs enabled,
then review exact-build test evidence before publishing compatibility approval.
No rebuilt executable may inherit another executable's qualification.

The older seven-check v2 report remains readable for existing selections and
interrupted-updater repair. It does not authorize new v3 admissions. Draft updates,
other roles, changed images and updates during unfinished work are deferred.
The broader matrix below is retained as future/historical design, **not** a
prerequisite for the narrowed first release. The three named integration runner
entry points use real signed local-storage ceremonies and actual source/candidate
executables. Focused unit tests alone are not qualification.

## Publish the app first, approve the tested bytes later

1. Publish target app B containing the upgrade and separate-approval support.
   Leave `release/upgrade-policy-v2.json` empty.
2. Download and authenticate B and its predecessor. Compile the qualification
   tests from the reviewed checkout; the private request uses
   `qualification_schema: relay-upgrade-qualification/v3` and exact asset paths.
   Run the qualification command below on a Docker-capable local machine.
3. Submit the sanitized report and exact policy pair for review. The report filename
   is the declaration's `AssetName()` under `release/upgrade-qualification/`.
   Do not commit the private request, credentials or raw logs.
4. A later protected-main release C authenticates B and every predecessor binary,
   compares their hashes to the reviewed report, then publishes approval/report.
   C does not rebuild B. Its provenance attests approval of local evidence, not
   execution of Mac tests in CI.
5. Install B; use `ceremony upgrade NAME --role coordinator --release
   role-images-B --approval-release role-images-C` with the saved settings root.
   The UI shows both releases. Omitting approval defaults to the target release
   for existing same-release approvals; it never searches other releases.

Declaration/report provenance must match C; executable/map provenance must match
B. The saved selection retains C, while existing selections without that field
retain their original meaning. B must contain this reader before qualification:
an arbitrary older binary cannot read new selection fields. Same-target repair
preserves the selected approval and does not reapply new-update admission.
Offline bundle preparation accepts the same `--approval-release`; its
`APPROVAL-RELEASE` text identifies the value to pass at installation. Offline
verification still requires an independently trusted root outside the bundle.

Completed-step admission result (2026-09-21, macOS ARM64): local two-phase
continuation **PASS, 203.29 seconds**, using the attested
`9b3f86d7dfe85e1f6b4256065748136cc8f42711` predecessor and a local candidate.
The update followed verified Phase 1 acceptance. Original images stayed pinned;
Phase 2, both future beacons, coordinator replay, tiny public proof, signing,
publication and empty-client reconstruction completed. The test exposed and fixed
a public-key newline comparison; its local harness now refreshes accepted progress
before updating, as normal CLI reopening does. This uses synthetic test-only
authorization and local storage, not published-pair qualification or provider testing.

## Implementation slices

| Slice | Required result | Current status |
| --- | --- | --- |
| Release authority | v2 declarations and attested CI publication | Strict reader, report-bound producer and publication wiring; no pairs enabled |
| Runtime resolution | Preserve signing/contribution and saved-action pins | Setup/resume, open and V4 operations wired for initialized connected roles; Tessera unchanged |
| Retained-work inventory | Include coordinator side files, not only generic journal | Workspace hashing, known workflow checks, commit/intent checks and related activity exclusion |
| Recovery adapters | Preserve original attempts; verify before reconciliation | Existing V4 recovery reused without journal migration; interrupted-contribution regression test |
| Execution safety | Clean-exit path for known sources; conservative maintenance path; future durable execution intents | Locks, mount checks and clean-exit confirmation only |
| Activation | Multi-hop selection, review recheck, script repair, offline metadata | Initialized profiles and standalone drafts implemented; rollback remains unsupported |
| All-role journeys | Whole enabled role journeys; mixed versions | Coordinator/participant/signer/auditor resolver; missing ordinary role journeys remain excluded |
| Qualification | Real old-to-candidate ceremony and failure matrix | Real native draft-resume tests and opt-in two-phase live coordinator-update scenario added; full qualification matrix remains pending |

Implement in this order: authority/resolver → inventory and adapters → execution
safety/activation → all-role journeys → end-to-end qualification. Do not spend a
release on each slice. Use local immutable test images, preserving original Linux
Proof-tool binaries separately from any native host inspector. Publish the paired
release only after the candidate matrix passes; verify published assets afterward.

## Broader matrix (deferred)

Initial intended release scope: coordinator, macOS ARM64, native application
only, retaining original online/signing/contribution images. This scope is not
enabled. The seven real qualification entry points remain future work for this
broader scope. Ordinary hosted macOS unit tests do not replace Docker journeys.
Do not register a developer's machine as a CI runner without explicit approval.

For each advertised source/target, host OS, Docker architecture and enabled role:

1. Use an actual source release and real signed tiny ceremony, not handcrafted
   state alone. Exercise normal setup and `start.sh`, then upgrade at each relevant
   stage. Other roles stay old; separately test mixed and all-upgraded combinations.
2. Reproduce an application bug in the old online image or native launcher. Show
   the target fixes it with identical cryptographic runtime pins and artifact bytes.
3. Complete both phases, future beacon rounds, coordinator full replay, exact final
   signing/publication, and a fresh client's complete verification.
4. Inject failure before/after signing, upload, manifest publication, conditional
   head update, local success save, selection publication and script replacement.
   Include remote success with missing local success, expired grants and collisions.
5. Test normal exit and killed parents with delayed/live descendants; stopped,
   restarting and root-mounted containers; competing commands; daemon replacement.
6. Reject wrong ceremony/role/platform, changed keys/storage/proof binaries,
   unrecognized retained state, corrupt cache and missing
   originals. A custom script is preserved with an explicit resume command,
   not reported as repaired. Test interrupted entry-point repair and A → B → C
   with the same A-created operation pending and both preserved/replaced adapters.
7. Open target-produced completed and interrupted state using every retained or
   previously activated app. Require safe reentry or tested effective exclusion;
   without either, reject the pair. No evidence rewinds or repeats.
8. For offline final signers, prepare before disconnection, activate without network,
   preserve offline signing, and reject superseded review packages on submission.
   Also transfer a prepared update into an already-offline signer, retaining its
   existing review package/signature; verify provenance without network access.
9. Run affected S3 and R2 operations against isolated live test storage; demonstrate
   immutable reconciliation and conditional updates. Report skipped cases plainly.
10. Test enabled witness/mirror/auditor journeys before advertising them. Disabled
    roles stay absent. Production policy constraints need separate negative tests;
    accelerated tiny rehearsal does not prove production timing or K=21 capacity.

Tests assert each transition's starting files/verification state, operator-visible
instruction, permitted action, resulting files and next instruction. Include branches
for uncertain outcomes and backend advancement, not just a successful trace.

## Non-circular qualification and release gates

Protected-main CI publishes immutable app assets first. An isolated local test
harness supplies test-only authorization to exercise those exact app and source
assets before approval exists. No runtime trust-bypass flag is shipped. The
report binds source/candidate digests and coverage, not its own future declaration.
After review, a later protected-main release publishes the declaration containing
the report hash and attests both. It authenticates the earlier published binaries;
it does not rebuild or promote different bytes. The report hash is not compiled
into the app. Post-approval smoke tests exercise delivered production authority,
not test injection. CI attestation does not itself establish that local tests ran.

- Run Go tests/vet, installer tests and applicable release, Docker, ceremony and
  Tessera checks on the candidate. Synthetic metadata is test-only.
- Qualification evidence binds exact source and candidate builds, declared scope
  and test outcomes. Final attested digests must correspond to the tested candidate;
  rebuilding materially different assets invalidates that qualification.
- Add only reviewed pairs/states to the policy. Publish declarations and assets
  through protected-main provenance; verify the delivered assets and a post-release
  smoke upgrade before directing an operator to use them.
- No new Proof-tool release is required unless the supposedly application-only
  fix crosses the fixed-runtime boundary; then it is outside this mechanism.
- Keep Tessera's frozen setup unchanged. Run client/server compatibility and deploy
  any required server adapter before advertising Tessera upgrade support.
- Public evidence contains versions, test names and limitations, never private
  account identifiers, local paths, keys, grants, credentials or raw private logs.

No universal compatibility switch, release-match bypass, automatic mass upgrade,
or automatic rollback is part of this design. Unsupported pairs remain blocked.

## Build-time runner

`go run ./scripts/qualify-ceremony-upgrade --request PRIVATE_JSON --out FRESH_JSON`
runs a reviewed integration-test executable against explicitly supplied candidate
and predecessor binaries. The request contains `declaration`, `candidate`,
`predecessors` (commit to absolute binary path), and `test_binary`. Each required
scenario must actually execute and pass; skipped subtests, missing tests, failures,
truncated output and changed input binaries reject the entire report. Execution is
deadline-bound; public reports exclude paths and test logs and bind predecessor
binary hashes plus original/signing image digests.
Ctrl-C/termination cancels the scenario process group; output is bounded and
overflow cancels execution. Every observed subtest must finish successfully.

The runner executes `TestUpgradeCleanExitContinuation`,
`TestUpgradeCleanExitInterruption`, and `TestUpgradeCleanExitRefusal` for v3.
Each finishes a real two-phase local-storage ceremony; the latter two additionally
exercise abrupt updater boundaries or refusal before continuing. Test-only
authorization permits pre-approval execution without a shipped bypass.
The broader seven `TestUpgradeQualification…` v2 entry points remain deferred;
ordinary unit tests cannot substitute for either suite.

Generated installer entry points retain preparation and their original settings.
An upgraded setup resolves its saved settings root from the active selection,
including nondefault roots. Operator-customized scripts are preserved with an
explicit resume command, not reported as successfully rewritten.

## Actual executable scenarios

`TestUpgradeRealDraftJourney` runs the attested predecessor and local candidate
through real terminals. It creates a draft with the predecessor, activates a
test-only selection, reopens the generated `start.sh`, and checks unchanged draft
bytes and absent keys/definition. It also checks predecessor reentry. This tests
setup continuity, not a completed ceremony or safe reentry after every operation.
The coordinator case then creates a real keypair through the updated launcher
and confirms that its child profile still pins the original signing image.

Local result (macOS ARM64): the four draft-resume cases and coordinator key
generation pass against source release `cc812222c7dbc1b04c21b8df0c7e7cc51c2e2183`
and the local candidate. The candidate uses local test-only authorization; this
is not evidence for a released or qualified target pair.

`TestUpgradeRealTwoPhaseJourney` extends the live R2 harness: original native
transport commands run before the Phase 1 barrier; the coordinator then selects
the candidate while other roles retain the source. The harness completes Phase 2,
beacons, replay, signing, publication and fresh reconstruction. Orchestration is
test-driven; both native coordinator guides also reopen the signed workspace at
the upgrade barrier. This is not complete interactive-menu coverage or the failure matrix.
Missing isolated provider fixtures skip the test and produce no qualification.
The R2 upgrade scenario has not run against live storage.

`TestUpgradeRealAWSTwoPhaseJourney` runs the same upgrade sequence on dedicated
AWS test resources. It requires `RELAY_AWS_LIVE_PROBES_APPROVED=1`, the expected
test account/principal, `RELAY_AWS_TEST_CLI`, and `RELAY_V4_LIVE_AWS_CONFIG`.
The test verifies the login identity and exports a protected temporary credential
snapshot. It never falls back to the operator's default AWS profile or needs R2
management credentials. Missing fixtures are not passing evidence.

`TestUpgradeResumeAWSAfterPhase2` resumes an explicitly retained test root
(`RELAY_UPGRADE_AWS_RESUME_ROOT`) after both contributions and the coordinator
update. It validates the original selection and executable, reuses original
runtime images and signed beacon bytes, and allows only beacon publication,
finalization, review and release. It refreshes isolated credential references
between operations and reconstructs the final release in an empty workspace.
It never initializes, contributes or activates an upgrade again. This is a
test-only continuation, not a new public recovery command or an enabled pair.
Temporary AWS session expiry is reported without credential contents. An old
HTTP 400 with no retained session expiry is not proof of expired credentials.

AWS result (2026-09-21, macOS ARM64): **PASS after recovery**. The attested
`9b3f86d7dfe85e1f6b4256065748136cc8f42711` coordinator launcher was updated
after Phase 1; Phase 2 then completed on the retained original cryptographic
images. An HTTP 400 interrupted beacon publication. The retained-run test
reconciled publication and finished coordinator replay, a real tiny proof,
release signing, inbox verification, final publication and empty-client
reconstruction in **740.98 seconds**, without repeating contributions or update.
The failed segment took 754.43 seconds. The precise cause of that earlier HTTP
400 remains undetermined; a current-login check found the exact object present.
This was test-driven, same-machine, minimal-role execution with synthetic local
update authorization. It is not an uninterrupted-run result, online-image
replacement test, full qualification matrix, or approval of a published pair.

`TestUpgradeLocalTwoPhaseJourney` uses the same two-phase sequence with an
ephemeral local HTTPS service and test-only AWS CLI adapter instead of cloud
storage. Enable it with `RELAY_UPGRADE_LOCAL_STORAGE=1` plus the request/map
paths above; it creates its own synthetic credentials. Original cryptographic
images are unchanged. It omits native macOS guide reopening against the local
CA and does not validate provider APIs, permissions or infrastructure privacy.
See [adapter limits](../../internal/teststore/README.md).

Local result (2026-09-21, macOS ARM64): **PASS**, 251.17 seconds. One real
contribution per phase, both future Quicknet rounds, coordinator full replay,
public tiny proof, required release signing, final publication and empty-client
reconstruction completed. The native coordinator switched from the attested
`cc812222c7dbc1b04c21b8df0c7e7cc51c2e2183` launcher to the local candidate after
Phase 1; all Docker images stayed original for this native-application test.
This does not qualify an online-image replacement or a published upgrade pair.

Both use `RELAY_UPGRADE_QUALIFICATION_REQUEST` and `RELAY_UPGRADE_TARGET_MAP`.
The live test also requires the existing `RELAY_V4_LIVE_R2_*` fixture paths and
`RELAY_V4_LIVE_PROOF_BINARY` (the exact original Linux container binary).
Upgrade lanes inspect through the original Docker image, never execute that
Linux binary directly on macOS, and do not add it twice to the binary allowlist.
Optional `RELAY_UPGRADE_PRIVATE_LOG_DIR` retains failed terminal logs locally.
Never publish those logs, requests, local paths or credential files. Synthetic
local authorization is confined to test code and cannot enable a release pair.

## Offline command surface

`ceremony upgrade-bundle` takes original/source/target release tags, role,
destination host/platform and a fresh output folder. It downloads public release
assets and their provenance, never role credentials or signing keys.
On the offline machine, `ceremony upgrade` accepts `--bundle DIR --trusted-root
FILE`; the independently trusted root must be outside the bundle. Original Docker
images must already be cached. Verification uses local GitHub attestation bundles.
Actual disconnected-machine testing is still required before advertising support.
