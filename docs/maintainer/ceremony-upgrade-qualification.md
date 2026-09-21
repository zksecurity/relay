# Qualification and remaining implementation

The compatibility policies are empty: no existing ceremony is approved for
updates yet. Implemented paths below are locally tested, not release-qualified.

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

## Required matrix

Initial intended release scope: coordinator, macOS ARM64, native application
only, retaining original online/signing/contribution images. This scope is not
enabled. The seven real qualification entry points and protected-main job still
need implementation. The repository currently has no registered dedicated Mac
runner; choosing/provisioning a Docker-capable qualification runner is a release
prerequisite, not something satisfied by ordinary hosted macOS unit tests.
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

Protected-main CI builds immutable candidate assets once. An isolated test harness
supplies test-only authorization to exercise the actual candidate and source
assets before a production declaration exists. No runtime trust-bypass flag is
shipped. The report binds source/candidate digests and coverage, not its own future
declaration. After tests, CI generates the declaration containing the report hash,
attests both, and promotes those exact tested assets without rebuilding binaries
or images. The report hash is not compiled into those binaries. Post-release
smoke tests exercise the delivered production authorization, not test injection.

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

The runner is **not** the scenario suite. The seven `TestUpgradeQualification…`
scenarios still need real old/candidate journeys; ordinary unit tests cannot
substitute. Publication remains blocked for nonempty policies without those
executed reports. No real pair or live-provider result is claimed here.

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
