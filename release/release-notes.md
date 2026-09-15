## What changed

- Added a narrowly scoped recovery command for the affected 1828 coordinator
  release when its first Phase 1 publication was interrupted by expired AWS
  session credentials. The command accepts only the retained authenticated
  index-0 publication, rotates only credential-file references, verifies any
  existing remote bytes, uses create-only writes for missing objects and the
  initial head, and resumes the original frozen workflow only after complete
  reconciliation. It refuses advanced, closed, conflicting, ambiguous or
  differently pinned workflows.
  Ordinary `coordinator publish` has no recovery switch. The hotfix launcher
  invokes a container-only compatibility command with the locked 1828 profile
  and workflow mounted read-only, then revalidates the complete profile,
  runtime, storage target and retained attempt after credential rotation.
  A retry also recognizes a completion checkpoint that landed despite an
  ambiguous local save result, without publishing again.
  In the original coordinator preparation, choose `6) Storage settings`, then
  AWS and the same existing resources to capture a fresh credential snapshot;
  do not change any storage value. Then run the hotfix launcher's
  `relay ceremony recover-publication CEREMONY_NAME`; on success, resume with
  the original release's start script.
- The storage-first design makes the signed beacon lead configurable before
  initialization in both rehearsal and production. Relay will default to 180
  seconds for rehearsals and 24 hours for production, warn explicitly before a
  shorter production choice is signed, and display the additional fixed
  observation window when witnesses are enabled. Existing setup contracts and
  ceremonies keep their original policy.

- Added the first storage-first ceremony protocol layer: bounded and version-
  pinned backend reads, conditional root updates, immutable signed-checkpoint
  discovery, workspace rollback/fork protection, a crash-safe coordinator
  commit journal, and deterministic Phase 1 next-action rules. Existing
  ceremonies continue using their current workflow; storage-first execution is
  not selected until a compatible proof-tool release and the complete role
  path are pinned.

- Reworked the ceremony flow map into seven explicit lanes covering identity
  collection, enrollment and storage distribution, participant custody turns,
  per-head mirror evidence, closure and beacon timing, phase transition,
  finalization, signed-release authorization, upload, and archival. The map now
  distinguishes public handoffs, private access, cryptographic verification,
  signing, and production authorization. This is documentation-only.

- Public-file import defaults to storage settings when the ceremony set is
  already present and storage is missing, instead of recommending it again.
  Handoff actions show counterparts, public file locations and expected replies.
  Custody delivery uses saved phase/turn packets and checks named payload hashes;
  missing files cannot be reported as delivered. Human reports still do not
  prove receipt or acceptance. No Tessera contract or proof-tool change.

- Coordinator enrollment guidance uses the latest collection check instead of
  getting stuck on earlier incomplete checks. Rechecks after imports, archives
  and before advancing retain validation; uncertain signing/upload recovery is
  unchanged. Existing history is preserved. No proof-tool or Tessera contract
  change is required.

- Importing R2 storage settings now collects all three credential files and
  saves protected copies together, avoiding the repeated-setup loop. Account
  and bucket selections are retained; source files are never session-owned.
  Cloud checks still require separate approval. No Tessera contract or proof-tool
  change is required.
- Fix guided enrollment collection rejecting valid one-witness, one-mirror and
  one-auditor requirements from the authenticated proof-tool projection. Higher
  reported requirements still apply; signatures and roster checks remain required.
- Coordinators can issue recipient-bound witness/mirror setup files that assign
  enrollment numbers. Observers import the file instead of typing a number.
  These are unsigned instructions, not enrollments; existing signed records and
  previously saved numbers remain resumable.
- Role onboarding can import the definition, signature and coordinator public
  key together from one folder. It retains independent fingerprint confirmation,
  authenticates the staged set with proof-tool and never replaces different files.
  Individual imports remain available with their existing menu numbers.
- Standalone coordinator drafts keep optional identity import visible once the
  required roster is present, without changing the recommended next step.
  Beacon help explains rehearsal versus production witness lead times.
- The Bash launcher installer now disables terminal focus reporting and filters
  queued focus events at every prompt, matching the CLI's input handling.
- Role setup explicitly guides public identity/enrollment delivery, requests the
  coordinator's public storage file before profile creation, and prepares both
  phase profiles. Participant Phase 2 preparation is recommended only when the
  authenticated schedule includes them. Reports remain distinct from receipt
  and verification.
- Coordinator guidance includes private grant delivery, later evidence access
  and collection, and canonical production-decision/signature exchanges.
- Audit uploads stage only the exact successful report/signature pair, including
  custom output paths. Receiving roles get explicit public-package instructions.
- Added a bounded onboarding model and real-menu regression for missing storage;
  this is not a claim of whole-CLI formal verification.

- Signing-container output distinguishes the enclosing ceremony role from its
  network-disabled execution environment; authorization and saved profiles are
  unchanged.
- Coordinator onboarding now orders inspection, sharing public ceremony files,
  then enrollment collection. Sharing displays the last successfully inspected
  file paths; existing task IDs and recorded progress are preserved.
- Ceremony, signature, coordinator-key and transcript-folder prompts explicitly
  explain that Enter uses the saved path; coordinator-key trust guidance remains.
- Before initialization, the storage menu recommends setup when local inputs
  are missing or invalid, and checks when they are present. Cloud checks and
  signing still require explicit approval.
- Interactive prompts disable terminal focus reporting and ignore queued focus
  events, including during hidden credential entry, so switching windows does
  not corrupt answers. Confirmation phrases remain required.
- R2 setup explains why a separate inbox-only credential is required, names the
  selected inbox bucket, and removes "parent" from the credential prompts.
- Standalone AWS setup is now a first-class storage menu option: review the
  selected account, use existing resources or approve dedicated provisioning,
  and save a protected credential snapshot. Temporary snapshots do not renew
  automatically. Existing storage checks still run with separate approval.
- Installation now says "Choose your task or role" to include upload-only work.
- The existing setup-v2 menu previews its bundled settings and distinguishes
  the 180-second rehearsal template from that legacy contract's 24-hour
  production minimum. The new storage-first contract will instead use the
  configurable signed policy described above.
- Guided onboarding and ceremony operations now retain up to 100 structured
  diagnostic events per role work folder, including fixed error categories.
- Choose **E — Export bug report** in the menus, or run
  `relay diagnostics export --work ROLE_WORK --out FRESH_ZIP`.
- Reports contain a short report ID, release/role/step context, operation outcomes,
  OS/CPU and local Docker client versions, and expected public-file presence.
  Raw terminal output, commands, environment, personal paths, keys, credentials,
  profiles, and ceremony artifacts are excluded. Reports are never uploaded.
- Diagnostic logging is separate from recovery state. Exporting a report cannot
  retry a command, complete a task, or overwrite an existing report.

## Tessera compatibility

The recovery command does not change setup contracts, signed definitions,
ceremony data, proof-tool pins, Tessera fields or selected releases. It is an
explicit compatibility bridge for one frozen Relay release and does not make
the hotfix release the ceremony runtime. No Tessera change is required.
Tessera's current grant API does not bind credentials to storage-first
checkpoint attempts. Relay must reject Tessera-backed storage-first ceremonies
until a versioned compatible grant/status contract is deployed. Existing
Tessera ceremonies and setup-v2/setup-v2r2 contracts are unchanged.

Setup contracts, ceremony data, and Tessera request fields are unchanged.
The ceremony-flow documentation does not change Tessera integration behavior.
The compiled workflow recipe adds handoff tasks while preserving existing task
IDs and command-field ordering. Existing selected releases stay pinned.
The additive export menu key does not renumber existing actions. No proof-tool
or website change is needed for local bug-report export. Existing role folders
begin recording diagnostics when opened with a compatible updated launcher.
