## What changed

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
- The beacon selection menu previews the bundled settings before selection and
  distinguishes the 180-second template from production's 24-hour minimum.
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

Setup contracts, ceremony data, and Tessera request fields are unchanged.
The additive export menu key does not renumber existing actions. No proof-tool
or website change is needed for local bug-report export. Existing role folders
begin recording diagnostics when opened with a compatible updated launcher.
