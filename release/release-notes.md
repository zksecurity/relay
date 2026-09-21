## What changed

- Adds compatible-update infrastructure with exact-build verification, atomic
  launcher selection and repair of installer-generated start scripts. Original
  ceremony files, signing keys and cryptographic Docker images remain pinned.
- Narrows new update admission to initialized coordinators between completed
  steps, with the original online image unchanged. Unfinished or uncertain work
  must be resolved with the current launcher first; existing selection repair
  remains available.
- Separates the three-scenario completed-step qualification format from the older
  seven-scenario format. Existing selections retain their original verification
  rules. **No upgrade pair is enabled.** Exact published-binary qualification and
  reviewed compatibility approval remain required.
- Adds isolated local-storage and retained AWS test helpers for two-phase update
  journeys. These test helpers do not authorize production updates.
- Allows a later protected-main release to publish reviewed approval of exact
  earlier app binaries. `--approval-release` keeps that approval separate from
  the installed app. Publication verifies both target and predecessor hashes;
  it does not claim local Mac tests ran in CI or rebuild the tested app.

## Validation and limits

A focused non-upgraded comparison against main covers all seven roles' setup
menus and saved state, plus original-image dispatch for saved actions. It does
not claim exhaustive interactive or live-provider coverage.

Go tests, vet and installer tests pass locally. Opt-in provider and release-pair
qualification tests are separate; missing fixtures or skipped tests are not
passing evidence. Broader role, draft-stage and interrupted-work upgrades remain
outside the initial enabled scope.

## Tessera compatibility

No shared setup contract, API, signed ceremony format or website changes.
Tessera-pinned ceremonies are not authorized for updates by this change.
