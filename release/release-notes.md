## What changed

- Compatible native-only updates retain the original online Docker image and
  verify it against the original release map. Qualification for that choice
  cannot authorize replacement Docker images. Upgrade inventory also preserves
  durable activity history and surfaces gaps without claiming clean execution.
  No upgrade pair is enabled; Tessera contracts and deployment are unchanged.

- Added `relay audit export` and `relay audit combine` to produce sanitized JSON
  and Markdown activity reports with source provenance and explicit history gaps.
- Guided actions now retain a durable activity journal beyond the existing
  100-event diagnostic buffer. A failed start-record write blocks the action;
  a failed completion-record write warns without retrying the completed action.
- Exports can optionally verify checkpoint structure using the pinned proof tool
  and an independently supplied coordinator key. Combined reports label imported
  verification results as exporter claims.

- The local compatible-update candidate completed a live AWS S3 tiny ceremony
  after recovering an interrupted publication. The coordinator launcher changed
  after Phase 1 while cryptographic images stayed original. Both contributions,
  coordinator replay, release signing, final publication and empty-client
  reconstruction passed without repeating the contributions or update.
  A test-only retained-run helper and credential-expiry diagnostics were added.
  This is recovered, same-machine test evidence—not production qualification or
  an enabled upgrade pair. The earlier HTTP 400's cause remains undetermined.
  Tessera contracts and deployment are unchanged.

- Added isolated local-storage testing for ongoing-ceremony updates. A real tiny
  two-phase ceremony passed with the coordinator launcher updated after Phase 1,
  original cryptographic images retained, final signing/publication completed,
  and an empty client reconstructing the release. No cloud credentials were used.
  This tests native-app continuity, not live R2/S3 or online-image replacement;
  no upgrade pair is enabled. Tessera contracts and deployment are unchanged.

- Adds standalone draft-stage compatible updates before a shared profile or
  identity exists. Original setup tools, frozen initialization inputs and later
  verified file groups are retained across updates. Actual old/new executable
  draft tests and an opt-in two-phase live update test are included; these do not
  enable an upgrade pair or replace release qualification. Tessera-linked setup
  updates remain excluded; no Tessera contract or website change is made.

- Compatible-update qualification now binds predecessor executable hashes and
  original/signing image digests. A build-time runner rejects absent, skipped or
  failed scenarios and changed binaries. The real release-pair scenario suite is
  still pending, so no pair is enabled. Updating an installer-generated `start.sh`
  now preserves its setup/resume entry point rather than skipping into operations.
  Tessera compatibility: no shared contract, API or website changes.

- Documents the reviewed all-role, all-stage compatible-update design, including
  pending-work recovery, repeated updates and offline signers. This documents the
  target behavior; it does not enable additional upgrades or change Tessera contracts.

- Adds v2 compatible-update infrastructure for initialized storage-first role
  profiles: exact-build declarations, retained-work inventory, repeated updates,
  atomic selection, offline asset bundles and recoverable `start.sh` replacement.
  Contribution/signing runtimes and old named-action images remain pinned; new
  online actions record their selected image. Existing profiles remain unchanged.
  **No release pair is enabled yet.** Missing ordinary
  observer/upload-station journeys, rollback and force-terminated sessions remain
  unsupported. Real old-to-new ceremony qualification is required before use.
  Tessera compatibility: no contract, API, selected-release, or website changes;
  this does not authorize updates of Tessera-pinned ceremonies.

- The storage-first participant guide now follows the authenticated transition
  from Phase 1 to Phase 2 when refreshed or reopened, using the same saved
  profile. Earlier-phase unfinished work is retained and blocks new actions.
  Tessera compatibility is unchanged: no setup contract, signed bytes, or API
  changes are required; existing released ceremonies remain on their pinned CLI.

## Validation and limits

Full Go tests, vet, and focused audit/guide race tests pass. Retrospective exports
from three roles in a completed tiny AWS rehearsal were combined successfully;
optional verification authenticated its final checkpoint and lifecycle progress.
This was a read-only check of existing evidence, not a new live ceremony.

Local activity records are unauthenticated observations. Reports identify missing
history and do not establish mathematical replay, global freshness, physical
erasure, or production readiness. Public replay payloads are not bundled.

## Tessera compatibility

Shared setup contracts, signed ceremony policy, proof-tool pins, and Tessera's
managed credential flow are unchanged. This change applies to standalone AWS
credential setup and compatible coordinator launchers.
