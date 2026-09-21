## What changed

- Added `relay audit export` and `relay audit combine` to produce sanitized JSON
  and Markdown activity reports with source provenance and explicit history gaps.
- Guided actions now retain a durable activity journal beyond the existing
  100-event diagnostic buffer. A failed start-record write blocks the action;
  a failed completion-record write warns without retrying the completed action.
- Exports can optionally verify checkpoint structure using the pinned proof tool
  and an independently supplied coordinator key. Combined reports label imported
  verification results as exporter claims.

## Validation and limits

Full Go tests, vet, and focused audit/guide race tests pass. Retrospective exports
from three roles in a completed tiny AWS rehearsal were combined successfully;
optional verification authenticated its final checkpoint and lifecycle progress.
This was a read-only check of existing evidence, not a new live ceremony.

Local activity records are unauthenticated observations. Reports identify missing
history and do not establish mathematical replay, global freshness, physical
erasure, or production readiness. Public replay payloads are not bundled.

## Tessera compatibility

Shared setup contracts, signed ceremony formats, and website activation are
unchanged. Existing ceremonies remain pinned to their selected releases.
