## What changed

- Standalone production setup defaults to a 30-minute (1800-second) beacon wait
  in each phase. Shorter choices still require explicit review. Saved and signed
  policies retain their selected wait.
- Added a draft offline release-signer handoff: the coordinator exports public
  evidence and imports the returned enrollment and signed release package.
- Added recognition of the new definition version. The production runtime pin
  and standalone circuit migration are still pending in this draft.

## Validation and limits

Integration validation is pending. This draft is not ready for a production
ceremony or publication.

## Tessera compatibility

Shared setup contracts and their historical defaults are unchanged. Existing
ceremonies remain pinned to their original runtime and signed policy.
