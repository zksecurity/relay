## What changed

- Let coordinators select an authenticated Relay update without waiting for a separate compatibility-approval release. Record the operator choice without claiming that qualification tests passed; preserve existing qualified selections.
- Keep proof-tool, signing identities, contributor/signing images, workspace locks and retained-state checks. Updates still require completed operations.
- Allow an initial coordinator upgrade after a failed first refresh by authenticating the configured AWS root and verifying its exact locally retained signed initial checkpoint. This recovery path requires a host AWS login binding.

## Tessera compatibility

Tessera setup contracts, signed ceremony formats and proof-tool pins are unchanged. The new local operator-selection record is intentionally rejected by older launchers; use the selected launcher for recovery. This release changes coordinator upgrade admission, not website release selection.
