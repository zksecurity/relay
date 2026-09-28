## What changed

The coordinator upgrade now accepts the retained public snapshot manifest created by the V5 `[H]` release-review handoff after the signed final release is recorded. It checks the manifest's exact local bytes, signed release-review checkpoint and final-release ancestry, and every referenced public file before selecting the new application. Unfinished grants, imports, and received release packages still block an upgrade. No ceremony files are changed by this check.

## Tessera compatibility

This is a Relay-only coordinator upgrade fix. The signed ceremony format, setup contracts, proof-tool pin, participant flow, and release-signer CLI are unchanged. Existing ceremonies retain their frozen ceremony release; the coordinator application can update through the supported upgrade check.
