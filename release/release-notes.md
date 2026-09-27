## What changed

At release review, a coordinator upgrade now recognizes the completed
preliminary public proof left by finalization. Its bytes must match the copy
in the accepted signed final candidate. Missing or changed evidence still
blocks the upgrade. This completes the retained-state fix begun in v0.6.5;
no ceremony command is replayed by the update.

## Tessera compatibility

The setup contracts, signed ceremony format, and proof-tool pin are unchanged.
Existing ceremonies retain their frozen role images. No Tessera schema or
website change is required. This is a Relay-only coordinator upgrade admission
fix; it does not alter mathematical verification or production GO/NO-GO rules.
