## What changed

An initialized coordinator can select a Relay CLI update when its only
unfinished local activity entry is an older release-signer enrollment import,
provided the signed accepted ceremony history independently verifies the exact
assigned signer's enrollment and all other clean-exit checks pass. The missing
activity completion remains visible as an audit gap; Relay does not invent a
successful completion or repeat the import. Other unfinished actions continue
to block an update.

## Tessera compatibility

The setup contracts, signed ceremony format, and proof-tool pin are unchanged.
Existing ceremonies retain their frozen role images. No Tessera schema or
website change is required. This is a Relay-only coordinator upgrade admission
fix; it does not alter mathematical verification or production GO/NO-GO rules.
