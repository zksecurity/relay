## What changed

- Allow larger public ceremony downloads more total time while cancelling connections that stop delivering data for 30 seconds.
- Reuse retained public artifacts only after copying and checking their bytes against the authenticated signed reference. Refresh still retrieves and verifies the published checkpoint history; local reuse does not demonstrate remote artifact availability.
- Preserve conflicting-file rejection, download size limits, cancellation cleanup and existing upgrade admission rules. This release does not itself approve an upgrade pair.

## Tessera compatibility

Tessera setup contracts, signed artifact formats and proof-tool pins are unchanged. These fixes affect public download timing and verified local artifact reuse. Frozen ceremonies require a separately qualified and published upgrade approval before installation.
