## What changed

- Avoid replaying contribution mathematics a second time when the coordinator publishes an already offline-accepted V4 checkpoint. Publication still verifies the exact signed checkpoint, complete signed ancestry, immutable artifact hashes, and conditional storage-head update.

## Tessera compatibility

Tessera setup contracts, signed ceremony formats, proof-tool pins, and stored checkpoint formats are unchanged. This changes only the coordinator's online publication verification work.
