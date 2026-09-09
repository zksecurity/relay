# Rehearsal workflow fixes

The guided coordinator and participant paths now place signed custody actions
before computation and acceptance. Each direction prepares an unsigned packet,
reviews/signs exact bytes on the offline profile, and transfers public files
through the agreed channel. Receiver preparation verifies the sender signature
and every received file before recording the receipt time. The coordinator checks
the participant's outbound receipt before issuing the grant, and signs the return
receipt before acceptance. Contributions still run through the Docker supervisor;
offline participant actions are restricted to operational custody commands.

Use fresh per-turn packet directories and retain interrupted outputs. The local
menu remains a checklist, not an authoritative global record. Final protocol
verification still enforces the actual transfer bindings and chronology. Never
recreate an already uploaded candidate or backdate missing custody evidence.

Both phases publish their newly recorded beacon. Phase 1 publishes again after
sealing, before Phase 2 initialization/participation, so mirrors and participants
can acquire the public seal and commons.

Mirror synchronization now reads the published inventory rather than inferring
remote files from local existence. Signed chain/circuit references take precedence;
conflicting inventory entries, duplicate names, private paths, and conflicting
local bytes fail. Historical signed chain prefixes are published and synchronized,
authenticated under the separate coordinator trust key, and compared with the
current chain's history. Inventory hashes establish byte consistency; they do not
replace phase-ending signature/evidence verification. Missing inventory entries
produce an instruction to republish. Coordinator trust anchors are never fetched
from the same inventory they authenticate.

The finalization stage offers `finalize rehearsal-evidence` for the exact tiny
circuit. It generates a real proof from public golden inputs; production uses its
matching external proof process. The released final verifier remains authoritative.

## Dependency release gate

This branch requires the companion proof-tool custody/signing/tiny-proof changes.
The currently pinned proof-tool release does not contain those commands. Do not
merge/release this CLI branch until that proof-tool change has passed review and
produced a protected-main release, then update `release/role-images.json` with its
exact URLs and checksums. Run the real role-image command checks and the private
Tessera integration status on the exact final CLI commit. Do not point live
Tessera at a local build, synthetic manifest, moving release, or unreviewed pin.

Saved workflows and frozen ceremonies are never silently migrated to this recipe.
