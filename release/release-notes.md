## What changed

- Add saved CPU and memory limits for ceremony operations, with consistent Docker and Go settings, capacity checks, and an explicit aggregate Relay budget for hosts running other unbounded containers. Running operations keep their original allocation.
- Preserve allocations across contribution, coordinator, and release-signing recovery. Retain lifecycle timestamps and exact commands so a retry cannot silently become a new operation. Older retained operations keep the released resource defaults.
- Admit Docker work under a daemon-bound local lock, record created containers before starting them, and reject duplicate or ambiguous retained launches. Show the selected allocation and an elapsed-time heartbeat for guided commands.

## Tessera compatibility

Tessera setup contracts, signed ceremony formats, and proof-tool checksum and attestation pins are unchanged. This release changes local execution policy, UI, and private recovery records. New private recovery metadata requires this release or a compatible successor; do not downgrade a workspace after it writes that metadata. Existing frozen ceremonies continue using their approved proof/signing images. A CLI upgrade remains subject to the supported between-operation compatibility checks; this release does not authorize replacing proof-tool mid-ceremony.
