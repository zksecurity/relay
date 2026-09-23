## What changed

- Add saved CPU and memory limits for ceremony operations, with consistent Docker and Go settings, capacity checks, and an explicit aggregate Relay budget for hosts running other unbounded containers. Running operations keep their original allocation.
- Preserve allocations across contribution, coordinator, and release-signing recovery. Retain lifecycle timestamps and exact commands so a retry cannot silently become a new operation. Older retained operations keep the released resource defaults.
- Admit Docker work under a daemon-bound local lock, record created containers before starting them, and reject duplicate or ambiguous retained launches. Show the selected allocation and an elapsed-time heartbeat for guided commands.
- Keep onboarding at tool preparation after an interrupted or failed setup, even when profiles or identity files already exist. Preserve conflicting receipts and identities for review and retry.
- Use authenticated allocated inputs to avoid repeated historical MPC replay during participant work, while retaining each new transition check and full final reconstruction. Update coordinator progress and resource guidance to match those operations.
- Offer the tiny and K11 test circuits in standalone production-mode setup. Require a signed GO/NO-GO decision for every production-mode circuit and bind GO to the exact signed circuit and release. Test-circuit keys cannot prove ownership.
- Update Relay's immutable proof-tool pin to the verified release containing the V5 ceremony changes.

## Tessera compatibility

Tessera setup contracts are unchanged. Standalone tiny and K11 circuit selection is not available through the current Tessera setup contract; website support requires a future versioned contract and compatible Tessera release. This release changes the signed V5 ceremony and decision formats, the proof-tool pin, local execution policy, UI, and private recovery records. New private recovery metadata requires this release or a compatible successor; do not downgrade a workspace after it writes that metadata. Existing frozen ceremonies continue using their approved proof/signing images. A CLI upgrade remains subject to the supported between-operation compatibility checks; this release does not authorize replacing proof-tool mid-ceremony.
