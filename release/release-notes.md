## What changed

- Avoid retransmitting previously verified immutable storage objects when authoritative ETag, version and size still match. Uncertain metadata retains conditional upload and full download verification.
- Preserve verified upload records after a partially failed publication batch so retries can reuse completed work.
- Show elapsed progress while authenticating a signed checkpoint before publication.

## Tessera compatibility

This change preserves setup contracts, signed artifact formats and software pins. Existing frozen ceremonies retain their pinned release. Runtime and AWS improvements are still being prepared and are not included in this draft yet.
