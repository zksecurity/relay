## What changed

- Bound proof containers to two CPUs and 6 GiB memory, with no additional swap, a 4 GiB Go memory target and GOGC=25. Verify participant limits and reject unsupported Docker capacity before computation.
- Support host IAM-user profiles for renewable 12-hour coordinator sessions and scoped grants. Permanent credentials remain on the host; the approved role image authenticates the ceremony request before grant issuance.
- Avoid retransmitting verified immutable storage objects when authoritative ETag, version and size match. Preserve successful upload records after partial failures, retaining full verification on uncertainty.
- Show elapsed progress during checkpoint authentication before publication.

## Tessera compatibility

Setup contracts, signed ceremony artifacts and proof-tool pins are unchanged. Local participant lifecycle receipts record runtime limits while retaining recovery support for older receipts. Existing frozen ceremonies keep their release. The new IAM host-issuer mode requires a compatible launcher and role image; this release does not claim a qualified upgrade for an already active ceremony.
