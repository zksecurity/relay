# Local ceremony-test storage

Test-only AWS CLI boundary adapter, not an S3/R2 implementation. No cloud
credential or fallback is used. `cmd/relay/testdata/localaws` sends bounded
requests to an ephemeral local HTTPS service; only online test containers mount
the adapter and CA. Original Proof-tool, contributor and signer images stay pinned.
The host test trusts the CA in its own HTTP client; OS trust is not changed.

The adapter enforces create-only writes, ETag conditional replacement, pinned
reads, bounded ranges, paginated lists, and the bucket/prefix/expiry of Relay's
locally derived R2 grant. Its objects are in memory and disappear after the test.
It accepts only the two synthetic test buckets and rejects unknown operations.

`TestUpgradeLocalTwoPhaseJourney` requires the exact-asset upgrade request and
candidate map described in the upgrade qualification guide, plus
`RELAY_UPGRADE_LOCAL_STORAGE=1`. It uses real cryptographic commands and future
beacons, switches the coordinator application after Phase 1, and reconstructs
the final release in an empty workspace. No provider configuration is needed.

Limitations: tiny artifacts (64 MiB per object), current versions only, no cloud
IAM/CDN/privacy checks, no infrastructure preflight, no provider conformance,
no public release authorization, and no native macOS guide reopening against
the temporary CA. These are not passing live-provider or full qualification tests.
The parent local native draft-reopening tests cover the separate setup UI path.

Never install this adapter in a release image or use real credentials with it.
