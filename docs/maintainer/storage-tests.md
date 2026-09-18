# Storage test coverage

Run the deterministic AWS S3 and R2 tests without credentials:

```bash
go test ./cmd/relay -run 'TestAWS|TestR2Scope|TestProbeCollision' -count=1
```

AWS tests exercise public reads, exact probe bytes, private-inbox denial,
permission failures, uncertain writes, collisions and cleanup failures. STS
request tests check the intended role/profile, narrow inbox-prefix policy and
session-duration limits. Mocked results do not establish real cloud permissions.

For an existing probe object, an anonymous "not found" response is inconclusive,
not a successful privacy check. See [AWS HeadObject semantics](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html).

## Live AWS infrastructure test

Obtain approval for temporary writes in two **existing test buckets**. Do not
create buckets, change IAM policies or enable public access as part of this test.
Provide a dedicated owner-only AWS credentials file containing only the test
coordinator/issuer profiles, plus administrator-prepared non-secret settings.
Alternatively, use the isolated test AWS CLI wrapper after a fresh interactive
login; the test obtains a short-lived protected snapshot without printing
credentials. Never use the machine's default company AWS profile.

Set these non-secret environment variables:

- `RELAY_AWS_LIVE_SETTINGS_FILE`: absolute administrator settings JSON path.
- `RELAY_AWS_LIVE_CREDENTIALS_FILE`: absolute dedicated protected file path.
  Omit only when using the isolated wrapper below.
- `RELAY_AWS_TEST_CLI`, `RELAY_AWS_LIVE_EXPECTED_ACCOUNT`, and
  `RELAY_AWS_LIVE_EXPECTED_PRINCIPAL`: required together for the isolated
  wrapper path; the test rejects any other logged-in identity.
- `RELAY_ROLE_ONLINE_IMAGE`: exact test image digest containing these changes.
- `RELAY_ROLE_PLATFORM`: `linux/amd64` or `linux/arm64`.
- `RELAY_AWS_LIVE_PROBES_APPROVED=1`: explicit approval for isolated probe writes.

Then run:

```bash
go test ./cmd/relay -run '^TestAWSLiveIsolatedStoragePreflight$' -count=1 -v
```

The test uses a local Docker daemon, fresh random `setup-probes/` keys and
read-only credential mounts. It checks write/read/public-read/private-inbox
behavior and deletion. Inspect exact reported keys after ambiguous writes or
cleanup failures; never delete a whole bucket or ceremony prefix.

This lane now tests version-pinned coordinator reads from both buckets. It does
**not** test STS grant scope or actual credential expiry. Those require separate
live grant checks; AWS role sessions last at least
[15 minutes](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).
Normal CI skips all live tests. Never put credentials in logs, arguments or PRs.

For a short signed-state provider check, set the same isolated wrapper/account
variables, `RELAY_PREPARE_TEST_IMAGE`, `RELAY_V4_LIVE_ONLINE_IMAGE`, and
`RELAY_V4_LIVE_PROOF_BINARY` (the exact-source native companion), then run
`go test ./cmd/relay -run '^TestV4LiveInitialAWS$' -count=1 -v`. This creates
a fresh tiny signed definition, publishes its initial checkpoint and required
public files to the dedicated AWS test bucket, verifies them from an empty
workspace, and checks conflicting blob/root writes are rejected. It does not
compute participant contributions. The signed synthetic test state remains in
the dedicated versioned bucket for inspection; there is no broad cleanup.

## Dedicated-account follow-up lanes

`TestAWSLiveGrantScopeAndExpiry` exercises real 15-minute STS expiry and narrowly
scoped read/write denials on fresh synthetic keys. Its coordinator control login
must remain valid through expiry and cleanup; an expired control makes the result
inconclusive. Set `RELAY_AWS_LIVE_EXPECTED_ACCOUNT` explicitly; the fixture only
accepts `relay-test-` bucket/role names in that account. Approval is still required.
For a fast scope check without waiting for expiry, set
`RELAY_AWS_LIVE_SCOPE_ONLY=1`; the test also requires the allowed prefix's
version-pinned read and explicitly reports that expiry was skipped. The isolated
test wrapper can refresh the protected coordinator snapshot in either mode.

`TestRoleFlowDockerFullCeremony` with `RELAY_FLOW_AWS_APPROVED=1` sends the six
candidate contributions through scoped AWS grants, then downloads, verifies,
accepts and publishes heads through S3/CloudFront. Audits, witness/mirror claims
and final-signer handoffs still use local same-host fixtures; this is not a test
of independent operators or every role's cloud transport.

An exported `aws login` snapshot does not refresh itself. The AWS ceremony test
uses its explicitly selected isolated CLI to obtain a fresh protected snapshot
before each coordinator action. Ordinary role profiles still need valid supplied
credentials; the harness does not establish automatic CLI-session refresh there.
The ceremony lane also requires `RELAY_AWS_TEST_CLI` (absolute isolated wrapper),
`RELAY_AWS_LIVE_EXPECTED_PRINCIPAL` (exact IAM-user ARN), and
`RELAY_AWS_TEST_BINARY` (Linux test executable containing the transport hook).

## Live R2 result

The opt-in full V4 R2 journey accepts local image names for developer builds,
but resolves each name to one immutable local `sha256:` image ID before ceremony
setup. All subsequent commands use that ID; production commands continue to
reject mutable tags. Its native inspection binary must be built from the exact
Proof-tool release commit, with clean VCS metadata and the same Go version,
CGO and trim-path settings as the Linux release binaries. A convenient local
build that omits `vcs.revision` is not an authenticated companion binary and
must fail before initialization.

Keep these inputs distinct:

- the approved Linux Proof-tool binary is inside each role image and performs
  ceremony work;
- `RELAY_V4_LIVE_PROOF_BINARY` is the exact-source native companion used only
  by the macOS test controller and signed into the mixed-platform allowlist.

Do not substitute one path for the other or rebuild the native companion from
a dirty checkout.

### Follow-up: bounded parallel immutable transfers

The current full-release lane transfers immutable objects serially. That is
safe but slow for a release package with many small files. After this release,
add bounded parallel uploads/downloads while preserving create-only writes,
manifest-last publication, exact byte/hash reconciliation, deterministic error
reporting, and safe retry after an interrupted batch. Do not make this
performance work a prerequisite for authenticating or resuming a ceremony.

On 2026-09-08, `TestR2LiveIsolatedStoragePreflight` passed in 56.33 seconds
using a local Linux/ARM64 development image. It checked public object bytes,
inbox domain privacy, parent denial on the selected published bucket, temporary
grant prefix/bucket restrictions, and deletion of its random probe objects.
It did not test other account buckets or a complete R2-backed ceremony.

R2 returned `SignatureDoesNotMatch` for an expired locally signed token. A
backdated-token rejection alone was inconclusive. The check now first uses a
20-second credential successfully, waits past its real expiry, verifies a fresh
control grant still works, then requires the original credential to be rejected.
That controlled sequence permits the observed R2 signature error; arbitrary
signature errors, network failures and unsuccessful control reads do not pass.
Normal CI uses an injected clock, never live credentials or real expiry waits.

## Role evidence handoffs

`TestAWSLiveRoleEvidenceHandoffs` uses a completed tiny rehearsal's public
artifacts. Separate containers issue enrolled-role grants, upload with only the
scoped grant, and download through coordinator access. It covers witness, mirror,
auditor and the offline signer's public release via the upload-station role.
Received bytes are compared with the previously verified fixture; this is not
independent human operation or a new ceremony observation.

Evidence transport uses `relay-evidence-submission-v2`: payload objects are under
`<attempt>/files/`, and `<attempt>/manifest.json` is written last. This prevents
a release bundle's own `manifest.json` from colliding with the transport marker.
The coordinator requires the v2 layout; do not mix old and new role releases.
Failed partial uploads remain unaccepted; preserve their exact prefix for review.

On 2026-09-08, the v2 witness/mirror/auditor upload-and-download retest passed
in 67.08 seconds; the release-bundle transport subtest passed in 863.76 seconds.
These are separate runs, not one uninterrupted all-role ceremony. A dedicated
downloaded-release cryptographic verification lane uses an independently supplied
public signer anchor. Long downloads need credentials with sufficient remaining
lifetime; an exported browser login can expire during the operation. This test
can issue a one-hour session restricted to the selected test release prefix;
ordinary coordinator commands do not automatically renew credentials.

## Parallel artifact publication (2026-09-18)

`coordinator commit-v4` publishes the cumulative artifact inventory with
bounded parallelism: a byte-weighted in-flight cap (default 2 GiB, so staged
copies of up-to-16 GiB artifacts never exceed it on coordinator disk) and a
worker cap (default 8), with deterministic first-artifact error reporting and
idempotent retries. A workspace-local `verified-objects.json` beside the
public artifact root records the object versions this coordinator has
digest-verified. Already-present artifacts are confirmed by one
object-metadata request and re-downloaded only when the stored version is
unknown, changed, or metadata is unavailable; the file is private workspace
state, is never published, and losing it only costs verification work.

Unit tests cover partial failure, an already-present object, a conflicting
remote object, cancellation, and retry (`internal/storagefirst/publish_test.go`
and `verified_objects_test.go`). Benchmarks with a simulated 2 ms provider
latency and 64 objects of 64 KiB on an Apple M1 Pro: sequential publication
235 ms, parallel publication 34 ms, memo-confirmed re-publication 26 ms.
