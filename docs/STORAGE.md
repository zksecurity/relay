# Storage setup reference

This reference describes the infrastructure that must exist before running
`relay coordinator configure-storage`. The ceremony procedure is in the
[coordinator runbook](../COORDINATOR_RUNBOOK.md).

## Storage model

Use two buckets on the same S3-compatible endpoint:

    <published bucket>
      state/<ceremony-id>/<phase>/head.json
      blob/sha256/<hex>

    <private inbox bucket>
      candidates/<ceremony-id>/<participant-id>/<phase>/<index>/<attempt-id>/
      operational/witnesses/<ceremony-id>/<witness-id>/<attempt-id>/
      operational/mirrors/<ceremony-id>/<mirror-id>/<attempt-id>/
      audits/<ceremony-id>/<auditor-id>/<attempt-id>/
      releases/<ceremony-id>/<release-signer-id>/<attempt-id>/
      decisions/<ceremony-id>/<signer-id>/<attempt-id>/

Published objects must be anonymously readable through an HTTPS base URL. The
bucket may remain private behind a CDN. Only the coordinator writes it. The
inbox remains private, and each writer receives temporary access only to their
own prefix.

The separate evidence prefixes reflect distinct proof-tool records: public
witness receipts, immutable-mirror receipts, audit records, release bundles,
and production-decision signatures. Possessing a storage credential proves
only access to a prefix; proof-tool verification decides whether an uploaded
record is valid.

## Common prerequisites

Before `configure-storage`:

1. Complete `mpc-ceremony init`. Storage prefixes require its ceremony ID.
2. Create a published bucket and private inbox bucket. Never attach a public
   policy, website endpoint, CDN behavior, or public hostname to the inbox.
3. Configure a public HTTPS URL for the published bucket. Disable caching, or
   use a deliberately short TTL, for mutable `state/*`. Cache immutable
   `blob/*` indefinitely.
4. Create a coordinator runtime credential that can read, write, and delete in
   the published bucket and list, read, write, and delete in the inbox. Deletes
   are needed only for disposable preflight probes.
5. Configure a provider-specific temporary-credential issuer limited to the
   inbox. Never distribute its parent credential to a ceremony role.
6. Decide the explicit credential TTL and minimum upload window for each role.
   Include replay, contribution, erasure, and upload time. Synchronize clocks.
7. From another machine, confirm that the public URL works anonymously, the
   inbox does not, and a scoped test credential cannot escape its prefix.

Create signed proof-of-possession enrollment records for every non-participant
identity that will receive a grant. Relay authenticates them before granting
witness, mirror, auditor, release, or decision access.

## Cloudflare R2

The S3 endpoint is:

    https://<account-id>.r2.cloudflarestorage.com

For production, map an ordinary HTTPS hostname controlled by the coordinator,
such as `https://ceremony.example.org`, to the published bucket. Cloudflare's
generated `r2.dev` URL is rate-limited and intended for development.

Create a parent R2 API token limited to the private inbox bucket and no broader
than the access it delegates. Record its access-key ID. Supply the parent token
through `RELAY_R2_PARENT_TOKEN` or a secret manager, never a command-line flag
or shell history. Revoking it revokes all credentials derived from it.

R2 grants must not exceed `168h`.

## AWS S3

Keep both buckets private. Put CloudFront in front of the published bucket and
use Origin Access Control so only CloudFront can read the S3 origin. A generated
CloudFront URL is sufficient; custom DNS is optional. Give `state/*` and
`blob/*` separate cache behaviors.

Create an IAM role dedicated to Relay inbox grants. Its base policy must be
limited to the inbox, and its trust policy must allow only the coordinator's
issuer to call `sts:AssumeRole`. Relay adds a session policy restricting each
session to one exact role prefix.

AWS grants must be at least `15m` and no longer than the role's configured
maximum session duration. AWS permits a role maximum from one to twelve hours.
Role chaining caps a session at one hour, so use a direct IAM identity when a
longer upload window is required.

## Evidentiary mirrors

R2 is appropriate for high-egress distribution, but it does not implement S3
Object Lock. Use S3 Object Lock in COMPLIANCE mode for an evidentiary mirror:

    aws s3api create-bucket --bucket <name> --object-lock-enabled-for-bucket
    aws s3api put-bucket-versioning --bucket <name> \
      --versioning-configuration Status=Enabled
    aws s3api put-object-lock-configuration --bucket <name> \
      --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Years":10}}}'

Object Lock must be enabled when the bucket is created. COMPLIANCE retention
cannot be shortened, even by the root account, so do not enable a long period
on a test bucket. GOVERNANCE mode can be bypassed and does not provide the same
claim.

Two mirrors operated in one account are still one administrative failure
domain. Evidentiary mirrors should have independent operators.
