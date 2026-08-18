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

## Three-machine rehearsal `.env` mapping

The [scripted three-machine rehearsal](../scripts/three-machine-rehearsal/README.md)
records non-secret paths, approved binary digests, and storage names in one
private `.env` per machine. These files are a rehearsal convenience, not the
production storage procedure.

Machine 1 copies
[its example](../scripts/three-machine-rehearsal/machine-1/.env.example) and
sets the storage variables as follows:

| Variable | Meaning |
|---|---|
| `STORAGE_PROVIDER` | `aws` for AWS S3 or `r2` for Cloudflare R2 |
| `PUBLISHED_BUCKET` | Published bucket name |
| `PUBLISHED_BASE_URL` | Anonymous HTTPS base URL for published objects |
| `INBOX_BUCKET` | Private inbox bucket name |
| `STORAGE_ENDPOINT` | S3-compatible endpoint URL, such as `https://s3.us-east-1.amazonaws.com` for AWS or the account endpoint for R2 |
| `COORDINATOR_PROFILE` | AWS CLI profile with coordinator bucket access |
| `REHEARSAL_WITNESS_BUFFER_SECONDS` | Tiny-rehearsal witness observation buffer |
| `AWS_REGION` | AWS region; used only when `STORAGE_PROVIDER=aws` |
| `ISSUER_PROFILE` | AWS CLI profile allowed to assume the inbox grant role |
| `GRANT_ROLE_ARN` | IAM role Relay assumes for scoped inbox grants |
| `GRANT_ROLE_MAX_TTL` | Maximum session duration configured on that role |
| `R2_ACCOUNT_ID` | R2 account ID; used only when `STORAGE_PROVIDER=r2` |
| `R2_PARENT_ACCESS_KEY_ID` | Access-key ID for the inbox-limited parent token |

Machines 2 and 3 copy their respective
[Machine 2](../scripts/three-machine-rehearsal/machine-2/.env.example) and
[Machine 3](../scripts/three-machine-rehearsal/machine-3/.env.example) examples.
Their `PUBLISHED_READER_PROFILE` names an AWS CLI profile with read-only access
to published ceremony objects. It is used by witness, mirror, and auditor
commands. `STORAGE_ENDPOINT` must match Machine 1's endpoint, including an R2
endpoint when applicable. Participants download published inputs through the
`PUBLISHED_BASE_URL` embedded in `relay-storage.json`; they do not receive the
coordinator profile or inbox issuer credential.

Keep each `.env` at mode `0600`. Do not put temporary role grants, AWS secret
access keys, `RELAY_R2_PARENT_TOKEN`, ceremony signing keys, or build-signing
keys in it. Configure named AWS profiles outside the repository. The R2 setup
script prompts for the parent token without echoing it. Evidence writers use
their separately issued, prefix-scoped grants; they never receive general
write access to either bucket.

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
