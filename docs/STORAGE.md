# Storage setup reference

This reference describes the infrastructure that must exist before running
`relay coordinator configure-storage`. The ceremony procedure is in the
[coordinator runbook](../COORDINATOR_RUNBOOK.md).

For complete provider provisioning instructions and setup scripts, use:

- [AWS S3, CloudFront, and IAM setup](AWS_SETUP.md)
- [Cloudflare R2 setup](R2_SETUP.md)

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
   inbox. For an R2 rehearsal, the guided setup can refresh the coordinator's
   current Wrangler OAuth token to verify the inbox's public-domain settings.
   The explicit production path instead uses a separate token with
   account-level `Workers R2 Storage Read`. Never distribute either credential
   to a ceremony role.
6. Decide the explicit credential TTL and minimum upload window for each role.
   Include replay, contribution, erasure, and upload time. Synchronize clocks.
7. From another machine, confirm that the public URL works anonymously, the
   inbox does not, and a scoped test credential cannot escape its prefix.

Create signed proof-of-possession enrollment records for every non-participant
identity that will receive a grant. Relay authenticates them before granting
witness, mirror, auditor, release, or decision access.

## Production configuration files

Production does not use the rehearsal shell `.env`. The coordinator's
validated configuration is `CEREMONY_HOME/config/relay-storage.json`, produced
by `relay coordinator configure-storage --home CEREMONY_HOME`. Each participant,
witness, mirror, auditor, or release upload station creates its own mode-`0600`
role profile with `relay ceremony init-config` after receiving that storage
file and staging the signed public ceremony.

The role profile copies only the published bucket name and HTTPS origin needed
for anonymous reads. It records absolute paths to the independently obtained
coordinator key, participant key, or operational enrollment, but embeds none of
their bytes. Temporary grants and provider credentials are never persistent
profile fields. Every role command reloads and validates the referenced
`relay-storage.json` and refuses a profile whose ceremony, bucket, or public
origin differs.

## Three-machine rehearsal `.env` mapping

The [scripted three-machine rehearsal](../scripts/three-machine-rehearsal/README.md)
records non-secret paths, approved binary digests, and storage names in one
private `.env` per machine. These files are a rehearsal convenience, not the
production storage procedure.

The verified ceremony kit's `setup --machine N` command creates the selected
`.env`, prefilling all software release fields. Machine 1 then sets the storage
variables as follows:

| Variable | Meaning |
|---|---|
| `WORK_ROOT` | Single absolute machine work root; all rehearsal data paths derive from it |
| `STORAGE_PROVIDER` | `aws` for AWS S3 or `r2` for Cloudflare R2 |
| `PUBLISHED_BUCKET` | Published bucket name |
| `PUBLISHED_BASE_URL` | Anonymous HTTPS base URL for published objects |
| `INBOX_BUCKET` | Private inbox bucket name |
| `STORAGE_ENDPOINT` | R2 account endpoint; for AWS it is derived from the selected profile's region |
| `COORDINATOR_PROFILE` | AWS CLI profile with coordinator bucket access; the guided AWS setup uses the same profile for both runtime fields |
| `REHEARSAL_WITNESS_BUFFER_SECONDS` | Tiny-rehearsal witness observation buffer |
| `AWS_REGION` | Optional AWS region override; normally read from `COORDINATOR_PROFILE` |
| `ISSUER_PROFILE` | AWS CLI profile allowed to assume the inbox grant role; normally equal to `COORDINATOR_PROFILE` in the simplified setup |
| `GRANT_ROLE_NAME` | IAM role name; AWS account ID is read with `sts get-caller-identity` |
| `GRANT_ROLE_ARN` | Optional full role-ARN override |
| `GRANT_ROLE_MAX_TTL` | Maximum session duration configured on that role |
| `R2_ACCOUNT_ID` | R2 account ID; used only when `STORAGE_PROVIDER=r2` |
| `R2_PARENT_ACCESS_KEY_ID` | Access-key ID for the inbox-limited parent token |
| `R2_PARENT_SECRET_FILE` | Protected local file containing the inbox-parent Secret Access Key used for local temporary-credential signing |
| `R2_PARENT_TOKEN_FILE` | Protected local file containing the inbox-parent API token; compatibility fallback for hosted issuance |
| `R2_CONTROL_TOKEN_FILE` | Optional protected control-token file for the explicit production path |
| `R2_CONTROL_WRANGLER_BIN` | Absolute Wrangler executable used to refresh the rehearsal control token |

The setup command likewise creates the Machine 2 and Machine 3 files from their
versioned templates. Witness, mirror, auditor, and participant reads use the
anonymous HTTPS origin recorded in the handed-off `relay-storage.json`; bucket
and origin settings are not repeated in the role-machine `.env`, and no
long-lived reader profile is needed. Role machines do not receive the
coordinator profile or inbox issuer credential.

Keep each `.env` at mode `0600`. Do not put temporary role grants, AWS secret
access keys, `RELAY_R2_CONTROL_TOKEN`, `RELAY_R2_PARENT_TOKEN`,
`RELAY_R2_PARENT_SECRET_ACCESS_KEY`, ceremony signing keys, or build-signing
keys in it. Configure named AWS profiles outside the repository. The
recommended R2 setup stores only protected credential-file paths and the
Wrangler executable path in the `.env`; it never stores credential values.
Evidence writers use their separately issued, prefix-scoped grants; they never
receive general write access to either bucket.

## Cloudflare R2

Use [R2_SETUP.md](R2_SETUP.md) to create both buckets, attach the published
custom domain, configure the coordinator profile, validate the parent and
control-plane credentials, and update the rehearsal `.env` automatically.

The S3 endpoint is:

    https://<account-id>.r2.cloudflarestorage.com

For production, map an ordinary HTTPS hostname controlled by the coordinator,
such as `https://ceremony.example.org`, to the published bucket. Cloudflare's
generated `r2.dev` URL is rate-limited and intended for development.

For a rehearsal, `configure-storage` refreshes the Wrangler OAuth token only
for its one-time inbox privacy check; later grants and uploads do not require
Wrangler. Its value is never written to the Machine 1 `.env`. For production
or a restricted environment, create a Cloudflare API bearer token with
account-level `Workers R2 Storage Read` and store it in a protected file.
Cloudflare does not support bucket-scoped configuration read; use a dedicated
ceremony R2 account if that scope is too broad.

Relay queries Cloudflare's control-plane API and refuses the configuration if
`r2.dev` is enabled or if any custom domain is attached to the inbox. An
anonymous request to the account S3 endpoint cannot perform this check because
R2 public buckets are exposed through separate domains.

Create a parent R2 API token limited to the private inbox bucket and no broader
than the access it delegates. The guided setup writes its API token and Secret
Access Key to separate mode-`0600` coordinator-owned files and puts only their
paths and the non-secret Access Key ID in Machine 1's `.env`. Relay normally
signs a short-lived JWT locally with the Secret Access Key and scopes it to one
identity prefix. The API token remains a compatibility fallback for hosted
issuance. Production may use an equivalent secret manager. Revoking the parent
token revokes all credentials derived from it.

The grant contains standard temporary S3 credentials, including a session
token. Treat it as a bearer secret until it expires. Never transfer the parent
Secret Access Key to a role machine.

R2 grants must not exceed `168h`.

## AWS S3

Use [AWS_SETUP.md](AWS_SETUP.md) to create both buckets, CloudFront OAC and
distribution, the scoped grant role, runtime policies, and print the rehearsal
`.env` values.

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
