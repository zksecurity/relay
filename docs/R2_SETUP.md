# Cloudflare R2 storage setup

This guide creates the Cloudflare R2 resources required by Relay and prints the
exact non-secret values for the coordinator's rehearsal `.env`. The same
resources can be passed to `relay coordinator configure-storage` in production.

The setup creates:

- a private published R2 bucket;
- a private inbox R2 bucket;
- a custom HTTPS domain attached only to the published bucket;
- disabled `r2.dev` access on both buckets;
- a local AWS CLI profile for coordinator S3-compatible access.

It does not store Cloudflare API token values in `.env`. The script prompts for
them without echo and removes them from its environment when validation is
complete. It never deletes buckets or objects and can incur Cloudflare charges.

## 1. Prepare the Cloudflare account and domain

Before starting:

1. Enable R2 for a dedicated ceremony Cloudflare account when possible.
2. Put the domain that will publish ceremony data in an active Cloudflare zone
   in the same account. For example, use `ceremony.example.org`.
3. Record the 32-character account ID and zone ID from the dashboard.
4. Install `curl`, `jq`, and AWS CLI v2. Relay uses AWS CLI as its
   S3-compatible transport even when the provider is R2.

This setup currently creates default-jurisdiction R2 buckets. Relay's R2 inbox
privacy request does not send a jurisdiction header, so do not choose an EU,
FedRAMP, or US jurisdictional bucket for this workflow yet.

## 2. Create a temporary provisioning token

Create a short-lived Cloudflare API bearer token that can create and configure
R2 buckets in the selected account and attach the published custom domain in
the selected zone. Give it only the account R2 write and relevant zone/DNS
permissions required by the dashboard. Restrict its lifetime and source IP
when practical.

The setup script prompts for this token and does not persist it. Revoke it when
setup is complete. Do not use it later as Relay's parent or control token.

## 3. Fill the setup configuration

```bash
cp scripts/storage-setup/r2.env.example /secure/relay-r2.env
chmod 0600 /secure/relay-r2.env
${EDITOR:-vi} /secure/relay-r2.env
```

Set the account and zone IDs, ceremony-specific bucket names, public hostname,
and coordinator AWS CLI profile name. Leave the file open for now: the inbox
parent Access Key ID is filled after the script creates the buckets.

The public hostname must be part of the zone identified by `R2_ZONE_ID`. Relay
will reject the configuration if the inbox has either an `r2.dev` address or a
custom domain.

## 4. Start the setup and create the scoped R2 tokens

Leave the provided placeholder in `R2_PARENT_ACCESS_KEY_ID`, set
`CONFIRM_CREATE=yes`, and start:

```bash
scripts/storage-setup/setup-r2.sh /secure/relay-r2.env
```

Enter the provisioning token when prompted. The script creates both buckets,
disables their `r2.dev` domains, attaches the custom domain only to the
published bucket, then exits so the bucket-scoped credentials can be created.

While it is waiting, open **R2 > Overview > Manage R2 API tokens** and create:

1. **Coordinator S3 token:** `Object Read & Write`, scoped to both the published
   and inbox buckets. Save its Access Key ID and Secret Access Key. The script
   stores these in the named AWS CLI profile, not `.env`.
2. **Inbox parent token:** `Object Read & Write`, scoped only to the inbox
   bucket. Save its API token value, Access Key ID, and Secret Access Key when
   they are shown. Relay's hosted temporary-credential request needs the API
   token value and matching Access Key ID. Keep all of them in the coordinator's
   secret manager.

Also create a separate standard Cloudflare API bearer token with account-level
`Workers R2 Storage Read` permission. This is the **control-plane read token**
Relay uses only to prove that the inbox has no public domain. Cloudflare does
not currently offer that configuration-read permission at individual-bucket
scope, so use a dedicated R2 account if account-wide read is unacceptable.

Put the inbox parent Access Key ID into `/secure/relay-r2.env`, then rerun the
script. On the second run, provide these values at the prompts:

- coordinator Access Key ID and Secret Access Key;
- inbox parent API token value;
- control-plane read token.

The script validates all three without printing the secrets. Its test temporary
credential expires after 15 minutes and is limited to `setup-validation/`.

## 5. Copy the printed `.env` values

The successful script prints a block like:

```bash
STORAGE_PROVIDER=r2
PUBLISHED_BUCKET=example-ceremony-published
PUBLISHED_BASE_URL=https://ceremony.example.org
INBOX_BUCKET=example-ceremony-inbox
STORAGE_ENDPOINT=https://ACCOUNT_ID.r2.cloudflarestorage.com
COORDINATOR_PROFILE=relay-r2-coordinator
AWS_REGION=
ISSUER_PROFILE=
GRANT_ROLE_NAME=
GRANT_ROLE_ARN=
R2_ACCOUNT_ID=ACCOUNT_ID
R2_PARENT_ACCESS_KEY_ID=PARENT_ACCESS_KEY_ID
```

Copy those non-secret values into Machine 1's `.env`. Do not put the parent API
token value, parent Secret Access Key, control-plane token, or coordinator
Secret Access Key in that file.

Cloudflare may take time to activate the custom-domain certificate. Wait until
the R2 bucket's Custom Domains panel reports the domain active before running
Relay's preflight.

## 6. Run Relay's preflight

```bash
REHEARSAL_ROOT=/home/REPLACE_WITH_USER/ceremony-tools/three-machine-rehearsal
"$REHEARSAL_ROOT/00-check-machine.sh" "$REHEARSAL_ROOT/machine-1/.env"
"$REHEARSAL_ROOT/01-coordinator-configure-storage.sh" \
  "$REHEARSAL_ROOT/machine-1/.env"
```

The configure script prompts separately for the control-plane read token. Later
grant commands prompt for the inbox parent token. Neither is echoed or saved in
the rehearsal `.env` or `relay-storage.json`.

Relay's preflight writes and reads a disposable published object through both
the S3-compatible endpoint and custom HTTPS domain. It also writes and removes
an inbox probe and queries Cloudflare's control API to verify that the inbox has
no public domains.

## Production notes

- Revoke the provisioning token after setup.
- Keep coordinator, parent, and control-plane credentials in separate secret
  records and rotate each independently.
- Do not enable `r2.dev`; it is intended for development and does not provide
  the production custom-domain controls.
- The default setup favors correctness by not adding cache rules. If an
  operator adds caching, keep mutable `state/*` uncached and cache only
  immutable `blob/*` paths.
- R2 does not provide S3 Object Lock. Use independent S3 Object Lock mirrors
  when immutable evidentiary retention is required.

Cloudflare references: [creating R2 buckets](https://developers.cloudflare.com/r2/buckets/create-buckets/),
[R2 API tokens](https://developers.cloudflare.com/r2/api/tokens/),
[public custom domains](https://developers.cloudflare.com/r2/buckets/public-buckets/),
and [temporary credentials](https://developers.cloudflare.com/r2/api/s3/temporary-credentials/).
