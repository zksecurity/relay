# Cloudflare R2 storage setup

The recommended rehearsal path uses one Wrangler browser login or a protected
token transferred from an authenticated laptop. Relay then discovers the
Cloudflare account and active zones, generates bucket names, creates both
buckets, validates the credentials, and updates Machine 1's `.env`. When the
account has an active zone, it attaches a custom hostname. Otherwise it uses a
Cloudflare-managed `r2.dev` URL for the published rehearsal bucket only.

The recommended path has one unavoidable dashboard step: create a short-lived
token manager. Relay uses it to create two differently scoped R2 tokens through
Cloudflare's API, stores their one-time credentials locally, and never uses the
powerful token for ceremony uploads.

## What the automatic setup creates

- a private published R2 bucket;
- a private inbox R2 bucket;
- either a custom HTTPS domain or rehearsal-only `r2.dev` access on the
  published bucket;
- disabled `r2.dev` access and no custom domain on the inbox;
- a local AWS CLI profile for coordinator S3-compatible access;
- mode-`0600` local files containing the inbox-parent Access Key ID, API token,
  and Secret Access Key;
- Machine 1 storage settings, without secret token values.

It never deletes buckets or objects and can incur Cloudflare charges. The
default setup uses R2's default jurisdiction because Relay's inbox privacy
request does not yet send a jurisdiction header.

## 1. Prepare the account once

Before starting:

1. Enable R2 in the ceremony Cloudflare account.
2. For a production-like origin, put the domain that will publish ceremony
   data in an active Cloudflare zone in the same account. The setup will
   propose a subdomain such as `relay-ceremony.example.org`. This is optional
   for a rehearsal: without a zone, the script clearly selects `r2.dev`.
3. Install AWS CLI v2, `curl`, `jq`, Node.js, and Wrangler v4. Relay uses AWS
   CLI as its S3-compatible R2 transport.

For a rehearsal, install Wrangler through the coordinator's approved package
channel. For example:

```bash
npm install --global wrangler@4
wrangler --version
```

## 2. Log in through the browser

On a desktop machine, this is normally enough:

```bash
wrangler login
wrangler whoami
```

For a remote SSH coordinator, forward Wrangler's callback port from the laptop:

```bash
ssh -L 8976:127.0.0.1:8976 USER@COORDINATOR
```

If SSH reports `Address already in use`, find and stop the local process that
already owns the callback port before reconnecting:

```bash
lsof -nP -iTCP:8976 -sTCP:LISTEN
```

An SSH `connect failed: Connection refused` message before Wrangler starts is
expected: the tunnel exists, but Wrangler has not opened its remote listener
yet. Start the login command below before opening the authorization URL.

Inside that same SSH session, run:

```bash
wrangler login \
  --browser=false \
  --callback-host 127.0.0.1 \
  --callback-port 8976
```

Open the printed URL in the laptop browser. Its redirect to
`http://localhost:8976` crosses the SSH tunnel back to Wrangler.
Binding Wrangler explicitly to `127.0.0.1` is important on systems where
`localhost` resolves to IPv6 but the SSH tunnel targets IPv4.

Use this callback flow if `wrangler login --device` returns HTTP 403 with a
Cloudflare challenge page. That failure means the device endpoint challenged
the server IP before account authentication; it does not mean the account
password was rejected.

If the browser callback succeeds but the final token exchange receives another
HTTP 403 challenge, authenticate Wrangler on the laptop instead. Export only
the current short-lived access token to a mode-`0600` file, transfer it over
SSH, and keep the refresh credential in the laptop's keychain:

```bash
# Laptop
wrangler login --use-keyring
umask 077
wrangler auth token >"$HOME/.cloudflare-relay-oauth-token"
chmod 0600 "$HOME/.cloudflare-relay-oauth-token"
ssh jason@COORDINATOR 'mkdir -m 0700 -p "$HOME/.config/relay"'
scp "$HOME/.cloudflare-relay-oauth-token" \
  jason@COORDINATOR:.config/relay/cloudflare-setup-oauth-token
ssh jason@COORDINATOR \
  'chmod 0600 "$HOME/.config/relay/cloudflare-setup-oauth-token"'
```

Then select that protected file with `--cloudflare-token-file` in step 3. Run
storage setup and `01-coordinator-configure-storage.sh` before the access token
expires. If necessary, `wrangler auth token` refreshes it on the laptop; repeat
the protected transfer. After preflight, run `wrangler logout` on the laptop
to invalidate the OAuth session, then remove the transferred copy from the
coordinator:

```bash
rm -- "$HOME/.config/relay/cloudflare-setup-oauth-token"
```

## 3. Create one short-lived token manager

In the Cloudflare dashboard, go to **Manage Account > Account API Tokens** and
create an account-owned token with:

- name `Relay R2 credential provisioner`;
- only **Account > Account API Tokens > Edit** permission;
- only the ceremony Cloudflare account as its resource;
- the shortest practical expiration and, when stable, the coordinator's source
  IP restriction.

Creating account-owned tokens requires a Super Administrator. This credential
can create other account tokens, so do not reuse it as an R2, Wrangler, or
ceremony credential. Copy its one-time value into a protected file without
putting it in shell history:

```bash
TOKEN_MANAGER_FILE="$HOME/.config/relay/cloudflare-token-manager"
mkdir -m 0700 -p "$(dirname "$TOKEN_MANAGER_FILE")"
read -rsp 'Cloudflare token manager: ' TOKEN_MANAGER
printf '\n'
printf '%s\n' "$TOKEN_MANAGER" >"$TOKEN_MANAGER_FILE"
chmod 0600 "$TOKEN_MANAGER_FILE"
unset TOKEN_MANAGER
```

Revoke this token from **Manage Account > Account API Tokens** immediately
after setup succeeds, then remove its local copy:

```bash
rm -- "$TOKEN_MANAGER_FILE"
```

The generated bucket-scoped credentials remain valid.

## 4. Run the automatic setup

From an extracted ceremony kit, Machine 1's default paths are:

```bash
STORAGE_SETUP_ROOT="$HOME/ceremony-tools/storage-setup"
MACHINE1_ENV="$HOME/ceremony-tools/three-machine-rehearsal/machine-1/.env"

"$STORAGE_SETUP_ROOT/scripts/storage-setup/setup-r2-wrangler.sh" \
  --token-manager-file "$TOKEN_MANAGER_FILE" \
  --machine-env "$MACHINE1_ENV"
```

If Wrangler is not on `PATH`, select its absolute executable:

```bash
"$STORAGE_SETUP_ROOT/scripts/storage-setup/setup-r2-wrangler.sh" \
  --wrangler-bin /absolute/path/to/wrangler \
  --token-manager-file "$TOKEN_MANAGER_FILE" \
  --machine-env "$MACHINE1_ENV"
```

If the coordinator uses the protected token transferred from its laptop:

```bash
"$STORAGE_SETUP_ROOT/scripts/storage-setup/setup-r2-wrangler.sh" \
  --cloudflare-token-file "$HOME/.config/relay/cloudflare-setup-oauth-token" \
  --token-manager-file "$TOKEN_MANAGER_FILE" \
  --machine-env "$MACHINE1_ENV"
```

The script automatically:

1. reads the authenticated accounts from `wrangler whoami --json`;
2. selects the only account, or asks which account to use;
3. lists active zones and selects the only one, asks which zone to use, or
   selects a rehearsal-only `r2.dev` origin when none exist;
4. proposes `relay-ceremony` as the resource prefix and generates both bucket
   names from it and the account ID;
5. proposes a published hostname below the selected zone, when one exists;
6. creates or validates the resources and their privacy settings;
7. creates a coordinator token scoped to both buckets and an inbox-parent token
   scoped only to the inbox;
8. derives their S3 credentials, stores all one-time values in mode-`0600`
   files, configures the coordinator AWS CLI profile, and configures Relay to
   sign temporary participant credentials locally with the parent Secret
   Access Key;
9. waits up to ten minutes for a custom domain and TLS certificate to become
   active; a generated `r2.dev` origin is available immediately.

Review the printed plan and type `yes` before it creates anything.

## Manual scoped-token fallback

Without `--token-manager-file`, setup pauses after creating the buckets. Open
**R2 Object Storage > Manage API Tokens** in the selected account and create:

1. **Coordinator S3 token:** `Object Read & Write`, scoped to the published and
   inbox buckets. Enter its Access Key ID and Secret Access Key at the prompts.
2. **Inbox parent token:** `Object Read & Write`, scoped only to the inbox
   bucket. Enter its Access Key ID, API token value, and Secret Access Key at
   the prompts. Relay uses the Secret Access Key to sign temporary credentials
   locally. It retains the API token only for compatibility with Cloudflare's
   hosted temporary-credential API.

Both automatic and manual paths validate the credentials without printing
them. They import the coordinator S3 pair into the chosen AWS CLI profile. The
automatic path stores the complete scoped credential set under the directory
below. The Wrangler wrapper also uses this directory when it falls back to
manual credential entry:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/relay/RESOURCE_PREFIX-r2/
```

The directory is mode `0700` and every credential file is mode `0600`. Machine
1's `.env` contains only absolute paths to the protected parent credential
files. Grant commands prefer the Secret Access Key, sign an expiring JWT on the
coordinator, and remove the secret from their environment immediately after
use. The issued grant contains only the temporary Access Key ID, derived Secret
Access Key, and session token; it never contains the parent credential. This
locally signed path was used in the real R2 rehearsal and does not call
Cloudflare's hosted temporary-credential API when a grant is issued.

With a coordinator-side Wrangler login, its OAuth token is refreshed on demand
for the inbox public-access check. With the laptop-transfer fallback, the
protected short-lived token file is reused for that one preflight. Token values
are never copied into `.env`.

## 5. Continue the rehearsal

The setup waits for any custom-domain certificate and updates Machine 1
automatically. A rehearsal-only `r2.dev` origin requires no certificate wait.
Then run:

```bash
REHEARSAL_ROOT="$HOME/ceremony-tools/three-machine-rehearsal"

"$REHEARSAL_ROOT/00-check-machine.sh" \
  "$REHEARSAL_ROOT/machine-1/.env"
"$REHEARSAL_ROOT/01-coordinator-configure-storage.sh" \
  "$REHEARSAL_ROOT/machine-1/.env"
```

Relay writes and reads a disposable published object through the S3-compatible
endpoint and published HTTPS origin. It also writes and removes an inbox probe
and uses the current Wrangler token to prove the inbox has neither `r2.dev` nor
a custom domain. The R2 endpoint is
`https://ACCOUNT_ID.r2.cloudflarestorage.com`; the AWS CLI region is `auto`.

After this preflight, an expired Wrangler login does not affect grants or
uploads. Log in again only when rerunning storage setup or `configure-storage`.
The bucket resources, AWS profile, and protected inbox-parent credentials
remain reusable.

## Choosing how much to test

You do not need to run the entire two-phase ceremony merely to check R2.

- Stop after `01-coordinator-configure-storage.sh` for a storage preflight. It
  proves coordinator writes, authenticated reads and deletes in both buckets,
  anonymous reads from the published origin, and the inbox public-domain
  configuration check.
- Continue through steps 2–14 of the three-machine rehearsal for an end-to-end
  ceremony transport check. This additionally proves participant-specific
  temporary credentials, ordered participant runs, candidate uploads to the
  private inbox, coordinator download and verification, publication of all
  three accepted contributions, phase closure, and anonymous witness reads.
  It is safe to stop before step 15; the beacon has not been recorded yet.

The second stopping point was exercised against real R2 on 2026-08-20. All
three participants uploaded through locally signed, prefix-scoped temporary
credentials, the coordinator accepted and published all three contributions,
and two role-machine views observed the closed phase at index 3.

Relay's published layout is content-addressed. Do not expect a readable name
such as `phase1/chain-0003.json` to appear as a literal R2 key. The mutable
`state/CEREMONY_ID/PHASE/head.json` maps logical filenames to immutable
`blob/sha256/HASH` objects.

## Explicit-token setup for production or restricted environments

Production operators may prefer a short-lived, least-privilege provisioning
token instead of Wrangler's broader OAuth session. Copy and review the explicit
configuration:

```bash
cp scripts/storage-setup/r2.env.example /secure/relay-r2.env
chmod 0600 /secure/relay-r2.env
${EDITOR:-vi} /secure/relay-r2.env
```

Create a provisioning token with account R2 write and the zone permissions
needed to attach the published domain. Put only its raw value in a protected
mode-`0600` file, then run:

```bash
mkdir -m 0700 -p /secure/relay-r2-credentials
scripts/storage-setup/setup-r2.sh \
  --provision-token-file /secure/r2-provision-token \
  --token-manager-file /secure/cloudflare-token-manager \
  --credential-root /secure/relay-r2-credentials \
  --parent-token-file /secure/relay-r2-credentials/inbox-parent-api-token \
  --control-token-file /secure/r2-control-read-token \
  --machine-env /absolute/path/to/machine-1/.env \
  /secure/relay-r2.env
```

The token manager needs only `Account > Account API Tokens > Edit`; revoke it
immediately after setup. The control token needs account-level `Workers R2 Storage Read`. Cloudflare
does not currently offer that configuration-read permission at individual
bucket scope, so use a dedicated ceremony R2 account if account-wide read is
unacceptable. Revoke the provisioning token after setup.

## Security notes

- Never put API token values or S3 secrets in the rehearsal `.env`, repository,
  shell history, or command-line arguments.
- Revoke the token manager and remove its local file after setup succeeds. It
  is more powerful than either generated R2 credential and is not used during
  the ceremony.
- Keep the coordinator and inbox-parent R2 credentials separate. A compromised
  parent credential must not gain published-bucket access. Never distribute
  its Secret Access Key to a participant; only distribute the expiring grant.
- Treat `r2.dev` as rehearsal-only. It is rate-limited and does not replace a
  production custom domain.
- R2 does not provide S3 Object Lock. Use independent S3 Object Lock mirrors
  when immutable evidentiary retention is required.
- If an operator adds caching, keep mutable `state/*` uncached and cache only
  immutable `blob/*` paths.

Cloudflare references: [Wrangler login](https://developers.cloudflare.com/workers/wrangler/commands/#login),
[creating R2 buckets](https://developers.cloudflare.com/r2/buckets/create-buckets/),
[R2 API tokens](https://developers.cloudflare.com/r2/api/tokens/),
[R2 custom domains](https://developers.cloudflare.com/r2/buckets/public-buckets/),
and [R2 temporary credentials](https://developers.cloudflare.com/r2/api/s3/temporary-credentials/).
