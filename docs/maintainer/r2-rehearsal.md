# R2 rehearsal provisioning

Production uses [explicit-token setup](r2.md).

The rehearsal path uses one Wrangler browser login. Relay then discovers the
Cloudflare account and active zones, generates bucket names, creates both
buckets, validates the credentials, and updates Machine 1's `.env`. When the
account has an active zone, it attaches a custom hostname. Otherwise it uses a
Cloudflare-managed `r2.dev` URL for the published rehearsal bucket only.

The recommended path has one unavoidable dashboard step: create a short-lived
token manager. Relay uses it to create two differently scoped R2 tokens through
Cloudflare's API, stores their one-time credentials locally, and never uses the
powerful token for ceremony uploads.

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

The coordinator-side Wrangler OAuth token is refreshed on demand for the inbox
public-access check. Token values are never copied into `.env`.

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


For credential scope, retention, and production hostname requirements, see [R2 production](r2.md).
