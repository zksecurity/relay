# AWS storage setup

## From the guided coordinator menu

Choose **Set up storage and protected credentials → Set up Amazon S3 and
credentials**. Use an existing AWS CLI v2 login; provisioning also requires
local Bash and `jq`. No source checkout is required: the launcher includes the
reviewed setup helper.

1. Select your AWS profile and confirm the displayed account and identity.
   Root credentials are rejected. Use a dedicated ceremony account/login.
2. Choose **Use existing ceremony resources** to enter bucket names, public
   HTTPS address and grant-role ARN without changing infrastructure. Or choose
   **Create or repair dedicated ceremony resources** to review the exact resource
   names, charges and policy changes before typing `CREATE RESOURCES`.
3. Review and approve the credential configuration. Temporary logins save a
   protected host binding to the selected profile, AWS CLI executable, source
   files, login cache, account, and principal. A non-expiring IAM-user profile
   saves the same kind of host binding; Relay does not copy its access key.
   Relay verifies that it can obtain a 12-hour temporary session before saving.
   Neither option reduces the login's permissions.
4. Follow **Check storage** before initialization. Provisioning alone does not
   prove access, public delivery, or inbox privacy. These checks ask before writing
   and removing temporary probe objects.

For temporary logins, Relay refreshes credentials on the coordinator host during
an action. Docker receives only verified temporary credentials through a
read-only directory and an expiring `credential_process` provider. The host login
cache never enters the container. This also supports refresh during a single
long-running upload. Transient renewal failures are retried while the previous
credentials remain safely valid; identity changes stop the action immediately.
Failure to renew stops the action before the credentials expire. Review the
retained action using the normal recovery workflow before retrying.

Automatic renewal cannot extend the overall AWS login session. `aws login`
credentials normally last 15 minutes and can refresh within a session lasting up
to 12 hours. When the session ends, log in again **on the coordinator host** with
the same profile and identity; no MacBook is needed for renewal while that host
session remains valid. AWS CLI upgrades require repeating setup to review and
rebind the executable. See AWS's [login credential documentation](https://docs.aws.amazon.com/sdkref/latest/guide/feature-login-credentials.html).

For asynchronous production ceremonies, a dedicated least-privilege IAM-user
profile can provide a 12-hour operating window. Its access key remains only in
the host AWS credential source selected during setup. The host obtains a
temporary `GetSessionToken` session for coordinator storage actions. When Relay
issues a participant or evidence grant, the host uses the IAM user directly for
one `AssumeRole` call with the exact derived inbox prefix and lifetime. The role
container receives only that expiring scoped result, authenticates the signed
ceremony request again, and rejects any mismatch. This avoids AWS's one-hour
role-chaining limit without mounting the IAM-user key in Docker.
Normal exit removes the temporary runtime directory. After a host crash or
forced kill, first confirm no `relay-aws-login-*` action container remains,
then remove its matching mode-0700 `/tmp/relay-aws-login-*` directory; a scoped
grant inside can remain usable until its displayed expiry.

The IAM user needs the bucket permissions documented below and
`sts:AssumeRole` only for the configured grant role. Its credentials must be
eligible for the STS `GetSessionToken` API under the account's MFA and other
security policies; AWS does not normally authorize that API through an IAM
permission entry. Treat the access key as long-lived: store it in the protected
host profile, rotate it under your normal key policy, and repeat Relay setup
after rotation.
The role trust policy must name that user and its maximum session duration must
match the reviewed `grant-role-max-ttl`. Relay defaults that maximum to 12 hours
for an IAM-user login and to one hour for an assumed-role login. Existing v1
bindings and frozen role images keep their prior behavior; repeat setup and use
a release that advertises the v2 AWS-login provider to opt in.

Existing snapshots are unchanged. To opt into renewal, repeat setup with a
currently logged-in temporary profile, choose **existing resources**, then update
saved workflow credential references if already initialized. The pinned role
image must support renewal; older frozen images and legacy publication recovery
retain their existing credential workflow. Do not change a frozen ceremony's
release to enable this feature. Tessera-managed renewal remains a separate menu
option.

Creation can incur charges and reapplies policies on matching named resources;
never select a prefix used for unrelated infrastructure. Interrupted provisioning
retains its non-secret setup files and may leave cloud resources. There is no
automatic retry, rollback or resource deletion. Review the retained plan before
approving another attempt.

## Administrator/scripted setup

This guide creates the AWS resources required by Relay and prints the exact
non-secret values for the coordinator's `.env`. The default setup uses one AWS
CLI profile for provisioning, coordinator storage access, and temporary grant
issuance.

The setup creates:

- a private, encrypted, versioned S3 published bucket;
- a private, encrypted, versioned S3 inbox bucket;
- a CloudFront distribution with Origin Access Control (OAC) for anonymous
  reads from the published bucket only;
- no-cache delivery by default, with managed optimized caching for `blob/*`;
- an IAM role from which Relay derives temporary, prefix-scoped inbox grants.

The script never creates access keys, edits the selected profile's permission
set, or deletes cloud resources. It can incur AWS charges. Use a dedicated AWS
account for a rehearsal when possible.

The coordinator/issuer profile needs `s3:GetObjectVersion` as well as
`s3:GetObject` for both ceremony buckets. Relay pins authenticated reads to
the exact S3 version returned by its preceding HEAD request. The short-lived
inbox role created by the setup script receives `s3:GetObjectVersion` only
within its assigned upload prefix; administrator-managed existing grant roles
must provide the same restricted permission. Ordinary storage probes may pass
without this permission, so verify a signed V4 state publication before using
an existing policy for a ceremony.

For a role already prepared by an administrator, set `USE_EXISTING_GRANT_ROLE=yes`
in the setup config. Setup checks its caller-only trust and session duration
before cloud writes, and skips all IAM changes. This metadata check does not
verify the role's permission policies; test temporary grants separately.

## 1. Prepare one AWS profile

Install AWS CLI v2 and `jq` through the administrator's approved package
channel. Then create or select one short-lived profile.
For AWS IAM Identity Center:

```bash
aws configure sso --profile relay-ceremony
aws sso login --profile relay-ceremony
aws --profile relay-ceremony sts get-caller-identity
```

You do not need to create three AWS portal users or three local profiles. The
profile must have permission to create and configure the S3, CloudFront, and
IAM resources listed above, and to operate the resulting buckets. Ask the AWS
administrator responsible for the account to assign those permissions through
the organization's normal process.

In IAM Identity Center, this means one account assignment with one permission
set. If you already have a suitable administrator role, no portal change is
needed. `aws configure sso` only creates a local name for that existing portal
assignment. When prompted, use any memorable SSO session name (for example
`relay`), enter the start URL and SSO region supplied by your administrator,
select the ceremony account and role, and keep `relay-ceremony` as the CLI
profile name.

Using one profile is simpler, but it gives one identity all coordinator and
grant-issuer privileges. Protect that profile and prefer short-lived SSO
sessions. Organizations requiring stricter separation can still configure
Relay manually with different `--profile` and `--issuer-profile` values.

An SSO profile is suitable for the included rehearsal, whose grants require
only a 15-minute minimum upload window. For multi-hour production work, read
the credential lifetime warning below before choosing the identity type. AWS
caps a second role assumption from SSO/assumed-role credentials at one hour;
use the dedicated IAM-user host profile above when a grant must last longer.

## 2. Run the guided setup

From a reviewed Relay checkout or extracted storage-setup bundle, run:

```bash
MACHINE1_ENV="$HOME/ceremony-tools/three-machine-rehearsal/machine-1/.env"
scripts/storage-setup/setup-aws.sh --machine-env "$MACHINE1_ENV" \
  --coordinator-settings /secure/coordinator-storage-settings.json
```

The export path must be fresh and its parent folder must already exist.
Send the resulting JSON to the coordinator for **Storage settings → Import**.
Deliver credentials separately; the export contains no secret keys or tokens.

The script asks for:

- the AWS profile, defaulting to `relay-ceremony`;
- a resource prefix, defaulting to `relay-ceremony`;
- the maximum temporary credential lifetime, defaulting to `1h`.

It reads the region, AWS account ID, and stable IAM role or user ARN through
AWS CLI. It derives globally unique bucket names by adding the account ID:

```text
relay-ceremony-123456789012-published
relay-ceremony-123456789012-inbox
```

Review the displayed plan and type `yes` to proceed. CloudFront deployment
commonly takes several minutes. The script validates the generated Machine 1
file before provisioning and again immediately before atomically updating its
non-secret storage fields. If the standard Machine 1 path already exists, an
interactive run also detects it automatically when `--machine-env` is omitted.

## Non-interactive setup

For a repeatable production run, copy the small configuration template:

```bash
cp scripts/storage-setup/aws.env.example /secure/relay-aws.env
chmod 0600 /secure/relay-aws.env
${EDITOR:-vi} /secure/relay-aws.env
scripts/storage-setup/setup-aws.sh /secure/relay-aws.env | tee /secure/relay-aws-result.txt
```

Usually only `AWS_PROFILE` needs changing. `AWS_REGION` is read from that
profile, and resource names are derived automatically. Set the optional region
or name fields only to override those defaults. `CONFIRM_CREATE=yes` is the
non-interactive acknowledgement.

The script is safe to rerun with the same values. It reuses the named buckets,
OAC, distribution, and grant role; validates the delivery configuration; and
reapplies their security settings.

## 3. Confirm the generated values

On success, the script prints a block like:

```bash
STORAGE_PROVIDER=aws
PUBLISHED_BUCKET=relay-ceremony-123456789012-published
PUBLISHED_BASE_URL=https://d111111abcdef8.cloudfront.net
INBOX_BUCKET=relay-ceremony-123456789012-inbox
STORAGE_ENDPOINT=
COORDINATOR_PROFILE=relay-ceremony
AWS_REGION=us-east-1
ISSUER_PROFILE=relay-ceremony
GRANT_ROLE_NAME=relay-ceremony-inbox-grant
GRANT_ROLE_ARN=arn:aws:iam::123456789012:role/relay-ceremony-inbox-grant
GRANT_ROLE_MAX_TTL=1h
```

The `.env` is generated outside the immutable downloaded kit when the
coordinator runs `./setup --machine 1`. Its default absolute path is:

```text
~/ceremony-tools/three-machine-rehearsal/machine-1/.env
```

The command above updates it automatically. Confirm the exact assignments with:

```bash
MACHINE1_ENV="$HOME/ceremony-tools/three-machine-rehearsal/machine-1/.env"
test -f "$MACHINE1_ENV"
grep -E '^(STORAGE_PROVIDER|PUBLISHED_BUCKET|PUBLISHED_BASE_URL|INBOX_BUCKET|STORAGE_ENDPOINT|COORDINATOR_PROFILE|AWS_REGION|ISSUER_PROFILE|GRANT_ROLE_NAME|GRANT_ROLE_ARN|GRANT_ROLE_MAX_TTL)=' \
  "$MACHINE1_ENV"
```

The values contain names and configuration, not secret credentials.
`STORAGE_ENDPOINT=` remains empty for AWS because Relay derives the standard
endpoint from `AWS_REGION`. Do not send the AWS profile or its local credential
files to role machines. Without `--machine-env`, the script only prints the
same block; this remains useful for production and custom layouts.

## 4. Run Relay's preflight

First check the complete Machine 1 configuration:

```bash
REHEARSAL_ROOT="$HOME/ceremony-tools/three-machine-rehearsal"
"$REHEARSAL_ROOT/00-check-machine.sh" "$REHEARSAL_ROOT/machine-1/.env"
```

After `mpc-ceremony init` has created the authenticated ceremony files, run:

```bash
"$REHEARSAL_ROOT/01-coordinator-configure-storage.sh" \
  "$REHEARSAL_ROOT/machine-1/.env"
```

Relay writes and reads a disposable probe through both the authenticated S3
path and anonymous CloudFront URL. It also confirms that the inbox probe is not
anonymously readable and removes both probes.

## Credential lifetime warning

Storage-first AWS guides request the configured `grant-role-max-ttl`, up to 12h,
for enrollment, contribution and release grants. The IAM role maximum must also
permit that duration. Longer grants require updated receiving clients: older
frozen Relay releases reject more than one hour of remaining validity.

Do not infer eligibility solely from `GetCallerIdentity`: the tested `aws login`
session reported an IAM-user ARN but AWS rejected a 43200-second AssumeRole
request as role chaining. Validate the actual issuer credential method with AWS.
Changing the role maximum alone cannot remove that credential-path restriction.

AWS limits a session created by role chaining to one hour. IAM Identity Center
and other assumed-role profiles therefore cannot issue a Relay upload session
longer than one hour, even if `GRANT_ROLE_MAX_TTL` is configured above `1h`.
The setup script rejects that impossible combination. Keep the default `1h`
for the included rehearsal.

For longer windows, use an issuer credential method AWS permits and verify actual
issuance. Otherwise retain one-hour grants and renew them when needed. Do not
replace renewable login credentials with permanent keys merely to change the
duration without reviewing that operational choice.

## Production checklist

- Use organization-managed short-lived authentication instead of permanent
  access keys.
- Review the generated bucket and trust policies independently.
- Enable CloudTrail data events or equivalent object-access logging according
  to the ceremony's audit policy.
- S3 versioning is not immutable retention. Use the independent Object Lock
  mirror described in [STORAGE.md](storage.md) when administrators must not be
  able to silently shorten retention.
- The default CloudFront behavior does not cache mutable `state/*`; the
  `blob/*` behavior uses AWS's managed optimized cache policy.

AWS references: [CloudFront OAC CLI setup](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/get-started-cli-tutorial.html),
[restricting an S3 origin](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html),
and [STS session policy and duration rules](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).
