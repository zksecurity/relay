# AWS storage setup

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

## 1. Prepare one AWS profile

Install AWS CLI v2 as described in [INSTALL.md](INSTALL.md), and install `jq`
through the operating system. Then create or select one short-lived profile.
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
the credential lifetime warning below before choosing the identity type.

## 2. Run the guided setup

From a reviewed Relay checkout or extracted storage-setup bundle, run:

```bash
scripts/storage-setup/setup-aws.sh
```

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
commonly takes several minutes.

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

## 3. Copy the generated values

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

Open it with:

```bash
MACHINE1_ENV="$HOME/ceremony-tools/three-machine-rehearsal/machine-1/.env"
test -f "$MACHINE1_ENV"
${EDITOR:-vi} "$MACHINE1_ENV"
```

Copy the generated storage block into the matching fields in that file. The
values contain names and configuration, not secret credentials. Leave
`STORAGE_ENDPOINT=` empty for AWS; Relay derives the standard endpoint from
`AWS_REGION`. Do not send the AWS profile or its local credential files to
role machines.

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

AWS limits a session created by role chaining to one hour. IAM Identity Center
and other assumed-role profiles therefore cannot issue a Relay upload session
longer than one hour, even if `GRANT_ROLE_MAX_TTL` is configured above `1h`.
The setup script rejects that impossible combination. Keep the default `1h`
for the included rehearsal.

If a production ceremony requires a participant upload window longer than one
hour, one-profile setup requires a direct IAM user profile, whose credential
storage and rotation must be approved by the AWS administrator. The safer
alternative is a separate issuer design or R2. Relay checks the remaining
credential lifetime before starting expensive work.

## Production checklist

- Use organization-managed short-lived authentication instead of permanent
  access keys.
- Review the generated bucket and trust policies independently.
- Enable CloudTrail data events or equivalent object-access logging according
  to the ceremony's audit policy.
- S3 versioning is not immutable retention. Use the independent Object Lock
  mirror described in [STORAGE.md](STORAGE.md) when administrators must not be
  able to silently shorten retention.
- The default CloudFront behavior does not cache mutable `state/*`; the
  `blob/*` behavior uses AWS's managed optimized cache policy.

AWS references: [CloudFront OAC CLI setup](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/get-started-cli-tutorial.html),
[restricting an S3 origin](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html),
and [STS session policy and duration rules](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).
