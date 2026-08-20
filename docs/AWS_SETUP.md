# AWS storage setup

This guide creates the AWS resources required by Relay and prints the exact
non-secret values for the coordinator's rehearsal `.env`. The same resources
can be passed to `relay coordinator configure-storage` in production.

The setup creates:

- a private, versioned S3 published bucket;
- a private, versioned S3 inbox bucket;
- a CloudFront distribution with Origin Access Control (OAC) for anonymous
  reads from the published bucket only;
- no-cache delivery by default, with managed optimized caching for `blob/*`;
- an IAM role from which Relay derives temporary, prefix-scoped inbox grants;
- least-privilege inline policies on existing coordinator and issuer
  principals.

The script never creates access keys and never deletes cloud resources. It can
incur AWS charges. Use a dedicated AWS account for a rehearsal when possible.

## 1. Install prerequisites

Install and authenticate AWS CLI v2 as described in [INSTALL.md](INSTALL.md),
and install `jq` through the operating system. Confirm:

```bash
aws --version
jq --version
```

## 2. Prepare three existing AWS profiles

Create or select these profiles before running the script:

1. A short-lived provisioning profile allowed to create and configure S3
   buckets, CloudFront distributions/OACs, and IAM roles and inline policies.
2. A coordinator runtime profile. Its IAM user or role will receive read,
   write, list, and preflight-delete access to both buckets.
3. An issuer runtime profile. Its IAM user or role will receive only permission
   to assume Relay's inbox-grant role.

Use your organization's normal authentication system. For example, AWS IAM
Identity Center profiles are configured with:

```bash
aws configure sso --profile relay-provisioning
aws configure sso --profile relay-coordinator
aws configure sso --profile relay-issuer
```

Verify each profile and make sure all three report the intended account:

```bash
aws --profile relay-provisioning sts get-caller-identity
aws --profile relay-coordinator sts get-caller-identity
aws --profile relay-issuer sts get-caller-identity
```

The setup config needs the stable IAM user or role ARN behind the coordinator
and issuer profiles. Do not use an `arn:aws:sts::...:assumed-role/...` session
ARN. An administrator can obtain the underlying role ARN from IAM or IAM
Identity Center. It looks like:

```text
arn:aws:iam::123456789012:role/relay-coordinator
```

If the issuer profile itself assumes another IAM role, AWS role chaining caps
the grants it creates at one hour. Use a direct identity when the ceremony
requires a longer upload window.

## 3. Fill the setup configuration

From a reviewed Relay checkout or verified operator bundle:

```bash
cp scripts/storage-setup/aws.env.example /secure/relay-aws.env
chmod 0600 /secure/relay-aws.env
${EDITOR:-vi} /secure/relay-aws.env
```

Choose globally unique, ceremony-specific bucket names. Set the provisioning
and runtime profile names, stable runtime principal ARNs, AWS region, grant
role name, and maximum grant TTL. The role maximum must be `1h` through `12h`.

Review the selected account and names carefully. The script is intentionally
not a cleanup tool, and S3 bucket names are global.

## 4. Run the setup

```bash
scripts/storage-setup/setup-aws.sh /secure/relay-aws.env | tee /secure/relay-aws-result.txt
```

The script is safe to rerun with the same configuration. It reuses the named
buckets, OAC, distribution, and grant role, validates the existing delivery
configuration, and reapplies bucket and IAM security settings. It may update
the named role's trust policy and the Relay inline policies on the coordinator
and issuer, which is why the config requires `CONFIRM_CREATE=yes`.

CloudFront deployment commonly takes several minutes. The script waits until
AWS reports that the distribution is deployed, then prints a block like:

```bash
STORAGE_PROVIDER=aws
PUBLISHED_BUCKET=example-ceremony-published
PUBLISHED_BASE_URL=https://d111111abcdef8.cloudfront.net
INBOX_BUCKET=example-ceremony-inbox
STORAGE_ENDPOINT=
COORDINATOR_PROFILE=relay-coordinator
AWS_REGION=us-east-1
ISSUER_PROFILE=relay-issuer
GRANT_ROLE_NAME=relay-inbox-grant
GRANT_ROLE_ARN=arn:aws:iam::123456789012:role/relay-inbox-grant
GRANT_ROLE_MAX_TTL=1h
```

These values are not credentials. Copy them into Machine 1's `.env` for the
three-machine rehearsal. Do not copy the setup profile into the rehearsal
file, and do not send either runtime profile to role machines.

## 5. Run Relay's preflight

First check the complete Machine 1 configuration:

```bash
REHEARSAL_ROOT=/home/REPLACE_WITH_USER/ceremony-tools/three-machine-rehearsal
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

## Production notes

- Use organization-managed short-lived profiles rather than permanent IAM user
  access keys.
- Review the generated bucket, trust, and identity policies independently
  before a production ceremony.
- Enable CloudTrail data events or equivalent object-access logging according
  to the ceremony's audit policy.
- S3 versioning is enabled, but versioning is not immutable retention. Use the
  independent Object Lock mirror described in [STORAGE.md](STORAGE.md) when the
  ceremony requires retention that administrators cannot silently shorten.
- The default CloudFront behavior does not cache mutable `state/*`; the
  `blob/*` behavior uses AWS's managed optimized cache policy.

AWS references: [CloudFront OAC CLI setup](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/get-started-cli-tutorial.html),
[restricting an S3 origin](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html),
and [STS session policy and duration rules](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).
