#!/usr/bin/env bash
set -euo pipefail
umask 077

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

[[ $# -le 1 ]] || die "usage: $0 [AWS_CONFIG]"
if [[ "${1:-}" == -h || "${1:-}" == --help ]]; then
  printf 'usage: %s [AWS_CONFIG]\n\n' "$0"
  printf 'Without a config file, interactively creates or updates Relay AWS storage.\n'
  printf 'With a config file, reads the variables documented in aws.env.example.\n'
  exit 0
fi
command -v aws >/dev/null 2>&1 || die "AWS CLI v2 is required"
command -v jq >/dev/null 2>&1 || die "jq is required"

config=${1:-}
interactive=no
if [[ -n "$config" ]]; then
  [[ -f "$config" && ! -L "$config" ]] || die "config must be a regular non-symlink file: $config"
  # This operator-owned file contains shell assignments, like the rehearsal .env.
  # shellcheck disable=SC1090
  source "$config"
else
  interactive=yes
  default_profile=${AWS_PROFILE:-relay-ceremony}
  read -rp "AWS CLI profile [$default_profile]: " AWS_PROFILE
  AWS_PROFILE=${AWS_PROFILE:-$default_profile}
  read -rp 'Resource prefix [relay-ceremony]: ' RESOURCE_PREFIX
  RESOURCE_PREFIX=${RESOURCE_PREFIX:-relay-ceremony}
  read -rp 'Maximum temporary credential lifetime [1h]: ' GRANT_ROLE_MAX_TTL
  GRANT_ROLE_MAX_TTL=${GRANT_ROLE_MAX_TTL:-1h}
fi

AWS_PROFILE=${AWS_PROFILE:-}
RESOURCE_PREFIX=${RESOURCE_PREFIX:-relay-ceremony}
AWS_REGION=${AWS_REGION:-}
PUBLISHED_BUCKET=${PUBLISHED_BUCKET:-}
INBOX_BUCKET=${INBOX_BUCKET:-}
GRANT_ROLE_NAME=${GRANT_ROLE_NAME:-}
GRANT_ROLE_MAX_TTL=${GRANT_ROLE_MAX_TTL:-1h}
CONFIRM_CREATE=${CONFIRM_CREATE:-}

[[ -n "$AWS_PROFILE" ]] || die "AWS_PROFILE is required"
[[ "$AWS_PROFILE" =~ ^[A-Za-z0-9_.-]+$ ]] || die "AWS profile name is malformed: $AWS_PROFILE"
configured_profiles=$(aws configure list-profiles)
grep -Fxq "$AWS_PROFILE" <<<"$configured_profiles" ||
  die "AWS profile $AWS_PROFILE was not found; run: aws configure sso --profile $AWS_PROFILE"
[[ "$RESOURCE_PREFIX" =~ ^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$ ]] ||
  die "RESOURCE_PREFIX must be 3-32 lowercase letters, numbers, or hyphens"
[[ "$GRANT_ROLE_MAX_TTL" =~ ^([1-9]|1[0-2])h$ ]] || die "GRANT_ROLE_MAX_TTL must be 1h through 12h"

if [[ -z "$AWS_REGION" ]]; then
  AWS_REGION=$(aws --profile "$AWS_PROFILE" configure get region 2>/dev/null || true)
fi
if [[ -z "$AWS_REGION" && "$interactive" == yes ]]; then
  read -rp 'AWS region (for example us-east-1): ' AWS_REGION
fi
[[ "$AWS_REGION" =~ ^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$ ]] ||
  die "AWS_REGION is missing from profile $AWS_PROFILE or is malformed"

if ! caller_identity=$(aws --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  sts get-caller-identity --output json); then
  die "could not authenticate profile $AWS_PROFILE; for SSO run: aws sso login --profile $AWS_PROFILE"
fi
setup_account=$(jq -r .Account <<<"$caller_identity")
caller_arn=$(jq -r .Arn <<<"$caller_identity")
[[ "$setup_account" =~ ^[0-9]{12}$ ]] || die "could not determine the AWS account"

if [[ "$caller_arn" =~ ^arn:aws:iam::${setup_account}:(role|user)/ ]]; then
  aws_principal_arn=$caller_arn
elif [[ "$caller_arn" =~ ^arn:aws:sts::${setup_account}:assumed-role/([^/]+)/ ]]; then
  max_ttl_hours=${GRANT_ROLE_MAX_TTL%h}
  (( max_ttl_hours == 1 )) ||
    die "assumed-role profile $AWS_PROFILE is limited by AWS role chaining to GRANT_ROLE_MAX_TTL=1h"
  role_name=${BASH_REMATCH[1]}
  if ! aws_principal_arn=$(aws --profile "$AWS_PROFILE" iam get-role \
    --role-name "$role_name" --query Role.Arn --output text); then
    die "profile $AWS_PROFILE needs iam:GetRole permission for $role_name"
  fi
else
  die "profile $AWS_PROFILE must authenticate as an IAM user or role, not $caller_arn"
fi
[[ "$aws_principal_arn" =~ ^arn:aws:iam::${setup_account}:(role|user)/[A-Za-z0-9+=,.@_/-]+$ ]] ||
  die "could not resolve a stable IAM principal ARN from $caller_arn"

PUBLISHED_BUCKET=${PUBLISHED_BUCKET:-$RESOURCE_PREFIX-$setup_account-published}
INBOX_BUCKET=${INBOX_BUCKET:-$RESOURCE_PREFIX-$setup_account-inbox}
GRANT_ROLE_NAME=${GRANT_ROLE_NAME:-$RESOURCE_PREFIX-inbox-grant}

[[ "$PUBLISHED_BUCKET" != "$INBOX_BUCKET" ]] || die "published and inbox buckets must differ"
[[ "$PUBLISHED_BUCKET" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] || die "PUBLISHED_BUCKET is malformed"
[[ "$INBOX_BUCKET" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] || die "INBOX_BUCKET is malformed"
[[ "$GRANT_ROLE_NAME" =~ ^[A-Za-z0-9+=,.@_-]{1,64}$ ]] || die "GRANT_ROLE_NAME is malformed"

printf '\nAWS setup plan:\n'
printf '  profile/principal: %s (%s)\n' "$AWS_PROFILE" "$aws_principal_arn"
printf '  account/region:    %s / %s\n' "$setup_account" "$AWS_REGION"
printf '  published bucket:  %s\n' "$PUBLISHED_BUCKET"
printf '  inbox bucket:      %s\n' "$INBOX_BUCKET"
printf '  temporary role:    %s (maximum %s)\n\n' "$GRANT_ROLE_NAME" "$GRANT_ROLE_MAX_TTL"

if [[ "$interactive" == yes ]]; then
  read -rp 'Type yes to create or update these resources: ' CONFIRM_CREATE
fi
[[ "$CONFIRM_CREATE" == yes ]] || die "set CONFIRM_CREATE=yes after reviewing the plan"

work_dir=$(mktemp -d /tmp/relay-aws-storage-setup.XXXXXXXX)
trap 'rm -rf -- "$work_dir"' EXIT

create_bucket() {
  local bucket=$1
  if aws --profile "$AWS_PROFILE" --region "$AWS_REGION" s3api head-bucket \
    --bucket "$bucket" --expected-bucket-owner "$setup_account" >/dev/null 2>&1; then
    printf 'Using existing bucket %s\n' "$bucket"
  else
    printf 'Creating bucket %s\n' "$bucket"
    if [[ "$AWS_REGION" == us-east-1 ]]; then
      aws --profile "$AWS_PROFILE" --region "$AWS_REGION" s3api create-bucket \
        --bucket "$bucket" >/dev/null
    else
      aws --profile "$AWS_PROFILE" --region "$AWS_REGION" s3api create-bucket \
        --bucket "$bucket" \
        --create-bucket-configuration "LocationConstraint=$AWS_REGION" >/dev/null
    fi
  fi

  aws --profile "$AWS_PROFILE" --region "$AWS_REGION" s3api put-public-access-block \
    --bucket "$bucket" \
    --public-access-block-configuration \
      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  aws --profile "$AWS_PROFILE" --region "$AWS_REGION" s3api put-bucket-ownership-controls \
    --bucket "$bucket" \
    --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
  aws --profile "$AWS_PROFILE" --region "$AWS_REGION" s3api put-bucket-encryption \
    --bucket "$bucket" \
    --server-side-encryption-configuration \
      'Rules=[{ApplyServerSideEncryptionByDefault={SSEAlgorithm=AES256},BucketKeyEnabled=false}]'
  aws --profile "$AWS_PROFILE" --region "$AWS_REGION" s3api put-bucket-versioning \
    --bucket "$bucket" --versioning-configuration Status=Enabled
}

create_bucket "$PUBLISHED_BUCKET"
create_bucket "$INBOX_BUCKET"

oac_name="relay-${PUBLISHED_BUCKET:0:40}-${setup_account}-oac"
oac_id=$(aws --profile "$AWS_PROFILE" cloudfront list-origin-access-controls \
  --query "OriginAccessControlList.Items[?OriginAccessControlConfig.Name=='$oac_name'].Id | [0]" --output text)
if [[ -z "$oac_id" || "$oac_id" == None ]]; then
  printf 'Creating CloudFront origin access control\n'
  oac_id=$(aws --profile "$AWS_PROFILE" cloudfront create-origin-access-control \
    --origin-access-control-config \
      "Name=$oac_name,Description=Relay ceremony published bucket,SigningProtocol=sigv4,SigningBehavior=always,OriginAccessControlOriginType=s3" \
    --query OriginAccessControl.Id --output text)
else
  printf 'Using existing CloudFront origin access control %s\n' "$oac_id"
fi
oac_config=$(aws --profile "$AWS_PROFILE" cloudfront get-origin-access-control --id "$oac_id")
jq -e --arg name "$oac_name" '
  .OriginAccessControl.OriginAccessControlConfig
  | .Name == $name
    and .SigningProtocol == "sigv4"
    and .SigningBehavior == "always"
    and .OriginAccessControlOriginType == "s3"
' >/dev/null <<<"$oac_config" || die "existing CloudFront OAC does not match Relay's required settings"

caching_disabled=$(aws --profile "$AWS_PROFILE" cloudfront list-cache-policies \
  --type managed \
  --query "CachePolicyList.Items[?CachePolicy.CachePolicyConfig.Name=='Managed-CachingDisabled'].CachePolicy.Id | [0]" \
  --output text)
caching_optimized=$(aws --profile "$AWS_PROFILE" cloudfront list-cache-policies \
  --type managed \
  --query "CachePolicyList.Items[?CachePolicy.CachePolicyConfig.Name=='Managed-CachingOptimized'].CachePolicy.Id | [0]" \
  --output text)
[[ "$caching_disabled" != None && -n "$caching_disabled" ]] || die "AWS managed CachingDisabled policy was not found"
[[ "$caching_optimized" != None && -n "$caching_optimized" ]] || die "AWS managed CachingOptimized policy was not found"

distribution_comment="Relay ceremony published bucket: $PUBLISHED_BUCKET"
distribution_id=$(aws --profile "$AWS_PROFILE" cloudfront list-distributions \
  --query "DistributionList.Items[?Comment=='$distribution_comment'].Id | [0]" --output text)
if [[ -z "$distribution_id" || "$distribution_id" == None ]]; then
  origin_id="S3-$PUBLISHED_BUCKET"
  jq -n \
    --arg caller "relay-$PUBLISHED_BUCKET-$(date +%s)" \
    --arg comment "$distribution_comment" \
    --arg origin "$origin_id" \
    --arg domain "$PUBLISHED_BUCKET.s3.$AWS_REGION.amazonaws.com" \
    --arg oac "$oac_id" \
    --arg disabled "$caching_disabled" \
    --arg optimized "$caching_optimized" \
    '{
      CallerReference: $caller,
      Comment: $comment,
      Enabled: true,
      IsIPV6Enabled: true,
      HttpVersion: "http2and3",
      PriceClass: "PriceClass_All",
      Origins: {Quantity: 1, Items: [{
        Id: $origin,
        DomainName: $domain,
        S3OriginConfig: {OriginAccessIdentity: ""},
        OriginAccessControlId: $oac
      }]},
      DefaultCacheBehavior: {
        TargetOriginId: $origin,
        ViewerProtocolPolicy: "redirect-to-https",
        AllowedMethods: {Quantity: 2, Items: ["HEAD", "GET"], CachedMethods: {Quantity: 2, Items: ["HEAD", "GET"]}},
        Compress: true,
        CachePolicyId: $disabled,
        TrustedSigners: {Enabled: false, Quantity: 0},
        TrustedKeyGroups: {Enabled: false, Quantity: 0}
      },
      CacheBehaviors: {Quantity: 1, Items: [{
        PathPattern: "blob/*",
        TargetOriginId: $origin,
        ViewerProtocolPolicy: "redirect-to-https",
        AllowedMethods: {Quantity: 2, Items: ["HEAD", "GET"], CachedMethods: {Quantity: 2, Items: ["HEAD", "GET"]}},
        Compress: true,
        CachePolicyId: $optimized,
        TrustedSigners: {Enabled: false, Quantity: 0},
        TrustedKeyGroups: {Enabled: false, Quantity: 0}
      }]},
      CustomErrorResponses: {Quantity: 0},
      Logging: {Enabled: false, IncludeCookies: false, Bucket: "", Prefix: ""},
      ViewerCertificate: {CloudFrontDefaultCertificate: true},
      Restrictions: {GeoRestriction: {RestrictionType: "none", Quantity: 0}}
    }' >"$work_dir/distribution.json"
  printf 'Creating CloudFront distribution\n'
  distribution_result=$(aws --profile "$AWS_PROFILE" cloudfront create-distribution \
    --distribution-config "file://$work_dir/distribution.json")
  distribution_id=$(jq -r .Distribution.Id <<<"$distribution_result")
  distribution_domain=$(jq -r .Distribution.DomainName <<<"$distribution_result")
else
  printf 'Using existing CloudFront distribution %s\n' "$distribution_id"
  distribution_domain=$(aws --profile "$AWS_PROFILE" cloudfront get-distribution \
    --id "$distribution_id" --query Distribution.DomainName --output text)
fi

distribution_config=$(aws --profile "$AWS_PROFILE" cloudfront get-distribution-config \
  --id "$distribution_id")
jq -e \
  --arg origin "S3-$PUBLISHED_BUCKET" \
  --arg domain "$PUBLISHED_BUCKET.s3.$AWS_REGION.amazonaws.com" \
  --arg oac "$oac_id" \
  --arg disabled "$caching_disabled" \
  --arg optimized "$caching_optimized" '
  .DistributionConfig
  | .Enabled == true
    and .Origins.Quantity == 1
    and .Origins.Items[0].Id == $origin
    and .Origins.Items[0].DomainName == $domain
    and .Origins.Items[0].OriginAccessControlId == $oac
    and .DefaultCacheBehavior.TargetOriginId == $origin
    and .DefaultCacheBehavior.CachePolicyId == $disabled
    and (.CacheBehaviors.Items // [] | any(
      .PathPattern == "blob/*"
      and .TargetOriginId == $origin
      and .CachePolicyId == $optimized
    ))
' >/dev/null <<<"$distribution_config" ||
  die "existing CloudFront distribution does not match Relay's required origin and cache policies"

distribution_arn="arn:aws:cloudfront::$setup_account:distribution/$distribution_id"
jq -n --arg bucket "$PUBLISHED_BUCKET" --arg source "$distribution_arn" --arg account "$setup_account" '{
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "DenyInsecureTransport",
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: [("arn:aws:s3:::" + $bucket), ("arn:aws:s3:::" + $bucket + "/*")],
      Condition: {Bool: {"aws:SecureTransport": "false"}}
    },
    {
      Sid: "AllowCloudFrontReadOnly",
      Effect: "Allow",
      Principal: {Service: "cloudfront.amazonaws.com"},
      Action: "s3:GetObject",
      Resource: ("arn:aws:s3:::" + $bucket + "/*"),
      Condition: {StringEquals: {"AWS:SourceArn": $source, "AWS:SourceAccount": $account}}
    }
  ]
}' >"$work_dir/published-bucket-policy.json"
aws --profile "$AWS_PROFILE" --region "$AWS_REGION" s3api put-bucket-policy \
  --bucket "$PUBLISHED_BUCKET" --policy "file://$work_dir/published-bucket-policy.json"

jq -n --arg bucket "$INBOX_BUCKET" '{
  Version: "2012-10-17",
  Statement: [{
    Sid: "DenyInsecureTransport",
    Effect: "Deny",
    Principal: "*",
    Action: "s3:*",
    Resource: [("arn:aws:s3:::" + $bucket), ("arn:aws:s3:::" + $bucket + "/*")],
    Condition: {Bool: {"aws:SecureTransport": "false"}}
  }]
}' >"$work_dir/inbox-bucket-policy.json"
aws --profile "$AWS_PROFILE" --region "$AWS_REGION" s3api put-bucket-policy \
  --bucket "$INBOX_BUCKET" --policy "file://$work_dir/inbox-bucket-policy.json"

max_ttl_hours=${GRANT_ROLE_MAX_TTL%h}
max_ttl_seconds=$((max_ttl_hours * 3600))
grant_role_arn="arn:aws:iam::$setup_account:role/$GRANT_ROLE_NAME"
jq -n --arg principal "$aws_principal_arn" '{
  Version: "2012-10-17",
  Statement: [{Effect: "Allow", Principal: {AWS: $principal}, Action: "sts:AssumeRole"}]
}' >"$work_dir/grant-trust.json"

if aws --profile "$AWS_PROFILE" iam get-role --role-name "$GRANT_ROLE_NAME" >/dev/null 2>&1; then
  printf 'Updating grant role %s\n' "$GRANT_ROLE_NAME"
  aws --profile "$AWS_PROFILE" iam update-assume-role-policy \
    --role-name "$GRANT_ROLE_NAME" --policy-document "file://$work_dir/grant-trust.json"
  aws --profile "$AWS_PROFILE" iam update-role \
    --role-name "$GRANT_ROLE_NAME" --max-session-duration "$max_ttl_seconds"
else
  printf 'Creating grant role %s\n' "$GRANT_ROLE_NAME"
  aws --profile "$AWS_PROFILE" iam create-role \
    --role-name "$GRANT_ROLE_NAME" \
    --max-session-duration "$max_ttl_seconds" \
    --assume-role-policy-document "file://$work_dir/grant-trust.json" >/dev/null
fi

jq -n --arg bucket "$INBOX_BUCKET" '{
  Version: "2012-10-17",
  Statement: [{
    Effect: "Allow",
    Action: ["s3:PutObject", "s3:GetObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
    Resource: ("arn:aws:s3:::" + $bucket + "/*")
  }]
}' >"$work_dir/grant-policy.json"
aws --profile "$AWS_PROFILE" iam put-role-policy \
  --role-name "$GRANT_ROLE_NAME" --policy-name RelayScopedInboxBase \
  --policy-document "file://$work_dir/grant-policy.json"

printf 'Waiting for CloudFront distribution %s to deploy; this can take several minutes.\n' "$distribution_id"
aws --profile "$AWS_PROFILE" cloudfront wait distribution-deployed --id "$distribution_id"

printf '\nAWS storage is ready. Copy these non-secret values into machine-1/.env:\n\n'
printf 'STORAGE_PROVIDER=aws\n'
printf 'PUBLISHED_BUCKET=%s\n' "$PUBLISHED_BUCKET"
printf 'PUBLISHED_BASE_URL=https://%s\n' "$distribution_domain"
printf 'INBOX_BUCKET=%s\n' "$INBOX_BUCKET"
printf 'STORAGE_ENDPOINT=\n'
printf 'COORDINATOR_PROFILE=%s\n' "$AWS_PROFILE"
printf 'AWS_REGION=%s\n' "$AWS_REGION"
printf 'ISSUER_PROFILE=%s\n' "$AWS_PROFILE"
printf 'GRANT_ROLE_NAME=%s\n' "$GRANT_ROLE_NAME"
printf 'GRANT_ROLE_ARN=%s\n' "$grant_role_arn"
printf 'GRANT_ROLE_MAX_TTL=%s\n' "$GRANT_ROLE_MAX_TTL"

printf '\nValidation identities:\n'
printf '%s\n' "$caller_identity"
