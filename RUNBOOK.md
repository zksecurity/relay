# Runbook

Operating `relay` during a ceremony: bucket setup, and what each role runs.

The ceremony itself is documented in the [proof-tool
repository](https://github.com/Emurgo/proof-tool). This covers only the
transport layer. Where a step says "run the ceremony command", the authority on
that command is the ceremony runbook, not this one.

## Division of labour

`relay` decides **where the ceremony is** and **what you should do about it**.
The ceremony CLI decides **whether anything is valid**.

That split is deliberate. Everything `relay` learns from the bucket is a
scheduling hint: it tells you which object to fetch, and the object's own
digest and signature decide whether to believe it. A bucket that lies can waste
your time. It cannot produce a transcript that verifies.

Concretely, `relay` never implements signature verification, never holds a
signing key, and never decides that a transcript is genuine. It invokes the
trusted ceremony CLI's read-only inspection commands for authentication.

## Brokerless storage design

The coordinator does not run an online credential broker. Instead, they create
short-lived, path-scoped credentials before each role needs to upload. The
coordinator's machine may be offline while that role works and uploads.

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

Published objects are anonymously readable through a configured HTTPS base URL;
the bucket itself may remain private behind a CDN. Only the coordinator can
write it. The inbox is private. Each non-coordinator writer receives access only
to their own prefix. Uploading to an inbox proves only that the caller possessed
a storage capability; proof-tool verification of the signed record decides
whether the evidence is valid. The coordinator promotes only verified evidence
to the content-addressed published bucket.

The word `receipts` is not used as an umbrella storage prefix. Proof-tool has
several distinct outputs:

* a public witness produces a public-witness receipt and detached signature;
* a mirror produces an immutable-mirror receipt and detached signature;
* an auditor produces an audit record and detached signature;
* the release signer produces the signed release bundle and may later sign the
  canonical production decision; and
* the coordinator, named auditors, and release signer each produce their own
  detached signature over that same production decision.

Keeping separate prefixes preserves those distinctions and lets a temporary
credential grant exactly one job.

### Before `relay coordinator configure-storage`

The command validates and records an existing storage deployment. It does not
create the provider account, buckets, public delivery endpoint, ceremony, or
parent credentials. Before calling it, the coordinator must:

1. Install the reviewed `relay` and `mpc-ceremony` binaries and record the
   trusted `mpc-ceremony` binary hash.
2. Complete `mpc-ceremony init`. Keep `ceremony.json`, `ceremony.sig`, the
   coordinator public key, and the coordinator signing key available in their
   appropriate public or protected locations. Storage prefixes depend on the
   resulting ceremony ID, so storage cannot be configured for an unspecified
   ceremony.
3. Confirm that `ceremony.json` contains the intended coordinator, participant
   schedule, at least two auditors, and distinct release signer. Public
   witnesses and mirror operators are not definition roles. Create signed
   proof-of-possession enrollment records for every non-participant identity
   that will receive an upload grant; Relay authenticates those records before
   issuing witness, mirror, auditor, release, or decision access.
4. Create two buckets in the selected provider: a published bucket and a private
   inbox bucket. Never expose the inbox through a public bucket policy, website
   endpoint, CDN behavior, or custom domain.
5. Configure an HTTPS base URL that anonymously serves the published objects.
   The domain name is not a trust anchor and does not need to be custom; Relay
   authenticates the bytes after downloading them. Configure `state/*` with
   caching disabled or a deliberately short TTL so participants see head
   changes promptly. `blob/*` is immutable and may be cached indefinitely.
6. Create a coordinator runtime credential that can read, write, and delete in
   the published bucket and can list, read, write, and delete in the inbox.
   Inbox write and both delete permissions are used for disposable preflight
   probes; normal operation writes published state and reads inbox submissions.
   Do not give this credential to any other role.
7. Configure the provider-specific temporary-credential issuer described below.
   Its parent permission must be limited to the private inbox and must never be
   distributed to a role.
8. Decide the explicit credential TTL and minimum upload window for every
   grant. Allow enough time for the full replay, contribution, erasure step, and
   upload. Synchronize the coordinator and role machines' clocks before relying
   on expiration checks.
9. Test from a separate machine that published objects are readable through the
   base URL without credentials, the inbox is not, and a test scoped credential
   cannot write outside its assigned prefix.

#### Cloudflare R2 prerequisites

Record the Cloudflare account ID and S3 endpoint:

    https://<account-id>.r2.cloudflarestorage.com

Connect the published bucket to a custom domain for production. Here, “custom
domain” means an ordinary HTTPS name controlled by the coordinator, such as
`https://ceremony.example.org`, that Cloudflare maps to the published bucket.
It is only the public download URL. Cloudflare's generated `r2.dev` URL is
rate-limited and intended for development, so it is not the production path.

Create a parent R2 API token limited to the private inbox bucket, with no more
permission than the temporary credentials it will delegate. Record its parent
access-key ID. Supply the parent token to Relay through the documented secret
environment variable or secret manager, never as a flag or in shell history.
Revoking this parent token revokes every temporary credential derived from it.
R2 grants must not request a TTL above `168h`.

Expose the API token only to the grant command's process:

    RELAY_R2_PARENT_TOKEN=<parent-api-token> relay coordinator grant ...

#### AWS S3 prerequisites

Keep both S3 buckets private. Put a public CloudFront distribution in front of
the published bucket and use Origin Access Control so only CloudFront can read
the S3 origin. The generated URL, such as
`https://d111111abcdef8.cloudfront.net`, is a valid published base URL; a custom
DNS name is optional. Add separate CloudFront cache behaviors for mutable
`state/*` and immutable `blob/*`.

Create an IAM role dedicated to Relay inbox grants. Its base policy must be
limited to the inbox bucket, and its trust policy must allow only the
coordinator's credential issuer to call `sts:AssumeRole`. Relay supplies a
session policy that narrows each assumed session to one role's exact prefix.
The requested TTL must be at least `15m` and no greater than the IAM role's
configured maximum session duration, which AWS permits to be between one and
twelve hours. Role chaining imposes a one-hour maximum, so the coordinator
should mint grants from a direct IAM identity when a longer upload window is
required.

Once the R2 prerequisites hold, run:

    relay coordinator configure-storage \
      --provider r2 \
      --account-id <cloudflare-account-id> \
      --parent-access-key-id <parent-access-key-id> \
      --endpoint https://<account-id>.r2.cloudflarestorage.com \
      --published-bucket <published-bucket> \
      --published-base-url https://ceremony.example.org \
      --inbox-bucket <private-inbox-bucket> \
      --profile r2-coordinator \
      --ceremony ceremony.json \
      --ceremony-signature ceremony.sig \
      --coordinator-key coordinator-public-key.hex

For AWS S3, the equivalent command is:

    relay coordinator configure-storage \
      --provider aws \
      --region us-east-1 \
      --published-bucket <published-bucket> \
      --published-base-url https://d111111abcdef8.cloudfront.net \
      --inbox-bucket <private-inbox-bucket> \
      --profile aws-coordinator \
      --issuer-profile aws-grant-issuer \
      --grant-role-arn arn:aws:iam::<account-id>:role/relay-inbox-grant \
      --grant-role-max-ttl 12h \
      --ceremony ceremony.json \
      --ceremony-signature ceremony.sig \
      --coordinator-key coordinator-public-key.hex

`configure-storage` must fail unless it can authenticate the ceremony, write
and re-read a disposable published-bucket probe, anonymously read that probe
through `--published-base-url`, and confirm that anonymous inbox reads fail. It
must remove its probe after the test; this preflight is not ceremony evidence.

### Issuing scoped grants

Credential expiration is explicit rather than defaulted:

    relay coordinator grant \
      --storage relay-storage.json \
      --role participant --identity participant-03 \
      --credential-ttl 72h --minimum-upload-window 2h \
      --out participant-03.grant.json

For R2, `--credential-ttl` must not exceed `168h`. For AWS it must fit the
configured IAM role session limit and the `15m` minimum. Relay writes the grant
with mode `0600`, never prints its secret fields, and includes the provider,
exact identity, bucket, prefix, issue time, expiration time, and minimum required
remaining validity. A role whose grant is expired or too close to expiration
must ask the coordinator for a replacement before beginning expensive work.

Participants receive grants for `candidates/.../<participant-id>/` only.
Witnesses, mirrors, and auditors receive grants for their exact evidence prefix.
They should upload their signed evidence themselves so the provenance and
handoff are explicit; the coordinator verifies it before publication.

The release role also needs an upload path, but the release signing machine
should remain offline and receive no storage credential. Move only the signed
output to a separate online upload station, then use the release signer's scoped
grant there. The same separation applies to production-decision signatures.

For every non-participant grant, also pass the identity's authenticated record:

    --enrollment operations/enrollments/<identity>.json \
    --enrollment-signature operations/enrollments/<identity>.sig

### Compatibility with proof-tool

The storage flow preserves proof-tool as the authority:

* participant contribution and erasure files remain inputs to
  `mpc-ceremony <phase> verify`;
* witness and mirror uploads use proof-tool's existing `public-witness` and
  `mirror-receipt` operational record types and signed enrollment model;
* auditor uploads are the record and signature emitted by `mpc-ceremony audit`;
* release uploads are the fresh directory emitted by
  `mpc-ceremony release sign`;
* production-decision uploads are detached signatures emitted by
  `mpc-ceremony decision sign`; and
* Relay transports these bytes but never substitutes a storage identity for a
  ceremony signature.

Relay requires the proof-tool version that provides:

* a read-only inspection that maps a local participant key to its authenticated
  definition identity;
* a read-only inspection/verification projection for operational enrollments,
  because witnesses and mirrors are enrolled there rather than in the ceremony
  definition; and
* a CLI wrapper around proof-tool's existing public-witness receipt builder, so
  Relay does not independently reproduce its closure, timing, and identity
  rules. Mirror receipt preparation already has
  `ops prepare-mirror-receipt`.

Relay consumes these proof-tool commands rather than parsing or reproducing
proof-tool's internal ceremony formats. The corresponding proof-tool changes
must be merged and the trusted binary rebuilt before `relay enroll` or
witness/mirror grant issuance will work.

### Participant handoff

The coordinator sends a participant two files over the agreed private channel:
the non-secret storage configuration and that participant's secret grant. The
participant enrolls once:

    relay enroll \
      --storage relay-storage.json \
      --grant participant-03.grant.json \
      --phase phase1 \
      --root /ceremony/public \
      --ceremony /ceremony/public/ceremony.json \
      --ceremony-signature /ceremony/public/ceremony.sig \
      --coordinator-key /trusted/coordinator-public-key.hex \
      --signing-key /secure/participant-03.ed25519.private.hex \
      --environment /secure/participant-03.environment.json \
      --candidate-parent /ceremony/candidates \
      --out participant-03.relay.json

`enroll` asks proof-tool to match the local private key to the authenticated
participant roster. It does not rely on a filename or coordinator assertion for
the participant identity.

Long stages report their start time and emit a one-minute elapsed-time
heartbeat until they complete or fail. Proof-tool replay counts remain visible
between those messages. A heartbeat proves only that the process is still
running; it is deliberately not presented as a percentage or ETA.

When contacted by the coordinator, the participant runs exactly one command:

    relay participate --config participant-03.relay.json

Relay checks the credential window and current public head before expensive
work. If it is not this participant's turn, the command fails without starting
the contribution. If it is their turn, Relay downloads and verifies the
transcript, invokes `mpc-ceremony <phase> contribute`, asks the participant to
destroy the contribution environment, and requires them to type `DESTROYED`
before proof-tool creates the signed erasure attestation. Relay then rechecks
that the public head has not moved and uploads the candidate.

Each candidate attempt contains exactly five files plus `manifest.json`.
Relay uploads the manifest last, so an interrupted partial upload never appears
in `coordinator candidates` as a complete candidate.

### Candidate review and acceptance

The coordinator lists completed submissions:

    relay coordinator candidates --storage relay-storage.json --phase phase1

The participant can copy the printed manifest key out of band, or the
coordinator can take it from this listing. To review, accept, and publish it:

    relay coordinator accept \
      --storage relay-storage.json \
      --candidate-key candidates/<ceremony-id>/participant-03/phase1/0003/<attempt>/manifest.json \
      --root /ceremony/public \
      --candidate-dir /ceremony/review/participant-03-<attempt> \
      --coordinator-signing-key /secure/coordinator.ed25519.private.hex \
      --verify-publish

Relay verifies the manifest scope and hashes, confirms that the candidate still
matches the public head and scheduled participant, downloads it into the fresh
review directory, and invokes `mpc-ceremony <phase> verify`. Only a successful
proof-tool acceptance is published as the new head. Relay never deletes inbox
submissions; invalid and partial attempts remain private for operator review or
provider lifecycle cleanup.

### Role evidence uploads

Witnesses, mirrors, auditors, release upload stations, and decision signers use
the same transport command after producing and signing their proof-tool output:

    relay submit-evidence --grant witness-01.grant.json --dir ./signed-witness-output

or:

    relay submit-evidence --grant auditor-01.grant.json \
      --file audit.json --file audit.sig

Relay rejects symlinks, non-regular files, duplicate names, and filenames that
look like private keys, grants, or credentials. It hashes each file and uploads
`manifest.json` last. The coordinator lists complete submissions with:

    relay coordinator evidence --storage relay-storage.json [--role witness]

The manifest is intake metadata, not proof of validity. The coordinator must
run the relevant proof-tool verification command before using or publishing
the submitted evidence.

## Advanced one-bucket transport

The older low-level commands remain available for manual transport and mirrors.
They use one bucket and long-lived AWS CLI profiles; new ceremonies should use
the brokerless two-bucket workflow above.

One bucket per ceremony. Two layouts inside it:

    blob/sha256/<hex>          immutable, content-addressed, never rewritten
    state/<phase>/head.json    mutable pointer, moved by the coordinator

Uploads to `blob/` use `If-None-Match: *`, so a retry that would overwrite fails
instead of replacing published bytes. `state/` is the one prefix that must be
overwritable, because moving it is how the ceremony advances.

### Cloudflare R2

    aws configure set aws_access_key_id     <key>    --profile r2
    aws configure set aws_secret_access_key <secret> --profile r2
    aws configure set region                auto     --profile r2

Endpoint is `https://<account-id>.r2.cloudflarestorage.com`. Region is `auto`:
R2 has no regions, but SigV4 requires the field.

On AWS CLI v2.23 or later, if uploads fail with a checksum error:

    aws configure set request_checksum_calculation when_required --profile r2
    aws configure set response_checksum_validation when_required --profile r2

Scope the API token to Object Read & Write on the single bucket. Admin
permissions are only needed to create the bucket, which is a one-off.

### AWS S3

    aws s3api create-bucket --bucket <name> --object-lock-enabled-for-bucket
    aws s3api put-bucket-versioning --bucket <name> \
        --versioning-configuration Status=Enabled

**Object Lock can only be enabled at creation.** Adding it later means going
through AWS support, so get it right the first time.

For the evidentiary mirror, use COMPLIANCE mode rather than GOVERNANCE:

    aws s3api put-object-lock-configuration --bucket <name> \
        --object-lock-configuration '{"ObjectLockEnabled":"Enabled",
          "Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Years":10}}}'

GOVERNANCE can be bypassed by anyone holding `s3:BypassGovernanceRetention`,
which defeats a mirror whose purpose is to be evidence against its own operator.
COMPLIANCE cannot be shortened by anyone, including the root account.

Note the consequence before enabling it on a test bucket: objects genuinely
cannot be deleted until retention expires, mistakes included.

### Which provider

R2 for distribution, S3 for the evidentiary mirror.

R2 charges no egress, which matters because every participant downloads the
whole accepted prefix before contributing and every auditor and mirror pulls the
full transcript. R2 does not implement the S3 Object Lock API at all, so it
cannot make the immutability claim an evidentiary mirror needs.

Two mirrors must also be two operators. Two buckets in one account is one
mirror: one credential, one legal entity, one deletion.

## Roles

Every command takes the same core flags, omitted below for brevity:

    --root DIR --ceremony FILE --ceremony-signature FILE \
    --coordinator-key FILE --bucket NAME --endpoint URL --profile P

`--ceremony-binary` defaults to `mpc-ceremony`. Operators may pin an explicit
trusted binary path instead of relying on `PATH`.

`--phase` defaults to `phase1`.

### Coordinator

After each accepted contribution, and after closure, beacon and seal:

    relay coordinator publish --chain /ceremony/public/phase1/chain-0003.json \
      --chain-signature /ceremony/public/phase1/chain-0003.sig

That uploads every file the transcript names and then moves the pointer. Order
matters and the tool enforces it: the pointer must never name an object that is
not yet in the bucket.

Once the phase is closed:

    relay coordinator publish --chain <final chain> --chain-signature <final chain signature> --closed

The `--closed` flag is what lets witnesses know there is something to observe.

### Participant

    relay participant status --role participant-03

Reports the position and whether it is your turn. If it is not, it says so and
exits non-zero:

    not your turn: you are index 3, 1 of 5 accepted, waiting on participant-02

That refusal is the point of the command. Discovering you were early after a
multi-hour replay is the expensive way to find out.

When it is your turn, use the participant configuration created during the
guided handoff:

    relay participate --config participant-03.relay.json

This pulls and verifies the accepted transcript, runs the contribution,
requires erasure confirmation, creates the signed erasure record, rechecks the
published head, and uploads the complete candidate for coordinator review.

### Public witness

    relay witness watch --interval 60s

Blocks until the coordinator publishes a closure, then tells you what to check.
`--once` polls a single time and exits.

The tool reports; it does not sign. A witness receipt attests that you saw a
closure published **before its beacon round existed**, which is a claim about
the world that no tool can make for you. Fetch the closure record, confirm its
round has not yet occurred and is at least the definition's witness lead away,
and only then sign.

### Mirror operator

    relay mirror sync

Pulls everything the current authenticated chain prefix names and keeps it. It
then prints a `mirror receipt` command for that exact accepted head:

    relay mirror receipt --root <transcript root> --chain <chain> --chain-signature <chain signature> --index 3 \
      --location s3://mirror/... --stored-at 2026-09-01T12:00:00Z \
      --out receipt-0003.json

That writes a **draft**. Feed it to the ceremony CLI to authenticate and canonicalize, then sign
the canonical bytes offline with your mirror key:

    mpc-ceremony ops prepare-mirror-receipt --draft receipt-0003.json \
      --ceremony ceremony.json --ceremony-signature ceremony.sig \
      --coordinator-public-key-file coordinator.pub --transcript-root . \
      --chain phase1/chain-0003.json --chain-signature phase1/chain-0003.sig \
      --mirror-enrollment operations/enrollments/mirror-01.json \
      --mirror-enrollment-signature operations/enrollments/mirror-01.sig \
      --out-dir receipt-0003-signing

Only the location's SHA-256 goes into the record. The location itself is never
published and nothing ever fetches it.

### Auditor

    relay auditor sync --phase phase1
    relay auditor sync --phase phase2

Then replay with the ceremony CLI's `audit`. Do this from mirrors you checked
independently, not from the coordinator.

## What relay does not do

**It does not implement signature verification.** It delegates definition and
chain authentication to the ceremony CLI using a coordinator public key you
obtained out of band, then checks bytes against the returned digests.

**It does not sync private material.** An allowlist restricts uploads to the
published transcript layout. A mis-pointed `--root` is refused rather than
uploaded.

**It does not make the bucket trustworthy.** The pointer is unsigned and
rewritable. It can roll back, vanish, or say different things to different
readers. None of that corrupts a transcript, because everything it names is
digest-verified — but a rollback would silently waste a replay, so each machine
records the furthest index it has seen under `~/.relay` and refuses a pointer
claiming less. Existing per-ceremony state under `~/.mpc-sync` is migrated on
first use.

If you see this, the bucket is stale or has been rewritten, and the right
response is to ask the coordinator rather than to delete the file:

    published state claims phase1 index 2 but this machine has already seen 3

## Out-of-band material

`coordinator-public-key.hex` and the ceremony binary's hash. Everything else can
cross untrusted transport, because tampering makes verification fail rather than
succeed. Those two decide *whether* verification means anything, so taking them
from the same bucket as the artifacts they check proves only that the bucket
agrees with itself.

Temporary grant files must also be delivered confidentially out of band because
they are bearer credentials. They are not trust anchors: stealing one permits
only the storage operations and prefix in that grant, and does not create a
valid ceremony signature. Nevertheless, disclose one only to its intended role
and replace it immediately if it leaks.

Out-of-band messaging between roles also remains part of the process. The
pointer makes "you're up" checkable; it does not replace a person saying it.
