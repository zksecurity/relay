# Runbook

Operating `mpc-sync` during a ceremony: bucket setup, and what each role runs.

The ceremony itself is documented in the [proof-tool
repository](https://github.com/Emurgo/proof-tool). This covers only the
transport layer. Where a step says "run the ceremony command", the authority on
that command is the ceremony runbook, not this one.

## Division of labour

`mpc-sync` decides **where the ceremony is** and **what you should do about it**.
The ceremony CLI decides **whether anything is valid**.

That split is deliberate. Everything `mpc-sync` learns from the bucket is a
scheduling hint: it tells you which object to fetch, and the object's own
digest and signature decide whether to believe it. A bucket that lies can waste
your time. It cannot produce a transcript that verifies.

Concretely, `mpc-sync` never verifies a signature, never holds a signing key,
and never decides that a transcript is genuine.

## Bucket setup

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

    --root DIR --ceremony FILE --bucket NAME --endpoint URL --profile P

`--phase` defaults to `phase1`.

### Coordinator

After each accepted contribution, and after closure, beacon and seal:

    mpc-sync publish --chain /ceremony/public/phase1/chain-0003.json

That uploads every file the transcript names and then moves the pointer. Order
matters and the tool enforces it: the pointer must never name an object that is
not yet in the bucket.

Once the phase is closed:

    mpc-sync publish --chain <final chain> --closed

The `--closed` flag is what lets witnesses know there is something to observe.

### Participant

    mpc-sync status --role participant-03

Reports the position and whether it is your turn. If it is not, it says so and
exits non-zero:

    not your turn: you are index 3, 1 of 5 accepted, waiting on participant-02

That refusal is the point of the command. Discovering you were early after a
multi-hour replay is the expensive way to find out.

When it is your turn:

    mpc-sync fetch --role participant-03 \
      --signing-key /secure/participant-03.ed25519.private.hex \
      --environment /secure/participant-03.environment.json

This pulls the accepted prefix, verifies every file against the signed chain,
and then runs the ceremony `contribute` command. Expect hours: contribution
replays the entire accepted chain before sampling any randomness.

Pass `--print` to see the command without running it — worth doing the first
time, and the way to re-run by hand if something fails part way through.

Then destroy the ephemeral environment, record the erasure with the ceremony
CLI's `attest-erasure`, and hand the candidate back:

    mpc-sync submit --role participant-03 --candidate /ceremony/candidates/phase1-0003

`submit` refuses if `erasure.json` is absent, because the coordinator will not
accept a contribution without it. It files the candidate under the index the
tool derived rather than one you supply, so a submission cannot land in someone
else's slot.

Tell the coordinator out of band. They run the ceremony's `verify` to accept it.

### Public witness

    mpc-sync watch --interval 60s

Blocks until the coordinator publishes a closure, then tells you what to check.
`--once` polls a single time and exits.

The tool reports; it does not sign. A witness receipt attests that you saw a
closure published **before its beacon round existed**, which is a claim about
the world that no tool can make for you. Fetch the closure record, confirm its
round has not yet occurred and is at least the definition's witness lead away,
and only then sign.

### Mirror operator

    mpc-sync sync

Pulls everything the transcript names and keeps it. It then prints a `receipt`
command per accepted head:

    mpc-sync receipt --chain <chain> --index 3 \
      --location s3://mirror/... --stored-at 2026-09-01T12:00:00Z \
      --out receipt-0003.json

That writes a **draft**. Feed it to the ceremony CLI to canonicalize, then sign
the canonical bytes offline with your mirror key:

    mpc-ceremony ops export-signing --record-type mirror-receipt --record receipt-0003.json ...

Only the location's SHA-256 goes into the record. The location itself is never
published and nothing ever fetches it.

### Auditor

    mpc-sync sync --phase phase1
    mpc-sync sync --phase phase2

Then replay with the ceremony CLI's `audit`. Do this from mirrors you checked
independently, not from the coordinator.

## What mpc-sync does not do

**It does not verify signatures.** Digests are checked against the chain; the
chain's authenticity is established by the ceremony CLI against a coordinator
public key you obtained out of band.

**It does not sync private material.** An allowlist restricts uploads to the
published transcript layout. A mis-pointed `--root` is refused rather than
uploaded.

**It does not make the bucket trustworthy.** The pointer is unsigned and
rewritable. It can roll back, vanish, or say different things to different
readers. None of that corrupts a transcript, because everything it names is
digest-verified — but a rollback would silently waste a replay, so each machine
records the furthest index it has seen under `~/.mpc-sync` and refuses a pointer
claiming less.

If you see this, the bucket is stale or has been rewritten, and the right
response is to ask the coordinator rather than to delete the file:

    published state claims phase1 index 2 but this machine has already seen 3

## Two things must still travel out of band

`coordinator-public-key.hex` and the ceremony binary's hash. Everything else can
cross untrusted transport, because tampering makes verification fail rather than
succeed. Those two decide *whether* verification means anything, so taking them
from the same bucket as the artifacts they check proves only that the bucket
agrees with itself.

Out-of-band messaging between roles also remains part of the process. The
pointer makes "you're up" checkable; it does not replace a person saying it.
