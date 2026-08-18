# relay

Moves MPC ceremony transcript artifacts between a local directory and
S3-compatible object storage (AWS S3, Cloudflare R2), and lets each ceremony
role discover from the bucket where the ceremony stands.

Operating procedures are split by audience:

- [Coordinator runbook](COORDINATOR_RUNBOOK.md)
- [Participant and other role runbook](ROLE_RUNBOOK.md)
- [Three-machine tiny rehearsal scripts](scripts/three-machine-rehearsal/README.md)

## What it is not

It is deliberately outside the ceremony's trust boundary.

`internal/mpcceremony` in the [ceremony repository](https://github.com/Emurgo/proof-tool) imports no networking, and its
verification "never fetches a URI or trusts mutable network state". Putting
fetch inside that binary would delete a property the design currently
guarantees. So this is a separate program: it moves bytes and reports position,
the ceremony CLI decides what is authentic.

Concretely, this tool:

- asks the trusted ceremony CLI to authenticate and interpret definitions and chains;
- checks transported bytes against the authenticated artifact digests it returns;
- contains no independent ceremony parser or signature implementation;
- never reads or holds signing-key material. Participant commands pass a key
  *path* to proof-tool for identity inspection and contribution; only the
  trusted ceremony binary opens the key.

Every artifact is digest-pinned in the coordinator-signed chain, so a hostile
bucket can make this tool fail loudly. It cannot make it lie. The one mutable
object it reads, the position pointer, is an unsigned scheduling hint: it can
waste a round trip or a replay, never corrupt a transcript.

Relay invokes `mpc-ceremony --format json inspect definition|chain|participant|enrollment` for the
security-sensitive boundary. Those read-only commands verify exact canonical
bytes, detached signatures, ceremony binding, and frozen participant order,
then return a versioned transport projection. Relay only resolves those names,
hashes local bytes, and moves them.

## Brokerless ceremony workflow

The normal flow uses two buckets:

    published bucket: state/<ceremony-id>/<phase>/head.json and blob/sha256/<hex>
    private inbox:    one identity-scoped prefix for candidates or signed role evidence

The coordinator validates the deployment once and mints explicit, expiring R2
or AWS credentials scoped to one identity's inbox prefix:

    relay coordinator configure-storage ... --out relay-storage.json
    relay coordinator grant --storage relay-storage.json --role participant \
      --identity participant-03 --credential-ttl 72h \
      --minimum-upload-window 2h --out participant-03.grant.json

The participant authenticates their local key once, then runs one command when
the coordinator contacts them:

    relay enroll --storage relay-storage.json --grant participant-03.grant.json \
      --phase phase1 --root /ceremony/public --ceremony /ceremony/public/ceremony.json \
      --ceremony-signature /ceremony/public/ceremony.sig \
      --coordinator-key /trusted/coordinator-public-key.hex --signing-key /secure/key \
      --environment /secure/environment.json --candidate-parent /ceremony/candidates \
      --out participant-03.relay.json
    relay participate --config participant-03.relay.json

`participate` refuses out of turn before computation. On success it runs the
contribution and erasure-attestation steps, rechecks the head, and uploads a
manifest-last candidate. The coordinator then runs:

    relay coordinator candidates --storage relay-storage.json
    relay coordinator accept --storage relay-storage.json --candidate-key KEY \
      --root /ceremony/public --candidate-dir /ceremony/review/attempt \
      --coordinator-signing-key /secure/coordinator-key

Other roles upload their already signed proof-tool outputs with
`relay submit-evidence --grant FILE --dir DIR`; the coordinator discovers them
with `relay coordinator evidence --storage FILE`. See the
[coordinator runbook](COORDINATOR_RUNBOOK.md) for provider setup and ceremony
operation, and the [role runbook](ROLE_RUNBOOK.md) for participant and evidence
workflows.

### Long-running progress

Guided operations print UTC start, completion, and failure timestamps to
stderr. While a stage is otherwise silent, Relay emits an elapsed-time
heartbeat once per minute. Proof-tool's own replay counters continue to stream
unchanged, and transfers announce the current public artifact name and size.
Relay does not invent percentages or completion estimates for cryptographic
operations whose underlying implementation exposes no measurable total.

## Published layout

Two prefixes:

    blob/sha256/<hex>                         immutable, content-addressed
    state/<ceremony-id>/<phase>/head.json     mutable pointer, moved by the coordinator

Every transcript file lives under `blob/`, keyed by its own hash. A location is
therefore derivable from the signed chain rather than trusted, and two uploads
of the same bytes collide on one key instead of racing. Uploads use
`If-None-Match: *`, the object-storage equivalent of the ceremony's
`RENAME_NOREPLACE`: a retry that would overwrite fails instead of silently
replacing published bytes.

This matters because the transcript is publish-once audit evidence: once an
object is up, auditors may already have fetched and verified it, so those bytes
must never change. Create-only PUTs mean a retry, a re-run against a stale
chain, or a second racing uploader gets a 412 instead of silently replacing
what is published. Content addressing makes the guard precise: an honest retry
of identical bytes losing a race is harmless, so the only write it can block is
one that would have changed published bytes — a loud failure, never a success.

`state/` is the single deliberate exception. The pointer names the current
chain head and every object the last publish uploaded, all by content hash, so
it can be rewritten freely: nothing it names can change, and everything it names
is re-hashed on arrival. It is namespaced by ceremony id so two ceremonies in
one bucket cannot overwrite each other's head. Delete the whole prefix and the
transcript is still verifiable; you just have to ask a person where to look.

## Usage

Recovery/debugging commands, given a chain document:

    relay advanced push --chain FILE --chain-signature FILE --root DIR --bucket B --endpoint U [--verify]
    relay advanced pull --chain FILE --chain-signature FILE --root DIR --bucket B --endpoint U
    relay mirror receipt --chain FILE --chain-signature FILE --root DIR --index N \
                    --location URI --stored-at TIME [--out FILE]

All commands that inspect ceremony documents also require:

    --ceremony FILE --ceremony-signature FILE --coordinator-key FILE

`--ceremony-binary` defaults to `mpc-ceremony`; set it to an explicitly trusted
binary path when `PATH` is not part of the operator's trust setup.

Role-scoped commands discover position from the bucket (`--root --ceremony
--bucket --endpoint` are always required; `--phase` defaults to `phase1`):

    relay coordinator publish --chain FILE --chain-signature FILE [--closed] [--verify]
    relay participant status [--role ID]                  report ceremony position
    relay witness watch [--interval D] [--once]           wait for a published closure
    relay mirror sync                                     pull the authenticated transcript
    relay mirror receipt --chain FILE ...                 draft mirror evidence
    relay auditor sync                                    pull the authenticated transcript

`advanced push` and `coordinator publish` upload what the chain names plus what
it cannot name: the
chain document and its signature, `ceremony.json` and its signature, the
compiled constraint system, and whichever closure, beacon and seal records exist
on disk. Every name is checked against an allowlist of the ceremony's published
layout, so a mis-pointed `--root` is refused rather than uploaded.

`--verify` re-downloads every object after upload and re-hashes it, rather than
trusting the upload response. It costs a full round trip of the transcript and
is off by default. On `coordinator publish` it instead re-derives what a reader will ask
for and confirms the bucket holds all of it.

`advanced pull`, `mirror sync` and `auditor sync` refuse to overwrite an existing local file. If one is
present it is hashed and compared, and a mismatch is an error rather than a
silent replacement.

`participant status` and `participate` refuse when it is not your turn. That refusal is the point:
discovering you were early after a multi-hour replay is the expensive way to
find out. Each machine also records the furthest index it has seen under
`~/.relay` and refuses a pointer that has moved backwards. On first use for a
ceremony, existing high-water state from `~/.mpc-sync` is migrated automatically.

`mirror receipt` drafts an `ImmutableMirrorReceipt` for the head of the exact chain
prefix passed to it. It stops at a draft: `mpc-ceremony ops
prepare-mirror-receipt` authenticates the chain and mirror enrollment,
recomputes the file set, and exports canonical bytes for the mirror operator to
sign offline with their own key.

### Credentials for advanced commands

The advanced one-bucket commands use an AWS CLI profile. The brokerless flow
instead reads short-lived credentials from a mode-`0600` grant and exposes them
only to the child AWS CLI process; it never prints their values.

    aws configure set aws_access_key_id     <key>    --profile r2
    aws configure set aws_secret_access_key <secret> --profile r2
    aws configure set region                auto     --profile r2

R2 endpoints are `https://<account-id>.r2.cloudflarestorage.com`. Region is
`auto`: R2 has no regions, but SigV4 requires the field.

If uploads fail with a checksum error on AWS CLI v2.23 or later:

    aws configure set request_checksum_calculation when_required --profile r2
    aws configure set response_checksum_validation when_required --profile r2

### Example

    relay coordinator publish \
      --root     /ceremony/public \
      --ceremony /ceremony/public/ceremony.json \
      --ceremony-signature /ceremony/public/ceremony.sig \
      --coordinator-key /trusted/coordinator-public-key.hex \
      --chain    /ceremony/public/phase1/chain-0003.json \
      --chain-signature /ceremony/public/phase1/chain-0003.sig \
      --bucket   my-mirror \
      --endpoint https://<account-id>.r2.cloudflarestorage.com \
      --profile  r2 \
      --verify

## Provider notes

The data plane is identical across S3 and R2, so one code path serves both. The
difference is immutability.

S3 Object Lock in COMPLIANCE mode cannot be shortened or removed by anyone,
including the root account, until retention expires. That is what makes a mirror
evidence against the party who runs it.

R2 does not implement the S3 Object Lock API at all: `PutObjectLockConfiguration`,
`PutObjectRetention`, `PutObjectLegalHold` and `PutBucketVersioning` are
unimplemented. It has prefix-scoped "bucket locks" configured through
Cloudflare's own API, with no documented mode that an account admin cannot
remove, and no per-object retention or legal hold.

So R2 suits the high-egress distribution copy, where its zero egress matters
because every participant pulls the full accepted prefix before contributing.
S3 with Object Lock suits the evidentiary mirror. Two mirrors also need to be
two operators, so running both is not redundant.

## Two things must still travel out of band

`coordinator-public-key.hex` and the ceremony binary's hash. Everything else can
cross untrusted transport, because tampering makes verification fail rather than
succeed. Those two decide *whether* verification means anything, so this tool
never fetches the coordinator key from the bucket: taking it from the same place
as the artifacts it checks would prove only that the bucket agrees with itself.

## Requirements

Operators need the AWS CLI and a trusted `mpc-ceremony` binary on `PATH`.
Published-binary installation is documented in
[docs/INSTALL.md](docs/INSTALL.md). Release maintainers and independent build
auditors need Go 1.26.5 and use [docs/RELEASE.md](docs/RELEASE.md). Relay has no
third-party Go dependencies; its production builder emits a signed,
reproducible release package.
