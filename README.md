# mpc-sync

Moves MPC ceremony transcript artifacts between a local directory and
S3-compatible object storage (AWS S3, Cloudflare R2), and lets each ceremony
role discover from the bucket where the ceremony stands.

Operating procedures per role and bucket setup are in [RUNBOOK.md](RUNBOOK.md).

## What it is not

It is deliberately outside the ceremony's trust boundary.

`internal/mpcceremony` in the [ceremony repository](https://github.com/Emurgo/proof-tool) imports no networking, and its
verification "never fetches a URI or trusts mutable network state". Putting
fetch inside that binary would delete a property the design currently
guarantees. So this is a separate program: it moves bytes and reports position,
the ceremony CLI decides what is authentic.

Concretely, this tool:

- checks digests against the signed chain document and ceremony definition;
- does **not** verify signatures;
- does **not** decide whether a transcript is genuine;
- never reads or holds signing-key material. `fetch` passes a key *path*
  through to `mpc-ceremony contribute`; the key is opened only by that binary.

Every artifact is digest-pinned in the coordinator-signed chain, so a hostile
bucket can make this tool fail loudly. It cannot make it lie. The one mutable
object it reads, the position pointer, is an unsigned scheduling hint: it can
waste a round trip or a replay, never corrupt a transcript.

The chain parser is an independent reimplementation rather than a shared
package. Go forbids importing another module's `internal/`, and independence is
better audit evidence anyway: if this tool and the ceremony CLI agree on a
digest, two implementations agree; if they diverge, that is a finding.

## Layout

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

Low-level, given a chain document:

    mpc-sync push    --chain FILE --root DIR --bucket B --endpoint U [--profile P] [--verify]
    mpc-sync pull    --chain FILE --root DIR --bucket B --endpoint U [--profile P]
    mpc-sync receipt --chain FILE --index N --location URI --stored-at TIME [--out FILE]

Role-scoped, discovering position from the bucket (`--root --ceremony --bucket
--endpoint` are always required; `--phase` defaults to `phase1`):

    mpc-sync publish --chain FILE [--closed] [--verify]      coordinator: push, then move the pointer
    mpc-sync status  [--role ID]                             anyone: where the ceremony stands
    mpc-sync fetch   --role ID --ceremony-signature FILE     participant: pull, verify, then
                     --coordinator-key FILE --signing-key FILE   run contribute (or --print it)
                     --environment FILE --out-dir DIR [--print]
    mpc-sync submit  --role ID --candidate DIR               participant: hand back a candidate
    mpc-sync watch   [--interval D] [--once]                 witness: block until a closure is published
    mpc-sync sync                                            mirror/auditor: pull everything

`push` and `publish` upload what the chain names plus what it cannot name: the
chain document and its signature, `ceremony.json` and its signature, the
compiled constraint system, and whichever closure, beacon and seal records exist
on disk. Every name is checked against an allowlist of the ceremony's published
layout, so a mis-pointed `--root` is refused rather than uploaded.

`--verify` re-downloads every object after upload and re-hashes it, rather than
trusting the upload response. It costs a full round trip of the transcript and
is off by default. On `publish` it instead re-derives what a reader will ask
for and confirms the bucket holds all of it.

`pull`, `fetch` and `sync` refuse to overwrite an existing local file. If one is
present it is hashed and compared, and a mismatch is an error rather than a
silent replacement.

`status` and `fetch` refuse when it is not your turn. That refusal is the point:
discovering you were early after a multi-hour replay is the expensive way to
find out. Each machine also records the furthest index it has seen under
`~/.mpc-sync` and refuses a pointer that has moved backwards.

`receipt` drafts an `ImmutableMirrorReceipt` for one accepted head. It stops at
a draft: the ceremony CLI canonicalizes it, and the mirror operator signs the
canonical bytes offline with their own key.

### Credentials

Credentials live in an AWS CLI profile; this program never handles them.

    aws configure set aws_access_key_id     <key>    --profile r2
    aws configure set aws_secret_access_key <secret> --profile r2
    aws configure set region                auto     --profile r2

R2 endpoints are `https://<account-id>.r2.cloudflarestorage.com`. Region is
`auto`: R2 has no regions, but SigV4 requires the field.

If uploads fail with a checksum error on AWS CLI v2.23 or later:

    aws configure set request_checksum_calculation when_required --profile r2
    aws configure set response_checksum_validation when_required --profile r2

### Example

    mpc-sync publish \
      --root     /ceremony/public \
      --ceremony /ceremony/public/ceremony.json \
      --chain    /ceremony/public/phase1/chain-0003.json \
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

Go 1.26.5 and the AWS CLI on `PATH`. No Go dependencies.
