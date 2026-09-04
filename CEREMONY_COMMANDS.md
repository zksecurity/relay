# MPC Ceremony Command Recipes

> This is the copy-oriented command companion to
> [COORDINATOR_CHECKLIST.md](COORDINATOR_CHECKLIST.md),
> [PARTICIPANT_CHECKLIST.md](PARTICIPANT_CHECKLIST.md), and
> [ROLE_RUNBOOK.md](ROLE_RUNBOOK.md). The runbooks explain why and when each
> operation is performed; this document shows the current Relay commands.

## Safety and placeholder rules

Use only the Relay, `mpc-ceremony`, and provider CLI binaries from the
authenticated ceremony kit. `relay --help` and the version-pinned proof-tool
documentation remain authoritative if this document differs from the installed
release.

Commands below use conspicuous placeholder values such as `CEREMONY_ID`,
`participant-03`, and `ceremony.example.org`. Replace them deliberately before
running anything. Use absolute, clean paths for ceremony homes, trust keys,
signing keys, enrollments, environment declarations, and saved candidates.

Never put these values in a command pasted into the coordination website,
operator log, shell history, or this document:

- private-key contents;
- contribution randomness;
- temporary grant contents;
- R2 parent secrets or control-plane tokens; or
- AWS secret or session credentials.

Commands may name a protected key or grant *file*. Relay passes participant
signing-key paths to the trusted ceremony binary; it does not read or store the
key bytes in a persistent profile. Keep every grant file mode `0600` and delete
it only under the approved retention and destruction procedure.

## Common non-secret paths

These examples use the following shell variables. They contain paths and public
identifiers, not secret values:

```sh
CEREMONY_ID=CEREMONY_ID
CEREMONY_HOME=/var/lib/mpc-ceremonies/$CEREMONY_ID
COORDINATOR_KEY=/trusted/coordinator-public-key.hex
STORAGE_CONFIG=$CEREMONY_HOME/config/relay-storage.json
PARTICIPANT_ID=participant-03
PHASE=phase1
ROLE_CONFIG=$CEREMONY_HOME/config/participant-$PHASE.json
TOOL_IDENTITY_RECEIPT=/trusted/tool-identity-receipt.env
```

Before running a recipe, display and review its effective non-secret paths:

```sh
printf 'ceremony home: %s\nstorage config: %s\nrole config: %s\n' \
  "$CEREMONY_HOME" "$STORAGE_CONFIG" "$ROLE_CONFIG"
```

Do not use `/`, `$HOME`, a repository root, or another broad directory as
`CEREMONY_HOME`.

## 1. Authenticate the installed tools

**Run by:** every role, once per installed release.

Verify the downloaded kit SHA-256 through [docs/INSTALL.md](docs/INSTALL.md),
then have the authenticated setup command write a fresh receipt:

```sh
cd /opt/ceremony-tools/ceremony-kit
./setup verify --receipt-out "$TOOL_IDENTITY_RECEIPT"
```

**Success evidence:** setup prints and writes a secret-free receipt containing
the resolved kit binary paths, release repositories and versions, release
identifiers, compatibility-test identity, and Relay and `mpc-ceremony` SHA-256
digests. No manual `command -v` or version transcription is required.

**Retry:** safe after correcting installation or path problems. Do not begin a
ceremony action while any identity or compatibility check fails.

### Generate a signing identity when your role requires one

Follow [PARTICIPANT_KEY_GENERATION.md](PARTICIPANT_KEY_GENERATION.md). The core
command is:

```sh
install -d -m 0700 /secure/public
mpc-ceremony identity generate \
  --identity-id "$PARTICIPANT_ID" \
  --display-name "Participant Three" \
  --private-key-out "/secure/$PARTICIPANT_ID.private.hex" \
  --public-identity-out "/secure/public/$PARTICIPANT_ID.identity.json"
```

Send only the public identity file to the coordinator. The key ID and public
fingerprint in that file are derived automatically.

## 2. Prepare a ceremony home

**Run by:** coordinator and each role on its own machine.

```sh
install -d -m 0700 \
  "$CEREMONY_HOME/public" \
  "$CEREMONY_HOME/config" \
  "$CEREMONY_HOME/run"
```

Stage the signed public definition as:

```text
CEREMONY_HOME/
├── public/
│   ├── ceremony.json
│   └── ceremony.sig
├── config/
└── run/
```

The coordinator later creates `config/relay-storage.json`. Role operators
receive that secret-free file from the coordinator. Keep the independently
obtained coordinator public key outside the ceremony storage trust path.

**Success evidence:** exact absolute home, directory modes, definition digest,
definition signature verification, and coordinator-key fingerprint.

**Retry:** `install -d` is safe for the same narrow home. Do not overwrite a
different ceremony definition or signature in place.

## 3. Initialize and freeze the cryptographic ceremony

**Run by:** coordinator, using the authenticated proof-tool procedure.

Run the exact `mpc-ceremony init` recipe shipped with the approved proof-tool
release. It must produce the canonical signed `ceremony.json`, circuit and
constraint-system bindings, initial phase material, participant order, auditor
identities, release signer, and beacon policies.

Start by confirming the installed command family rather than guessing flags:

```sh
mpc-ceremony help
mpc-ceremony init --help
```

The exact initialization flags are intentionally not duplicated in this Relay
repository because the signed ceremony definition is owned by proof-tool and
its release-specific documentation. Follow the authenticated ceremony kit,
then use the verification steps in
[COORDINATOR_RUNBOOK.md](COORDINATOR_RUNBOOK.md#2-prepare-the-ceremony).

**Success evidence:** signed definition and detached signature, definition
digest, verified circuit and software bindings, exact role-key roster, and
native initialization receipt.

**Retry:** initialization must write to a fresh ceremony home. Never repair a
signed definition manually or overwrite a partially reviewed definition.

## 4. Configure and validate storage

Complete exactly one provider guide before running these commands:

- [AWS S3 and CloudFront](docs/AWS_SETUP.md)
- [Cloudflare R2](docs/R2_SETUP.md)

### Cloudflare R2

**Run by:** coordinator on the trusted online coordinator machine.

Read the control-plane bearer token without putting it on the command line:

```sh
read -rsp 'R2 control-plane API token: ' RELAY_R2_CONTROL_TOKEN
export RELAY_R2_CONTROL_TOKEN
printf '\n'

relay coordinator configure-storage \
  --home "$CEREMONY_HOME" \
  --provider r2 \
  --account-id CLOUDFLARE_ACCOUNT_ID \
  --parent-access-key-id PARENT_ACCESS_KEY_ID \
  --endpoint https://CLOUDFLARE_ACCOUNT_ID.r2.cloudflarestorage.com \
  --published-bucket PUBLISHED_BUCKET \
  --published-base-url https://ceremony.example.org \
  --inbox-bucket PRIVATE_INBOX_BUCKET \
  --profile r2-coordinator \
  --coordinator-key "$COORDINATOR_KEY" \
  --out "$STORAGE_CONFIG"

unset RELAY_R2_CONTROL_TOKEN
```

The token requires the permission and isolation described in
[docs/R2_SETUP.md](docs/R2_SETUP.md). The inbox must have neither `r2.dev`
access nor a public custom domain.

### AWS

**Run by:** coordinator on the trusted online coordinator machine.

```sh
relay coordinator configure-storage \
  --home "$CEREMONY_HOME" \
  --provider aws \
  --region us-east-1 \
  --published-bucket PUBLISHED_BUCKET \
  --published-base-url https://CLOUDFRONT_DISTRIBUTION.cloudfront.net \
  --inbox-bucket PRIVATE_INBOX_BUCKET \
  --profile relay-ceremony \
  --issuer-profile relay-ceremony \
  --grant-role-arn arn:aws:iam::AWS_ACCOUNT_ID:role/relay-ceremony-inbox-grant \
  --grant-role-max-ttl 1h \
  --coordinator-key "$COORDINATOR_KEY" \
  --out "$STORAGE_CONFIG"
```

`configure-storage` authenticates the ceremony, checks coordinator access,
tests published write/read/delete, reads the published probe anonymously,
checks inbox privacy, removes the probe, and writes a fresh secret-free config.

**Success evidence:** successful probe results, public origin, separate bucket
names, provider, configuration digest, coordinator-key fingerprint, and mode
`0600` on `relay-storage.json`.

**Retry:** investigate failed probes first. The output path is create-only; use
a reviewed fresh path rather than overwriting an existing storage config.

## 5. Initialize a participant profile

**Run by:** participant, once for each phase, before receiving a grant.

```sh
relay ceremony init-config \
  --home "$CEREMONY_HOME" \
  --role participant \
  --phase "$PHASE" \
  --coordinator-key "$COORDINATOR_KEY" \
  --tool-identity-receipt "$TOOL_IDENTITY_RECEIPT" \
  --signing-key /secure/participant-03.ed25519.private.hex \
  --environment /secure/participant-03.environment.json \
  --out "$ROLE_CONFIG"
```

Relay authenticates the definition and coordinator trust key, derives the
public key from the local participant key, and matches it to the exact roster
identity, key ID, fingerprint, and Phase 1/2 positions. The resulting mode-
`0600` profile stores paths, not private-key bytes or temporary grants.
Before invoking proof-tool, Relay resolves and hashes its own executable and
the configured `mpc-ceremony` executable against the setup receipt.

**Success evidence:** the authenticated ceremony ID and mode, participant
identity, key ID, fingerprint, both phase positions, selected phase, and fresh
profile path printed by Relay. The participant must confirm that the mode and
assignments match what they agreed to; they do not manually repeat the
cryptographic key comparison.

**Retry:** the output is create-only. If any authenticated value is wrong,
stop; do not edit the generated JSON. Resolve the source problem and use a
fresh reviewed output path.

## 6. Check participant status

**Run by:** participant, at any time without an upload grant.

```sh
relay participant status --config "$ROLE_CONFIG"
```

**Success evidence:** authenticated ceremony ID and mode, phase, accepted
index, current chain-head digest, next participant identity, and the
participant's turn/position result. The participant must compare these values
with the independently authenticated roster and coordinator notice.

**Retry:** safe. A non-success status, rollback warning, unexpected head, or
wrong next identity is a stop condition—not permission to delete local
high-water state.

### Authenticate Phase 2 prerequisites

Before starting Phase 2, inspect the complete local transcript with the
approved proof-tool binary:

```sh
mpc-ceremony inspect \
  --ceremony "$CEREMONY_HOME/public/ceremony.json" \
  --ceremony-signature "$CEREMONY_HOME/public/ceremony.sig" \
  --coordinator-public-key-file "$COORDINATOR_KEY" \
  --transcript-dir "$CEREMONY_HOME/public" \
  --full
```

The local transcript must already contain the complete closed Phase 1 chain,
closure, beacon response and record, seal and commons, compiled R1CS, and the
signed Phase 2 initialization. At full depth, proof-tool authenticates and
replays Phase 1, derives the sealed commons, verifies the beacon/seal
transition, and checks that Phase 2 genesis is the deterministic initialization
bound to that exact seal.

**Success evidence:** successful exit at `full` depth, Phase 1 reported sealed,
Phase 2 reported started at its authenticated chain, and no missing artifact.

**Platform gap:** no participant-facing Relay command currently fetches this
complete prerequisite set and attaches the inspection result before grant
delivery. Until one exists, stage the authenticated transcript under the
approved procedure and attach the secret-free output manually. `relay
participant run` still repeats the authoritative Phase 1 replay, seal, and
Phase 2 initialization checks before sampling contribution randomness.

## 7. Issue a participant grant

**Run by:** coordinator, only when the authenticated public head names this
participant next. Never issue overlapping turns.

Choose provider-appropriate lifetimes. These examples are starting points, not
guarantees that a production contribution will finish in time:

```sh
CREDENTIAL_TTL=72h
MINIMUM_REMAINING=2h
GRANT_FILE=$CEREMONY_HOME/run/$PARTICIPANT_ID-$PHASE.grant.json
```

For AWS, respect the configured STS limit; a direct IAM role may allow up to
12 hours, while role chaining may be limited to one hour.

For R2, expose the inbox parent token only to the grant process:

```sh
read -rsp 'R2 inbox parent API token: ' RELAY_R2_PARENT_TOKEN
export RELAY_R2_PARENT_TOKEN
printf '\n'

relay coordinator grant \
  --storage "$STORAGE_CONFIG" \
  --role participant \
  --identity "$PARTICIPANT_ID" \
  --credential-ttl "$CREDENTIAL_TTL" \
  --minimum-remaining "$MINIMUM_REMAINING" \
  --out "$GRANT_FILE"

unset RELAY_R2_PARENT_TOKEN
```

For AWS, run the same `relay coordinator grant` command without the R2 token;
Relay uses the issuer profile and grant role in `relay-storage.json`.

Privately send the fresh grant file only to the named participant when their
turn begins. Do not send its contents through the coordination website.

**Success evidence:** role, authenticated identity, exact scoped prefix,
issuance time, expiry, minimum-remaining window, fresh filename, and private
delivery acknowledgement. Never record the credential values.

**Retry:** never overwrite or reuse a grant filename. If issuance or delivery
fails, determine whether a usable grant already exists before issuing another.
Revoke or expire suspected leaks under the incident procedure.

## 8. Run a participant contribution

**Run by:** the participant using the execution mode already frozen in the
validated profile.

```sh
relay participant run \
  --config "$ROLE_CONFIG" \
  --grant PARTICIPANT_GRANT.json
```

Relay checks grant lifetime and scope, authenticates the public head, refuses
an out-of-turn attempt before expensive work, downloads and verifies the
accepted transcript, invokes proof-tool contribution, guides erasure
attestation, rechecks the head, and uploads `manifest.json` last.

In Docker mode, Relay requires the pinned image to be locally present, creates
and inspects a networkless read-only contributor, runs it with only
authenticated read-only inputs and one fresh public-output handoff, removes
the exact container ID, verifies it is absent, and only then validates the
handoff and asks for `NO COPIES RETAINED`. Native mode retains the ceremony
kit's manual destruction procedure and `DESTROYED` confirmation.

**Success evidence:** successful process exit plus:

```text
candidate submitted for coordinator review
attempt: ...
candidate directory: /absolute/path/to/candidate
destroyed_at: 2026-09-04T12:00:00Z
manifest: candidates/.../manifest.json
```

Record the printed manifest key, attempt ID, saved candidate directory, and
signed erasure timestamp. Retain the public candidate until acceptance is
independently confirmed.

**Retry:** do not rerun after computation and erasure merely because upload
failed. Use the resume recipe below. If Relay reports an out-of-turn or stale
head, stop and contact the coordinator.

## 9. Resume an interrupted participant upload

**Run by:** participant, only after the coordinator confirms the public head
has not advanced and supplies a replacement grant in a fresh file.

```sh
relay participant run \
  --config "$ROLE_CONFIG" \
  --grant REPLACEMENT_GRANT.json \
  --resume-candidate /absolute/path/printed/by/relay
```

Relay re-hashes every saved file, authenticates the ceremony, role, phase,
position, attempt, and starting head, verifies already uploaded remote bytes,
and uploads the manifest last.

**Success evidence:** successful exit, the same attempt binding, and:

```text
candidate upload resumed without recomputing the contribution
attempt: ...
candidate directory: /absolute/path/to/candidate
destroyed_at: 2026-09-04T12:00:00Z
manifest: candidates/.../manifest.json
```

**Retry:** another network interruption may be resumed with another fresh
grant. A stale head, changed saved file, or conflicting remote byte is a stop
condition. Never edit the candidate to make a resume pass.

## 10. Discover complete participant candidates

**Run by:** coordinator after receiving a manifest key or checking the inbox.

```sh
relay coordinator candidates \
  --storage "$STORAGE_CONFIG" \
  --phase "$PHASE"
```

The command lists schema-valid manifests for the configured ceremony. `ready`
means ready for acceptance review, not cryptographically valid or complete:
`relay coordinator accept` later checks the exact participant/phase/index/
attempt path, downloads every referenced object, verifies its hash, and
authenticates the contribution against the current chain head. Relay's own
uploader writes `manifest.json` last, but the inbox remains untrusted, so never
infer object completeness from this listing alone.

**Success evidence:** exact candidate manifest key, participant identity,
phase, and index recorded in the turn record. Acceptance later verifies the
attempt binding and complete file set.

**Retry:** safe. Listing a candidate does not authenticate its contribution or
authorize acceptance.

## 11. Accept and publish a participant candidate

**Run by:** coordinator after reviewing the exact manifest key and unlocking
the protected coordinator signing key for this action.

```sh
relay coordinator accept \
  --storage "$STORAGE_CONFIG" \
  --candidate-key CANDIDATES_MANIFEST_KEY \
  --coordinator-signing-key /secure/coordinator.ed25519.private.hex \
  --verify-publish
```

For Phase 2, Relay uses the default Phase 1 seal paths beneath the transcript
root. Supply `--phase1-seal` and `--phase1-seal-signature` only when the
authenticated layout requires explicit alternate paths.

Relay validates manifest scope and hashes, checks the scheduled identity and
current head, downloads into a fresh review directory, invokes
`mpc-ceremony PHASE verify`, rechecks that the head did not advance, publishes
the coordinator-signed accepted chain, then re-derives and confirms the
published file set because `--verify-publish` is present.

**Success evidence:** native proof-tool verification output, candidate and
acceptance timestamps, signed chain and signature digests, new index, and:

```text
accepted candidate CANDIDATES_MANIFEST_KEY and advanced the published head
```

Independently fetch and authenticate the new public head before notifying the
next participant.

**Retry:** do not rerun blindly. The command uses a fresh review directory and
may already have produced or published an accepted chain. Inspect the signed
public head and local output first. Never delete high-water state or overwrite
signed records to force a retry.

## 12. Publish a signed lifecycle update

**Run by:** coordinator after proof-tool has produced and signed an authenticated
closure, beacon/seal transition, or other chain update.

```sh
relay coordinator publish \
  --storage "$STORAGE_CONFIG" \
  --chain /absolute/path/to/chain-NNNN.json \
  --chain-signature /absolute/path/to/chain-NNNN.sig \
  --verify
```

For a phase closure, add `--closed`:

```sh
relay coordinator publish \
  --storage "$STORAGE_CONFIG" \
  --chain /absolute/path/to/final-chain.json \
  --chain-signature /absolute/path/to/final-chain.sig \
  --closed \
  --verify
```

Relay authenticates the signed chain, uploads referenced immutable artifacts
before moving the public pointer, and verifies the published file set when
`--verify` is present.

The proof-tool commands that create phase closure, fetch and authenticate the
pinned future beacon, seal Phase 1, initialize Phase 2, and close Phase 2 must
come from the authenticated proof-tool procedure for the pinned release. Check
the installed interface with:

```sh
mpc-ceremony help
mpc-ceremony help phase1
mpc-ceremony help phase2
```

**Success evidence:** authenticated input and output chain digests, detached
signature, closure state if applicable, published head, independent public
read, and verified immutable file set.

**Retry:** content-addressed immutable uploads are retry-safe only when the
bytes match. Inspect the current signed pointer before retrying a lifecycle
publication.

## 13. Initialize a non-participant role

**Run by:** witness, mirror, auditor, or online release upload station after
receiving its authenticated signed enrollment.

Set `ROLE` to exactly one of `witness`, `mirror`, `auditor`, or `release`, and
select the corresponding enrollment paths:

```sh
ROLE=witness
IDENTITY_ID=witness-01
ENROLLMENT=/trusted/witness-01.json
ENROLLMENT_SIGNATURE=/trusted/witness-01.sig
ROLE_CONFIG=$CEREMONY_HOME/config/$ROLE-$PHASE.json

relay ceremony init-config \
  --home "$CEREMONY_HOME" \
  --role "$ROLE" \
  --identity "$IDENTITY_ID" \
  --phase "$PHASE" \
  --coordinator-key "$COORDINATOR_KEY" \
  --tool-identity-receipt "$TOOL_IDENTITY_RECEIPT" \
  --enrollment "$ENROLLMENT" \
  --enrollment-signature "$ENROLLMENT_SIGNATURE" \
  --out "$ROLE_CONFIG"
```

**Success evidence:** authenticated ceremony, enrollment role and identity,
phase, coordinator key, and fresh mode-`0600` profile path.

**Retry:** stop on any role, identity, or ceremony mismatch. Do not edit the
generated profile; correct the authenticated inputs and use a fresh path.

## 14. Issue a non-participant evidence grant

**Run by:** coordinator after authenticating the signed enrollment.

```sh
relay coordinator grant \
  --storage "$STORAGE_CONFIG" \
  --role "$ROLE" \
  --identity "$IDENTITY_ID" \
  --credential-ttl "$CREDENTIAL_TTL" \
  --minimum-remaining "$MINIMUM_REMAINING" \
  --enrollment "$ENROLLMENT" \
  --enrollment-signature "$ENROLLMENT_SIGNATURE" \
  --out "$CEREMONY_HOME/run/$IDENTITY_ID-$ROLE.grant.json"
```

For R2, expose `RELAY_R2_PARENT_TOKEN` only around the command as shown in the
participant-grant recipe. A production-decision grant uses `--role decision`
and an eligible coordinator, auditor, or release-signer enrollment.

**Success evidence:** authenticated enrollment, role, identity, exact evidence
prefix, issue and expiry timestamps, minimum-remaining window, and private
delivery acknowledgement. Never record credential values.

**Retry:** use a fresh filename. Possession of a grant authorizes storage
transport only; it does not authorize or sign ceremony evidence.

## 15. Observe a phase closure as a public witness

**Run by:** witness using a validated witness profile.

```sh
relay witness run --config "$ROLE_CONFIG" --interval 60s
```

For a single non-blocking check:

```sh
relay witness run --config "$ROLE_CONFIG" --once
```

`--once` exits non-zero when no closure is available. After a closure is
reported, the witness must independently decide whether it was observed before
the beacon round and with the required lead time. Relay deliberately cannot
make that real-world claim or sign the receipt.

**Success evidence:** authenticated closed phase, accepted index, chain digest,
observation time, and the witness's independent timing review.

**Retry:** continuous polling is safe. Do not treat a successful network read
alone as a signed witness observation.

## 16. Synchronize a mirror or auditor

**Run by:** mirror operator or auditor using its own validated profile and
independently controlled destination.

Mirror:

```sh
relay mirror run --config "$CEREMONY_HOME/config/mirror-$PHASE.json"
```

Auditor, once per phase:

```sh
relay auditor run --config "$CEREMONY_HOME/config/auditor-phase1.json"
relay auditor run --config "$CEREMONY_HOME/config/auditor-phase2.json"
```

Relay authenticates the chain and verifies every newly fetched digest-pinned
transcript file. It does not overwrite an existing local file, but the sync
path does not yet compare every pre-existing artifact with its authenticated
digest. Mirror receipt preparation and the full audit must perform that final
complete-set check. An auditor must run the exact `mpc-ceremony audit`
procedure shipped with the approved proof-tool release against the
independently obtained transcript:

```sh
mpc-ceremony audit --help
```

**Success evidence:** authenticated head, exact retained file-set digest,
destination identity, and—where applicable—the complete proof-tool audit
record and detached signature.

**Retry:** safe when existing local files match their authenticated digests.
Relay will not overwrite existing local bytes, but current sync does not prove
that they match. Require the corresponding proof-tool verification and
investigate any mismatch rather than deleting evidence reflexively.

## 17. Prepare a mirror receipt

**Run by:** mirror operator after synchronizing the exact authenticated head.

```sh
relay mirror receipt \
  --config "$CEREMONY_HOME/config/mirror-$PHASE.json" \
  --chain /absolute/path/to/chain-NNNN.json \
  --chain-signature /absolute/path/to/chain-NNNN.sig \
  --index N \
  --location s3://independent-mirror/prefix \
  --stored-at 2026-09-04T12:00:00Z \
  --out "$CEREMONY_HOME/run/mirror-receipt-N.json"
```

Authenticate and canonicalize the draft with the approved proof-tool release:

```sh
mpc-ceremony ops prepare-mirror-receipt \
  --draft "$CEREMONY_HOME/run/mirror-receipt-N.json" \
  --ceremony "$CEREMONY_HOME/public/ceremony.json" \
  --ceremony-signature "$CEREMONY_HOME/public/ceremony.sig" \
  --coordinator-public-key-file "$COORDINATOR_KEY" \
  --transcript-root "$CEREMONY_HOME/public" \
  --chain /absolute/path/to/chain-NNNN.json \
  --chain-signature /absolute/path/to/chain-NNNN.sig \
  --mirror-enrollment "$ENROLLMENT" \
  --mirror-enrollment-signature "$ENROLLMENT_SIGNATURE" \
  --out-dir "$CEREMONY_HOME/run/mirror-receipt-N-signing"
```

Review and sign the exported canonical bytes offline using the mirror's key,
then move only the signed output to the upload environment.

**Success evidence:** exact chain prefix, accepted head, index, retained file
set, location digest, stored-at time, enrollment binding, canonical signing
payload, and detached signature.

**Retry:** both Relay outputs are create-only. Use fresh reviewed output names;
never overwrite a draft or canonical payload that may already be under review.

## 18. Submit signed role evidence

**Run by:** witness, mirror, auditor, or online release upload station after
the applicable proof-tool record has been reviewed and signed.

Submit one directory:

```sh
relay witness submit \
  --config "$CEREMONY_HOME/config/witness-$PHASE.json" \
  --grant WITNESS_GRANT.json \
  --dir /absolute/path/to/signed-witness-output
```

The equivalent command prefixes are `relay mirror submit` and
`relay auditor submit`. To submit an explicit set of files, repeat `--file`:

```sh
relay auditor submit \
  --config "$CEREMONY_HOME/config/auditor-$PHASE.json" \
  --grant AUDITOR_GRANT.json \
  --file /absolute/path/to/audit.json \
  --file /absolute/path/to/audit.sig
```

On the separate online release station:

```sh
relay release run \
  --config "$CEREMONY_HOME/config/release-$PHASE.json" \
  --grant RELEASE_GRANT.json \
  --dir /absolute/path/to/signed-release-output
```

For production-decision output, use the generic compatibility command with a
decision-scoped grant:

```sh
relay submit-evidence \
  --grant DECISION_GRANT.json \
  --dir /absolute/path/to/signed-decision-output
```

Relay rejects symlinks, non-regular files, duplicate names, and filenames that
look like private keys, credentials, grants, or signing keys. It uploads the
manifest last.

**Success evidence:** successful exit and the printed evidence manifest key.
Send only that key and approved public status to the coordinator.

**Retry:** a failed evidence submission does not appear complete without its
manifest. Inspect the error and grant lifetime before retrying. The generic
evidence command does not currently expose participant-style saved-candidate
resume semantics.

## 19. Discover and review role evidence

**Run by:** coordinator.

List every supported evidence role:

```sh
relay coordinator evidence --storage "$STORAGE_CONFIG"
```

Or filter to one of `witness`, `mirror`, `auditor`, `release`, or `decision`:

```sh
relay coordinator evidence \
  --storage "$STORAGE_CONFIG" \
  --role auditor
```

This discovers complete, correctly scoped manifests; it does not establish
that the contained ceremony evidence is valid. Download each selected
submission into a fresh review directory and run the corresponding
version-pinned proof-tool verification command before promotion.

**Success evidence:** submission role, authenticated identity, manifest key,
file hashes, proof-tool verification output, acceptance or rejection reason,
and any superseded evidence relationship.

**Retry:** listing is safe. Never promote evidence because storage upload or
manifest validation alone succeeded.

## 20. Release, archive, and cleanup

There is intentionally no single Relay command that makes the production
go/no-go decision, signs a release, proves independent mirror operation, or
authorizes destructive cleanup.

The release and production-decision machines remain offline. They run the
exact proof-tool review and signing procedures from the authenticated ceremony
kit. Separate online stations use the evidence-submission commands above to
transport only signed output.

The coordinator must then:

1. verify release and decision records with proof-tool;
2. confirm every artifact refers to one ceremony and coherence set;
3. record the explicit human go/no-go authorization;
4. preserve the signed definition, both phase chains, closures, beacons,
   seals, evidence, audits, decision, release bundle, and checksums on the
   required independent mirrors;
5. verify the archive before expiring grants or issuer access; and
6. perform cleanup only under the approved retention and destruction procedure.

Do not put generic recursive deletion commands in a reusable ceremony recipe.
Cleanup targets must be resolved from the authenticated ceremony record and
approved explicitly for that completed ceremony.

## Quick failure guide

| Result | Action |
| --- | --- |
| Tool, signature, digest, identity, role, phase, or position mismatch | Stop and preserve secret-free output. |
| Public head moved backward or conflicts between observers | Stop; never delete high-water state. |
| Public head advanced during contribution or acceptance | Do not upload or publish the stale candidate. |
| Grant expired or has insufficient remaining time before work | Request a fresh grant; do not weaken the minimum. |
| Upload failed after contribution and erasure | Retain the public candidate and use `--resume-candidate`. |
| Resume reports changed local or conflicting remote bytes | Stop; do not edit files to make it pass. |
| Evidence upload succeeded but proof-tool verification failed | Reject the evidence; storage success is not authorization. |
| Private key, grant, parent credential, or control token may have leaked | Pause, contain, rotate or revoke, and record the incident. |

For anything not covered here, use the failure procedures in
[COORDINATOR_RUNBOOK.md](COORDINATOR_RUNBOOK.md#8-failure-and-recovery) and
[ROLE_RUNBOOK.md](ROLE_RUNBOOK.md#9-failure-and-recovery).
