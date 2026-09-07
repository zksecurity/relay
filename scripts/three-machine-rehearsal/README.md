# Three-machine tiny rehearsal

This directory turns the tiny Relay rehearsal into explicit machine steps.
All three machines use the same reviewed Relay and `mpc-ceremony` binaries.
This is the detailed rehearsal walkthrough; production operators instead use
the Relay coordinator or role reference from the authenticated source release.

The role split is:

| Machine | Roles |
|---|---|
| Machine 1 | coordinator, storage issuer, candidate acceptance, publication |
| Machine 2 | participant-01, participant-03, witness-01, mirror-01, auditor-01 |
| Machine 3 | participant-02, witness-02, mirror-02, auditor-02, release signer |

This is a functional rehearsal, not production independence evidence. The
rehearsal config generated all fixture keys centrally, and the optional
operational-evidence helper uses those centralized fixture keys again.

Commands below are intentionally flush left for copying.

## From this rehearsal to a fully distributed ceremony

This rehearsal deliberately co-locates roles and takes two shortcuts so the
whole flow runs quickly on three hosts. A real ceremony where every role is a
separate, independently operated machine drops those shortcuts. The numbered
scripts still apply — each already takes the identity as an argument — but three
things change. The [coordinator runbook](../../docs/operator/COORDINATOR_RUNBOOK.md) and
[role reference](../../docs/operator/roles-reference.md) are the authority for the distributed
procedure; this table maps each rehearsal shortcut to what replaces it.

| Rehearsal shortcut | Fully distributed replacement |
|---|---|
| **Central key generation.** `00-coordinator-initialize.sh` mints every fixture keypair on Machine 1 and hands each role its private key. | Each role generates its **own** keypair on its own machine and never shares the private key. Only its public key and a signed enrollment record reach the coordinator, which authenticates them into the roster. |
| **Central operational evidence (steps 33–41).** The coordinator generates the witness and mirror receipts centrally with `10-coordinator-generate-operational-fixtures.sh` using the centralized fixture keys; the role machines only re-upload them. | Each witness, mirror, and auditor **produces and signs its own record** on its own machine — `mpc-ceremony ops prepare-public-witness-receipt`, `relay mirror receipt` → `mpc-ceremony ops prepare-mirror-receipt`, and `mpc-ceremony audit` — then submits it. Steps 33–41 do not model independent evidence; they exercise only the upload transport. |
| **Role co-location.** Machines 2 and 3 each hold five role keys under one `KEYS_ROOT`. | Each machine holds a **single** role key with its own `.env` and single-key `KEYS_ROOT`. Because the scripts take the identity as an argument (for example `04-role-participate.sh "$E" phase1 participant-01`), the three-machine split here is illustrative, not required — the same scripts drive one role per machine. |

Because of the first two rows, a passing run here shows that the orchestration
and transport work end to end; it is **not** evidence of independent
contribution, witnessing, mirroring, or auditing. Only a run where each role
holds and uses its own key on its own machine, per the runbooks above, produces
that.

## Before you begin

This README is Machine 1's master process guide. Complete the coordinated-tool
installation first, then complete exactly one storage-provider guide before
the first numbered ceremony step:

- [installation guide](../../docs/setup/INSTALL.md)
- [AWS setup guide](../../docs/setup/AWS_SETUP.md)
- [Cloudflare R2 setup guide](../../docs/setup/R2_SETUP.md)

Those links are for a source checkout. An authenticated downloaded rehearsal
contains copies under its own `docs/` directory. From the downloaded directory,
Machine 1 can review them with:

```bash
cd "$HOME/ceremony-tools/three-machine-rehearsal"
S=$PWD
less "$S/docs/setup/INSTALL.md"
less "$S/docs/setup/AWS_SETUP.md"    # choose AWS
less "$S/docs/setup/R2_SETUP.md"     # or choose R2
```

The Machine 1 installation command from `INSTALL.md` also extracts the provider
scripts as the sibling directory `$S/../storage-setup`. Machines 2 and 3 do not
configure storage; they install their assigned kit and wait for Machine 1's
authenticated handoff. After installation and provider setup, continue through
this README from top to bottom and run each numbered command on the named
machine.

## Expected rehearsal timing

The table below records the AWS-backed single-host validation run on
2026-08-20. It used the five-constraint `rehearsal-tiny-v1` circuit, existing
buckets, and a one-second observation buffer. The normal 120-second buffer adds
about two minutes to each beacon step. Network latency, secure handoffs, human
confirmation of environment destruction, and first-time bucket or CloudFront
provisioning add time.

| Steps | Work | Measured time |
|---|---|---:|
| Before 1 | Initialize ceremony and check Machine 1 | under 1 second |
| 1 | Configure existing AWS storage | 9 seconds |
| 2 | Publish initial Phase 1 head with verification | 16 seconds |
| 3, 6, 9 | Issue each Phase 1 participant grant | about 1 second each |
| 4, 7, 10 | Each Phase 1 contribution and upload | 10–20 seconds plus destruction time |
| 5, 8, 11 | Accept Phase 1 participants 1, 2, and 3 | about 35, 50, and 70 seconds |
| 12 | Close and publish Phase 1 | 1 minute 20 seconds |
| 13–14 | Both witness checks | under 2 seconds in parallel |
| 15 | Wait for beacon, seal Phase 1, initialize Phase 2 | 5 minutes 42 seconds; about 7 minutes 41 seconds with the default buffer |
| 16, 19, 22 | Issue each Phase 2 participant grant | about 1 second each |
| 17, 20, 23 | Each Phase 2 contribution and upload | 20–30 seconds plus destruction time |
| 18, 21, 24 | Accept Phase 2 participants 1, 2, and 3 | about 40, 55, and 75 seconds |
| 25 | Close and publish Phase 2 | 1 minute 19 seconds |
| 26–27 | Both witness checks | under 2 seconds in parallel |
| 28 | Wait for and publish the Phase 2 beacon | 5 minutes 26 seconds; about 7 minutes 25 seconds with the default buffer |
| 29–32 | All mirror and auditor synchronizations | 4 seconds when parallel |
| 33 | Generate operational fixtures | 1 second |
| 34, 36, 38, 40 | Issue four evidence grants | about 1 second each |
| 35, 37, 39, 41 | Upload four evidence pairs | 4 seconds when parallel |
| 42 | List and validate evidence manifests | 9 seconds |

The measured end-to-end run took about 27 minutes after initialization. Budget
about 31 minutes with the default witness buffers, before human handoff time.
This timing says nothing about production: the real circuit and contribution
replay can take hours, and transcript upload time grows with its size.

### Short R2 validation

If the goal is only to prove that the R2 integration works, choose one of these
explicit stopping points:

- Stop after step 1 for a storage-only check. Relay has exercised coordinator
  writes, reads and deletes, the anonymous published origin, the private inbox,
  and the inbox control-plane privacy check.
- Stop after step 14 for an end-to-end ceremony transport check. Relay has also
  exercised three locally signed, identity-prefix-scoped temporary grants;
  participant uploads; coordinator candidate downloads and verification;
  accepted publication; closure publication; and anonymous witness reads from
  two role-machine views.

Step 15 begins the timed beacon and is not needed for either R2 check. If it is
already waiting, interrupting it before the target round is reached leaves the
published phase closed with no beacon recorded. Continuing past step 15 is
needed to test phase 2, beacon publication, mirror/auditor synchronization, and
role-evidence uploads.

The second stopping point was successfully exercised against real Cloudflare
R2 on 2026-08-20 with the tiny circuit. The public phase 1 head was closed at
index 3 after all three candidate uploads were accepted.

## One-time setup on each machine

Download and verify the versioned ceremony kit on all three machines by
following the installation guide above. Running `setup --machine N` installs both
binaries, extracts this standalone directory, and creates the selected private
`.env` with all release fields prefilled. No Relay source checkout is needed.
Install Bash, Python 3, and GNU coreutils in addition to the three programs
checked below.

Machine 1:

```bash
cd "$HOME/ceremony-tools/three-machine-rehearsal"
test -f machine-1/.env
chmod 0600 machine-1/.env
```

Machine 2:

```bash
cd "$HOME/ceremony-tools/three-machine-rehearsal"
test -f machine-2/.env
chmod 0600 machine-2/.env
```

Machine 3:

```bash
cd "$HOME/ceremony-tools/three-machine-rehearsal"
test -f machine-3/.env
chmod 0600 machine-3/.env
```

The setup command prints the resulting `.env` path and automatically sets its
one `WORK_ROOT` to an absolute, access-controlled directory. All ceremony,
configuration, key, trust, run, and storage-config paths are derived from it.
Review the generated file before continuing.

On Machine 1, create the fresh signed tiny rehearsal directly with the
authenticated `mpc-ceremony` binary bundled in the kit:

```bash
cd "$HOME/ceremony-tools/three-machine-rehearsal"
S=$PWD
E="$S/machine-1/.env"
"$S/00-coordinator-initialize.sh" "$E"
```

This command creates fresh same-host fixture keys, canonical configuration,
and the signed `rehearsal-tiny-v1` ceremony. It also places a same-host copy of
the coordinator public key at Machine 1's standard trust path. This tests the
workflow only; it is not independent trust or production evidence.

The resulting files use this layout:

```text
WORK_ROOT/
├── public/                    ceremony.json, ceremony.sig, transcript files
├── config/                    environment.json and local public configuration
├── keys/                      assigned private role keys; Machine 1 retains all fixtures
├── trust/
│   ├── coordinator-public-key.hex
│   └── relay-storage.json     Machines 2 and 3 after coordinator handoff
└── run/                       fresh Relay outputs
```

Machine 1 writes `run/relay-storage.json` instead. The initializer's same-host
coordinator-key copy is only a functional fixture; a production ceremony or an
independence rehearsal must authenticate that key through an independent trust
channel. Never copy all rehearsal private keys to Machines 2 or 3.

Machine 1 retains the initialized transcript and all centrally generated
fixture keys. Machines 2 and 3 need securely transferred local copies of:

- `ceremony.json` and `ceremony.sig`;
- the coordinator public key obtained through the independent trust channel;
- `config/environment.json`;
- only the participant and role private keys assigned to that machine; and
- the identical Relay and `mpc-ceremony` binaries.

Do not transfer all fixture keys to Machines 2 or 3. Machine 2 receives only
`participant-01`, `participant-03`, `witness-01`, `mirror-01`, and `auditor-01`.
Machine 3 receives only `participant-02`, `witness-02`, `mirror-02`,
`auditor-02`, and `release-signer`.

Run the machine check only after the preceding initialization or handoff is
complete:

Machine 1:

```bash
cd "$HOME/ceremony-tools/three-machine-rehearsal"
S=$PWD
E="$S/machine-1/.env"
"$S/00-check-machine.sh" "$E"
```

Machine 2:

```bash
cd "$HOME/ceremony-tools/three-machine-rehearsal"
S=$PWD
E="$S/machine-2/.env"
"$S/00-check-machine.sh" "$E"
```

Machine 3:

```bash
cd "$HOME/ceremony-tools/three-machine-rehearsal"
S=$PWD
E="$S/machine-3/.env"
"$S/00-check-machine.sh" "$E"
```

In the remaining sections, `S` and `E` mean the values set above on that
machine.

## Phase 1

### 1. Machine 1: configure storage

If the storage does not exist yet, run the provider setup first:

- Downloaded kit: `$S/docs/setup/AWS_SETUP.md` or `$S/docs/setup/R2_SETUP.md`
- Source checkout: [AWS setup](../../docs/setup/AWS_SETUP.md) or
  [Cloudflare R2 setup](../../docs/setup/R2_SETUP.md)

The provider scripts are in the same relative location in a source checkout
and in the extracted kit. Resolve that directory first:

```bash
STORAGE_SETUP_ROOT=$(realpath "$S/../storage-setup")
```

For AWS, pass the generated Machine 1 file to the setup command:

```bash
"$STORAGE_SETUP_ROOT/scripts/storage-setup/setup-aws.sh" --machine-env "$E"
```

The default file is
`$HOME/ceremony-tools/three-machine-rehearsal/machine-1/.env`, outside the
immutable downloaded `ceremony-kit` directory. AWS setup atomically populates
its non-secret storage fields; `STORAGE_ENDPOINT=` intentionally remains
empty. All secret credential values remain outside the file. Provider scripts
still print the resulting non-secret block for the operator log.

For R2, authenticate Wrangler and create the short-lived token manager described
in the provider guide, then pass the generated Machine 1 file to the wrapper:

```bash
TOKEN_MANAGER_FILE="$HOME/.config/relay/cloudflare-token-manager"
"$STORAGE_SETUP_ROOT/scripts/storage-setup/setup-r2-wrangler.sh" \
  --token-manager-file "$TOKEN_MANAGER_FILE" \
  --machine-env "$E"
```

The wrapper discovers the authenticated account and active Cloudflare zones,
generates the bucket names, provisions the resources, stores the inbox-parent
API token and Secret Access Key in separate protected local files, and
atomically populates the non-secret Machine 1 fields. Relay prefers the Secret
Access Key to sign temporary credentials locally. With no active zone it uses
a rate-limited, rehearsal-only `r2.dev` origin for the published bucket while
keeping the inbox private.
Cloudflare requires one account token to be created in its dashboard with
**Account > Account API Tokens > Edit**. The wrapper uses that short-lived
token to create the two differently scoped R2 credentials automatically. Revoke
the token manager and remove its local file as soon as setup succeeds. Without
it, the wrapper falls back to prompting for two manually created R2
credentials.

```bash
"$S/01-coordinator-configure-storage.sh" "$E"
```

For the recommended R2 rehearsal path, step 1 refreshes the current Wrangler
OAuth token only long enough to confirm that the inbox has neither public
`r2.dev` access nor an attached custom domain. Later grant and upload steps do
not require Wrangler. The OAuth value is not stored in the rehearsal `.env`.
The explicit-token production path instead uses a protected control-token file
with account-level `Workers R2 Storage Read`; Cloudflare does not offer
bucket-scoped configuration read, so use a dedicated ceremony account if that
scope is unacceptable.

For AWS, the guided setup uses one profile for both coordinator and issuer
operations, so Machine 1 sets both profile fields to the same name. Relay also
supports separate coordinator and issuer profiles when an organization needs
stricter privilege separation. Machine 1 also records both bucket names, the
published HTTPS origin, and the grant role name. The wrapper reads the region
and account ID through the selected AWS CLI profile, then derives the regional
S3 endpoint and full role ARN. It prints the resolved
values before Relay performs its disposable storage probes. It never lists
buckets or CloudFront distributions and never guesses which resources to use.
After configuration, later coordinator steps reload those resolved values from
`run/relay-storage.json` instead of repeating AWS discovery.

Privately copy the resulting `relay-storage.json` to `trust/relay-storage.json`
under `WORK_ROOT` on Machines 2 and 3. It contains no temporary role credential,
but do not use the public ceremony bucket as the handoff. Role machines read
the published bucket and anonymous HTTPS origin from this file rather than
repeating them in their `.env`; no long-lived reader profile is needed.

### 2. Machine 1: publish the initial Phase 1 head

```bash
"$S/02-coordinator-publish-initial.sh" "$E" phase1
```

### 3. Machine 1: issue the participant-01 grant

```bash
"$S/03-coordinator-issue-participant-grant.sh" "$E" phase1 participant-01 /secure/handoff/phase1-participant-01.grant.json
```

Privately copy the grant to Machine 2 with mode `0600`.

### 4. Machine 2: run participant-01

```bash
"$S/04-role-participate.sh" "$E" phase1 participant-01 /secure/handoff/phase1-participant-01.grant.json
```

The script prints the path of a manifest-key file. Copy that small file to
Machine 1 as `/secure/handoff/phase1-participant-01.manifest-key.txt`.

If a participant finishes computation but its upload is interrupted, the
script archives the completed candidate and prints a five-argument recovery
command. Machine 1 issues a replacement grant for the same phase and identity
using a fresh grant filename. Run the printed command on the participant
machine with that new grant and archived candidate directory. Relay verifies
the saved candidate and unchanged public head, then continues the same upload
without recomputing. The replacement grant's minimum remaining time only needs
to cover verification and upload.

### 5. Machine 1: accept participant-01

```bash
"$S/05-coordinator-accept-participant.sh" "$E" phase1 participant-01 /secure/handoff/phase1-participant-01.manifest-key.txt
```

### 6. Machine 1: issue the participant-02 grant

```bash
"$S/03-coordinator-issue-participant-grant.sh" "$E" phase1 participant-02 /secure/handoff/phase1-participant-02.grant.json
```

Privately copy the grant to Machine 3.

### 7. Machine 3: run participant-02

```bash
"$S/04-role-participate.sh" "$E" phase1 participant-02 /secure/handoff/phase1-participant-02.grant.json
```

Copy its manifest-key file to Machine 1 as
`/secure/handoff/phase1-participant-02.manifest-key.txt`.

### 8. Machine 1: accept participant-02

```bash
"$S/05-coordinator-accept-participant.sh" "$E" phase1 participant-02 /secure/handoff/phase1-participant-02.manifest-key.txt
```

### 9. Machine 1: issue the participant-03 grant

```bash
"$S/03-coordinator-issue-participant-grant.sh" "$E" phase1 participant-03 /secure/handoff/phase1-participant-03.grant.json
```

Privately copy the grant to Machine 2.

### 10. Machine 2: run participant-03

```bash
"$S/04-role-participate.sh" "$E" phase1 participant-03 /secure/handoff/phase1-participant-03.grant.json
```

Copy its manifest-key file to Machine 1 as
`/secure/handoff/phase1-participant-03.manifest-key.txt`.

### 11. Machine 1: accept participant-03

```bash
"$S/05-coordinator-accept-participant.sh" "$E" phase1 participant-03 /secure/handoff/phase1-participant-03.manifest-key.txt
```

### 12. Machine 1: close and publish Phase 1

```bash
"$S/06-coordinator-close-phase.sh" "$E" phase1
```

Do not run the beacon step yet.

### 13. Machine 2: witness-01 checks the closure notification

```bash
"$S/07-role-witness-watch.sh" "$E" phase1 witness-01
```

### 14. Machine 3: witness-02 checks the closure notification

```bash
"$S/07-role-witness-watch.sh" "$E" phase1 witness-02
```

### 15. Machine 1: wait for and record the Phase 1 beacon

```bash
"$S/08-coordinator-record-beacon.sh" "$E" phase1
```

This waits about seven minutes for the pinned round, records and seals Phase 1,
initializes Phase 2, and publishes its initial head. The extra two minutes give
both witness machines time to see the notification while the signed five-minute
lead still remains. `witness watch` does not itself create a signed witness
receipt; the optional fixture section tests that upload shape separately.

## Phase 2

### 16. Machine 1: issue the participant-01 grant

```bash
"$S/03-coordinator-issue-participant-grant.sh" "$E" phase2 participant-01 /secure/handoff/phase2-participant-01.grant.json
```

Privately copy the grant to Machine 2.

### 17. Machine 2: run participant-01

```bash
"$S/04-role-participate.sh" "$E" phase2 participant-01 /secure/handoff/phase2-participant-01.grant.json
```

Copy its manifest-key file to Machine 1 as
`/secure/handoff/phase2-participant-01.manifest-key.txt`.

### 18. Machine 1: accept participant-01

```bash
"$S/05-coordinator-accept-participant.sh" "$E" phase2 participant-01 /secure/handoff/phase2-participant-01.manifest-key.txt
```

### 19. Machine 1: issue the participant-02 grant

```bash
"$S/03-coordinator-issue-participant-grant.sh" "$E" phase2 participant-02 /secure/handoff/phase2-participant-02.grant.json
```

Privately copy the grant to Machine 3.

### 20. Machine 3: run participant-02

```bash
"$S/04-role-participate.sh" "$E" phase2 participant-02 /secure/handoff/phase2-participant-02.grant.json
```

Copy its manifest-key file to Machine 1 as
`/secure/handoff/phase2-participant-02.manifest-key.txt`.

### 21. Machine 1: accept participant-02

```bash
"$S/05-coordinator-accept-participant.sh" "$E" phase2 participant-02 /secure/handoff/phase2-participant-02.manifest-key.txt
```

### 22. Machine 1: issue the participant-03 grant

```bash
"$S/03-coordinator-issue-participant-grant.sh" "$E" phase2 participant-03 /secure/handoff/phase2-participant-03.grant.json
```

Privately copy the grant to Machine 2.

### 23. Machine 2: run participant-03

```bash
"$S/04-role-participate.sh" "$E" phase2 participant-03 /secure/handoff/phase2-participant-03.grant.json
```

Copy its manifest-key file to Machine 1 as
`/secure/handoff/phase2-participant-03.manifest-key.txt`.

### 24. Machine 1: accept participant-03

```bash
"$S/05-coordinator-accept-participant.sh" "$E" phase2 participant-03 /secure/handoff/phase2-participant-03.manifest-key.txt
```

### 25. Machine 1: close and publish Phase 2

```bash
"$S/06-coordinator-close-phase.sh" "$E" phase2
```

### 26. Machine 2: witness-01 checks the closure notification

```bash
"$S/07-role-witness-watch.sh" "$E" phase2 witness-01
```

### 27. Machine 3: witness-02 checks the closure notification

```bash
"$S/07-role-witness-watch.sh" "$E" phase2 witness-02
```

### 28. Machine 1: wait for and record the Phase 2 beacon

```bash
"$S/08-coordinator-record-beacon.sh" "$E" phase2
```

This also waits about seven minutes: five minutes of signed witness lead plus
the two-minute rehearsal observation buffer.

## Read-only role synchronization

### 29. Machine 2: mirror-01 synchronizes both phases

```bash
"$S/09-role-sync.sh" "$E" mirror phase1 mirror-01
"$S/09-role-sync.sh" "$E" mirror phase2 mirror-01
```

### 30. Machine 3: mirror-02 synchronizes both phases

```bash
"$S/09-role-sync.sh" "$E" mirror phase1 mirror-02
"$S/09-role-sync.sh" "$E" mirror phase2 mirror-02
```

### 31. Machine 2: auditor-01 synchronizes both phases

```bash
"$S/09-role-sync.sh" "$E" auditor phase1 auditor-01
"$S/09-role-sync.sh" "$E" auditor phase2 auditor-01
```

### 32. Machine 3: auditor-02 synchronizes both phases

```bash
"$S/09-role-sync.sh" "$E" auditor phase1 auditor-02
"$S/09-role-sync.sh" "$E" auditor phase2 auditor-02
```

## Optional evidence-upload transport test

This section uses proof-tool's centralized same-host rehearsal helper. It tests
Relay's enrollment authentication and scoped uploads, but it does not convert
the three-machine run into independent witness or mirror evidence.

Unlike every step above, this section is not kit-only: step 33 builds the
fixture helper from proof-tool source on Machine 1, so it additionally needs a
Go toolchain (`go` on `PATH`, or `GO_BIN`) and `PROOF_TOOL_ROOT` in Machine 1's
`.env` pointing at a proof-tool checkout at the approved `MPC_TAG` commit. The
rehearsal is complete without this section; skip steps 33-42 on machines that
install only the kit.

### 33. Machine 1: generate and verify operational fixtures

```bash
"$S/10-coordinator-generate-operational-fixtures.sh" "$E"
```

### 34. Machine 1: grant witness-01 upload access

```bash
"$S/11-coordinator-issue-evidence-grant.sh" "$E" witness witness-01 /secure/handoff/witness-01.grant.json
```

Privately transfer the grant and these two generated files to Machine 2:

```text
operational/phase1/witnesses/witness-01.json
operational/phase1/witnesses/witness-01.sig
```

They are beneath Machine 1's configured `CEREMONY_ROOT`. Rename neither file
when placing it at the `/secure/handoff/` paths used below.

### 35. Machine 2: submit witness-01 evidence

```bash
"$S/12-role-submit-evidence.sh" "$E" /secure/handoff/witness-01.grant.json /secure/handoff/witness-01.json /secure/handoff/witness-01.sig
```

### 36. Machine 1: grant witness-02 upload access

```bash
"$S/11-coordinator-issue-evidence-grant.sh" "$E" witness witness-02 /secure/handoff/witness-02.grant.json
```

Transfer the corresponding Phase 1 witness pair and grant to Machine 3.

### 37. Machine 3: submit witness-02 evidence

```bash
"$S/12-role-submit-evidence.sh" "$E" /secure/handoff/witness-02.grant.json /secure/handoff/witness-02.json /secure/handoff/witness-02.sig
```

### 38. Machine 1: grant mirror-01 upload access

```bash
"$S/11-coordinator-issue-evidence-grant.sh" "$E" mirror mirror-01 /secure/handoff/mirror-01.grant.json
```

Transfer the Phase 1 head-0003 `mirror-01.json` and `mirror-01.sig` pair and the
grant to Machine 2.

The source pair on Machine 1 is:

```text
operational/phase1/heads/0003/mirrors/mirror-01.json
operational/phase1/heads/0003/mirrors/mirror-01.sig
```

### 39. Machine 2: submit mirror-01 evidence

```bash
"$S/12-role-submit-evidence.sh" "$E" /secure/handoff/mirror-01.grant.json /secure/handoff/mirror-01.json /secure/handoff/mirror-01.sig
```

### 40. Machine 1: grant mirror-02 upload access

```bash
"$S/11-coordinator-issue-evidence-grant.sh" "$E" mirror mirror-02 /secure/handoff/mirror-02.grant.json
```

Transfer the Phase 1 head-0003 `mirror-02.json` and `mirror-02.sig` pair and the
grant to Machine 3.

The source pair on Machine 1 is:

```text
operational/phase1/heads/0003/mirrors/mirror-02.json
operational/phase1/heads/0003/mirrors/mirror-02.sig
```

### 41. Machine 3: submit mirror-02 evidence

```bash
"$S/12-role-submit-evidence.sh" "$E" /secure/handoff/mirror-02.grant.json /secure/handoff/mirror-02.json /secure/handoff/mirror-02.sig
```

### 42. Machine 1: list complete evidence uploads

```bash
"$S/13-coordinator-list-evidence.sh" "$E"
```

## Stop

The scripted three-machine flow ends here. The later ceremony stages are not
scripted in this directory, but they are *not* blocked by the tiny circuit:
`mpc-ceremony finalize prepare`, public evidence, `finalize complete`, `audit`,
and `release sign` compile the circuit named by the signed ceremony definition
(via `compileCircuitForCeremony`), so they run against `rehearsal-tiny-v1` just
as they would against `ownership-destination-v2`.

The one stage a tiny run can never satisfy is the production GO/NO-GO
**decision**: its `exact-k21-rehearsal` gate requires the exact
`ownership-destination-v2` circuit at domain 2^21. That gate is intentional —
the production decision must reference a real K=21 ceremony — so end-to-end
production decision testing still requires a fresh K=21 rehearsal.
