# Prepare the legacy three-machine rehearsal

Follow this before [Phase 1](phase1.md).

## Before you begin

This README is Machine 1's master process guide. Complete the coordinated-tool
installation first, then complete exactly one storage-provider guide before
the first numbered ceremony step:

- [installation guide](INSTALL.md)
- [AWS setup guide](../../docs/maintainer/aws.md)
- [Cloudflare R2 setup guide](../../docs/maintainer/r2-rehearsal.md)

Those links are for a source checkout. An authenticated downloaded rehearsal
contains copies under its own `docs/` directory. From the downloaded directory,
Machine 1 can review them with:

```bash
cd "$HOME/ceremony-tools/three-machine-rehearsal"
S=$PWD
less "$S/INSTALL.md"
less "$S/docs/maintainer/aws.md"    # choose AWS
less "$S/docs/maintainer/r2-rehearsal.md" # or choose R2
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
