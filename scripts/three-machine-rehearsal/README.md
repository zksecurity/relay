# Three-machine tiny rehearsal

This directory turns the tiny Relay rehearsal into explicit machine steps.
All three machines use the same reviewed Relay and `mpc-ceremony` binaries.
This is the detailed rehearsal walkthrough; production operators instead use
the Relay coordinator or role runbook from the authenticated source release.

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

## One-time setup on each machine

Download and verify the versioned ceremony kit on all three machines by
following Relay's installation guide. Running `setup --machine N` installs both
binaries, extracts this standalone directory, and creates the selected private
`.env` with all release fields prefilled. No Relay source checkout is needed.
Install Bash, Python 3, and GNU coreutils in addition to the three programs
checked below.

Machine 1:

```bash
cd /path/to/three-machine-rehearsal
test -f machine-1/.env
chmod 0600 machine-1/.env
```

Machine 2:

```bash
cd /path/to/three-machine-rehearsal
test -f machine-2/.env
chmod 0600 machine-2/.env
```

Machine 3:

```bash
cd /path/to/three-machine-rehearsal
test -f machine-3/.env
chmod 0600 machine-3/.env
```

The setup command prints the resulting `.env` path. Replace its remaining
ceremony, identity, storage, and local-path placeholders before continuing.

Machine 1 retains the initialized transcript and coordinator key. Machines 2
and 3 need local copies of:

- `ceremony.json` and `ceremony.sig`;
- the coordinator public key obtained through the independent trust channel;
- `config/environment.json`;
- only the participant and role keys assigned to that machine; and
- the identical Relay and `mpc-ceremony` binaries.

Run the machine check everywhere:

Machine 1:

```bash
cd /path/to/three-machine-rehearsal
S=$PWD
E="$S/machine-1/.env"
"$S/00-check-machine.sh" "$E"
```

Machine 2:

```bash
cd /path/to/three-machine-rehearsal
S=$PWD
E="$S/machine-2/.env"
"$S/00-check-machine.sh" "$E"
```

Machine 3:

```bash
cd /path/to/three-machine-rehearsal
S=$PWD
E="$S/machine-3/.env"
"$S/00-check-machine.sh" "$E"
```

In the remaining sections, `S` and `E` mean the values set above on that
machine.

## Phase 1

### 1. Machine 1: configure storage

```bash
"$S/01-coordinator-configure-storage.sh" "$E"
```

For R2, the script prompts without echo for a Cloudflare API bearer token with
the account-level `Workers R2 Storage Read` permission, called R2 Admin Read
only in the R2 token UI. Cloudflare does not offer bucket-scoped configuration
read, so use a dedicated rehearsal account if necessary. Relay uses the token
only to confirm that the inbox has neither public `r2.dev` access nor an
attached custom domain; the script removes it from the environment immediately
afterward.

Privately copy the resulting `relay-storage.json` to the `STORAGE_CONFIG` path
configured in the `.env` files on Machines 2 and 3. It contains no temporary
role credential, but do not use the public ceremony bucket as the handoff.

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

The tiny transcript ends here. Proof-tool intentionally rejects tiny-circuit
finalization. Finalization, independent audit, release signing, and production
decision testing require a fresh `ownership-destination-v2` K=21 rehearsal.
