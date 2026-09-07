# Legacy rehearsal: Phase 2 and evidence

Continue from [Phase 1](phase1.md); keep the same setup variables.

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
