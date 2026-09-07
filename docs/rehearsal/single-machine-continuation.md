# Rehearsal workflow

The previous single-machine command walkthrough has been replaced by the
[scripted three-machine rehearsal](../../scripts/three-machine-rehearsal/README.md).
That guide is the single source of truth for rehearsal order and commands. It
uses one private environment file per machine:

- [Machine 1](../../scripts/three-machine-rehearsal/machine-1/.env.example):
  coordinator and storage configuration
- [Machine 2](../../scripts/three-machine-rehearsal/machine-2/.env.example):
  participants 01 and 03 plus the first witness, mirror, and auditor
- [Machine 3](../../scripts/three-machine-rehearsal/machine-3/.env.example):
  participant 02 plus the second witness, mirror, auditor, and release signer

For a one-machine functional test, run every machine's steps on one host in the
documented order, but keep three separate `.env` files and three separate run
roots. This checks the workflow; it does not provide independent-machine or
independent-operator evidence.

The scripts exercise the tiny test ceremony only. Production operators use the
[coordinator runbook](../operator/COORDINATOR_RUNBOOK.md) and
[role reference](../operator/roles-reference.md).
