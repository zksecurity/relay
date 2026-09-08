# Coordinator

You schedule turns, verify submissions, and publish accepted ceremony state.
Other roles keep their own private keys.

## Start or resume

Complete [installation](../install.md), then run the `start.sh` printed by
the installer. For an existing installation, run `./scripts/role.sh` from
your authenticated source checkout and select your settings file.

1. Follow [coordinator preparation](../coordinator-setup.md): generate your
   identity, import public identities, review the circuit and policy, and initialize.
2. Send your public `identity.json` and the signed ceremony definition to
   the roles through your agreed coordination channel.
3. Collect their reviewed, signed enrollments. Relay checks required keys differ;
   it cannot tell whether they belong to independent people or organizations.
4. Have the storage administrator provision storage, then enter the settings
   in the helper and require its storage checks to pass.
5. Choose **Continue the guided coordinator workflow** after initialization.
   Reopening preparation does not initialize the ceremony again.

## Follow the numbered workflow

- Verify the current head and next participant before issuing a private grant.
  Deliver the grant only to its named owner; do not overlap turns.
- Receive the candidate manifest key, verify and accept the candidate,
  and confirm publication before notifying the next participant.
- Close each phase, arrange actual pre-beacon witness observations, and follow
  the prompted beacon, seal, and Phase 2 steps in order.
- Collect mirror receipts, independent audits, and the final signer's public
  output. Verify the evidence and required production decision before release.
- Retain and verify the complete public archive before retiring access.

The menu asks for inputs and shows each action before running it.
A successful upload is not acceptance, and a checked menu item is not proof.
See [workflow and recovery](../role-workflow.md).

## Work outside the helper

Storage provisioning, independent communications, operational-record authoring,
and public-proof generation still need the agreed tools and people.
The helper identifies these handoffs; it does not fabricate evidence or consent.
Storage administration is covered in [AWS](../maintainer/aws.md) and
[R2](../maintainer/r2.md).

## If something fails

Pause the affected turn and retain outputs and secret-free error logs.
Inspect signed local and public heads: an interrupted action may have advanced
the ceremony. Use the workflow's reviewed recovery path, not a fresh attempt
that forgets the earlier result. Never edit signed files or relax verification.
