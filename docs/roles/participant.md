# Participant

You contribute on your own machine, retain your identity key, and confirm the
cleanup precautions that software cannot observe.

## Start or resume

Complete [installation](../install.md), then run the `start.sh` printed by
the installer. Existing installation? Run `./scripts/role.sh` from your
authenticated source checkout and select your settings file.

Follow [role onboarding](../role-onboarding.md):

1. Prepare the approved images.
2. Generate your identity. Send only `identity.json` to the coordinator.
3. Import the signed ceremony files and independently authenticate the
   coordinator's public-key fingerprint.
4. Follow the environment-check prompts, review the precautions, then create
   each assigned phase's profile. Preparation downloads the pinned Linux tool
   and records the measured tool identities automatically.
5. Continue to the numbered ceremony workflow.

The helper checks your signing identity against the signed assignment.
It does not invent tool approval or your environment statements.

## Each turn

- Wait for the coordinator's notice and your private grant.
- Check the ceremony, phase, next participant, and accepted head shown by Relay.
- Choose the contribution action and supply the grant file when prompted.
- Relay verifies inputs, contributes in the isolated container, removes it,
  checks removal, and separately asks about retained copies.
- Confirm cleanup precautions only if every displayed statement is true.
  Stop and report uncertainty rather than claiming a precaution you did not take.
- Send the resulting manifest key to the coordinator and retain the public
  candidate. Wait for independently verified acceptance.

Docker cleanup does **not** prove every secret copy was erased. Host/VM memory,
swap, snapshots, backups, or a compromised host may retain data. This workflow
does not require a whole-machine wipe. Use the agreed dedicated-machine and
backup policy; see the [security tradeoffs](../maintainer/isolation.md).

Linux participants require native Docker Engine and disabled host swap,
including after a reboot. Relay checks before contribution; the
[computer setup guide](../setup-host.md) explains preparation.

## If something fails

Keep the error and public candidate. If computation finished but upload failed,
use the workflow's candidate-resume option with a replacement grant if needed;
do not recompute. A changed head, changed files, or incomplete cleanup requires
investigation. Status alone does not remove an orphan after power loss.
See [workflow recovery](../role-workflow.md#recovery).
