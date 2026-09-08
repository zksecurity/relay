# Set up your role

Use the `start.sh` printed by [installation](install.md) to start or resume.
For an older installation, run `./scripts/role.sh` from your authenticated
source checkout and select your own installer-created settings file.
The helper needs a matching launcher release containing `ceremony prepare`.

Coordinators use [coordinator preparation](coordinator-setup.md).
Other roles see this menu:

1. **Prepare approved images:** verifies the release map, selects this machine's
   images, and downloads missing images. Do this before disconnecting a signer.
2. **Generate/review MY identity:** assigns an ID automatically and asks for
   your public display name. Send only the displayed `identity.json` to the
   coordinator; keep `signing.hex` private. Existing keys are not overwritten.
3. **Import a received public file:** choose the file type and local file.
   The helper shows its destination and hash, then copies it after approval.
   Existing different files are not overwritten.
4. **Authenticate and create a phase profile:** verifies the supplied tools,
   signed ceremony, and role assignment. Repeat for each assigned phase.
5. **Continue the ceremony workflow:** opens the numbered role-specific steps.
6. **Show folders and remaining input requirements:** lists what to obtain next.

Choose **0 — Save and exit** to retain setup choices and files.

Required answers cannot be blank. A displayed default can be accepted with Enter.

## What to obtain

Through your agreed channel, obtain the signed ceremony definition, its signature,
public storage configuration, and matching tool-identity receipt. Compare the
coordinator's public-key fingerprint through an independent channel before
confirming it. Merely importing a file does not authenticate its contents.

Non-participant transport profiles also require your reviewed, signed enrollment.
Its signature must come from the enrolled owner—not a coordinator claiming consent.
Enrollment authoring/signing and offline witness/mirror receipt signing still
use the agreed external procedure; this helper does not yet replace that signer.

Participants additionally need the approved host-local Linux proof-tool file
and truthful v2 environment JSON. The Linux file must currently have the same
absolute path on the host and in the image. The receipt must match the native
launcher and this file; receipts for different tools are rejected.
Do not manufacture a receipt to get past a failed check. Ask the coordinator
and release maintainer for matching approved material.

The helper imports the small setup files, not entire transcripts or evidence
directories. Exchange those public directories through the agreed channel and
place them in your work folder when the workflow requests them.
Private grants are delivered separately only to their named recipient.

## Role differences

- Final-parameter signers prepare images online, then disconnect before key
  generation and signing. Skip transport-profile creation.
- Upload stations skip key generation and never receive a private signing key.
- Participants run computation through the host supervisor, not a nested Docker
  controller. Linux requires native Docker and disabled swap.
- [Advanced profile reference](maintainer/profiles.md) explains the underlying
  checks and remaining tool/environment preparation requirements.

## Recovery

Reopen the same helper with the same role folder and release. It retains your
choices, never silently replaces keys or signed inputs, and stops on failed
verification. Existing action history remains authoritative.
See [workflow recovery](role-workflow.md#recovery) for interrupted ceremony work.
