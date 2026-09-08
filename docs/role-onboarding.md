# Set up your role

Use the `start.sh` printed by [installation](install.md) to start or resume.
For an older installation, run `./scripts/role.sh` from your authenticated
source checkout and select your own installer-created settings file.
The helper needs a matching launcher release containing `ceremony prepare`.

Coordinators use [coordinator preparation](coordinator-setup.md).
Other roles see this menu:

1. **Prepare approved images:** verifies the release map, selects this machine's
   images, downloads missing images, and prepares the measured tool record.
   Participants also get the pinned Linux proof tool automatically.
   Do this before disconnecting a signer.
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
7. **Prepare, review and sign MY enrollment:** after importing the signed
   definition and trusted coordinator key, write your public disclosure and
   review the exact record. Disconnect the signing host, then confirm. The
   offline image signs with your own key and verifies the result. Send the
   displayed public export directory to the coordinator, including its disclosure.

Choose **0 — Save and exit** to retain setup choices and files.

Required answers cannot be blank. A displayed default can be accepted with Enter.

## What to obtain

Through your agreed channel, obtain the signed ceremony definition, its signature,
and public storage configuration. Tool records are prepared locally; do not
copy another operator's record. Compare the
coordinator's public-key fingerprint through an independent channel before
confirming it. Merely importing a file does not authenticate its contents.

Non-participant transport profiles also require your reviewed, signed enrollment.
Its signature must come from the enrolled owner—not a coordinator claiming consent.
Use option 7 before creating a non-participant transport profile. Witnesses and
mirrors obtain their enrollment number from the coordinator; other role positions
come from the signed definition. Distinct keys do not prove independent people.

Participants follow the environment prompts rather than writing JSON. Relay
checks Docker and the applicable swap requirements, explains the container
controls, and asks about the precautions they will follow. The saved plan does
not prove physical erasure. Host and container binary paths are managed separately.
Changed cached tools or mismatched existing records stop preparation; preserve
the error and ask the coordinator or release maintainer rather than bypassing it.

The helper imports the small setup files, not entire transcripts or evidence
directories. Exchange those public directories through the agreed channel and
place them in your work folder when the workflow requests them.
Private grants are delivered separately only to their named recipient.

## Role differences

- Final-parameter signers prepare images online, then disconnect before key
  generation and signing. Skip transport-profile creation.
- Upload stations import the final signer's public enrollment; they never
  generate or receive a private signing key. Inapplicable menu options are hidden.
- Participants run computation through the host supervisor, not a nested Docker
  controller. Linux requires native Docker and disabled swap.
- [Advanced profile reference](maintainer/profiles.md) explains the underlying
  checks and remaining tool/environment preparation requirements.

## Recovery

Reopen the same helper with the same role folder and release. It retains your
choices, never silently replaces keys or signed inputs, and stops on failed
verification. Existing action history remains authoritative.
See [workflow recovery](role-workflow.md#recovery) for interrupted ceremony work.
