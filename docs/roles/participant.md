# Participant

You contribute on your own machine, keep your identity key, and confirm the
cleanup statements that software cannot observe. Repeat the turn section for
each assigned phase.
After preparing your profiles, use the [guided workflow](../role-workflow.md)
to handle both phases from one resumable menu.

## Prepare once

- [ ] Complete [installation](../install.md).
      When using the Linux [computer setup](../setup-host.md#ubuntu--debian)
      script, include `--participant` to check swap as well as prerequisites.
- [ ] Receive the coordinator key, release ID, signed assignment, phase positions,
      emergency contact, and profile-preparation instructions through the agreed channel.
- [ ] Confirm your public identity and position match the assignment.
- [ ] Understand that Docker cleanup cannot rule out host/VM secret remnants
      or later recovery. No whole-machine wipe is required by this workflow.
- [ ] Use the dedicated machine and backup/snapshot policy agreed for this ceremony.
      Linux participants need native Docker Engine and disabled host swap.

Generate your identity using the installation directories and your assigned
`IDENTITY_ID` and public `DISPLAY_NAME`:

```bash
"$RELAY" ceremony setup participant-identity --role keygen \
  --release "$RELAY_RELEASE" --work "$ROLE_KEYS" -- \
  mpc-ceremony identity generate --identity-id "$IDENTITY_ID" \
  --display-name "$DISPLAY_NAME" --private-key-out /work/signing.hex \
  --public-identity-out /work/identity.json
"$RELAY" ceremony open participant-identity --role keygen
```

- [ ] Send only `identity.json`; keep `signing.hex` protected locally.
- [ ] Prepare one authenticated Docker profile per phase using the coordinator's
      reviewed arguments and [profile preparation](../maintainer/profiles.md).
      This preparation is still manual; setup does not create that profile.
      It needs a matching tool receipt and a host-local Linux proof-tool file.

## Save each phase

Set `TURN` to a distinct name such as `ceremony-phase1`, and `ROLE_CONFIG`
to the absolute path of that phase's prepared profile:

```bash
"$RELAY" ceremony setup "$TURN" --role participant \
  --config "$ROLE_CONFIG" --release "$RELAY_RELEASE"
"$RELAY" ceremony open "$TURN" --role participant
```

Setup selects your machine's image from the verified release and checks it
against your profile. Success displays authenticated status.
It does not mean your turn has started. Do not change the image or signed
binary policy if setup rejects it.

## Each turn

- [ ] On Linux, recheck that host swap is disabled, especially after a reboot.
      Run `./scripts/setup/linux.sh --check --participant` from the source
      checkout used during setup. Relay also checks before contributing.
- [ ] Wait for the coordinator's notice and a fresh grant addressed to you.
- [ ] Confirm the ceremony, phase, next participant, and head shown by Relay.
- [ ] Set `GRANT` to the absolute path of that private grant file.

```bash
"$RELAY" ceremony open "$TURN" --role participant --grant "$GRANT"
```

Review the action and confirm. Relay verifies the inputs, computes in the
isolated contributor, removes it, checks removal, and asks about retained copies.
Only type `CLEANUP PRECAUTIONS CONFIRMED` if the displayed assertions are true.
This acknowledges precautions, not proof that every secret copy was erased:
you retained no snapshots, memory dumps, contribution randomness, or backup copy.
Uncertainty is a reason to stop.

Success prints `candidate submitted for coordinator review`, a manifest key,
and the saved public candidate directory.

- [ ] Send the manifest key to the coordinator; retain the public candidate.
- [ ] Wait for independently verified acceptance before treating the turn as done.
- [ ] Repeat with the Phase 2 profile when assigned. Relay replays the required
      Phase 1 seal and Phase 2 initialization before sampling randomness.

## If something fails

Keep the error and saved candidate path; contact the coordinator.
Do not recompute merely because upload failed after successful contribution.
With a replacement grant and an unchanged accepted head:

```bash
"$RELAY" ceremony open "$TURN" --role participant --grant "$GRANT" \
  --resume-candidate "$CANDIDATE_DIRECTORY"
```

Success resumes upload without recomputing. Changed files, a conflicting head,
or incomplete cleanup require investigation, not editing files or deleting state.
After power loss, a status check alone does not clean a recorded orphan;
the same profile's run/recovery path must verify cleanup before proceeding.

## Finish

- [ ] Retain approved public evidence and protect your signing key according to
      the agreed retention plan. Never upload your key or grant contents.
