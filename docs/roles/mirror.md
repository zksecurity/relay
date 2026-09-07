# Mirror operator

Your task is to retain an independent copy of the authenticated transcript.
Use this guide for each assignment; retain its public evidence and results.

## Prepare once

- [ ] Complete [installation](../install.md).
- [ ] Receive the coordinator key, release ID, signed assignment/enrollment,
      phase, reviewed command arguments, and retention obligations.
- [ ] Confirm the identity and assignment match what you agreed to do.
      Software checks distinct keys; it cannot establish independent people.
- [ ] Keep your signing key on your own trusted machine.

Generate your identity with the assigned `IDENTITY_ID` and public `DISPLAY_NAME`:
```bash
"$RELAY" ceremony setup mirror-identity --role keygen \
  --release "$RELAY_RELEASE" --work "$ROLE_KEYS" -- \
  mpc-ceremony identity generate --identity-id "$IDENTITY_ID" \
  --display-name "$DISPLAY_NAME" --private-key-out /work/signing.hex \
  --public-identity-out /work/identity.json
"$RELAY" ceremony open mirror-identity --role keygen
```
Send only `identity.json`. For a witness or mirror, the subsequent signed
enrollment must bind to the initialized ceremony.

## Save and run actions

Stage the signed public files, matching tool receipt, and reviewed role profile
under the installation directories. Authenticate the profile using
[profile preparation](../maintainer/profiles.md) before running role commands.
Define this helper in Bash or Zsh; give each operation a fresh `ACTION` name.
Setup verifies the release's image list and selects your role/machine's image.
Open shows the saved command and asks before running it in Docker:

```bash
role_action() {
  local action="$1"; shift
  "$RELAY" ceremony setup "$action" --role mirror \
    --release "$RELAY_RELEASE" --work "$ROLE_WORK" --trust "$ROLE_TRUST" \
    --keys "$ROLE_KEYS" -- "$@" &&
  "$RELAY" ceremony open "$action" --role mirror
}
```

## Synchronize and sign

```bash
role_action "$ACTION-sync" relay mirror run \
  --config /work/ceremony/config/mirror-phase1.json
```

Repeat for the assigned phase/head. Independently control the destination and
administrative account; two folders in one account do not establish independence.

- [ ] Confirm the exact bytes are durably retained at the agreed destination.
- [ ] Prepare a receipt for the head actually retained:

```bash
role_action "$ACTION-receipt" relay mirror receipt \
  --config /work/ceremony/config/mirror-phase1.json \
  --chain "$CHAIN" --chain-signature "$CHAIN_SIGNATURE" --index "$INDEX" \
  --location "$MIRROR_LOCATION" --stored-at "$STORED_AT" \
  --out /work/receipt.json
```

All command paths above are container paths. Keep private location details out
of public logs. The public record uses a location digest.
Run the pinned proof-tool `ops prepare-mirror-receipt` recipe over the draft,
full retained transcript, exact chain, and signed enrollment. Require its full
file verification: Relay sync does not re-hash every pre-existing local file.
Review and sign the canonical output in the agreed offline environment.

## Submit and retain

```bash
role_action "$ACTION-submit" relay mirror submit \
  --config /work/ceremony/config/mirror-phase1.json \
  --grant /work/mirror.grant.json --dir /work/signed-output
```

Success prints the manifest key. Send it to the coordinator, retain the exact
transcript for the agreed period, and report any loss, mutation, or change in
administrative control.

## If something fails

Preserve the error, signed outputs, and current head; notify the coordinator.
Do not edit signed evidence or delete retained state to make a retry pass.
After reviewing an ordinary interrupted action, use its saved name with
`open --reviewed-retry` if a retry is appropriate. For expired grants, obtain
a replacement before submission. An upload is not acceptance of the evidence.
