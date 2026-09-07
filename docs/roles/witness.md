# Public witness

Your task is to independently observe a phase closure before its agreed beacon round.
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
"$RELAY" ceremony setup witness-identity --role keygen \
  --release "$RELAY_RELEASE" --work "$ROLE_KEYS" -- \
  mpc-ceremony identity generate --identity-id "$IDENTITY_ID" \
  --display-name "$DISPLAY_NAME" --private-key-out /work/signing.hex \
  --public-identity-out /work/identity.json
"$RELAY" ceremony open witness-identity --role keygen
```
Send only `identity.json`. For a witness or mirror, the subsequent signed
enrollment must bind to the initialized ceremony.

## Save and run actions

Stage the signed public files, matching tool receipt, and reviewed role profile
under the installation directories. Authenticate the profile using
[profile preparation](../maintainer/profiles.md) before running role commands.
Define this helper in Bash; give each operation a fresh `ACTION` name:

```bash
role_action() {
  local action="$1"; shift
  "$RELAY" ceremony setup "$action" --role witness \
    --release "$RELAY_RELEASE" --work "$ROLE_WORK" --trust "$ROLE_TRUST" \
    --keys "$ROLE_KEYS" -- "$@" &&
  "$RELAY" ceremony open "$action" --role witness
}
```

## Observe and sign

```bash
role_action "$ACTION-observe" relay witness run \
  --config /work/ceremony/config/witness-phase1.json --interval 60s
```

Use the phase-specific profile supplied for your assignment.
A continuous observation command runs until stopped; `--once` checks once
and exits nonzero if no closure is published yet.

- [ ] Tell the coordinator when observation is active.
- [ ] Retrieve and retain the exact public closure bytes during the window.
      Relay polling alone does not preserve all witness evidence.
- [ ] Confirm your observation precedes the beacon round by the signed lead time.
      Record the actual observation time; do not copy a coordinator timestamp.
- [ ] Prepare the receipt with the pinned proof-tool recipe, review its
      canonical bytes, and sign only a claim you personally observed.
      Use the agreed offline signing environment for the private key.

## Submit

With the signed output staged at `/work/signed-output` and your fresh grant:

```bash
role_action "$ACTION-submit" relay witness submit \
  --config /work/ceremony/config/witness-phase1.json \
  --grant /work/witness.grant.json --dir /work/signed-output
```

Success prints an evidence manifest key. Send it to the coordinator and retain
the receipt and observation evidence until the agreed retention date.
Report a missed window or clock error instead of signing an unsupported claim.

## If something fails

Preserve the error, signed outputs, and current head; notify the coordinator.
Do not edit signed evidence or delete retained state to make a retry pass.
After reviewing an ordinary interrupted action, use its saved name with
`open --reviewed-retry` if a retry is appropriate. For expired grants, obtain
a replacement before submission. An upload is not acceptance of the evidence.
