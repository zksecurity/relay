# Final-parameter signer

You independently review and sign the final ceremony parameters.
This protocol role is separate from software publishing.

## Prepare once

- [ ] Complete [installation](../install.md) and preload the signing image/actions.
- [ ] Receive the coordinator key, signed assignment, candidate, audit reports,
      operational evidence, and the release-specific review/signing recipe.
- [ ] Confirm your identity and the intended ceremony/release label.
- [ ] Keep the signing machine offline during key generation, review, and signing.
      Container network isolation alone does not disconnect the machine.

Before disconnecting, save key generation with your assigned public values:

```bash
"$RELAY" ceremony setup release-identity --role keygen \
  --release "$RELAY_RELEASE" --work "$ROLE_KEYS" -- \
  mpc-ceremony identity generate --identity-id "$IDENTITY_ID" \
  --display-name "$DISPLAY_NAME" --private-key-out /work/signing.hex \
  --public-identity-out /work/identity.json
```

After disconnecting:
```bash
"$RELAY" ceremony open release-identity --role keygen
```

Send only `identity.json` through the approved transfer process.
Never bring storage credentials or an online upload profile onto this machine.

## Review and sign

- [ ] Review the exact candidate, ceremony, auditor identities, both phases,
      beacon evidence, independent witness/mirror requirements, and incidents.
- [ ] Run the pinned proof-tool verification recipe over the entire evidence set.
- [ ] Require exactly one verified wipe confirmation for each signed-policy Mac
      participant, with wipe time later than their final contribution time.
      Provisional acceptance or an uploaded record is insufficient.
- [ ] Authorize signing only the exact verified release manifest.

Prepare each reviewed command before disconnecting using:
```bash
"$RELAY" ceremony setup "$ACTION" --role release-signer \
  --release "$RELAY_RELEASE" --work "$ROLE_WORK" --trust "$ROLE_TRUST" \
  --keys "$ROLE_KEYS" -- mpc-ceremony release sign REPLACE_WITH_REVIEWED_ARGUMENTS
```

The arguments depend on the pinned proof-tool recipe and actual evidence paths.
Replace the placeholder before saving; signing inputs use `/work`, `/trust`,
and `/keys` paths. Setup does not execute the signing action.
On the disconnected machine, review and open that action:
```bash
"$RELAY" ceremony open "$ACTION" --role release-signer
```

Success produces the signed public release output. Verification authenticates
wipe statements and their timing; it does not physically prove erasure.

## Handoff and recovery

- [ ] Transfer only signed public output to the separate [upload station](../tasks/upload.md).
- [ ] Keep your key offline; retain the verification result and transfer record.
- [ ] Wait for the coordinator's independently verified acceptance.

If a check fails or signing is interrupted, preserve the output and investigate
before retrying. Do not sign substitute files or infer success from an upload.
Report missing evidence, changed identities, and suspected key exposure.
