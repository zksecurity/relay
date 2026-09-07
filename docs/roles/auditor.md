# Auditor

Your task is to independently replay the ceremony and sign the resulting audit.
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
"$RELAY" ceremony setup auditor-identity --role keygen \
  --release "$RELAY_RELEASE" --work "$ROLE_KEYS" -- \
  mpc-ceremony identity generate --identity-id "$IDENTITY_ID" \
  --display-name "$DISPLAY_NAME" --private-key-out /work/signing.hex \
  --public-identity-out /work/identity.json
"$RELAY" ceremony open auditor-identity --role keygen
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
  "$RELAY" ceremony setup "$action" --role auditor \
    --release "$RELAY_RELEASE" --work "$ROLE_WORK" --trust "$ROLE_TRUST" \
    --keys "$ROLE_KEYS" -- "$@" &&
  "$RELAY" ceremony open "$action" --role auditor
}
```

## Acquire and audit

- [ ] Choose independently checked mirror sources and retain the source evidence.
      Do not rely solely on the coordinator's local copy.

```bash
role_action "$ACTION-phase1" relay auditor run \
  --config /work/ceremony/config/auditor-phase1.json
role_action "$ACTION-phase2" relay auditor run \
  --config /work/ceremony/config/auditor-phase2.json
```

- [ ] Run the pinned `mpc-ceremony audit` recipe against the complete transcript
      and evidence, using the reviewed arguments for this ceremony.
- [ ] Require replay and re-hashing of the entire local file set.
      Relay synchronization alone does not re-check every pre-existing artifact.
- [ ] Review the audit scope, both phases, warnings, operational evidence,
      signed cleanup claims and their limitations, and final result.
- [ ] Authorize only the exact successful audit report and signature.

The profile and full audit arguments must be supplied and reviewed before
starting; there is no automatic end-to-end audit wizard.
Use container paths and keep the auditor key in the dedicated key mount.

## Submit

```bash
role_action "$ACTION-submit" relay auditor submit \
  --config /work/ceremony/config/auditor-phase2.json \
  --grant /work/auditor.grant.json --dir /work/signed-output
```

Success prints an evidence manifest key. Send it to the coordinator and retain
the audit inputs, source evidence, signed output, and secret-free logs.
A failed replay or conflicting source must be reported even if transport worked.

## If something fails

Preserve the error, signed outputs, and current head; notify the coordinator.
Do not edit signed evidence or delete retained state to make a retry pass.
After reviewing an ordinary interrupted action, use its saved name with
`open --reviewed-retry` if a retry is appropriate. For expired grants, obtain
a replacement before submission. An upload is not acceptance of the evidence.
