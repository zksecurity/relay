# Sign a production decision

Use your existing eligible coordinator, auditor, or final-parameter-signer
identity. This task does not create a new ceremony identity.

- [ ] Complete [installation](../install.md) and prepare the offline image.
- [ ] Receive the exact decision draft, evidence inventory, coordinator key,
      and the pinned proof-tool decision-signing recipe.
- [ ] Review the ceremony, each required gate, incidents, and the exact GO/NO-GO
      statement. Another person's approval is not your decision.
- [ ] Authorize your key to sign only the unchanged tool-generated statement.

Before disconnecting, save the reviewed command. The placeholder must be
replaced with the entire pinned proof-tool command and its container paths:

```bash
"$RELAY" ceremony setup "$ACTION" --role decision-signer \
  --release "$RELAY_RELEASE" --work "$ROLE_WORK" --trust "$ROLE_TRUST" \
  --keys "$ROLE_KEYS" -- mpc-ceremony REPLACE_WITH_REVIEWED_DECISION_COMMAND
```

On the disconnected signing machine:
```bash
"$RELAY" ceremony open "$ACTION" --role decision-signer
```

Success produces the exact decision file and your detached signature.
Transfer only these public files and approved evidence to the
[upload station](upload.md). Keep the private key offline.
Retain the verification output and coordinator's final verified decision.

If the evidence is incomplete, the statement changes, or signing is interrupted,
pause and preserve the output. Do not reformat signed bytes or copy another
person's signature as your own authorization.
