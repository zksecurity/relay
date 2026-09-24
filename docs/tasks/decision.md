# Sign a production decision

Use your existing eligible coordinator, auditor, or final-parameter-signer
identity. This task does not create a new ceremony identity.

For a V5 production ceremony, reopen your installer-created `start.sh`, choose
**Open ceremony operations and progress**, then choose **D — Production
GO/NO-GO decision** after importing or refreshing the signed final release.
The action is absent for rehearsal mode and before the final release. It uses
the ceremony's already prepared, pinned offline signing image and existing key.
For a fresh V5 run, place reviewed public evidence under
`work/ceremony/public/decision/evidence/`. The coordinator prepares
`work/ceremony/public/decision/decision.json` from a reviewed
`work/decision-draft.json`; the same public tree is the verifier's evidence
root. Existing work-root decisions keep their prior paths for recovery.
After signing, transfer only public signatures; the coordinator's **D** action
verifies the full required signature
set. A saved signature alone does not establish a verified GO decision.

- [ ] Complete [installation](../install.md) and prepare the offline image.
- [ ] Receive the exact decision draft, evidence inventory, coordinator key,
      and the pinned proof-tool decision-signing recipe.
- [ ] Review the ceremony, each required gate, incidents, and the exact GO/NO-GO
      statement. Another person's approval is not your decision.
- [ ] Authorize your key to sign only the unchanged tool-generated statement.

For earlier workflows and recovery, the separate one-command action remains
available. Before disconnecting, save the reviewed command. The placeholder
must be replaced with the entire pinned proof-tool command and its container
paths:

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
Transfer only these public files and approved evidence to the coordinator for
[publication](upload.md). Keep the private key offline.
Retain the verification output and coordinator's final verified decision.

If the evidence is incomplete, the statement changes, or signing is interrupted,
pause and preserve the output. Do not reformat signed bytes or copy another
person's signature as your own authorization.
The V5 menu records a signing attempt before using the key. If an attempt is
interrupted without a complete signature, inspect the retained work; retrying
the same exact decision requires a separate explicit confirmation. A changed
decision or an existing output cannot be retried over the retained attempt.
