# Upload already signed evidence

This station transports public signed output. It never receives a signer's key.

- [ ] Complete [installation](../install.md).
- [ ] Agree on the evidence type, signer enrollment, and transfer procedure.
- [ ] Receive the expected public files and a fresh role-scoped grant.
- [ ] Run the pinned proof-tool verification recipe; require its ceremony and
      signer to match the assignment before uploading.
- [ ] Stage only approved signed output in `ROLE_WORK/signed-output` and the
      private grant in `ROLE_WORK/evidence.grant.json`.

Save the upload action with a fresh name:
```bash
"$RELAY" ceremony setup "$ACTION" --role upload-station \
  --release "$RELAY_RELEASE" --work "$ROLE_WORK" --trust "$ROLE_TRUST" -- \
  relay submit-evidence --grant /work/evidence.grant.json \
  --dir /work/signed-output
"$RELAY" ceremony open "$ACTION" --role upload-station
```

Do not supply a key mount. The grant must match the evidence type and signer.
The uploader rejects suspicious files and publishes its manifest last.
Success prints the evidence manifest key; send that key to the coordinator.
A successful transport does not establish valid ceremony evidence.

For a release-specific prepared profile, the equivalent tool command is:
```bash
relay release run --config /work/ceremony/config/release-phase2.json \
  --grant /work/evidence.grant.json --dir /work/signed-output
```
Run it through the same upload-station setup, never directly with host paths.

If upload fails, inspect the error and grant expiry before retrying the saved
action with `--reviewed-retry`. This task has no participant-style candidate
resume command. Never edit the signed output to resolve a mismatch.
Retain public evidence and logs; retire expired grants only under the agreed
retention procedure.
