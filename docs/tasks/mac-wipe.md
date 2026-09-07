# Confirm a production Mac wipe

Only for participants listed in the signed `host_wipe_participants` policy.
A Mac acting only as coordinator does not acquire this participant obligation.

- [ ] Wait for acceptance of your final scheduled contribution.
- [ ] Arrange separately protected storage for only approved public ceremony
      files and signing/config material needed for confirmation.
- [ ] Follow the agreed whole-device erase and clean-reinstall procedure.
      Do not restore pre-wipe backups, snapshots, Docker state, or contributor copies.
- [ ] Reinstall the same [launcher release](../install.md) and restore only
      the approved public and separately protected signing/config material.
- [ ] Obtain a fresh `host-wipe` grant from the coordinator.

The coordinator issues the grant with no enrollment flags:
```bash
relay coordinator grant --storage /work/ceremony/config/relay-storage.json \
  --role host-wipe --identity "$PARTICIPANT_ID" \
  --credential-ttl 2h --minimum-remaining 30m \
  --out "/work/ceremony/run/$PARTICIPANT_ID.host-wipe.grant.json"
```
Run that command through the coordinator's saved Docker action.

On the clean Mac, use your host launcher with the restored absolute paths:
```bash
"$RELAY" participant attest-host-wipe --config "$ROLE_CONFIG" \
  --grant "$GRANT" --out-dir "$WIPE_EVIDENCE_DIRECTORY"
```

Type `MAC WIPED AND CLEANLY REINSTALLED` only when every displayed assertion
is true. Send the printed manifest key to the coordinator.

The final signer requires successful proof-tool verification of exactly one
record per required participant, dated after their last accepted contribution's
contribution timestamp. Verification authenticates the statement and timing;
it does not physically prove erasure. Upload alone does not satisfy the gate.

If confirmation or upload fails, preserve the evidence and contact the
coordinator. Do not sign a replacement with an invented wipe time.
