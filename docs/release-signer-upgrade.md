# Update an existing V5 release signer for the AWS GO handoff

The release signer can select the published Relay release that adds the online,
keyless decision transfer menu. This changes the local launcher only. The signed
definition, identity, saved progress, and original network-disabled signing
image stay pinned. The coordinator updates its own installation separately.

Finish the current signer action, exit both the offline guide and setup menu
normally, and keep the original installation. An interrupted signing attempt
must be resolved with the original Relay before updating. The update refuses
incomplete local activity and changed frozen inputs; it does not sign or upload
anything.

On the signer host, download and verify the new launcher as described in
[step 2 of the coordinator upgrade guide](coordinator-upgrade.md#2-download-and-verify-the-new-launcher),
substituting the published target version and the host's platform. Use the saved
signer role's local name and settings root, then run:

```bash
"$upgrade_dir/$binary" ceremony upgrade YOUR_SAVED_SIGNER_NAME \
  --role release-signer \
  --settings-root "/absolute/path/to/your/existing/settings-root" \
  --release "role-images-$commit"
```

Review the displayed source and target commits and original image before
confirming. Wait for the message that the application selection and `start.sh`
update succeeded. Reopen that exact `start.sh`. Its **online, keyless decision
transfer** action can download the coordinator's public packet with a temporary
private grant. Exit it, disconnect the host, and use the original offline
signing image to review and sign. Reconnect only afterward to return the public
signature with a separate temporary grant. Never put a grant or AWS profile in
the offline signing work, key, or trust mounts.

The original signer launcher may refuse an operator-selected update; use the
selected launcher for recovery. If the update refuses retained work, preserve
the files and resolve the reported cause using the original release. This path
does not claim the exact source/target pair has passed a full ceremony test.
