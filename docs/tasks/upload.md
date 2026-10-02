# Hand off the signed release and publish the decision

For a V5 production ceremony using this Relay release, the coordinator handles
the release signer's public package and final publication. There is no upload
station to install or operate. The release signer remains on a separate,
disconnected signing host and transfers **only** its signed public package.

## Receive the release signer's package

1. Finish the signed release-review checkpoint. Give its authenticated public
   snapshot to the release signer through the agreed offline handoff.
2. After signing, copy the complete public release-package directory into a
   fresh folder **inside the coordinator's work directory**. Never copy the
   signer's `signing.hex`, profile, or private recovery material.
3. In the coordinator's `start.sh`, choose **Open ceremony operations and
   progress**, then **U — Import the offline signer's returned public release
   package**. Give the absolute path to that fresh folder. Relay runs the pinned
   proof-tool release verification, checks that the public package contains
   exactly its checksum-listed files, and retains it without replacement.
4. Choose the next coordinator action to verify the retained package and record
   the signed final-release checkpoint. An import alone is not acceptance or
   public publication.

V5 ceremonies with a release upload grant already retained keep their original
grant and private-inbox recovery path. Resolve that work before attempting a
direct import; Relay refuses both handoffs at once. Older V4 ceremonies keep
their original upload-station journey.

## Publish a signed production decision

After the exact final-release checkpoint is recorded and all required decision
signatures are verified, the coordinator chooses **P**. Relay re-verifies the
signed decision and packs the exact public archive without using the
coordinator's signing key. For GO, choose **A** next. Relay shows the ceremony,
release, final checkpoint, decision and archive hashes, and exact storage
destination. After a separate `SIGN GO PUBLICATION` confirmation, the upgraded
Relay image signs `go-publication.json` in a network-disabled container with no
storage credentials. This authorization is separate from the signed GO decision.
A retained complete archive and authorization can be rechecked and reused
after an interruption; mismatched bytes stop the action.

- For **GO**, choose **G**. Relay rechecks the archive, signed GO, release,
  final checkpoint and destination using the pinned proof-tool. It uses the
  coordinator's configured AWS profile to create the content-addressed
  archive and one fixed, create-only approved pointer. Existing objects count
  as a retry only after exact public readback. Then choose **V** for a separate
  coordinator readback using the approved Docker image.
- For an explicitly signed **NO-GO trial**, choose **T**. Relay verifies and
  publishes the exact trial archive and notice under a content-addressed trial
  prefix. It creates no approved-production pointer.

The coordinator now performs the upload as well as the readback. Those checks
establish exact published bytes; they do not establish an independent machine
or operator. Before production use, review the coordinator credential's bucket
permissions and obtain an independent public verification of the published
release. Never infer official publication from a signed GO archive alone.

An external verifier needs the independently trusted public storage URL,
ceremony ID, and coordinator public key:

```bash
relay verify-ceremony --archive go-ceremony.zip \
  --published-base-url https://YOUR-TRUSTED-PUBLIC-ORIGIN \
  --expected-ceremony-id sha256:YOUR-TRUSTED-CEREMONY-ID \
  --expected-coordinator-public-key-file /path/to/trusted-coordinator-public-key.hex
```

The JSON report says `"officially_published": true` only after the verifier
authenticates the official pointer, archive, signed decision and final-release
checkpoint. Keep the public evidence and logs for the agreed retention period.

On macOS, the released `relay-darwin-arm64` or `relay-darwin-amd64` executable
accepts the same `verify-ceremony` command. It authenticates the matching
release's Linux online image and runs the pinned proof tool through a **local**
Docker Desktop daemon. Install Docker Desktop and GitHub CLI first; no ceremony
role, signing key, AWS profile, or `start.sh` is needed. The archive and any
independently trusted coordinator public key are mounted read-only, and expanded
files use a temporary private directory on the Mac. Allow enough local disk
space for the archive's expanded contents. Relay removes that directory and the
verification container when the command ends. Archive-only verification runs
without container network access. For a guided V5 decision with no official
pointer, omit the three publication flags above and independently compare the
report's `ceremony_id`; `officially_published` will remain false.

## Upgrading a ceremony already in progress

An initialized v0.6.0 coordinator can select a new published coordinator
release **between completed operations**, including before Phase 2. Follow the
[coordinator upgrade guide](../coordinator-upgrade.md) from the new launcher.
The signed definition, identities, circuit, proof-tool pin, participant images,
and release-signer image remain unchanged. Do not change frozen files or start a
new ceremony. The participant and release signer can continue on their original
releases. A target release must be qualified against the exact source release
and current ceremony state before a real upgrade.

If an action or upload is unfinished, resolve it with the current release
before upgrading. Keep the original installation and `.relay-upgrades` records.
