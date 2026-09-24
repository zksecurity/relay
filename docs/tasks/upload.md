# Upload already signed evidence

This station transports signed public output. It never receives a signer's key.

## Start or resume

Complete [installation](../install.md), choosing **upload-station**, then run
your installer-created `start.sh`. For an existing installation, run
`./scripts/role.sh` from your authenticated source checkout.

Follow [role onboarding](../role-onboarding.md): prepare the online image,
import the public ceremony/enrollment files, and create the release Phase 2
profile. Skip identity generation: this station must not hold signing keys.

Choose **Continue the ceremony workflow**. The V4/V5 guide authenticates the
published checkpoint without a signing identity or key mount.

## Verify, upload, and hand off

1. Receive the exact signed release package at `work/release`, preserving its
   directory contents. Receive the private release upload grant separately.
2. Choose **1**. Relay verifies the signed package, current authenticated
   checkpoint, final signer assignment, grant scope and destination before it
   uploads to the private inbox. The coordinator must fetch and verify the
   result before recording the final release.
3. For an explicitly signed **NO-GO trial**, the coordinator can choose **P**
   after decision verification to pack the exact public inventory. Transfer its
   ZIP to `work/no-go-trial-ceremony.zip` and choose **3** at this station. Relay
   checks the closed archive inventory against the signed checkpoint, verifies
   the release and NO-GO signatures, then publishes to a content-addressed
   trial prefix and reads the bytes back. It creates no approved-release pointer.
4. For a fully signed **GO**, the coordinator chooses **P** to verify and pack
   `go-ceremony.zip` and sign `go-publication.json`. Transfer both public files
   into this station's work folder and choose **4**. The station independently
   verifies the archive, final checkpoint, release, GO signers, coordinator
   signature, and destination. It uploads the archive without replacing an
   existing object, reads it back, then creates the one fixed approved pointer.
   An existing pointer is accepted only when its bytes match exactly. The
   coordinator then chooses **V** to read back the official pointer and archive
   independently. Until the pointer is verified, the GO is signed but its
   publication is not established.

The Relay-only GO lane is an explicit alternative for a frozen V5 proof-tool
that cannot append a decision checkpoint after final release. It keeps
proof-tool as the verifier of the signed GO, and uses a coordinator-signed
publication record outside that checkpoint chain. It currently supports AWS
publication. The public verifier must be given the independently trusted
official URL:

```bash
relay verify-ceremony --archive go-ceremony.zip \
  --published-base-url https://YOUR-TRUSTED-PUBLIC-ORIGIN
```

The URL comes from the operator's trusted ceremony information, not from the
archive. The verifier downloads the official pointer and archive and checks
their exact bytes. A signed GO archive checked without this URL establishes
the signatures and proofs, but does not establish official publication.

The current `ceremony upgrade` command applies only to an existing coordinator
workspace. An existing upload station must use a freshly installed matching
Relay release and authenticate the same signed definition and coordinator key
before taking action. This transition needs an end-to-end qualification run
before use with an already frozen ceremony.

Transport success is not evidence acceptance. Retain the public evidence and
logs according to the agreed retention procedure.

## If something fails

Keep the signed files unchanged. Review the error and grant expiry before
retrying through [workflow recovery](../role-workflow.md#recovery).
This station has no participant-style candidate-resume command.
