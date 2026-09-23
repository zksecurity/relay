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

The NO-GO trial lane uses the configured AWS profile on this upload host and is
not the official GO promotion protocol. Official GO publication still requires
the terminal-decision and coordinator publication checkpoints described in the
[storage-first design](../maintainer/storage-first-ceremony-design.md).

Transport success is not evidence acceptance. Retain the public evidence and
logs according to the agreed retention procedure.

## If something fails

Keep the signed files unchanged. Review the error and grant expiry before
retrying through [workflow recovery](../role-workflow.md#recovery).
This station has no participant-style candidate-resume command.
