# Upload already signed evidence

This station transports signed public output. It never receives a signer's key.

## Start or resume

Complete [installation](../install.md), choosing **upload-station**, then run
your installer-created `start.sh`. For an existing installation, run
`./scripts/role.sh` from your authenticated source checkout.

Follow [role onboarding](../role-onboarding.md): prepare the online image,
import the public ceremony/enrollment files, and create the release Phase 2
profile. Skip identity generation: this station must not hold signing keys.

Choose **Continue the ceremony workflow**.

## Verify, upload, and hand off

1. Agree on the evidence type, expected signer, and transfer procedure.
2. Receive only the expected public files and a fresh role-scoped private grant.
3. Verify the complete signed release through the menu. Independently obtain
   the expected final signer's public key and check the ceremony and assignment.
4. Select the directory containing only signed public output and the grant file.
5. Upload. A private Tessera role connection reports the manifest key
   automatically; otherwise send it to the coordinator.

Transport success is not evidence acceptance. Retain the public evidence and
logs according to the agreed retention procedure.

## If something fails

Keep the signed files unchanged. Review the error and grant expiry before
retrying through [workflow recovery](../role-workflow.md#recovery).
This station has no participant-style candidate-resume command.
