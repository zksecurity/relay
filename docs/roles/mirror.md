# Mirror operator

You retain an independently controlled copy of the authenticated transcript.

## Start or resume

Complete [installation](../install.md), then run your installer-created
`start.sh`. Existing installation? Run `./scripts/role.sh` from your
authenticated source checkout.

Follow [role onboarding](../role-onboarding.md): prepare images, generate your
identity, send only `identity.json` to the coordinator, import your public
ceremony files, review/sign your enrollment, and create the phase profiles.

Choose **Continue the ceremony workflow** for the numbered mirror steps.

## Follow the workflow

1. Confirm your assignment and independently authenticate the coordinator.
2. Synchronize each required phase/head to storage you independently control.
   Two folders in one account do not establish independent administration.
3. Check that the exact bytes are durably retained at the agreed destination.
4. Confirm the authenticated local head, then enter the storage location and time.
   The public receipt uses a location digest; keep private location details
   out of shared logs.
5. Run the receipt verification over the complete retained files. Synchronizing
   alone does not rehash every pre-existing local file.
6. Review your receipt. The helper signs it in the prepared network-disabled
   image and verifies the signature. Disconnecting the host too is an optional
   extra precaution unless ceremony policy requires it.
7. Upload only signed public output with your scoped grant and send the
   manifest key to the coordinator. A private Tessera role connection performs
   this report automatically.

Enrollment and offline receipt signing are explicit handoffs, not automatic
approvals. Keep your signing key out of public transfers.

## Retain and recover

Retain the exact transcript for the agreed period. Report loss, mutation, or
changed administrative control. Preserve outputs after failure and restart the
same [guided workflow](../role-workflow.md#recovery); do not edit signed receipts.
