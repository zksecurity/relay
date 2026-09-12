# Public witness

You independently observe a phase closure before its agreed beacon round.

## Start or resume

Complete [installation](../install.md), then run your installer-created
`start.sh`. Existing installation? Run `./scripts/role.sh` from your
authenticated source checkout.

Follow [role onboarding](../role-onboarding.md): prepare images, generate your
identity, send only `identity.json` to the coordinator, import your public
ceremony files, review/sign your enrollment, and create the phase profiles.

Choose **Continue the ceremony workflow** for the numbered witness steps.

## Follow the workflow

1. Confirm your assignment and independently authenticate the coordinator.
2. Begin observing before the agreed window; tell the coordinator you are ready.
   A one-time check fails if the closure is not published yet.
3. Retrieve and retain the exact closure bytes during the window.
   Polling alone does not preserve all observation evidence.
4. Enter when **you actually observed** publication. Check that it precedes
   the beacon round by the required lead time; do not copy someone else's time.
5. Prepare and review your receipt. The helper uses the prepared network-disabled
   signing image with your own key and verifies the signature. Disconnecting the
   host too is an optional extra precaution unless ceremony policy requires it.
6. Upload the signed public output using your private grant.
   A private Tessera role connection reports the manifest key automatically.
   Otherwise send it to the coordinator. Retain the observation evidence.

Your enrollment also requires your own reviewed signature bound to this ceremony;
a coordinator-provided signature is not your consent.

## If something fails

Report a missed window or clock error instead of signing an unsupported claim.
Keep the evidence and restart the same [guided workflow](../role-workflow.md#recovery).
Never change a timestamp or signed file to make verification pass.
