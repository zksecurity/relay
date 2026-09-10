# Auditor

You independently replay the ceremony and sign the resulting audit.

## Start or resume

Complete [installation](../install.md), then run your installer-created
`start.sh`. Existing installation? Run `./scripts/role.sh` from your
authenticated source checkout.

Follow [role onboarding](../role-onboarding.md): prepare images, generate your
identity, send only `identity.json` to the coordinator, import the public
ceremony/enrollment files, and create the phase profiles.
Keep your private key on your own trusted machine.

Choose **Continue the ceremony workflow** for the numbered audit steps.

## Follow the workflow

1. Confirm the signed assignment and independently authenticate the coordinator.
2. Acquire the transcript from independently checked sources and retain the
   source evidence. Do not rely solely on the coordinator's local copy.
3. Supply the complete transcript and operational evidence when prompted.
   Synchronization alone does not recheck every pre-existing local file.
4. Run the audit and review both phases, warnings, cleanup claims, and result.
   Cleanup claims do not prove physical erasure or exclude host/VM remnants.
5. Upload only the exact successful signed public audit with your scoped grant.
   A private Tessera role connection reports the resulting manifest key
   automatically. Otherwise send it to the coordinator.
6. Complete any required production decision and retain the audit inputs,
   source evidence, signed output, and secret-free logs.

A different signing key does not establish an independent person or organization.

## If something fails

Report failed replay or conflicting sources even if transport succeeded.
Preserve evidence, stop signing, and use [reviewed recovery](../role-workflow.md#recovery).
An upload does not mean the coordinator accepted your audit.
