# Final-parameter signer

You independently review and sign the final ceremony parameters.
This role is separate from publishing Relay software.

## Start or resume

Complete [installation](../install.md), then run your installer-created
`start.sh`. Existing installation? Run `./scripts/role.sh` from your
authenticated source checkout.

1. Choose **Prepare approved images** while still online. This prepares both
   identity generation and the offline signing workflow.
2. Disconnect the signing machine before generating its key, reviewing, or signing.
   A network-isolated container does not disconnect the host.
3. Generate your identity through the helper; transfer only `identity.json`
   to the coordinator using the agreed public-file transfer procedure.
4. Import the public ceremony and enrollment files, independently authenticate
   the coordinator, and choose **Continue the ceremony workflow**.
   This role does not need a transport profile.

Prepared actions do not download images or contact GitHub. Do not choose image
preparation again while operating offline. Never bring storage credentials
or an online upload profile onto the signing machine.

## Follow the workflow

- Review the exact candidate, both phases, auditor identities, beacon evidence,
  witness/mirror evidence, incidents, and contribution-bound cleanup statements.
- Supply the evidence paths when prompted and require verification to pass.
- Authorize signing only the exact verified release manifest.
- Independently verify the signed release and complete any required production
  decision. A tiny rehearsal does not satisfy production decision requirements.
- Transfer only the signed public output to the separate
  [upload station](../tasks/upload.md). Keep your private key offline.

Cleanup statements do not prove physical erasure or exclude host/VM remnants.

## If something fails

Retain the output and investigate before signing or retrying.
Use [reviewed recovery](../role-workflow.md#recovery); do not sign substitute
files or infer success from an upload. Report suspected key exposure immediately.
