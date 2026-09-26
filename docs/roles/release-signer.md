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
preparation again while operating offline. The GO decision handoff uses a
separate online, keyless `start.sh` action with temporary grants kept outside
the signing work, key, and trust folders. Exit that action and disconnect the
host before reviewing or signing. An existing V5 signer can follow the
[release-signer update guide](../release-signer-upgrade.md) to add this menu.

## Follow the workflow

- Review the exact candidate, both phases, any enabled auditor identities, the signed beacon records,
  witness/mirror evidence, incidents, and contribution-bound cleanup statements.
- Supply the evidence paths when prompted and require verification to pass.
- Authorize signing only the exact verified release manifest.
- Independently verify the signed release and complete the production decision
  when the signed ceremony uses production mode. Rehearsal mode does not require
  this decision. A GO for a tiny or K11 test circuit approves only its exact
  signed circuit and release; those keys do not prove ownership.
- Transfer only the signed public output to the coordinator for
  [verification and publication](../tasks/upload.md). Keep your private key offline.

Cleanup statements do not prove physical erasure or exclude host/VM remnants.

## If something fails

Retain the output and investigate before signing or retrying.
Restart the same [guided workflow](../role-workflow.md#recovery); do not sign
substitute files or infer success from an upload. Report suspected key exposure
immediately.
