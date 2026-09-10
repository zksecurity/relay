# Prepare a ceremony

Use this helper before running participant turns. It keeps an editable draft
and asks separately before generating your key, signing, or checking cloud storage.
It does not send messages, publish ceremony artifacts, or provision buckets.

## Start or resume

Complete [installation](install.md), then run its printed `start.sh` command.
For an existing installation, run `./scripts/role.sh` from your authenticated
checkout and select your own installer-created settings file and coordinator role.
The earlier `./scripts/coordinator.sh` entry point remains available.
Reuse the same file and ceremony name when returning; never load someone else's
settings file. Standard policy settings are included in the launcher; no source
checkout or policy-file path is required when using the installed start script.
The installed Relay release must include `coordinator prepare`; older launchers
cannot run the helper. Install a matching new release rather than mixing binaries.

## Fill in the draft

If the ceremony was drafted in Tessera, start with **Open setup downloaded
from Tessera**. After initialization and verification, use **Export setup
for Tessera**. See the [website setup guide](tessera-setup-v2.md).

Setup highlights **NEXT REQUIRED ACTION** with its reason. Use **Show other
actions and requirements** for edits, optional checks, and offline preparation.
Action numbers stay stable. Choosing another action never bypasses its checks.

1. Choose **Basics**: explicitly select rehearsal or production and the circuit.
   Select from the numbered choices; no internal names need to be typed.
   `rehearsal-tiny-v1` is only for testing; `ownership-destination-v2` is the
   supported production circuit.
2. Generate your coordinator identity, or keep your existing keypair.
   The helper assigns an ID automatically; you only enter a public display name.
   Send only `identity.json` to the ceremony roles through your agreed channel.
   Accept the offer to assign it as your coordinator identity.
3. Import the final-parameter signer's identity, at least
   one auditor, and the participants. Compare each full fingerprint with its
   owner's copy through your independent channel, then type `VERIFIED` if it matches.
   Reimport the same ID to replace its draft entry; remove mistaken assignments
   with **Remove an identity assignment**. Private keys stay with their owners.
4. Choose **Orders, minimum contributions and reviewed beacon policy**.
   Choose the standard settings: drand Quicknet with a 180-second witness lead
   time. Pick participant orders and minimum counts from the prompts, then
   review and confirm. Reopening keeps your saved beacon settings by default.
   A custom policy file is available only through the **Advanced** choice.
   Review this choice with the roles. Adjust both participant orders and minimum
   contribution counts; the helper initially suggests the import order.
   Enter participant numbers such as `2,1,3`, not their generated identity IDs.
5. Both Intel/AMD and ARM64 computers are supported by default. Before
   initialization, the helper downloads and authenticates the companion Linux
   proof-tool build pinned by this release. No binary path is required.
   Macs use these Linux builds through Docker. Narrowing this selection or
   supplying a reviewed custom binary is available under **Supported computers**.
6. Choose **Storage settings**. For Cloudflare, choose **Set up Cloudflare R2
   and credentials** and follow the numbered prompts. Select existing buckets,
   then enter credentials only at the hidden prompt or select protected files.
   Any password manager works. Administrator-file import and individual
   infrastructure settings remain available. Saving settings alone does not
   prove permissions; approve **Check storage** to test actual access.

Witness and mirror enrollments happen after initialization because they must
refer to the exact signed definition. Different signing keys are checked;
different people or organizations are not established by software.

## Review, then initialize

Choose **Review draft**. Check the mode, circuit, public identities, both orders,
minimum counts, software selection and beacon policy with your ceremony roles.
You can save and exit without signing anything.
Required prompts repeat when left blank unless a valid default is shown.

Choose **Review and approve initialization** only when ready. Type the full displayed
confirmation, then review the Docker command and confirm again.
The helper first asks you to check storage, set it up, or explicitly prepare
offline. Offline preparation does not authorize grants or publication.
Production initialization can require substantial RAM, disk and computation.
The helper freezes a copy of the inputs before invoking proof-tool.

Success means proof-tool created the initial artifacts and authenticated the
signed definition against the coordinator key you confirmed earlier.
It does not mean a complete ceremony or a full transcript audit has succeeded.
Distribute the signed public definition for assignment review and collect
the required enrollments before granting participant access.
Choose **Prepare, review and sign MY coordinator enrollment** for your own
statement. Preload its network-disabled signing image and review your public
disclosure. Disconnecting the coordinator host is an additional precaution,
not required by this enrollment prompt; follow any stricter agreed procedure.
Other roles create and sign their own enrollments. Final-parameter signers
retain their dedicated disconnected-host signing procedure.

## Storage and next steps

After definition verification, find **Configure storage** under **Show other
actions and requirements**. This uses the
administrator's existing buckets and permissions. It writes temporary test
objects, checks access, and attempts to remove those objects.
Cloud costs can apply. R2 still needs the administrator's
[credential handoff](maintainer/r2.md).

Choose **Open ceremony operations and progress** for the
[resumable role menu](role-workflow.md). It saves shared settings and guides
the remaining stages without repeating initialization. The
[coordinator guide](roles/coordinator.md) summarizes handoffs and safe recovery.

## If something fails

Your draft is in `work/coordinator-setup/draft.json`. Frozen inputs and launch
activity records are retained. Never delete them just to make a retry pass.
After an initialization attempt, ceremony-setting edits are blocked; storage
settings remain separate. Use **Verify existing definition** after an interruption
if the signed output exists. A failed verification removes the success status.
For partial initialization, inspect the saved action and outputs with a maintainer;
the helper does not automatically re-sign, overwrite output, or restart a ceremony.
