## What changed

Relay now guides a V5 production GO/NO-GO review in the coordinator's `start.sh`
flow for ceremonies whose signed policy has no optional audit, witness, or
mirror requirements. It collects attributed answers, generates the required
review reports and decision draft, shows the reports before signing, and uses
the pinned proof-tool to prepare and verify the exact decision. Incomplete or
adverse structured answers yield NO-GO. The reviewed manual V5 draft path
remains available for other signed policies and recovery.

The coordinator can send the exact decision packet through the ceremony's
private AWS inbox. The release signer's upgraded `start.sh` has a separate
online, keyless action to download it, and another to return the already-signed
public decision signature. The coordinator issues separate temporary private
download and upload grants; the signer needs no persistent AWS profile. An
expired upload grant can be renewed without signing again. The signer still
reviews and signs offline. Object
hashes and the final checkpoint are checked during transfer; pinned proof-tool
verification remains required before the signature counts.

Before release signing, the coordinator can publish the frozen public review
snapshot through AWS. The signer downloads and hash-checks it from the public
origin in a keyless `start.sh` action, then authenticates and signs it offline.
After signing, another keyless action uploads only the verified public release
package with a temporary grant scoped to that signer and review checkpoint.
The coordinator fetches and verifies that package before recording the release.
The existing public-directory handoff remains available for recovery.

Host-side AWS calls for decision transfer and publication use the coordinator's
reviewed login binding instead of assuming its container-only profile exists on
the host. The legacy GO publication action checks access to the exact archive
and pointer keys before requesting the final publish confirmation.

For guided decisions, the coordinator verifies the required signatures and
packs the exact GO or NO-GO archive in the decision menu. It checks the
extracted staged archive against the signed decision before retaining it. A
GO archive can be shared through a chosen public channel without a separate
official-publication pointer; verifiers must independently compare the
ceremony ID. Older pointer-based publication records remain verifiable.

## Tessera compatibility

The setup contracts, signed ceremony format, and proof-tool pin are unchanged.
The AWS decision handoff and report display require this Relay release on both
the coordinator and release signer. Existing frozen ceremonies keep their
original approved release and may select coordinator and release-signer CLI
updates separately between completed operations. The signer update retains the
original network-disabled signing image and refuses incomplete local actions.
Tessera does not need a schema change for this
guided flow; it should treat the hosted archive and signed GO as historical
approval, not as a claim that the archive is the latest ceremony state.
