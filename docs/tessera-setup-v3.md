# Tessera setup v3

Setup v3 is the website/CLI contract for ceremonies that use configurable
assurance roles and a configurable wait before the future beacon round. It is
an additive contract: Relay continues to accept and verify setup v2 files.

The signed setup records:

- the coordinator, final signer, participants and any enabled auditors;
- the participant order and minimum for both phases;
- the exact positive closure-to-beacon wait selected for this ceremony;
- how many witness, mirror, ceremony-audit and external-audit results are
required, where zero explicitly disables that requirement;
- the storage destinations and exact approved Relay/proof-tool release.

Relay imports the setup, verifies the release manifest, and reproduces the
same values in the signed ceremony definition. Before exporting the completed
setup, Relay verifies that the definition has the same circuit, beacon and
assurance policy. Changing any of those values requires a new website setup.

Witness and mirror identities are deliberately not part of the authoritative
setup plan. Only their required counts are signed. Tessera may keep invitations
as website-local coordination data; after initialization, the coordinator
assigns numbers and verifies each observer's signed enrollment.

New releases publish and attest `ceremony-software-manifest-v3.json`. Tessera
uses v3 for new ceremonies and retains v2 verification with the older release
selected by an existing v2 setup. A new release does not advertise a v2
manifest because its proof-tool emits definition v3.

The defaults remain 180 seconds for rehearsals and 86,400 seconds for
production. A shorter production wait is allowed only after an explicit CLI
warning and is recorded in the signed definition. Zero is never allowed.

Disabling an assurance role removes its required enrollment and evidence; it
does not weaken signature, contribution, beacon, final-file or release
verification. The CLI must show the lost assurance when a requirement is zero.

`--trusted-manifest` is an administrator-controlled trust input. Provision it
from the independently attested release catalogue; never accept a manifest
supplied beside an uploaded setup file. Relay may execute the selected image
before it can inspect the ceremony artifacts inside it.
