# Shared setup v3 contract

This contract uses `ceremony-setup-v3` and `two-phase-v3`, version 3. It adds an
explicit assurance policy and makes the beacon lead configurable in rehearsal
and production. Defaults are 180 seconds for rehearsal and 24 hours for
production; another positive value may be signed. Relay must prominently warn
before a coordinator signs a shorter production value.

Witnesses, mirrors and ceremony audits are independently configurable. Zero
explicitly disables a control. Witness and mirror identities are assigned and
enrolled after initialization; only their counts are signed here. External
security-audit signoffs remain represented in the proof protocol, but this
setup revision requires zero until the website and CLI implement their complete
collection journey. Production still requires two participants per phase and
all scheduled contributions.

`../setupv2/` and `../setupv2r2/` remain immutable for older ceremonies. Do not
convert or silently upgrade a frozen setup.

The new proof-tool and CLI release must be published and provisioned before this
revision is available in Tessera. Source changes alone do not update release pins.

This directory is the source of the public `ceremony-setup-v3` contract used by
the CLI and Tessera. `schema.json`, `ruleset.json`, `beacon.json`, `setup.mjs` and
`fixtures.json` are vendored byte-for-byte into Tessera by its
`scripts/sync-setup-contract.mjs` script. Go embeds the JSON resources here.

Both implementations reject duplicate keys, invalid Unicode, unknown fields and
versions, excessive nesting, and files larger than 8 MiB. Shared fixtures cover
canonical hashes and acceptance/rejection. Run `go test ./contracts/setupv3` in
this repository and Tessera's matching shared-contract test for the same vectors.

The website downloads its exact public `setup` object. The CLI retains the plan
and adds only `result`, preserving definition/signature/key/manifest bytes inside
base64 artifacts. Website ownership, account bindings and notification settings
are not part of this object. Phase membership exists only in the ordered phase
lists. Role IDs and signing identity IDs are different kinds of identifiers.

Hashes use RFC 8785 canonical JSON and these UTF-8 prefixes, including the newline:

* Input: `ceremony-setup-input-v3\n` plus the object without `result`.
* Result: `ceremony-setup-result-v3\n` plus the result object.
* Complete setup: `ceremony-setup-v3\n` plus the full setup object.

Artifact hashes cover exact original bytes. Ruleset and workflow-recipe hashes
cover canonical JSON without a prefix. The release manifest's contract hash
covers exact `schema.json` bytes. No digest is embedded in the object it hashes.

Contract validation does **not** authenticate signatures, release provenance,
ownership, protocol enrollment or progress. Callers must perform the appropriate
additional checks. The synthetic fixtures deliberately contain no real ceremony
signatures and must never be provisioned as trusted release metadata.

Public artifact base URLs use HTTPS with a DNS hostname, an optional valid port,
and an optional path. IP literals, user information, query strings, fragments,
control characters and malformed percent escapes are outside this v3 profile.
