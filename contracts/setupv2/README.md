# Shared setup v2 contract

This directory is the source of the public `ceremony-setup-v2` contract used by
the CLI and Tessera. `schema.json`, `ruleset.json`, `beacon.json`, `setup.mjs` and
`fixtures.json` are vendored byte-for-byte into Tessera by its
`scripts/sync-setup-contract.mjs` script. Go embeds the JSON resources here.

Both implementations reject duplicate keys, invalid Unicode, unknown fields and
versions, excessive nesting, and files larger than 8 MiB. Shared fixtures cover
canonical hashes and acceptance/rejection. Run `go test ./contracts/setupv2` in
this repository and Tessera's `tessera-setup-v2.test.mjs` for the same vectors.

The website downloads its exact public `setup` object. The CLI retains the plan
and adds only `result`, preserving definition/signature/key/manifest bytes inside
base64 artifacts. Website ownership, account bindings and notification settings
are not part of this object. Phase membership exists only in the ordered phase
lists. Role IDs and signing identity IDs are different kinds of identifiers.

Hashes use RFC 8785 canonical JSON and these UTF-8 prefixes, including the newline:

* Input: `ceremony-setup-input-v2\n` plus the object without `result`.
* Result: `ceremony-setup-result-v2\n` plus the result object.
* Complete setup: `ceremony-setup-v2\n` plus the full setup object.

Artifact hashes cover exact original bytes. Ruleset and workflow-recipe hashes
cover canonical JSON without a prefix. The release manifest's contract hash
covers exact `schema.json` bytes. No digest is embedded in the object it hashes.

Contract validation does **not** authenticate signatures, release provenance,
ownership, protocol enrollment or progress. Callers must perform the appropriate
additional checks. The synthetic fixtures deliberately contain no real ceremony
signatures and must never be provisioned as trusted release metadata.

Public artifact base URLs use HTTPS with a DNS hostname, an optional valid port,
and an optional path. IP literals, user information, query strings, fragments,
control characters and malformed percent escapes are outside this v2 profile.
