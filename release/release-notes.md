## What changed

- Fix AWS upload-grant issuance from a host IAM-user profile: once Relay captures and authenticates the credentials, it no longer asks the isolated AWS CLI to load the hidden profile again for AssumeRole.
- Preserve the exact issuer identity, scoped upload policy, and requested grant lifetime, including 12-hour grants.
- Document coordinator upgrades, release verification, resuming, and interrupted-installation recovery.

## Tessera compatibility

Tessera setup contracts, signed ceremony formats, proof-tool pins and upgrade records are unchanged. This fix affects host-side AWS grant issuance.
