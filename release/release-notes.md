## What changed

- AWS storage-first enrollment, contribution and release grants use the configured
  grant-role maximum, up to 12 hours. Existing 1h configurations remain at 1h.
- Explain AWS role-chaining rejection for longer grants. An IAM-user caller ARN
  alone does not establish eligibility for 12h sessions.
- Older clients retain their one-hour acceptance limit. Longer grants require
  compatible updated clients; frozen ceremonies are not upgraded.

## Tessera compatibility

Shared setup contracts, signed ceremony policy and proof-tool pins are unchanged.
Tessera must use compatible Relay clients before issuing grants longer than one
hour. Website activation and its credential issuer are not changed here.
