## What changed

- Standalone AWS setup binds temporary logins to the coordinator host and renews
  verified credentials during Docker actions, including long-running uploads.
  The host login cache stays outside Docker. Static credential files remain
  supported.
- Renewal checks the original AWS account and principal, retries transient
  failures within the credential lifetime, and stops safely before expiry.
  The overall AWS login session still requires operator login when it ends.
- Older frozen images are not upgraded automatically. AWS CLI changes require
  reviewing and rebinding the host executable through storage setup.

## Tessera compatibility

Shared setup contracts, signed ceremony policy, proof-tool pins, and Tessera's
managed credential flow are unchanged. This change applies to standalone AWS
credential setup and compatible coordinator launchers.
