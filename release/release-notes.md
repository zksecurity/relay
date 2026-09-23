## What changed

- Verify public archives containing V4/V5 production GO decisions. Those decisions bind a final release checkpoint instead of reporting a manifest digest; Relay now checks that the approved checkpoint contains the same manifest as the release it independently verified and replayed.

## Tessera compatibility

The setup contracts and proof-tool pin are unchanged. This fixes public verification of V4/V5 ceremony archives and does not change signed ceremony files, existing frozen ceremonies, or the release and deployment selection process.
