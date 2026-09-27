## What changed

An initialized coordinator can select a Relay CLI update after an early generated
storage setup check failed, provided a later completed `configure-storage`
operation checked the corrected settings and wrote the exact ceremony-bound
configuration. Relay retains and reports the old failure. Interrupted setup
checks, unexpected outputs, and failed signing, upload, grant, or publication
actions still block the update. A failed storage probe may have left a test
object under `setup-probes/` if its cleanup also failed; operators should
inspect that prefix when the original error reported a cleanup failure.

## Tessera compatibility

The setup contracts, signed ceremony format, and proof-tool pin are unchanged.
Existing ceremonies retain their frozen role images. No Tessera schema or
website change is required. This is a Relay-only coordinator upgrade admission
fix; it does not alter the ceremony's mathematical verification or production
GO/NO-GO rules.
