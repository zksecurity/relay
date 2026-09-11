## What changed

- Relay releases now include a short, reviewed summary of the user-visible and operational changes.
- Pull requests must update this summary, so release pages do not fall back to a raw commit list or a generic build message.
- Final release signing now works with the documented one-auditor minimum. The pinned proof tool previously rejected fewer than two audit reports at its command-line boundary.

## Tessera compatibility

Ceremony data, guided actions, and the Tessera handoff contract are unchanged. The proof-tool pin is updated to the protected-main release containing the corrected one-auditor gate.
