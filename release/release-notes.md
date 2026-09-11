## What changed

- Relay releases now include a short, reviewed summary of the user-visible and operational changes.
- Pull requests must update this summary, so release pages do not fall back to a raw commit list or a generic build message.
- Final release signing now works with the documented one-auditor minimum. The pinned proof tool previously rejected fewer than two audit reports at its command-line boundary.
- Pull requests retain a real two-phase future-beacon ceremony with a 12-second non-production witness window. Protected-main and scheduled runs use Tessera's full 180-second rehearsal window.
- Guided custody now keeps the coordinator's online workflow and offline signer under one ceremony name. Older local profiles are migrated with a retained backup, or Relay stops if two possible profiles would make the choice ambiguous.
- Participant custody setup now retains its public work, trust, and key-folder references so handoff receipts can use the already-prepared offline signer.

## Tessera compatibility

Ceremony data, guided actions, and the Tessera handoff contract are unchanged. The proof-tool pin is updated to the protected-main release containing the corrected one-auditor gate.
