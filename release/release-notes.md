## What changed

- Relay releases now include a short, reviewed summary of the user-visible and operational changes.
- Pull requests must update this summary, so release pages do not fall back to a raw commit list or a generic build message.
- Final release signing now works with the documented one-auditor minimum. The pinned proof tool previously rejected fewer than two audit reports at its command-line boundary.
- Pull requests retain a real two-phase future-beacon ceremony with a 12-second non-production witness window. Protected-main and scheduled runs use Tessera's full 180-second rehearsal window.
- Guided custody now keeps the coordinator's online workflow and offline signer under one ceremony name. Older local profiles are migrated with a retained backup, or Relay stops if two possible profiles would make the choice ambiguous.
- Participant custody setup now retains its public work, trust, and key-folder references so handoff receipts can use the already-prepared offline signer.
- Guided menus now explain why each action is needed in plain language. Production decision actions are shown as required only after Relay authenticates that the ceremony is production; rehearsal actions remain hidden.
- Guided role menus now separate numbered ceremony actions from letter-keyed navigation: view an area's details, open the ceremony map, review results, go back, or save and exit. These navigation controls never complete or skip work.
- Guided recommendations follow the authored workflow order, not a local readiness heuristic. Readiness explains why the prescribed next action is waiting; it cannot let a later handoff leapfrog a contribution awaiting a fresh grant or profile.
- When preparing a participant's outbound custody packet or issuing their grant, Relay now displays the ordered participant IDs from the authenticated phase schedule, marks the expected next participant, and fills that value without allowing an out-of-order substitution.
- Guided workflows create a required offline signing profile when it is missing, before offline custody work begins. Recipe-fixed custody direction is displayed for review and cannot be mistyped as a menu number.

## Tessera compatibility

Ceremony data, guided actions, and the Tessera handoff contract are unchanged. The proof-tool pin is updated to the protected-main release containing the corrected one-auditor gate.
