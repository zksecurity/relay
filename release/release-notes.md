## What changed

- New standalone ceremonies use ownership-destination-v3 and the proof-tool
  release at `80f1692778e2d34813f0c9b20d3b7ddb3fec392b`. New definitions remove
  participant-independence and live twenty-party evidence as approval gates.
  Historical signed definitions retain their original requirements.
- Standalone production setup defaults to a 30-minute (1800-second) beacon wait
  in each phase. Shorter choices require explicit review; saved and signed
  policies retain their selected wait.
- Release signers can review a transferred public snapshot and sign offline.
  The coordinator imports their public enrollment and uploads the returned
  signed package. These handoff actions are recorded in the local activity log.
- The participant Docker launcher recognizes definition v5 when selecting the
  exact signed binary for its platform.
- New initialization rejects older circuit drafts and incompatible Tessera setup
  imports before changing ceremony state. Existing ceremonies use their original
  pinned release; no automatic migration is provided.

## Validation and limits

Both architecture assets of the pinned proof tool passed checksum and GitHub
attestation verification against the exact protected-main commit. Integration
validation, including the live AWS offline-signing rehearsal, is still pending.
This draft is not ready for a production ceremony or publication.

## Tessera compatibility

Shared setup contracts and historical verification paths are unchanged. This
release enables new standalone ceremonies only. New Tessera initialization needs
compatible circuit-v3 and definition-v5 contracts and a separate release rollout;
current setup imports are rejected with guidance to use their original release.
