## What changed

The V5 coordinator guide can preserve a locally prepared, unsigned GO/NO-GO decision and prepare a corrected one for the same signed final release. It checks the retained decision with the pinned proof-tool, blocks replacement after signing or handoff begins, and resumes an interrupted retirement from exact file hashes. The guided questionnaire now shows which answers keep GO gates pending, lets the coordinator edit a selected gate, and requires an explicit GO or NO-GO preparation phrase.

## Tessera compatibility

This is a Relay-only coordinator workflow change. The signed ceremony format, setup contracts, proof-tool pin, participant flow, and release-signer CLI are unchanged. Existing ceremonies remain on their frozen release; a coordinator update requires the supported upgrade check and must be qualified against its retained state before use.
