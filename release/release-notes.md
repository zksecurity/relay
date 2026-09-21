## What changed

- Clarify the storage-first role menu prompt: “Choose an action [Enter = save
  and exit]”. Pressing Enter still exits; type the displayed action number to
  continue. This avoids presenting Q as a suggested next ceremony action.
- Show start, one-minute elapsed-time heartbeats, and completion or failure while
  Relay waits for Phase 1 and Phase 2 contribution computation. The heartbeat
  indicates elapsed waiting time, not a percentage or proof of forward progress.
- Show candidate-upload file sizes, staging and retry-verification steps, bytes
  confirmed in storage, and elapsed heartbeats. Counts advance after complete
  files are confirmed; the final upload manifest remains last. Upload completion
  still requires coordinator verification and signed acceptance.
- Release this fix as `v0.2.1` and require an explicit version check in the
  maintainer guidance for future user-facing changes.

## Tessera compatibility

Tessera setup contracts, signed artifacts, role actions and software pins are
unchanged. This is a prompt clarification only; existing ceremonies keep their
frozen launcher and its original wording.
