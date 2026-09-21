## What changed

- Clarify the storage-first role menu prompt: “Choose an action [Enter = save
  and exit]”. Pressing Enter still exits; type the displayed action number to
  continue. This avoids presenting Q as a suggested next ceremony action.
- Release this fix as `v0.2.1` and require an explicit version check in the
  maintainer guidance for future user-facing changes.

## Tessera compatibility

Tessera setup contracts, signed artifacts, role actions and software pins are
unchanged. This is a prompt clarification only; existing ceremonies keep their
frozen launcher and its original wording.
