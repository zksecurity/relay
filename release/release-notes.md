## What changed

This numbered release includes the guided ceremony changes published after v0.5.2.

- The V5 coordinator guide now generates the fixed public ownership proof during finalization, then reuses authenticated preliminary keys for release preparation. The final candidate still receives an independent full replay.
- The V4/V5 upload-station guide now verifies and uploads the release signer's public package without a signing key. After a signed NO-GO, the coordinator can prepare a closed public trial archive and the upload station can verify, publish, and read it back under a content-addressed test prefix. This path creates no approved production pointer.
- Fresh V5 decisions are written into the public evidence tree, and idle guide menus no longer report an operation as still running.
- Archive packing accepts a selected manifest with deliberately unbound hashes, fills those hashes from the selected files, and still rejects any mismatch against a pre-bound signed digest.

## Tessera compatibility

The setup contracts and signed ceremony formats are unchanged. This release pins proof-tool commit `8471106bcb796b88302e898f30377c6dfe0161b8` and packages its public finalization-evidence helper in the online role image. Existing frozen ceremonies remain on their pinned release. The NO-GO trial publication lane does not implement official GO promotion or authorize production ownership keys.
