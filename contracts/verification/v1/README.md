# Public ceremony verification archive v1

This contract is separate from `ceremony-setup-v2`: it packages a completed
ceremony's public protocol evidence. It does not change a frozen setup, replace
website data, restore a participant workspace, or contain executables/credentials.
The website hosting the ZIP supplies the trusted ceremony identity and public keys.

The ZIP contains `verification.json` plus exactly the regular files in its inventory.
Signed bytes are unchanged. The manifest has:

- `schema`: `ceremony-verification-v1`
- `ceremony_id`: protocol `sha256:...` ID (not the website UUID)
- `definition_sha256`: lowercase, unprefixed SHA-256 of the exact definition bytes
- `release_key_id`: expected release signer key ID, checked against the signed definition
- `inputs`: the fixed path map below; no executable, image, flags, URL or credential selectors
- `decision`: null for a rehearsal without approval; otherwise `{record, signatures, evidence_root}`
- `files`: `[{path, size, sha256}]`; SHA-256 is lowercase, unprefixed hex

Required input keys are `ceremony`, `ceremony-signature`,
`coordinator-public-key-file`, `transcript-root`, `keys-dir`,
`manifest-public-key-file`; for each phase, `phaseN-chain`,
`phaseN-chain-signature`, `phaseN-close`, `phaseN-close-signature`,
`phaseN-beacon`, `phaseN-beacon-signature`; additionally `phase1-seal` and
`phase1-seal-signature`. `keys-dir` is the complete signed release, which retains
its coordinator-signed candidate. Decision paths and evidence are also inventoried.
The signed definition alone determines whether production approval is required.

Paths use portable ASCII relative names, with no traversal, backslashes, symlinks,
special files, case collisions, or file/directory collisions. Only regular file ZIP
entries are accepted (omit directory entries). No missing or extra files are accepted.
The reader enforces duplicate/unknown JSON field rejection, UTF-8, depth 16,
16 MiB manifest size, 100,000 inventory files, and an explicit expanded-byte limit
(default 64 GiB, locally configurable up to 1 TiB). Extraction is into a fresh private
temporary directory; it never modifies a participant workspace. No archive code runs.

## Prepare a public package

Choose public files explicitly. Never point a recursive collection at a participant
workspace. Write a packing descriptor using the fields above and list every intended
file as `{ "path": "relative/public/file" }`; size/digests are filled by the packer.
Supply the signed protocol ID and release key ID from the ceremony. Include complete
transcripts, release, operational evidence, and production decision evidence if used.
Include downloaded Tessera record data as an additional inventoried file when desired;
it remains coordinator-reported website history, not authenticated protocol evidence.

```
relay pack-ceremony --manifest descriptor.json --root PUBLIC_DIR --out ceremony.zip
relay verify-ceremony --archive ceremony.zip
```

Packing rejects changed files and refuses to overwrite the output. It does not assert
verification or publish anything. The second command requires the locally installed
`mpc-ceremony` matching the installed CLI release's compiled checksum pin; a different
path can be supplied with `--mpc-ceremony`, but its pin is still enforced. Install tools
from the reviewed, attested release, never from this archive.

The verifier authenticates the definition through proof-tool inspection, verifies the
release, independently replays both phases, and verifies approval where applicable.
Approval must be GO and bind the exact manifest just verified; a valid NO-GO signature
or approval for a different release is not a pass. JSON output names passed, failed,
missing-evidence, not-run and not-applicable stages. Any required failure exits nonzero.
A rehearsal passing these checks does not acquire production approval.

Secret deletion, entropy quality, offline-host integrity, human independence, freshness
of the website snapshot, and the truth of website reports are not established.

## Availability and compatibility

Requires the proof-tool `replay` command and `release_manifest_sha256` in release and
decision verification output. This is PR code until compatible protected-main releases
are reviewed, built and provisioned. Existing frozen ceremonies pin exact software;
new verifier code cannot silently substitute for the historical binary. An archive
made with an older binary may therefore be unsupported for this unsigned replay path.
Never loosen that pin, sign a new audit, or regenerate the frozen ceremony to pass.

Tests: `go test ./...`; `go vet ./...`. The full Docker ceremony lane can additionally
pack and publicly verify its fresh output when `RELAY_VERIFY_MPC_BINARY` points to the
same new proof-tool binary as its explicitly supplied test image. It needs the normal
contributor host requirements (including disabled swap) and two future Quicknet rounds.
Test images and locally compiled tools must never enter the live release catalogue.
